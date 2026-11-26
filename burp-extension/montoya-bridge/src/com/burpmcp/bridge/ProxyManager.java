package com.burpmcp.bridge;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.http.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Manages live HTTP Proxy interception queue and Match/Replace rules via Montoya handlers.
 */
public final class ProxyManager implements ProxyRequestHandler, ProxyResponseHandler {
    private static final long INTERCEPT_TIMEOUT_SECONDS = 120L;

    public static final class MatchReplaceRule {
        public final String id;
        public final String ruleType;
        public final String match;
        public final String replace;
        public final boolean isSimpleMatch;
        public final boolean enabled;
        public final String comment;

        public MatchReplaceRule(String id, String ruleType, String match, String replace,
                                boolean isSimpleMatch, boolean enabled, String comment) {
            this.id = id;
            this.ruleType = ruleType;
            this.match = match;
            this.replace = replace;
            this.isSimpleMatch = isSimpleMatch;
            this.enabled = enabled;
            this.comment = comment;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id);
            m.put("rule_type", ruleType);
            m.put("match", match);
            m.put("replace", replace);
            m.put("is_simple_match", isSimpleMatch);
            m.put("enabled", enabled);
            m.put("comment", comment);
            return m;
        }
    }

    private static final class PendingMessage {
        final CountDownLatch latch = new CountDownLatch(1);
        final boolean isRequest;
        final Map<String, Object> summary;
        volatile String action = "forward";
        volatile String modifiedRaw;

        PendingMessage(boolean isRequest, Map<String, Object> summary) {
            this.isRequest = isRequest;
            this.summary = summary;
        }
    }

    private final MontoyaApi api;
    private volatile boolean interceptRequests;
    private volatile boolean interceptResponses;
    private final List<MatchReplaceRule> rules = new CopyOnWriteArrayList<>();
    private final ConcurrentHashMap<String, PendingMessage> pending = new ConcurrentHashMap<>();

    public ProxyManager(MontoyaApi api) {
        this.api = api;
    }

    public Map<String, Object> setIntercept(boolean isRequest, boolean enabled) {
        if (isRequest) {
            this.interceptRequests = enabled;
        } else {
            this.interceptResponses = enabled;
        }
        if (interceptRequests || interceptResponses) {
            api.proxy().enableIntercept();
        } else {
            api.proxy().disableIntercept();
        }
        int released = 0;
        if (!enabled) {
            for (PendingMessage pm : pending.values()) {
                if (pm.isRequest == isRequest) {
                    pm.action = "forward";
                    pm.latch.countDown();
                    released++;
                }
            }
        }
        Map<String, Object> res = new LinkedHashMap<>();
        res.put("intercept_requests", interceptRequests);
        res.put("intercept_responses", interceptResponses);
        res.put("released_pending", released);
        return res;
    }

    public void releaseAll() {
        for (PendingMessage pm : pending.values()) {
            pm.action = "forward";
            pm.latch.countDown();
        }
        pending.clear();
    }

    public List<Map<String, Object>> listPending() {
        List<Map<String, Object>> list = new ArrayList<>();
        for (PendingMessage pm : pending.values()) {
            list.add(new LinkedHashMap<>(pm.summary));
        }
        return list;
    }

    public boolean resolvePending(String id, String action, String modifiedRaw) {
        PendingMessage pm = pending.get(id);
        if (pm == null) return false;
        pm.action = action;
        pm.modifiedRaw = modifiedRaw;
        pm.latch.countDown();
        return true;
    }

    public List<Map<String, Object>> listRules() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (MatchReplaceRule r : rules) out.add(r.toMap());
        return out;
    }

    public MatchReplaceRule addRule(Map<String, Object> body) {
        MatchReplaceRule r = new MatchReplaceRule(
            UUID.randomUUID().toString().substring(0, 8),
            Optional.ofNullable(BridgeSupport.asString(body.get("rule_type"))).orElse("request_header"),
            Optional.ofNullable(BridgeSupport.asString(body.get("match"))).orElse(""),
            Optional.ofNullable(BridgeSupport.asString(body.get("replace"))).orElse(""),
            Optional.ofNullable(BridgeSupport.asBool(body.get("is_simple_match"))).orElse(true),
            Optional.ofNullable(BridgeSupport.asBool(body.get("enabled"))).orElse(true),
            Optional.ofNullable(BridgeSupport.asString(body.get("comment"))).orElse("")
        );
        rules.add(r);
        return r;
    }

    public boolean deleteRule(String id) {
        return rules.removeIf(r -> r.id.equals(id));
    }

    private static String applySubstitution(String text, MatchReplaceRule rule, boolean[] changed) {
        if (rule.match == null || rule.match.isEmpty() || text == null) return text;
        if (rule.isSimpleMatch) {
            if (text.contains(rule.match)) {
                changed[0] = true;
                return text.replace(rule.match, rule.replace);
            }
            return text;
        }
        Matcher m = Pattern.compile(rule.match).matcher(text);
        if (m.find()) {
            changed[0] = true;
            return m.replaceAll(Matcher.quoteReplacement(rule.replace));
        }
        return text;
    }

    private String applyRules(boolean isRequest, String raw) {
        if (rules.isEmpty() || raw == null || raw.isEmpty()) return raw;
        String sep = raw.contains("\r\n\r\n") ? "\r\n\r\n" : "\n\n";
        String lineSep = raw.contains("\r\n") ? "\r\n" : "\n";
        int splitIdx = raw.indexOf(sep);
        String head = splitIdx >= 0 ? raw.substring(0, splitIdx) : raw;
        String body = splitIdx >= 0 ? raw.substring(splitIdx + sep.length()) : "";
        String[] headLines = head.split(Pattern.quote(lineSep), -1);
        String firstLine = headLines.length > 0 ? headLines[0] : "";
        List<String> hdrLines = new ArrayList<>();
        for (int i = 1; i < headLines.length; i++) hdrLines.add(headLines[i]);

        boolean[] changed = {false};
        for (MatchReplaceRule rule : rules) {
            if (!rule.enabled) continue;
            if (isRequest && "request_first_line".equals(rule.ruleType)) {
                firstLine = applySubstitution(firstLine, rule, changed);
            } else if (isRequest && "request_header".equals(rule.ruleType)) {
                List<String> next = new ArrayList<>();
                for (String hl : hdrLines) {
                    String nl = applySubstitution(hl, rule, changed);
                    if (nl != null && !nl.isEmpty()) next.add(nl);
                }
                hdrLines = next;
            } else if (isRequest && "request_body".equals(rule.ruleType)) {
                body = applySubstitution(body, rule, changed);
            } else if (!isRequest && "response_header".equals(rule.ruleType)) {
                List<String> next = new ArrayList<>();
                for (String hl : hdrLines) {
                    String nl = applySubstitution(hl, rule, changed);
                    if (nl != null && !nl.isEmpty()) next.add(nl);
                }
                hdrLines = next;
            } else if (!isRequest && "response_body".equals(rule.ruleType)) {
                body = applySubstitution(body, rule, changed);
            }
        }
        if (!changed[0]) return raw;
        List<String> rebuilt = new ArrayList<>();
        rebuilt.add(firstLine);
        rebuilt.addAll(hdrLines);
        return String.join(lineSep, rebuilt) + sep + body;
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest req) {
        String original = req.toByteArray().toString();
        String rewritten = applyRules(true, original);
        HttpRequest current = rewritten.equals(original)
            ? req
            : HttpRequest.httpRequest(req.httpService(), rewritten);

        if (!interceptRequests) {
            return ProxyRequestReceivedAction.continueWith(current);
        }

        String id = String.valueOf(req.messageId());
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("id", id);
        summary.put("is_request", true);
        summary.put("host", req.httpService().host());
        summary.put("port", req.httpService().port());
        summary.put("protocol", req.httpService().secure() ? "https" : "http");
        summary.put("method", req.method());
        summary.put("url", req.url());
        summary.put("raw", BridgeSupport.safePrefix(rewritten, 20000));

        PendingMessage pm = new PendingMessage(true, summary);
        pending.put(id, pm);
        try {
            pm.latch.await(INTERCEPT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        } finally {
            pending.remove(id);
        }

        if ("drop".equals(pm.action)) {
            return ProxyRequestReceivedAction.drop();
        }
        if (pm.modifiedRaw != null) {
            current = HttpRequest.httpRequest(req.httpService(), pm.modifiedRaw);
        }
        return ProxyRequestReceivedAction.doNotIntercept(current);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest req) {
        return ProxyRequestToBeSentAction.continueWith(req);
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse resp) {
        String original = resp.toByteArray().toString();
        String rewritten = applyRules(false, original);
        HttpResponse current = rewritten.equals(original)
            ? resp
            : HttpResponse.httpResponse(rewritten);

        if (!interceptResponses) {
            return ProxyResponseReceivedAction.continueWith(current);
        }

        String id = "resp-" + resp.messageId();
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("id", id);
        summary.put("is_request", false);
        summary.put("host", resp.initiatingRequest().httpService().host());
        summary.put("port", resp.initiatingRequest().httpService().port());
        summary.put("protocol", resp.initiatingRequest().httpService().secure() ? "https" : "http");
        summary.put("method", resp.initiatingRequest().method());
        summary.put("url", resp.initiatingRequest().url());
        summary.put("status_code", (int) resp.statusCode());
        summary.put("raw", BridgeSupport.safePrefix(rewritten, 20000));

        PendingMessage pm = new PendingMessage(false, summary);
        pending.put(id, pm);
        try {
            pm.latch.await(INTERCEPT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        } finally {
            pending.remove(id);
        }

        if ("drop".equals(pm.action)) {
            return ProxyResponseReceivedAction.drop();
        }
        if (pm.modifiedRaw != null) {
            current = HttpResponse.httpResponse(pm.modifiedRaw);
        }
        return ProxyResponseReceivedAction.doNotIntercept(current);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse resp) {
        return ProxyResponseToBeSentAction.continueWith(resp);
    }
}
