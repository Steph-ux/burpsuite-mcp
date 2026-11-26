package com.burpmcp.bridge;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.EnhancedCapability;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.bambda.BambdaImportResult;
import burp.api.montoya.burpsuite.TaskExecutionEngine;
import burp.api.montoya.core.Version;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.intruder.HttpRequestTemplate;
import burp.api.montoya.organizer.OrganizerItem;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.bchecks.BCheckImportResult;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.net.InetSocketAddress;
import java.net.URI;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;

/**
 * Full Burp Suite Professional / Community Montoya Bridge for burpsuite-mcp.
 * Exposes all REST endpoints expected by burpsuite-mcp on 127.0.0.1:1337.
 */
public final class MontoyaBridgeExtension implements BurpExtension {
    private static final String BRIDGE_ID = "burp-mcp-pro-bridge";
    private static final String BRIDGE_NAME = "BurpSuite MCP Full Pro Bridge (Montoya)";
    private static final String BRIDGE_VERSION = "1.0.0";

    private MontoyaApi api;
    private ProxyManager proxyMgr;
    private ProFeaturesManager proMgr;
    private HttpServer server;
    private String apiKey = "";
    private final List<String> outputLog = new CopyOnWriteArrayList<>();
    private final Map<String, List<Map<String, Object>>> trackedScope = new LinkedHashMap<>();

    @Override
    public Set<EnhancedCapability> enhancedCapabilities() {
        return EnumSet.noneOf(EnhancedCapability.class);
    }

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.trackedScope.put("include", new CopyOnWriteArrayList<>());
        this.trackedScope.put("exclude", new CopyOnWriteArrayList<>());

        api.extension().setName(BRIDGE_NAME);
        this.proxyMgr = new ProxyManager(api);
        this.proMgr = new ProFeaturesManager(api);

        api.proxy().registerRequestHandler(proxyMgr);
        api.proxy().registerResponseHandler(proxyMgr);

        int port = 1337;
        String envPort = System.getenv("BURP_API_PORT");
        if (envPort != null && !envPort.isBlank()) {
            try { port = Integer.parseInt(envPort.trim()); } catch (NumberFormatException ignored) {}
        }
        String envKey = System.getenv("BURP_API_KEY");
        this.apiKey = envKey == null ? "" : envKey;

        try {
            this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
            this.server.createContext("/", this::handleHttp);
            this.server.setExecutor(Executors.newFixedThreadPool(6));
            this.server.start();
            log("[" + BRIDGE_NAME + " v" + BRIDGE_VERSION + "] Listening on http://127.0.0.1:" + port
                + " (edition=" + api.burpSuite().version().edition()
                + ", api_key=" + (apiKey.isEmpty() ? "disabled" : "configured") + ")");
        } catch (Exception e) {
            api.logging().logToError("[" + BRIDGE_NAME + "] Failed to start HTTP server on port " + port, e);
            return;
        }

        api.extension().registerUnloadingHandler(() -> {
            log("[" + BRIDGE_NAME + "] Unloading...");
            if (proxyMgr != null) proxyMgr.releaseAll();
            if (proMgr != null) proMgr.shutdown();
            if (server != null) server.stop(0);
        });
    }

    private void log(String msg) {
        api.logging().logToOutput(msg);
        outputLog.add(msg);
        while (outputLog.size() > 300) {
            outputLog.remove(0);
        }
    }

    private void handleHttp(HttpExchange exchange) {
        try {
            String path = BridgeSupport.checkAuthAndStripPath(exchange, apiKey);
            if (path == null) {
                BridgeSupport.sendJson(exchange, 401, Map.of("error", "Unauthorized"));
                return;
            }
            String method = exchange.getRequestMethod().toUpperCase(Locale.ROOT);
            Map<String, String> query = BridgeSupport.parseQuery(exchange.getRequestURI().getRawQuery());

            // ── Root / Core / Version ─────────────────────────
            if ("GET".equals(method) && ("/v0.1".equals(path) || "/v0.1/".equals(path))) {
                BridgeSupport.sendJson(exchange, 200, Map.of(
                    "bridge", BRIDGE_ID,
                    "version", BRIDGE_VERSION,
                    "montoya", true,
                    "edition", api.burpSuite().version().edition().name(),
                    "pro", proMgr.isProfessional()
                ));
                return;
            }

            if ("GET".equals(method) && ("/v0.1/burp/version".equals(path) || "/burp/versions".equals(path))) {
                Version v = api.burpSuite().version();
                Map<String, Object> out = new LinkedHashMap<>();
                out.put("edition", v.name());
                out.put("edition_enum", v.edition().name());
                out.put("version", v.toString());
                out.put("buildNumber", v.buildNumber());
                out.put("project", Map.of("id", api.project().id(), "name", api.project().name()));
                out.put("bridge", true);
                out.put("bridge_type", "montoya");
                BridgeSupport.sendJson(exchange, 200, out);
                return;
            }

            if ("GET".equals(method) && "/v0.1/burp/configuration".equals(path)) {
                String json = api.burpSuite().exportProjectOptionsAsJson();
                BridgeSupport.sendJson(exchange, 200, JsonCodec.parse(json));
                return;
            }

            if ("PUT".equals(method) && "/v0.1/burp/configuration".equals(path)) {
                String raw = BridgeSupport.readBodyString(exchange);
                api.burpSuite().importProjectOptionsFromJson(raw);
                BridgeSupport.sendJson(exchange, 200, Map.of("updated", true));
                return;
            }

            if ("/v0.1/burp/task_engine".equals(path)) {
                TaskExecutionEngine engine = api.burpSuite().taskExecutionEngine();
                if ("POST".equals(method) || "PUT".equals(method)) {
                    Map<String, Object> body = BridgeSupport.readJsonBody(exchange);
                    String desired = Optional.ofNullable(BridgeSupport.asString(body.get("state"))).orElse("").toUpperCase(Locale.ROOT);
                    if ("PAUSED".equals(desired)) {
                        engine.setState(TaskExecutionEngine.TaskExecutionEngineState.PAUSED);
                    } else if ("RUNNING".equals(desired)) {
                        engine.setState(TaskExecutionEngine.TaskExecutionEngineState.RUNNING);
                    } else {
                        BridgeSupport.sendJson(exchange, 400, Map.of("error", "state must be RUNNING or PAUSED"));
                        return;
                    }
                }
                BridgeSupport.sendJson(exchange, 200, Map.of("state", engine.getState().name()));
                return;
            }

            // ── Proxy History & WebSockets ────────────────────
            if ("GET".equals(method) && "/v0.1/proxy/history".equals(path)) {
                boolean includeBody = !"false".equalsIgnoreCase(query.getOrDefault("include_body", "true"));
                String filter = query.getOrDefault("filter", "").toLowerCase(Locale.ROOT);
                Integer limit = BridgeSupport.asInt(query.get("limit"));
                boolean inScopeOnly = "true".equalsIgnoreCase(query.get("in_scope"));

                List<ProxyHttpRequestResponse> raw = api.proxy().history();
                List<Map<String, Object>> messages = new ArrayList<>();
                for (int i = 0; i < raw.size(); i++) {
                    ProxyHttpRequestResponse item = raw.get(i);
                    HttpRequest req = item.finalRequest() != null ? item.finalRequest() : item.request();
                    if (inScopeOnly && (req == null || !req.isInScope())) continue;
                    String reqUrl = req != null && req.url() != null ? req.url() : "";
                    if (!filter.isEmpty() && !reqUrl.toLowerCase(Locale.ROOT).contains(filter)) {
                        continue;
                    }
                    messages.add(BridgeSupport.serializeProxyEntry(item, i + 1, includeBody, 16384));
                    if (limit != null && messages.size() >= limit) break;
                }
                BridgeSupport.sendJson(exchange, 200, Map.of("messages", messages));
                return;
            }

            if ("GET".equals(method) && path.startsWith("/v0.1/proxy/history/")) {
                int targetId = Integer.parseInt(path.substring(path.lastIndexOf('/') + 1));
                List<ProxyHttpRequestResponse> raw = api.proxy().history();
                ProxyHttpRequestResponse match = null;
                for (ProxyHttpRequestResponse item : raw) {
                    if (item.id() == targetId) { match = item; break; }
                }
                if (match == null && targetId >= 1 && targetId <= raw.size()) {
                    match = raw.get(targetId - 1);
                }
                if (match == null) {
                    BridgeSupport.sendJson(exchange, 404, Map.of("error", "Proxy history item not found"));
                } else {
                    BridgeSupport.sendJson(exchange, 200, BridgeSupport.serializeProxyEntry(match, targetId, true, 100000));
                }
                return;
            }

            if ("GET".equals(method) && "/v0.1/proxy/websockets".equals(path)) {
                String filter = query.getOrDefault("filter", "").toLowerCase(Locale.ROOT);
                String dirFilter = query.getOrDefault("direction", "").toUpperCase(Locale.ROOT);
                Integer limit = BridgeSupport.asInt(query.get("limit"));

                List<ProxyWebSocketMessage> wsList = api.proxy().webSocketHistory();
                List<Map<String, Object>> messages = new ArrayList<>();
                for (ProxyWebSocketMessage ws : wsList) {
                    if (!dirFilter.isEmpty() && !ws.direction().name().equals(dirFilter)) continue;
                    String url = ws.upgradeRequest() != null ? ws.upgradeRequest().url() : "";
                    String payload = ws.payload() != null ? ws.payload().toString() : "";
                    if (!filter.isEmpty() && !url.toLowerCase(Locale.ROOT).contains(filter)
                        && !payload.toLowerCase(Locale.ROOT).contains(filter)) {
                        continue;
                    }
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("id", ws.id());
                    m.put("web_socket_id", ws.webSocketId());
                    m.put("direction", ws.direction().name());
                    m.put("url", url);
                    m.put("listener_port", ws.listenerPort());
                    m.put("time", ws.time() != null ? ws.time().toString() : null);
                    m.put("payload", BridgeSupport.safePrefix(payload, 32768));
                    m.put("payload_size", ws.payload() != null ? ws.payload().length() : 0);
                    m.put("edited_payload", ws.editedPayload() != null ? BridgeSupport.safePrefix(ws.editedPayload().toString(), 32768) : null);
                    messages.add(m);
                    if (limit != null && messages.size() >= limit) break;
                }
                BridgeSupport.sendJson(exchange, 200, Map.of("count", messages.size(), "messages", messages));
                return;
            }

            // ── Proxy Intercept & Match/Replace ───────────────
            if ("PUT".equals(method) && ("/v0.1/proxy/intercept_requests".equals(path) || "/v0.1/proxy/intercept_responses".equals(path))) {
                Map<String, Object> body = BridgeSupport.readJsonBody(exchange);
                boolean enabled = "enabled".equalsIgnoreCase(BridgeSupport.asString(body.get("intercept")));
                BridgeSupport.sendJson(exchange, 200, proxyMgr.setIntercept(path.endsWith("intercept_requests"), enabled));
                return;
            }

            if ("GET".equals(method) && "/v0.1/proxy/intercept_requests".equals(path)) {
                BridgeSupport.sendJson(exchange, 200, Map.of("requests", proxyMgr.listPending()));
                return;
            }

            if ("POST".equals(method) && path.startsWith("/v0.1/proxy/intercept_requests/")) {
                String[] parts = path.replaceAll("^/+|/+$", "").split("/");
                if (parts.length == 5 && ("forward".equals(parts[4]) || "drop".equals(parts[4]))) {
                    String itemId = parts[3];
                    String action = parts[4];
                    Map<String, Object> body = BridgeSupport.readJsonBody(exchange);
                    String modReq = "forward".equals(action) ? BridgeSupport.asString(body.get("request")) : null;
                    boolean ok = proxyMgr.resolvePending(itemId, action, modReq);
                    BridgeSupport.sendJson(exchange, ok ? 200 : 404,
                        ok ? Map.of("ok", true, "id", itemId, "action", action)
                           : Map.of("error", "Intercepted request not found", "id", itemId));
                    return;
                }
            }

            if ("GET".equals(method) && "/v0.1/proxy/match_replace_rules".equals(path)) {
                BridgeSupport.sendJson(exchange, 200, Map.of("rules", proxyMgr.listRules()));
                return;
            }

            if ("POST".equals(method) && "/v0.1/proxy/match_replace_rules".equals(path)) {
                Map<String, Object> body = BridgeSupport.readJsonBody(exchange);
                BridgeSupport.sendJson(exchange, 201, proxyMgr.addRule(body).toMap());
                return;
            }

            if ("DELETE".equals(method) && path.startsWith("/v0.1/proxy/match_replace_rules/")) {
                String ruleId = path.substring(path.lastIndexOf('/') + 1);
                boolean deleted = proxyMgr.deleteRule(ruleId);
                BridgeSupport.sendJson(exchange, deleted ? 200 : 404, Map.of("deleted", deleted, "id", ruleId));
                return;
            }

            // ── Target Sitemap & Scope ────────────────────────
            if ("GET".equals(method) && "/v0.1/target/sitemap".equals(path)) {
                String hostFilter = query.getOrDefault("host", query.getOrDefault("base_url", ""));
                List<AuditIssue> allIssues = api.siteMap().issues();

                Map<String, List<Map<String, Object>>> issuesByUrl = new HashMap<>();
                for (AuditIssue issue : allIssues) {
                    String bUrl = issue.baseUrl() != null ? issue.baseUrl() : "";
                    issuesByUrl.computeIfAbsent(bUrl, k -> new ArrayList<>()).add(BridgeSupport.serializeIssue(issue));
                }

                List<HttpRequestResponse> rrList = api.siteMap().requestResponses();
                List<Map<String, Object>> nodes = new ArrayList<>();
                String normFilter = hostFilter.toLowerCase(Locale.ROOT);
                for (int i = 0; i < rrList.size(); i++) {
                    HttpRequestResponse item = rrList.get(i);
                    String itemHost = item.httpService() != null ? item.httpService().host().toLowerCase(Locale.ROOT) : "";
                    String rawUrl = item.request() != null && item.request().url() != null ? item.request().url() : "";
                    String itemUrl = rawUrl.toLowerCase(Locale.ROOT);
                    if (!normFilter.isEmpty() && !itemHost.contains(normFilter) && !itemUrl.contains(normFilter)) {
                        continue;
                    }
                    List<Map<String, Object>> matched = issuesByUrl.get(rawUrl);
                    nodes.add(BridgeSupport.serializeSiteMapEntry(item, i + 1, matched, false, 4096));
                }
                BridgeSupport.sendJson(exchange, 200, nodes);
                return;
            }

            if ("GET".equals(method) && "/v0.1/target/scope".equals(path)) {
                BridgeSupport.sendJson(exchange, 200, trackedScope);
                return;
            }

            if ("GET".equals(method) && "/v0.1/target/scope/check".equals(path)) {
                String u = query.getOrDefault("url", "");
                boolean inScope = !u.isEmpty() && api.scope().isInScope(u);
                BridgeSupport.sendJson(exchange, 200, Map.of("inScope", inScope));
                return;
            }

            if ("PUT".equals(method) && "/v0.1/target/scope".equals(path)) {
                Map<String, Object> body = BridgeSupport.readJsonBody(exchange);
                updateScope(body.get("include"), true);
                updateScope(body.get("exclude"), false);
                BridgeSupport.sendJson(exchange, 200, Map.of("updated", true));
                return;
            }

            // ── Scanner, Issues, BChecks & Bambda (Pro!) ──────
            if ("POST".equals(method) && "/v0.1/scan".equals(path)) {
                if (!proMgr.isProfessional()) {
                    BridgeSupport.sendJson(exchange, 501, Map.of("error", "Endpoint not supported by Community Bridge"));
                    return;
                }
                Map<String, Object> body = BridgeSupport.readJsonBody(exchange);
                Map<String, Object> task = proMgr.startScan(body);
                String taskId = String.valueOf(task.get("task_id"));
                BridgeSupport.sendJson(exchange, 201, task, Map.of("Location", "/v0.1/scan/" + taskId));
                return;
            }

            if ("GET".equals(method) && "/v0.1/scan".equals(path)) {
                if (!proMgr.isProfessional()) {
                    BridgeSupport.sendJson(exchange, 501, Map.of("error", "Endpoint not supported by Community Bridge"));
                    return;
                }
                BridgeSupport.sendJson(exchange, 200, proMgr.listScans());
                return;
            }

            if ("GET".equals(method) && path.startsWith("/v0.1/scan/")) {
                if (!proMgr.isProfessional()) {
                    BridgeSupport.sendJson(exchange, 501, Map.of("error", "Endpoint not supported by Community Bridge"));
                    return;
                }
                String taskId = path.substring(path.lastIndexOf('/') + 1);
                Map<String, Object> detail = proMgr.getScan(taskId);
                BridgeSupport.sendJson(exchange, detail != null ? 200 : 404,
                    detail != null ? detail : Map.of("error", "Scan task not found", "task_id", taskId));
                return;
            }

            if ("DELETE".equals(method) && path.startsWith("/v0.1/scan/")) {
                String taskId = path.substring(path.lastIndexOf('/') + 1);
                boolean ok = proMgr.stopScan(taskId);
                BridgeSupport.sendJson(exchange, ok ? 200 : 404, Map.of("stopped", ok, "task_id", taskId));
                return;
            }

            if ("GET".equals(method) && ("/v0.1/issue-definitions".equals(path) || "/v0.1/knowledge_base/issue_definitions".equals(path))) {
                if (!proMgr.isProfessional()) {
                    BridgeSupport.sendJson(exchange, 501, Map.of("error", "Endpoint not supported by Community Bridge"));
                    return;
                }
                BridgeSupport.sendJson(exchange, 200, proMgr.listIssueDefinitions());
                return;
            }

            if ("GET".equals(method) && "/v0.1/scanner/issues".equals(path)) {
                String hostFilter = query.getOrDefault("host", "").toLowerCase(Locale.ROOT);
                String sevFilter = query.getOrDefault("severity", "").toLowerCase(Locale.ROOT);
                List<AuditIssue> issues = api.siteMap().issues();
                List<Map<String, Object>> out = new ArrayList<>();
                for (AuditIssue issue : issues) {
                    Map<String, Object> m = BridgeSupport.serializeIssue(issue);
                    String h = String.valueOf(m.getOrDefault("host", "")).toLowerCase(Locale.ROOT);
                    String bu = String.valueOf(m.getOrDefault("base_url", "")).toLowerCase(Locale.ROOT);
                    if (!hostFilter.isEmpty() && !h.contains(hostFilter) && !bu.contains(hostFilter)) continue;
                    if (!sevFilter.isEmpty() && !sevFilter.equals(String.valueOf(m.getOrDefault("severity", "")))) continue;
                    out.add(m);
                }
                BridgeSupport.sendJson(exchange, 200, Map.of("count", out.size(), "issues", out));
                return;
            }

            if ("POST".equals(method) && "/v0.1/scanner/bchecks".equals(path)) {
                if (!proMgr.isProfessional()) {
                    BridgeSupport.sendJson(exchange, 501, Map.of("error", "BChecks require Burp Suite Pro"));
                    return;
                }
                Map<String, Object> body = BridgeSupport.readJsonBody(exchange);
                String script = BridgeSupport.asString(body.get("script"));
                boolean enabled = Optional.ofNullable(BridgeSupport.asBool(body.get("enabled"))).orElse(true);
                if (script == null || script.isBlank()) {
                    BridgeSupport.sendJson(exchange, 400, Map.of("error", "script is required"));
                    return;
                }
                BCheckImportResult res = api.scanner().bChecks().importBCheck(script, enabled);
                BridgeSupport.sendJson(exchange, 200, Map.of(
                    "status", res.status().name(),
                    "ok", res.status() == BCheckImportResult.Status.LOADED_WITHOUT_ERRORS,
                    "errors", res.importErrors()
                ));
                return;
            }

            if ("POST".equals(method) && "/v0.1/bambda".equals(path)) {
                Map<String, Object> body = BridgeSupport.readJsonBody(exchange);
                String script = BridgeSupport.asString(body.get("script"));
                if (script == null || script.isBlank()) {
                    BridgeSupport.sendJson(exchange, 400, Map.of("error", "script is required"));
                    return;
                }
                BambdaImportResult res = api.bambda().importBambda(script);
                BridgeSupport.sendJson(exchange, 200, Map.of(
                    "status", res.status().name(),
                    "ok", res.status() == BambdaImportResult.Status.LOADED_WITHOUT_ERRORS,
                    "errors", res.importErrors()
                ));
                return;
            }

            // ── Collaborator OAST (Pro!) ──────────────────────
            if ("GET".equals(method) && "/v0.1/collaborator/status".equals(path)) {
                if (!proMgr.isProfessional()) {
                    BridgeSupport.sendJson(exchange, 501, Map.of("error", "Collaborator requires Burp Suite Pro"));
                    return;
                }
                BridgeSupport.sendJson(exchange, 200, proMgr.collaboratorStatus());
                return;
            }

            if ("POST".equals(method) && "/v0.1/collaborator/generate".equals(path)) {
                if (!proMgr.isProfessional()) {
                    BridgeSupport.sendJson(exchange, 501, Map.of("error", "Collaborator requires Burp Suite Pro"));
                    return;
                }
                Map<String, Object> body = BridgeSupport.readJsonBody(exchange);
                BridgeSupport.sendJson(exchange, 200, proMgr.generateCollaboratorPayload(body));
                return;
            }

            if ("GET".equals(method) && "/v0.1/collaborator/interactions".equals(path)) {
                if (!proMgr.isProfessional()) {
                    BridgeSupport.sendJson(exchange, 501, Map.of("error", "Collaborator requires Burp Suite Pro"));
                    return;
                }
                String filterId = query.getOrDefault("interaction_id", query.getOrDefault("payload_id", ""));
                String secretKey = query.getOrDefault("secret_key", "");
                BridgeSupport.sendJson(exchange, 200, proMgr.pollCollaboratorInteractions(filterId, secretKey));
                return;
            }

            // ── Repeater / Intruder / Organizer UI ────────────
            if ("POST".equals(method) && "/v0.1/repeater".equals(path)) {
                Map<String, Object> body = BridgeSupport.readJsonBody(exchange);
                HttpService svc = BridgeSupport.resolveService(body, null);
                HttpRequest req = BridgeSupport.buildHttpRequest(body, svc);
                String tab = Optional.ofNullable(BridgeSupport.asString(body.get("tab_name"))).orElse("MCP");
                api.repeater().sendToRepeater(req, tab);
                BridgeSupport.sendJson(exchange, 200, Map.of("sent", true, "host", svc.host(), "port", svc.port()));
                return;
            }

            if ("POST".equals(method) && "/v0.1/intruder".equals(path)) {
                Map<String, Object> body = BridgeSupport.readJsonBody(exchange);
                HttpService svc = BridgeSupport.resolveService(body, null);
                String rawMarked = BridgeSupport.asString(body.get("request_template"));
                String tab = Optional.ofNullable(BridgeSupport.asString(body.get("tab_name"))).orElse("MCP");
                if (rawMarked != null && !rawMarked.isBlank() && rawMarked.contains("§")) {
                    HttpRequestTemplate tmpl = BridgeSupport.buildIntruderTemplate(rawMarked);
                    api.intruder().sendToIntruder(svc, tmpl, tab);
                } else {
                    HttpRequest req = BridgeSupport.buildHttpRequest(body, svc);
                    api.intruder().sendToIntruder(req, tab);
                }
                BridgeSupport.sendJson(exchange, 200, Map.of("sent", true, "host", svc.host(), "port", svc.port(), "tab", tab));
                return;
            }

            if ("GET".equals(method) && "/v0.1/organizer".equals(path)) {
                Integer limit = BridgeSupport.asInt(query.get("limit"));
                List<OrganizerItem> items = api.organizer().items();
                List<Map<String, Object>> out = new ArrayList<>();
                for (OrganizerItem oi : items) {
                    Map<String, Object> m = BridgeSupport.serializeSiteMapEntry(oi, oi.id(), null, false, 4096);
                    m.put("status", oi.status() != null ? oi.status().name() : "UNKNOWN");
                    if (oi.annotations() != null && oi.annotations().hasNotes()) {
                        m.put("notes", oi.annotations().notes());
                    }
                    out.add(m);
                    if (limit != null && out.size() >= limit) break;
                }
                BridgeSupport.sendJson(exchange, 200, Map.of("count", out.size(), "items", out));
                return;
            }

            if ("POST".equals(method) && "/v0.1/organizer".equals(path)) {
                Map<String, Object> body = BridgeSupport.readJsonBody(exchange);
                Integer proxyId = BridgeSupport.asInt(body.get("proxy_history_id"));
                if (proxyId != null) {
                    List<ProxyHttpRequestResponse> hist = api.proxy().history();
                    ProxyHttpRequestResponse match = null;
                    for (ProxyHttpRequestResponse item : hist) {
                        if (item.id() == proxyId) { match = item; break; }
                    }
                    if (match == null && proxyId >= 1 && proxyId <= hist.size()) match = hist.get(proxyId - 1);
                    if (match == null) {
                        BridgeSupport.sendJson(exchange, 404, Map.of("error", "Proxy history item not found"));
                        return;
                    }
                    HttpRequest req = match.finalRequest() != null ? match.finalRequest() : match.request();
                    HttpResponse resp = match.hasResponse() ? match.response() : null;
                    if (resp != null) api.organizer().sendToOrganizer(HttpRequestResponse.httpRequestResponse(req, resp));
                    else api.organizer().sendToOrganizer(req);
                    BridgeSupport.sendJson(exchange, 200, Map.of("sent", true, "proxy_history_id", proxyId));
                    return;
                }
                HttpService svc = BridgeSupport.resolveService(body, null);
                HttpRequest req = BridgeSupport.buildHttpRequest(body, svc);
                String respRaw = BridgeSupport.asString(body.get("response"));
                if (respRaw != null && !respRaw.isBlank()) {
                    api.organizer().sendToOrganizer(HttpRequestResponse.httpRequestResponse(req, HttpResponse.httpResponse(respRaw)));
                } else {
                    api.organizer().sendToOrganizer(req);
                }
                BridgeSupport.sendJson(exchange, 200, Map.of("sent", true, "host", svc.host(), "port", svc.port()));
                return;
            }

            // ── Extensions Self-Management ────────────────────
            if ("GET".equals(method) && "/v0.1/extensions".equals(path)) {
                BridgeSupport.sendJson(exchange, 200, List.of(Map.of(
                    "id", BRIDGE_ID,
                    "name", BRIDGE_NAME,
                    "version", BRIDGE_VERSION,
                    "state", "enabled",
                    "pro", proMgr.isProfessional(),
                    "filename", Optional.ofNullable(api.extension().filename()).orElse("")
                )));
                return;
            }

            if ("GET".equals(method) && ("/v0.1/extensions/" + BRIDGE_ID).equals(path)) {
                BridgeSupport.sendJson(exchange, 200, Map.of(
                    "id", BRIDGE_ID,
                    "name", BRIDGE_NAME,
                    "version", BRIDGE_VERSION,
                    "state", "enabled",
                    "pro", proMgr.isProfessional()
                ));
                return;
            }

            if ("GET".equals(method) && ("/v0.1/extensions/" + BRIDGE_ID + "/output").equals(path)) {
                BridgeSupport.sendJson(exchange, 200, Map.of(
                    "id", BRIDGE_ID,
                    "stdout", String.join("\n", outputLog),
                    "stderr", ""
                ));
                return;
            }

            if (("DELETE".equals(method) || "POST".equals(method)) && path.startsWith("/v0.1/extensions/" + BRIDGE_ID + "/output")) {
                outputLog.clear();
                BridgeSupport.sendJson(exchange, 200, Map.of("cleared", true));
                return;
            }

            if ("DELETE".equals(method) && ("/v0.1/extensions/" + BRIDGE_ID).equals(path)) {
                BridgeSupport.sendJson(exchange, 200, Map.of("unloading", true, "id", BRIDGE_ID));
                api.extension().unload();
                return;
            }

            BridgeSupport.sendJson(exchange, 404, Map.of("error", "Endpoint not found in Montoya Bridge", "path", path));
        } catch (Exception e) {
            try {
                BridgeSupport.sendJson(exchange, 500, Map.of("error", String.valueOf(e.getMessage()), "type", e.getClass().getSimpleName()));
            } catch (Exception ignored) {}
        }
    }

    private void updateScope(Object rawList, boolean include) {
        if (!(rawList instanceof Collection<?> col)) return;
        List<Map<String, Object>> bucket = trackedScope.get(include ? "include" : "exclude");
        for (Object item : col) {
            String u = null;
            if (item instanceof Map<?, ?> m) {
                u = Optional.ofNullable(BridgeSupport.asString(m.get("url"))).orElse(BridgeSupport.asString(m.get("rule")));
            } else if (item != null) {
                u = String.valueOf(item);
            }
            if (u == null || u.isBlank()) continue;
            if (include) api.scope().includeInScope(u);
            else api.scope().excludeFromScope(u);
            final String fu = u;
            if (bucket.stream().noneMatch(r -> fu.equals(r.get("url")))) {
                bucket.add(Map.of("url", fu, "enabled", Boolean.TRUE));
            }
        }
    }
}
