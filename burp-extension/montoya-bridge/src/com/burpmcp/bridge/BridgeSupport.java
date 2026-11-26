package com.burpmcp.bridge;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.intruder.HttpRequestTemplate;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Shared HTTP, auth, serialization, and request-building helpers for the Montoya Bridge.
 */
public final class BridgeSupport {
    private static final Set<MimeType> BINARY_MIMES = EnumSet.of(
        MimeType.IMAGE_UNKNOWN, MimeType.IMAGE_JPEG, MimeType.IMAGE_GIF,
        MimeType.IMAGE_PNG, MimeType.IMAGE_BMP, MimeType.IMAGE_TIFF,
        MimeType.SOUND, MimeType.VIDEO, MimeType.APPLICATION_FLASH,
        MimeType.FONT_WOFF, MimeType.FONT_WOFF2, MimeType.LEGACY_SER_AMF
    );

    private BridgeSupport() {}

    public static Map<String, String> parseQuery(String rawQuery) {
        Map<String, String> map = new LinkedHashMap<>();
        if (rawQuery == null || rawQuery.isBlank()) return map;
        for (String pair : rawQuery.split("&")) {
            if (pair.isEmpty()) continue;
            int idx = pair.indexOf('=');
            String k = URLDecoder.decode(idx >= 0 ? pair.substring(0, idx) : pair, StandardCharsets.UTF_8);
            String v = idx >= 0 ? URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8) : "";
            map.putIfAbsent(k, v);
        }
        return map;
    }

    public static String checkAuthAndStripPath(HttpExchange exchange, String apiKey) {
        String rawPath = exchange.getRequestURI().getRawPath();
        if (rawPath == null || rawPath.isEmpty()) rawPath = "/";
        if (apiKey == null || apiKey.isEmpty()) return rawPath;

        String prefix = "/" + apiKey + "/v0.1";
        if (rawPath.startsWith(prefix)) {
            return "/v0.1" + rawPath.substring(prefix.length());
        }

        Headers hdrs = exchange.getRequestHeaders();
        for (String h : List.of("X-Burp-Api-Token", "API-KEY", "Authorization")) {
            String val = hdrs.getFirst(h);
            if (apiKey.equals(val)) {
                return rawPath;
            }
        }
        return null;
    }

    public static String readBodyString(HttpExchange exchange) throws IOException {
        try (InputStream is = exchange.getRequestBody();
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[4096];
            int n;
            while ((n = is.read(buf)) != -1) {
                baos.write(buf, 0, n);
            }
            return baos.toString(StandardCharsets.UTF_8);
        }
    }

    public static Map<String, Object> readJsonBody(HttpExchange exchange) throws IOException {
        return JsonCodec.parseObject(readBodyString(exchange));
    }

    public static void sendJson(HttpExchange exchange, int status, Object data) throws IOException {
        sendJson(exchange, status, data, null);
    }

    public static void sendJson(HttpExchange exchange, int status, Object data, Map<String, String> extraHeaders) throws IOException {
        byte[] bytes = JsonCodec.stringify(data).getBytes(StandardCharsets.UTF_8);
        Headers hdrs = exchange.getResponseHeaders();
        hdrs.set("Content-Type", "application/json; charset=utf-8");
        if (extraHeaders != null) {
            for (Map.Entry<String, String> e : extraHeaders.entrySet()) {
                hdrs.set(e.getKey(), e.getValue());
            }
        }
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    public static boolean isBinaryResponse(MimeType mime, String contentType) {
        if (mime == MimeType.IMAGE_SVG_XML) return false;
        if (mime != null && BINARY_MIMES.contains(mime)) return true;
        String ct = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT);
        if (ct.contains("svg")) return false;
        if (ct.startsWith("image/") || ct.startsWith("video/") || ct.startsWith("audio/") || ct.startsWith("font/")) {
            return true;
        }
        return ct.contains("application/octet-stream") || ct.contains("application/pdf")
            || ct.contains("application/zip") || ct.contains("application/x-gzip");
    }

    public static Map<String, String> headersToMap(List<HttpHeader> headers) {
        Map<String, String> out = new LinkedHashMap<>();
        if (headers == null) return out;
        for (HttpHeader h : headers) {
            String key = h.name().toLowerCase(Locale.ROOT);
            if (out.containsKey(key)) {
                out.put(key, out.get(key) + ", " + h.value());
            } else {
                out.put(key, h.value());
            }
        }
        return out;
    }

    public static Map<String, Object> serializeRequest(HttpRequest req, boolean includeBody, int maxBody) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (req == null) return out;
        out.put("method", req.method());
        out.put("url", req.url());
        out.put("path", req.path());
        out.put("httpVersion", req.httpVersion());
        out.put("headers", headersToMap(req.headers()));
        int bodyLen = req.body() != null ? req.body().length() : 0;
        String bodyStr = (includeBody && bodyLen > 0) ? safePrefix(req.bodyToString(), maxBody) : "";
        out.put("body", bodyStr);
        out.put("bodySize", bodyLen);
        out.put("bodyTruncated", includeBody && bodyLen > maxBody);
        return out;
    }

    public static Map<String, Object> serializeResponse(HttpResponse resp, boolean includeBody, int maxBody) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (resp == null) return out;
        MimeType mime = resp.statedMimeType();
        Map<String, String> hdrs = headersToMap(resp.headers());
        String ct = hdrs.getOrDefault("content-type", "");
        boolean binary = isBinaryResponse(mime, ct);
        int bodyLen = resp.body() != null ? resp.body().length() : 0;
        String bodyStr = "";
        boolean skippedOrTruncated = false;
        if (binary || !includeBody) {
            skippedOrTruncated = binary || bodyLen > 0;
        } else if (bodyLen > 0) {
            bodyStr = safePrefix(resp.bodyToString(), maxBody);
            skippedOrTruncated = bodyLen > maxBody;
        }
        out.put("statusCode", (int) resp.statusCode());
        out.put("headers", hdrs);
        out.put("body", bodyStr);
        out.put("bodySize", bodyLen);
        out.put("bodyTruncated", skippedOrTruncated);
        out.put("mimeType", mime != null ? mime.description() : "");
        return out;
    }

    public static Map<String, Object> serializeProxyEntry(ProxyHttpRequestResponse item, int fallbackId, boolean includeBody, int maxBody) {
        HttpRequest req = item.finalRequest() != null ? item.finalRequest() : item.request();
        HttpResponse resp = item.hasResponse() ? item.response() : null;
        HttpService svc = item.httpService();
        int id = item.id() > 0 ? item.id() : fallbackId;

        Map<String, Object> out = new LinkedHashMap<>();
        String reqUrl = req != null ? req.url() : "";
        out.put("id", id);
        out.put("messageId", id);
        out.put("host", svc != null ? svc.host() : "");
        out.put("port", svc != null ? svc.port() : 80);
        out.put("protocol", (svc != null && svc.secure()) ? "https" : "http");
        out.put("path", req != null ? req.path() : "/");
        out.put("url", reqUrl);
        out.put("method", req != null ? req.method() : "");
        out.put("responseCode", resp != null ? (int) resp.statusCode() : 0);
        out.put("mimeType", item.mimeType() != null ? item.mimeType().description() : "");
        out.put("inScope", req != null && req.isInScope());
        out.put("edited", item.edited());
        out.put("time", item.time() != null ? item.time().toString() : null);
        if (item.annotations() != null) {
            if (item.annotations().hasNotes()) out.put("comment", item.annotations().notes());
            if (item.annotations().hasHighlightColor()) out.put("highlight", item.annotations().highlightColor().name());
        }
        out.put("request", serializeRequest(req, includeBody, maxBody));
        out.put("response", serializeResponse(resp, includeBody, maxBody));
        return out;
    }

    public static Map<String, Object> serializeSiteMapEntry(
        HttpRequestResponse item,
        int id,
        List<Map<String, Object>> matchingIssues,
        boolean includeBody,
        int maxBody
    ) {
        HttpRequest req = item.request();
        HttpResponse resp = item.hasResponse() ? item.response() : null;
        HttpService svc = item.httpService();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", id);
        out.put("host", svc != null ? svc.host() : "");
        out.put("port", svc != null ? svc.port() : 80);
        out.put("protocol", (svc != null && svc.secure()) ? "https" : "http");
        out.put("path", req != null ? req.path() : "/");
        out.put("url", req != null ? req.url() : "");
        out.put("responseCode", resp != null ? (int) resp.statusCode() : 0);
        out.put("mimeType", resp != null && resp.statedMimeType() != null ? resp.statedMimeType().description() : "");
        out.put("request", serializeRequest(req, includeBody, maxBody));
        out.put("response", serializeResponse(resp, includeBody, maxBody));
        if (matchingIssues != null && !matchingIssues.isEmpty()) {
            out.put("issues", matchingIssues);
        }
        return out;
    }

    public static Map<String, Object> serializeIssue(AuditIssue issue) {
        Map<String, Object> out = new LinkedHashMap<>();
        AuditIssueDefinition def = issue.definition();
        HttpService svc = issue.httpService();
        String baseUrl = issue.baseUrl() != null ? issue.baseUrl() : "";
        String path = "/";
        String origin = "";
        try {
            URI u = URI.create(baseUrl);
            if (u.getHost() != null) {
                origin = u.getScheme() + "://" + u.getAuthority();
                path = (u.getRawPath() == null || u.getRawPath().isEmpty()) ? "/" : u.getRawPath();
                if (u.getRawQuery() != null) path += "?" + u.getRawQuery();
            }
        } catch (Exception ignored) {}
        if (origin.isEmpty() && svc != null) {
            origin = (svc.secure() ? "https://" : "http://") + svc.host()
                + ((svc.port() == 80 && !svc.secure()) || (svc.port() == 443 && svc.secure()) ? "" : ":" + svc.port());
        }

        out.put("name", issue.name());
        out.put("severity", issue.severity() != null ? issue.severity().name().toLowerCase(Locale.ROOT) : "info");
        out.put("confidence", issue.confidence() != null ? issue.confidence().name().toLowerCase(Locale.ROOT) : "tentative");
        out.put("origin", origin);
        out.put("host", svc != null ? svc.host() : origin);
        out.put("base_url", baseUrl);
        out.put("path", path);
        out.put("detail", issue.detail() != null ? issue.detail() : "");
        out.put("description", issue.detail() != null ? issue.detail() : (def != null && def.background() != null ? def.background() : ""));
        out.put("remediation", issue.remediation() != null ? issue.remediation() : (def != null && def.remediation() != null ? def.remediation() : ""));
        if (def != null) {
            out.put("type_index", def.typeIndex());
        }
        if (issue.collaboratorInteractions() != null && !issue.collaboratorInteractions().isEmpty()) {
            out.put("collaborator_interactions_count", issue.collaboratorInteractions().size());
        }
        return out;
    }

    public static HttpService resolveService(Map<String, Object> body, HttpRequest fallbackReq) {
        String host = asString(body.get("host"));
        Integer port = asInt(body.get("port"));
        String proto = asString(body.get("protocol"));
        Boolean useHttps = asBool(body.get("use_https"));
        String urlStr = asString(body.get("url"));

        if ((host == null || host.isEmpty()) && urlStr != null && !urlStr.isEmpty()) {
            URI u = URI.create(urlStr);
            host = u.getHost();
            if (proto == null) proto = u.getScheme();
            if (port == null && u.getPort() > 0) port = u.getPort();
        }
        if ((host == null || host.isEmpty()) && fallbackReq != null && fallbackReq.httpService() != null) {
            return fallbackReq.httpService();
        }
        boolean secure = useHttps != null ? useHttps : !"http".equalsIgnoreCase(proto);
        int resolvedPort = port != null ? port : (secure ? 443 : 80);
        return HttpService.httpService(host, resolvedPort, secure);
    }

    @SuppressWarnings("unchecked")
    public static HttpRequest buildHttpRequest(Map<String, Object> container, HttpService service) {
        if (container == null) throw new IllegalArgumentException("Missing request payload");
        Object nested = container.get("request");
        if (nested instanceof String rawNested && !rawNested.isBlank()) {
            return HttpRequest.httpRequest(service, rawNested);
        }
        if (nested instanceof Map<?, ?> nestedMap) {
            return buildHttpRequest((Map<String, Object>) nestedMap, service);
        }
        String raw = asString(container.get("raw"));
        if (raw != null && !raw.isBlank()) {
            return HttpRequest.httpRequest(service, raw);
        }
        String urlStr = asString(container.get("url"));
        String method = Optional.ofNullable(asString(container.get("method"))).orElse("GET");
        String path = asString(container.get("path"));
        if ((path == null || path.isEmpty()) && urlStr != null && !urlStr.isEmpty()) {
            URI u = URI.create(urlStr);
            path = (u.getRawPath() == null || u.getRawPath().isEmpty()) ? "/" : u.getRawPath();
            if (u.getRawQuery() != null) path += "?" + u.getRawQuery();
        }
        if (path == null || path.isEmpty()) path = "/";

        StringBuilder sb = new StringBuilder();
        sb.append(method).append(' ').append(path).append(" HTTP/1.1\r\n");
        boolean hasHost = false;
        Object hdrObj = container.get("headers");
        if (hdrObj instanceof Map<?, ?> hdrs) {
            for (Map.Entry<?, ?> e : hdrs.entrySet()) {
                String k = String.valueOf(e.getKey());
                if ("host".equalsIgnoreCase(k)) hasHost = true;
                sb.append(k).append(": ").append(String.valueOf(e.getValue())).append("\r\n");
            }
        }
        if (!hasHost && service != null) {
            sb.append("Host: ").append(service.host()).append("\r\n");
        }
        String bodyStr = Optional.ofNullable(asString(container.get("body"))).orElse("");
        sb.append("\r\n").append(bodyStr);
        return HttpRequest.httpRequest(service, sb.toString());
    }

    /**
     * Parses Intruder §marker§ delimiters into clean template text plus Range insertion point offsets.
     */
    public static HttpRequestTemplate buildIntruderTemplate(String markedRequest) {
        StringBuilder clean = new StringBuilder(markedRequest.length());
        List<Range> ranges = new ArrayList<>();
        int i = 0;
        while (i < markedRequest.length()) {
            int open = markedRequest.indexOf('§', i);
            if (open < 0) {
                clean.append(markedRequest, i, markedRequest.length());
                break;
            }
            int close = markedRequest.indexOf('§', open + 1);
            if (close < 0) {
                clean.append(markedRequest, i, markedRequest.length());
                break;
            }
            clean.append(markedRequest, i, open);
            int start = clean.length();
            clean.append(markedRequest, open + 1, close);
            int end = clean.length();
            ranges.add(Range.range(start, end));
            i = close + 1;
        }
        return HttpRequestTemplate.httpRequestTemplate(ByteArray.byteArray(clean.toString()), ranges);
    }

    public static String safePrefix(String text, int maxLen) {
        if (text == null) return "";
        return text.length() <= maxLen ? text : text.substring(0, maxLen);
    }

    public static String asString(Object o) {
        return o == null ? null : String.valueOf(o);
    }

    public static Integer asInt(Object o) {
        if (o instanceof Number n) return n.intValue();
        if (o instanceof String s && !s.isBlank()) {
            try { return Integer.parseInt(s.trim()); } catch (NumberFormatException ignored) {}
        }
        return null;
    }

    public static Boolean asBool(Object o) {
        if (o instanceof Boolean b) return b;
        if (o instanceof String s) return Boolean.parseBoolean(s);
        return null;
    }
}
