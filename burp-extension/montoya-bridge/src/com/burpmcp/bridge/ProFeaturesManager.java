package com.burpmcp.bridge;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.*;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.Crawl;
import burp.api.montoya.scanner.CrawlConfiguration;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;

import java.net.URI;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Manages Burp Suite Pro scanner tasks (crawl + active/passive audit), issue
 * definitions, and Burp Collaborator OAST client interactions via Montoya.
 */
public final class ProFeaturesManager {
    private static final class ScanTaskRecord {
        final String id;
        final String kind; // "crawl" | "active_audit" | "passive_audit" | "crawl_and_audit"
        final List<String> urls;
        final String createdAt;
        volatile Crawl crawl;
        volatile Audit audit;
        volatile boolean stopped;
        final Set<String> fedKeys = ConcurrentHashMap.newKeySet();

        ScanTaskRecord(String id, String kind, List<String> urls) {
            this.id = id;
            this.kind = kind;
            this.urls = urls;
            this.createdAt = Instant.now().toString();
        }
    }

    private final MontoyaApi api;
    private final AtomicInteger nextScanId = new AtomicInteger(1);
    private final ConcurrentHashMap<String, ScanTaskRecord> scans = new ConcurrentHashMap<>();
    private final ScheduledExecutorService feederPool = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "burp-mcp-crawl-feeder");
        t.setDaemon(true);
        return t;
    });
    private volatile CollaboratorClient collabClient;

    public ProFeaturesManager(MontoyaApi api) {
        this.api = api;
    }

    public boolean isProfessional() {
        return api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL;
    }

    public void shutdown() {
        feederPool.shutdownNow();
    }

    // ── Scanner & Crawl ──────────────────────────────────────

    @SuppressWarnings("unchecked")
    public Map<String, Object> startScan(Map<String, Object> body) {
        List<String> urls = new ArrayList<>();
        Object rawUrls = body.get("urls");
        if (rawUrls instanceof Collection<?> col) {
            for (Object o : col) {
                if (o != null && !String.valueOf(o).isBlank()) urls.add(String.valueOf(o).trim());
            }
        }
        List<Object> captured = body.get("captured_requests") instanceof List<?> list
            ? (List<Object>) list
            : Collections.emptyList();

        if (urls.isEmpty() && captured.isEmpty()) {
            throw new IllegalArgumentException("At least one URL or captured request is required");
        }

        // Apply optional scope rules passed inline to start_scan / spider_start_crawl
        if (body.get("scope") instanceof Map<?, ?> scopeMap) {
            applyScopeList(scopeMap.get("include"), true);
            applyScopeList(scopeMap.get("exclude"), false);
        }

        Object scanConfigs = body.get("scan_configurations");
        String scanMode = BridgeSupport.asString(body.get("scan_mode"));
        boolean crawlOnly = (scanConfigs instanceof Collection<?> col && col.isEmpty() && captured.isEmpty() && scanMode == null)
            || "crawl".equalsIgnoreCase(scanMode);
        boolean passiveOnly = "passive_audit".equalsIgnoreCase(scanMode) || !captured.isEmpty();

        String id = String.valueOf(nextScanId.getAndIncrement());

        if (crawlOnly) {
            Crawl crawl = api.scanner().startCrawl(CrawlConfiguration.crawlConfiguration(urls.toArray(String[]::new)));
            ScanTaskRecord rec = new ScanTaskRecord(id, "crawl", urls);
            rec.crawl = crawl;
            scans.put(id, rec);
            return buildScanSummary(rec);
        }

        BuiltInAuditConfiguration auditCfg = passiveOnly
            ? BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS
            : BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS;

        Audit audit = api.scanner().startAudit(AuditConfiguration.auditConfiguration(auditCfg));
        String kind = passiveOnly
            ? "passive_audit"
            : ("active_audit".equalsIgnoreCase(scanMode) ? "active_audit" : "crawl_and_audit");
        ScanTaskRecord rec = new ScanTaskRecord(id, kind, urls);
        rec.audit = audit;

        if (!captured.isEmpty()) {
            for (Object itemObj : captured) {
                if (!(itemObj instanceof Map<?, ?> m)) continue;
                String itemUrl = Optional.ofNullable(BridgeSupport.asString(m.get("url"))).orElse(urls.isEmpty() ? "" : urls.get(0));
                String reqStr = decodeRawOrBase64(BridgeSupport.asString(m.get("request")));
                String respStr = decodeRawOrBase64(BridgeSupport.asString(m.get("response")));
                if (reqStr != null && !reqStr.isEmpty()) {
                    URI u = URI.create(itemUrl);
                    boolean secure = "https".equalsIgnoreCase(u.getScheme());
                    int port = u.getPort() > 0 ? u.getPort() : (secure ? 443 : 80);
                    HttpService svc = HttpService.httpService(u.getHost(), port, secure);
                    HttpRequest req = HttpRequest.httpRequest(svc, reqStr);
                    HttpResponse resp = (respStr != null && !respStr.isEmpty()) ? HttpResponse.httpResponse(respStr) : HttpResponse.httpResponse("");
                    audit.addRequestResponse(HttpRequestResponse.httpRequestResponse(req, resp));
                }
            }
        } else {
            for (String u : urls) {
                try {
                    api.scope().includeInScope(u);
                } catch (Exception ignored) {}
                feedUrl(rec, u);
            }
            feedMatchingSiteMapItems(rec);
            if ("crawl_and_audit".equals(kind)) {
                rec.crawl = api.scanner().startCrawl(CrawlConfiguration.crawlConfiguration(urls.toArray(String[]::new)));
                scheduleCrawlToAuditBridge(rec);
            }
        }

        scans.put(id, rec);
        return buildScanSummary(rec);
    }

    private void feedUrl(ScanTaskRecord rec, String u) {
        if (rec.audit == null || u == null || u.isEmpty()) return;
        String key = "SEED " + u;
        if (rec.fedKeys.add(key)) {
            try {
                rec.audit.addRequest(HttpRequest.httpRequestFromUrl(u));
            } catch (Exception e) {
                api.logging().logToError("[MontoyaBridge] Failed to queue seed URL " + u + ": " + e.getMessage());
            }
        }
    }

    private void feedMatchingSiteMapItems(ScanTaskRecord rec) {
        if (rec.audit == null) return;
        Set<String> hosts = extractHosts(rec.urls);
        for (HttpRequestResponse item : api.siteMap().requestResponses()) {
            if (rec.stopped) return;
            HttpRequest req = item.request();
            if (req == null || req.httpService() == null) continue;
            String host = req.httpService().host().toLowerCase(Locale.ROOT);
            if (!hosts.contains(host)) continue;
            String key = req.method() + " " + req.url();
            if (rec.fedKeys.add(key)) {
                try {
                    if (item.hasResponse() && item.response() != null) {
                        rec.audit.addRequestResponse(item);
                    } else {
                        rec.audit.addRequest(req);
                    }
                } catch (Exception ignored) {}
            }
        }
    }

    private void scheduleCrawlToAuditBridge(ScanTaskRecord rec) {
        final int[] ticks = {0};
        feederPool.scheduleAtFixedRate(() -> {
            try {
                if (rec.stopped || ticks[0]++ > 120) { // up to 10 minutes
                    return;
                }
                feedMatchingSiteMapItems(rec);
            } catch (Exception ignored) {}
        }, 3, 5, TimeUnit.SECONDS);
    }

    private static Set<String> extractHosts(List<String> urls) {
        Set<String> hosts = new HashSet<>();
        for (String u : urls) {
            try {
                URI uri = URI.create(u);
                if (uri.getHost() != null) hosts.add(uri.getHost().toLowerCase(Locale.ROOT));
            } catch (Exception ignored) {}
        }
        return hosts;
    }

    private void applyScopeList(Object listObj, boolean include) {
        if (!(listObj instanceof Collection<?> col)) return;
        for (Object item : col) {
            String u = null;
            if (item instanceof Map<?, ?> m) {
                u = BridgeSupport.asString(m.get("rule"));
                if (u == null) u = BridgeSupport.asString(m.get("url"));
            } else if (item != null) {
                u = String.valueOf(item);
            }
            if (u != null && !u.isBlank()) {
                try {
                    if (include) api.scope().includeInScope(u);
                    else api.scope().excludeFromScope(u);
                } catch (Exception ignored) {}
            }
        }
    }

    private static String decodeRawOrBase64(String input) {
        if (input == null || input.isBlank()) return input;
        String trimmed = input.trim();
        if (trimmed.startsWith("GET ") || trimmed.startsWith("POST ") || trimmed.startsWith("PUT ")
            || trimmed.startsWith("DELETE ") || trimmed.startsWith("HEAD ") || trimmed.startsWith("OPTIONS ")
            || trimmed.startsWith("PATCH ") || trimmed.startsWith("HTTP/")) {
            return input;
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(trimmed);
            return new String(decoded, java.nio.charset.StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ignored) {
            return input;
        }
    }

    public List<Map<String, Object>> listScans() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (ScanTaskRecord rec : scans.values()) {
            out.add(buildScanSummary(rec));
        }
        return out;
    }

    public Map<String, Object> getScan(String id) {
        ScanTaskRecord rec = scans.get(id);
        if (rec == null) return null;
        return buildScanDetail(rec);
    }

    public boolean stopScan(String id) {
        ScanTaskRecord rec = scans.get(id);
        if (rec == null) return false;
        rec.stopped = true;
        if (rec.crawl != null) {
            try { rec.crawl.delete(); } catch (Exception ignored) {}
        }
        if (rec.audit != null) {
            try { rec.audit.delete(); } catch (Exception ignored) {}
        }
        return true;
    }

    private String computeStatus(ScanTaskRecord rec) {
        if (rec.stopped) return "cancelled";
        String msg = "";
        if (rec.audit != null && rec.audit.statusMessage() != null) msg = rec.audit.statusMessage();
        else if (rec.crawl != null && rec.crawl.statusMessage() != null) msg = rec.crawl.statusMessage();
        String lower = msg.toLowerCase(Locale.ROOT);
        if (lower.contains("finish") || lower.contains("complet") || lower.contains("succeed") || lower.contains("idle")) {
            return "succeeded";
        }
        if (rec.crawl != null && rec.audit == null) return "crawling";
        return "auditing";
    }

    private Map<String, Object> buildScanSummary(ScanTaskRecord rec) {
        int crawlReqs = rec.crawl != null ? rec.crawl.requestCount() : 0;
        int auditReqs = rec.audit != null ? rec.audit.requestCount() : 0;
        int errs = (rec.crawl != null ? rec.crawl.errorCount() : 0) + (rec.audit != null ? rec.audit.errorCount() : 0);
        int issues = rec.audit != null ? rec.audit.issues().size() : 0;
        String statusMsg = rec.audit != null ? rec.audit.statusMessage() : (rec.crawl != null ? rec.crawl.statusMessage() : "");

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", rec.id);
        out.put("task_id", rec.id);
        out.put("kind", rec.kind);
        out.put("scan_status", computeStatus(rec));
        out.put("status", computeStatus(rec));
        out.put("status_message", statusMsg);
        out.put("urls", rec.urls);
        out.put("crawl_requests_made", crawlReqs);
        out.put("audit_requests_made", auditReqs);
        out.put("error_count", errs);
        out.put("issue_count", issues);
        out.put("createdAt", rec.createdAt);
        return out;
    }

    private Map<String, Object> buildScanDetail(ScanTaskRecord rec) {
        Map<String, Object> detail = buildScanSummary(rec);
        List<Map<String, Object>> events = new ArrayList<>();
        List<Map<String, Object>> flatIssues = new ArrayList<>();
        if (rec.audit != null) {
            for (AuditIssue issue : rec.audit.issues()) {
                Map<String, Object> serialized = BridgeSupport.serializeIssue(issue);
                flatIssues.add(serialized);
                events.add(Map.of("issue", serialized));
            }
        }
        Set<String> hosts = extractHosts(rec.urls);
        int discovered = 0;
        for (HttpRequestResponse item : api.siteMap().requestResponses()) {
            if (item.httpService() != null && hosts.contains(item.httpService().host().toLowerCase(Locale.ROOT))) {
                discovered++;
            }
        }
        detail.put("urls_discovered", discovered);
        detail.put("issue_events", events);
        detail.put("issues", flatIssues);
        return detail;
    }

    public List<Map<String, Object>> listIssueDefinitions() {
        Map<Integer, Map<String, Object>> byId = new LinkedHashMap<>();
        for (AuditIssue issue : api.siteMap().issues()) {
            AuditIssueDefinition def = issue.definition();
            if (def == null) continue;
            byId.computeIfAbsent(def.typeIndex(), k -> {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("type_index", def.typeIndex());
                m.put("issue_type_id", def.typeIndex());
                m.put("name", def.name());
                m.put("description", def.background() != null ? def.background() : "");
                m.put("remediation", def.remediation() != null ? def.remediation() : "");
                m.put("typical_severity", def.typicalSeverity() != null ? def.typicalSeverity().name().toLowerCase(Locale.ROOT) : "info");
                return m;
            });
        }
        return new ArrayList<>(byId.values());
    }

    // ── Collaborator OAST ────────────────────────────────────

    private synchronized CollaboratorClient ensureCollaborator(String secretKeyStr) {
        if (secretKeyStr != null && !secretKeyStr.isBlank()) {
            collabClient = api.collaborator().restoreClient(SecretKey.secretKey(secretKeyStr.trim()));
        } else if (collabClient == null) {
            collabClient = api.collaborator().createClient();
        }
        return collabClient;
    }

    public Map<String, Object> collaboratorStatus() {
        CollaboratorClient client = ensureCollaborator(null);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("initialized", true);
        out.put("server_address", client.server().address());
        out.put("is_literal_address", client.server().isLiteralAddress());
        out.put("secret_key", client.getSecretKey().toString());
        return out;
    }

    public Map<String, Object> generateCollaboratorPayload(Map<String, Object> body) {
        String secret = BridgeSupport.asString(body.get("secret_key"));
        CollaboratorClient client = ensureCollaborator(secret);
        String customData = BridgeSupport.asString(body.get("custom_data"));
        CollaboratorPayload payload = (customData != null && !customData.isBlank())
            ? client.generatePayload(customData)
            : client.generatePayload();

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("payload", payload.toString());
        out.put("interaction_id", payload.id().toString());
        out.put("custom_data", payload.customData().orElse(null));
        out.put("server", payload.server().map(CollaboratorServer::address).orElse(client.server().address()));
        out.put("secret_key", client.getSecretKey().toString());
        return out;
    }

    public Map<String, Object> pollCollaboratorInteractions(String filterId, String secretKey) {
        CollaboratorClient client = ensureCollaborator(secretKey);
        List<Interaction> raw = client.getAllInteractions();
        List<Map<String, Object>> parsed = new ArrayList<>();
        for (Interaction ix : raw) {
            String ixId = ix.id().toString();
            if (filterId != null && !filterId.isBlank() && !ixId.equalsIgnoreCase(filterId.trim())) {
                continue;
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("interaction_id", ixId);
            m.put("type", ix.type().name());
            m.put("timestamp", ix.timeStamp() != null ? ix.timeStamp().toString() : null);
            m.put("client_ip", ix.clientIp() != null ? ix.clientIp().getHostAddress() : null);
            m.put("client_port", ix.clientPort());
            m.put("custom_data", ix.customData().orElse(null));

            ix.dnsDetails().ifPresent(dns -> {
                Map<String, Object> d = new LinkedHashMap<>();
                d.put("query_type", dns.queryType().name());
                byte[] qBytes = dns.query().getBytes();
                d.put("query_base64", Base64.getEncoder().encodeToString(qBytes));
                d.put("query_ascii", new String(qBytes, java.nio.charset.StandardCharsets.ISO_8859_1)
                    .replaceAll("[^\\x20-\\x7e]", "."));
                m.put("dns", d);
            });
            ix.httpDetails().ifPresent(http -> {
                Map<String, Object> h = new LinkedHashMap<>();
                h.put("protocol", http.protocol().name());
                HttpRequestResponse rr = http.requestResponse();
                if (rr != null) {
                    if (rr.request() != null) h.put("request", rr.request().toByteArray().toString());
                    if (rr.response() != null) h.put("response", rr.response().toByteArray().toString());
                }
                m.put("http", h);
            });
            ix.smtpDetails().ifPresent(smtp -> {
                Map<String, Object> s = new LinkedHashMap<>();
                s.put("protocol", smtp.protocol().name());
                s.put("conversation", smtp.conversation());
                m.put("smtp", s);
            });
            parsed.add(m);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("count", parsed.size());
        out.put("server", client.server().address());
        out.put("interactions", parsed);
        return out;
    }
}
