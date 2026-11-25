// ============================================================
// BurpSuite MCP – Shared Community-Mode Local Store, Proxy Agents,
// Passive Security Analyser & Local HTTP/HTTPS Crawler
// ============================================================

import http from "node:http";
import { randomUUID } from "node:crypto";
import axios, { AxiosRequestConfig } from "axios";
import { HttpProxyAgent } from "http-proxy-agent";
import { HttpsProxyAgent } from "https-proxy-agent";
import { logger } from "./logger.js";

// ── Proxy-aware HTTP/HTTPS agents (tolerates Burp MITM CA cert) ──

class BurpHttpsProxyAgent extends HttpsProxyAgent<string> {
  private readonly rejectUnauthorizedTls: boolean;

  constructor(proxyUrl: string, rejectUnauthorizedTls: boolean) {
    super(proxyUrl);
    this.rejectUnauthorizedTls = rejectUnauthorizedTls;
  }

  override connect(
    req: http.ClientRequest,
    opts: Parameters<HttpsProxyAgent<string>["connect"]>[1]
  ) {
    if (opts.secureEndpoint) {
      return super.connect(req, {
        ...opts,
        rejectUnauthorized: this.rejectUnauthorizedTls,
      });
    }
    return super.connect(req, opts);
  }
}

export function createProxyAgents(
  proxyUrl: string,
  rejectUnauthorized = false
): { httpAgent: HttpProxyAgent<string>; httpsAgent: HttpsProxyAgent<string> } {
  return {
    httpAgent: new HttpProxyAgent(proxyUrl),
    httpsAgent: new BurpHttpsProxyAgent(proxyUrl, rejectUnauthorized),
  };
}

// ── Shared Types ─────────────────────────────────────────────

export interface LocalExchangeRecord {
  id: number;
  messageId: number;
  timestamp: string;
  source: "repeater" | "intruder" | "spider" | "passive_scan";
  proxied: boolean;
  protocol: "http" | "https";
  host: string;
  port: number;
  path: string;
  request: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
  };
  response: {
    statusCode: number;
    statusMessage: string;
    headers: Record<string, string>;
    body: string;
    mimeType: string;
    responseTime: number;
  };
}

export interface LocalPassiveIssue {
  serial_number: string;
  issue_type: number;
  name: string;
  severity: "high" | "medium" | "low" | "info";
  confidence: "certain" | "firm" | "tentative";
  host: string;
  path: string;
  url: string;
  description: string;
  remediation: string;
  evidence?: string;
  detected_at: string;
}

export interface LocalMatchReplaceRule {
  id: string;
  rule_type:
    | "request_header"
    | "response_header"
    | "request_body"
    | "response_body"
    | "request_first_line";
  match: string;
  replace: string;
  is_simple_match: boolean;
  enabled: boolean;
  comment: string;
}

export interface LocalCrawlTask {
  task_id: string;
  status: "running" | "succeeded" | "stopped" | "failed";
  urls: string[];
  scope_included: string[];
  scope_excluded: string[];
  max_depth: number;
  max_links: number;
  crawl_requests_made: number;
  crawl_requests_queued: number;
  urls_discovered: string[];
  proxied: boolean;
  stop_requested: boolean;
  created_at: string;
  finished_at?: string;
  error?: string;
}

export const PASSIVE_ISSUE_DEFINITIONS = [
  {
    type_index: 9001,
    name: "Missing Strict-Transport-Security Header",
    severity: "low",
    description: "HTTPS response lacks a Strict-Transport-Security (HSTS) header.",
    remediation: "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
  },
  {
    type_index: 9002,
    name: "Missing Content-Security-Policy Header",
    severity: "info",
    description: "HTML response does not define a Content-Security-Policy header.",
    remediation: "Define a strict Content-Security-Policy to mitigate XSS and data injection.",
  },
  {
    type_index: 9003,
    name: "Missing X-Frame-Options / Clickjacking Protection",
    severity: "low",
    description: "HTML response lacks X-Frame-Options and CSP frame-ancestors.",
    remediation: "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' and CSP frame-ancestors.",
  },
  {
    type_index: 9004,
    name: "Missing X-Content-Type-Options Header",
    severity: "info",
    description: "Response does not include 'X-Content-Type-Options: nosniff'.",
    remediation: "Add 'X-Content-Type-Options: nosniff' to prevent MIME-sniffing.",
  },
  {
    type_index: 9005,
    name: "Cookie Without HttpOnly Flag",
    severity: "low",
    description: "A Set-Cookie header omits the HttpOnly flag.",
    remediation: "Mark session and sensitive cookies with the HttpOnly attribute.",
  },
  {
    type_index: 9006,
    name: "Cookie Without Secure Flag on HTTPS",
    severity: "low",
    description: "A Set-Cookie header sent over HTTPS omits the Secure flag.",
    remediation: "Add the Secure attribute to cookies transmitted over HTTPS.",
  },
  {
    type_index: 9007,
    name: "Cookie Without SameSite Attribute",
    severity: "info",
    description: "A Set-Cookie header does not explicitly declare SameSite.",
    remediation: "Set SameSite=Lax or SameSite=Strict on cookies.",
  },
  {
    type_index: 9008,
    name: "Permissive Cross-Origin Resource Sharing (CORS)",
    severity: "medium",
    description: "Response exposes overly permissive Access-Control-Allow-Origin headers.",
    remediation: "Restrict Access-Control-Allow-Origin to explicit trusted origins and avoid wildcard with credentials.",
  },
  {
    type_index: 9009,
    name: "Server / Technology Version Disclosure",
    severity: "info",
    description: "Response headers disclose server or framework versions.",
    remediation: "Suppress or generalize Server, X-Powered-By, and X-AspNet-Version headers.",
  },
  {
    type_index: 9010,
    name: "Detailed Error / Stack Trace Disclosure",
    severity: "medium",
    description: "Response body appears to contain an unhandled exception, stack trace, or SQL error.",
    remediation: "Disable debug error pages in production and return generic error responses.",
  },
  {
    type_index: 9011,
    name: "Cleartext Form Submission Target",
    severity: "medium",
    description: "An HTML form targets an unencrypted http:// action URL.",
    remediation: "Submit all forms over HTTPS.",
  },
];

// ── Store State ──────────────────────────────────────────────

const MAX_HISTORY_ITEMS = 2_000;
let nextHistoryId = 1;
const historyItems: LocalExchangeRecord[] = [];
const scopeConfig: { included: string[]; excluded: string[] } = {
  included: [],
  excluded: [],
};
const matchReplaceRules = new Map<string, LocalMatchReplaceRule>();
const passiveIssues = new Map<string, LocalPassiveIssue>();
const localCrawls = new Map<string, LocalCrawlTask>();

// ── Passive Analyzer ─────────────────────────────────────────

function lowerHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    out[k.toLowerCase()] = v;
  }
  return out;
}

export function analyzePassiveExchange(params: {
  url: string;
  statusCode?: number;
  responseHeaders: Record<string, string>;
  responseBody: string;
}): LocalPassiveIssue[] {
  let parsed: URL;
  try {
    parsed = new URL(params.url);
  } catch {
    return [];
  }

  const hostOrigin = `${parsed.protocol}//${parsed.host}`;
  const path = parsed.pathname + parsed.search;
  const h = lowerHeaders(params.responseHeaders);
  const ct = h["content-type"] ?? "";
  const isHtml = /text\/html|application\/xhtml/i.test(ct) || /<html[\s>]/i.test(params.responseBody.slice(0, 512));
  const now = new Date().toISOString();
  const found: LocalPassiveIssue[] = [];

  const addIssue = (
    typeIndex: number,
    confidence: LocalPassiveIssue["confidence"],
    evidence?: string
  ) => {
    const def = PASSIVE_ISSUE_DEFINITIONS.find((d) => d.type_index === typeIndex);
    if (!def) return;
    const dedupKey = `${typeIndex}:${hostOrigin}:${path}`;
    const issue: LocalPassiveIssue = {
      serial_number: passiveIssues.get(dedupKey)?.serial_number ?? randomUUID(),
      issue_type: typeIndex,
      name: def.name,
      severity: def.severity as LocalPassiveIssue["severity"],
      confidence,
      host: hostOrigin,
      path: path || "/",
      url: params.url,
      description: def.description,
      remediation: def.remediation,
      evidence,
      detected_at: now,
    };
    passiveIssues.set(dedupKey, issue);
    found.push(issue);
  };

  if (parsed.protocol === "https:" && !h["strict-transport-security"]) {
    addIssue(9001, "certain");
  }

  if (isHtml) {
    if (!h["content-security-policy"]) {
      addIssue(9002, "certain");
    }
    const csp = h["content-security-policy"] ?? "";
    if (!h["x-frame-options"] && !/frame-ancestors/i.test(csp)) {
      addIssue(9003, "firm");
    }
  }

  if (!h["x-content-type-options"]) {
    addIssue(9004, "certain");
  }

  const setCookie = h["set-cookie"];
  if (setCookie) {
    if (!/;\s*httponly/i.test(setCookie)) {
      addIssue(9005, "certain", setCookie.split(";")[0]);
    }
    if (parsed.protocol === "https:" && !/;\s*secure/i.test(setCookie)) {
      addIssue(9006, "certain", setCookie.split(";")[0]);
    }
    if (!/;\s*samesite=/i.test(setCookie)) {
      addIssue(9007, "certain", setCookie.split(";")[0]);
    }
  }

  const acao = h["access-control-allow-origin"];
  const acac = h["access-control-allow-credentials"];
  if (acao === "*" && acac?.toLowerCase() === "true") {
    addIssue(9008, "certain", `ACAO: ${acao}, ACAC: ${acac}`);
  } else if (acao === "*") {
    addIssue(9008, "tentative", `ACAO: *`);
  }

  const disclosed: string[] = [];
  for (const hdr of ["server", "x-powered-by", "x-aspnet-version"]) {
    if (h[hdr] && /\d/.test(h[hdr])) {
      disclosed.push(`${hdr}: ${h[hdr]}`);
    }
  }
  if (disclosed.length > 0) {
    addIssue(9009, "certain", disclosed.join("; "));
  }

  const errorPatterns = [
    /SQL syntax.*MySQL/i,
    /Warning.*pg_/i,
    /ORA-\d{5}/,
    /Unclosed quotation mark after the character string/i,
    /Traceback \(most recent call last\):/,
    /at [a-zA-Z0-9_.]+\([a-zA-Z0-9_]+\.(?:java|cs|js|ts):\d+\)/,
  ];
  for (const re of errorPatterns) {
    const m = params.responseBody.match(re);
    if (m) {
      addIssue(9010, "firm", m[0].slice(0, 160));
      break;
    }
  }

  if (isHtml && /<form[^>]+action\s*=\s*["']http:\/\//i.test(params.responseBody)) {
    addIssue(9011, "certain");
  }

  return found;
}

// ── Store Operations ─────────────────────────────────────────

export function recordLocalExchange(
  entry: Omit<LocalExchangeRecord, "id" | "messageId" | "timestamp">
): LocalExchangeRecord {
  const id = nextHistoryId++;
  const full: LocalExchangeRecord = {
    ...entry,
    id,
    messageId: id,
    timestamp: new Date().toISOString(),
  };

  historyItems.push(full);
  if (historyItems.length > MAX_HISTORY_ITEMS) {
    historyItems.shift();
  }

  // Run lightweight passive checks automatically on non-intruder traffic (and unique URLs)
  if (entry.source !== "intruder") {
    analyzePassiveExchange({
      url: entry.request.url,
      statusCode: entry.response.statusCode,
      responseHeaders: entry.response.headers,
      responseBody: entry.response.body,
    });
  }

  return full;
}

export function getLocalHistory(limit = 100, filter?: string): LocalExchangeRecord[] {
  let items = [...historyItems].reverse();
  if (filter) {
    const f = filter.toLowerCase();
    items = items.filter((item) => item.request.url.toLowerCase().includes(f));
  }
  return items.slice(0, limit);
}

export function getLocalHistoryItem(id: number): LocalExchangeRecord | undefined {
  return historyItems.find((item) => item.id === id || item.messageId === id);
}

export function getLocalSiteMap(hostFilter?: string) {
  const filtered = hostFilter
    ? historyItems.filter(
        (item) => item.host.toLowerCase() === hostFilter.toLowerCase()
      )
    : historyItems;

  return filtered.map((item) => ({
    host: item.host,
    path: item.path,
    protocol: item.protocol,
    port: item.port,
    responseCode: item.response.statusCode,
    mimeType: item.response.mimeType,
    request: {
      method: item.request.method,
      url: item.request.url,
      headers: item.request.headers,
      body: item.request.body,
    },
    response: {
      statusCode: item.response.statusCode,
      statusMessage: item.response.statusMessage,
      headers: item.response.headers,
      body: item.response.body,
      mimeType: item.response.mimeType,
      responseTime: item.response.responseTime,
    },
  }));
}

export function clearLocalSiteMap(host?: string): number {
  const before = historyItems.length;
  if (!host) {
    historyItems.length = 0;
    return before;
  }
  const target = host.toLowerCase();
  for (let i = historyItems.length - 1; i >= 0; i--) {
    if (historyItems[i]!.host.toLowerCase() === target) {
      historyItems.splice(i, 1);
    }
  }
  return before - historyItems.length;
}

// ── Scope Operations ─────────────────────────────────────────

function matchesScopePattern(url: string, pattern: string): boolean {
  const trimmed = pattern.trim();
  if (!trimmed) return false;
  if (url.toLowerCase().startsWith(trimmed.toLowerCase())) return true;
  try {
    const parsedUrl = new URL(url);
    if (parsedUrl.hostname.toLowerCase() === trimmed.toLowerCase()) return true;
    const re = new RegExp(trimmed, "i");
    return re.test(url);
  } catch {
    return url.toLowerCase().includes(trimmed.toLowerCase());
  }
}

export function getLocalScope() {
  return {
    included: scopeConfig.included.map((url) => ({ enabled: true, url })),
    excluded: scopeConfig.excluded.map((url) => ({ enabled: true, url })),
    total_included: scopeConfig.included.length,
    total_excluded: scopeConfig.excluded.length,
  };
}

export function addLocalScopeUrl(url: string): void {
  if (!scopeConfig.included.includes(url)) {
    scopeConfig.included.push(url);
  }
}

export function excludeLocalScopeUrl(url: string): void {
  if (!scopeConfig.excluded.includes(url)) {
    scopeConfig.excluded.push(url);
  }
}

export function setLocalScope(included: string[], excluded: string[]): void {
  scopeConfig.included = [...included];
  scopeConfig.excluded = [...excluded];
}

export function isLocalUrlInScope(url: string): boolean {
  if (scopeConfig.excluded.some((p) => matchesScopePattern(url, p))) {
    return false;
  }
  if (scopeConfig.included.length === 0) return false;
  return scopeConfig.included.some((p) => matchesScopePattern(url, p));
}

// ── Match & Replace Operations ───────────────────────────────

export function addLocalMatchReplaceRule(
  rule: Omit<LocalMatchReplaceRule, "id">
): LocalMatchReplaceRule {
  const id = randomUUID();
  const created: LocalMatchReplaceRule = { id, ...rule };
  matchReplaceRules.set(id, created);
  return created;
}

export function listLocalMatchReplaceRules(): LocalMatchReplaceRule[] {
  return Array.from(matchReplaceRules.values());
}

export function deleteLocalMatchReplaceRule(id: string): boolean {
  return matchReplaceRules.delete(id);
}

export function getLocalPassiveIssues(host?: string): LocalPassiveIssue[] {
  const all = Array.from(passiveIssues.values());
  if (!host) return all;
  const norm = host.replace(/\/$/, "").toLowerCase();
  return all.filter((i) => {
    const h = i.host.replace(/\/$/, "").toLowerCase();
    return h.includes(norm) || norm.includes(h);
  });
}

// ── Local Crawler (routes through Burp Community Proxy :8080) ──

function extractLinksAndForms(html: string, baseUrl: string): string[] {
  const discovered = new Set<string>();
  const patterns = [
    /(?:href|src|action)\s*=\s*["']([^"'#]+)["']/gi,
    /fetch\(\s*["'](\/[^"']+)["']/gi,
  ];

  for (const re of patterns) {
    let match: RegExpExecArray | null;
    while ((match = re.exec(html)) !== null) {
      const raw = match[1]?.trim();
      if (!raw || /^(?:javascript:|mailto:|tel:|data:)/i.test(raw)) continue;
      try {
        const resolved = new URL(raw, baseUrl);
        if (resolved.protocol === "http:" || resolved.protocol === "https:") {
          resolved.hash = "";
          discovered.add(resolved.toString());
        }
      } catch {
        /* ignore malformed relative URLs */
      }
    }
  }

  return Array.from(discovered);
}

function urlMatchesCrawlScope(
  url: string,
  included: string[],
  excluded: string[]
): boolean {
  if (excluded.some((p) => matchesScopePattern(url, p))) return false;
  return included.some((p) => matchesScopePattern(url, p));
}

export function startLocalCrawl(params: {
  urls: string[];
  scope_included?: string[];
  scope_excluded?: string[];
  max_depth?: number;
  max_links?: number;
  proxyBaseUrl: string;
  rejectUnauthorized?: boolean;
}): LocalCrawlTask {
  const taskId = `local-crawl-${randomUUID().slice(0, 8)}`;
  const seedOrigins = params.urls
    .map((u) => {
      try {
        return new URL(u).origin;
      } catch {
        return u;
      }
    });

  const task: LocalCrawlTask = {
    task_id: taskId,
    status: "running",
    urls: params.urls,
    scope_included:
      params.scope_included && params.scope_included.length > 0
        ? params.scope_included
        : seedOrigins,
    scope_excluded: params.scope_excluded ?? [],
    max_depth: params.max_depth ?? 10,
    max_links: params.max_links ?? 10_000,
    crawl_requests_made: 0,
    crawl_requests_queued: params.urls.length,
    urls_discovered: [...params.urls],
    proxied: true,
    stop_requested: false,
    created_at: new Date().toISOString(),
  };

  localCrawls.set(taskId, task);

  void runLocalCrawl(task, params.proxyBaseUrl, params.rejectUnauthorized ?? false);
  return task;
}

async function runLocalCrawl(
  task: LocalCrawlTask,
  proxyBaseUrl: string,
  rejectUnauthorized: boolean
): Promise<void> {
  const visited = new Set<string>();
  const discovered = new Set<string>(task.urls);
  const queue: Array<{ url: string; depth: number }> = task.urls.map((url) => ({
    url,
    depth: 0,
  }));
  let useProxy = true;

  try {
    while (queue.length > 0 && !task.stop_requested) {
      if (task.crawl_requests_made >= task.max_links) break;
      const item = queue.shift()!;
      if (visited.has(item.url) || item.depth > task.max_depth) continue;
      visited.add(item.url);
      task.crawl_requests_queued = queue.length;

      const parsed = new URL(item.url);
      const agents = useProxy
        ? createProxyAgents(proxyBaseUrl, rejectUnauthorized)
        : undefined;

      const reqConfig: AxiosRequestConfig = {
        method: "GET",
        url: item.url,
        timeout: 10_000,
        maxRedirects: 3,
        validateStatus: () => true,
        responseType: "text",
        transformResponse: [(d: unknown) => d],
        ...(agents ?? {}),
      };

      const started = Date.now();
      let resp;
      try {
        resp = await axios(reqConfig);
      } catch (err) {
        // If Burp proxy (:8080) isn't running yet, fall back to direct crawl
        if (useProxy && axios.isAxiosError(err) && err.code === "ECONNREFUSED") {
          useProxy = false;
          task.proxied = false;
          logger.warn(
            `Local spider: Burp proxy ${proxyBaseUrl} unreachable, falling back to direct HTTP crawl`
          );
          const directCfg = { ...reqConfig };
          delete directCfg.httpAgent;
          delete directCfg.httpsAgent;
          resp = await axios(directCfg);
        } else {
          logger.debug(`Local spider error for ${item.url}: ${String(err)}`);
          continue;
        }
      }

      const elapsed = Date.now() - started;
      task.crawl_requests_made++;

      const resHeaders: Record<string, string> = {};
      for (const [k, v] of Object.entries(resp.headers)) {
        resHeaders[k] = Array.isArray(v) ? v.join(", ") : String(v ?? "");
      }
      const bodyStr =
        typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data ?? "");
      const mimeType = (resHeaders["content-type"] ?? "").split(";")[0]?.trim() || "text/plain";

      recordLocalExchange({
        source: "spider",
        proxied: useProxy,
        protocol: parsed.protocol === "https:" ? "https" : "http",
        host: parsed.hostname,
        port: parsed.port
          ? Number(parsed.port)
          : parsed.protocol === "https:"
          ? 443
          : 80,
        path: parsed.pathname + parsed.search,
        request: {
          method: "GET",
          url: item.url,
          headers: { "user-agent": "BurpSuite-MCP-Spider/1.0" },
        },
        response: {
          statusCode: resp.status,
          statusMessage: resp.statusText,
          headers: resHeaders,
          body: bodyStr.slice(0, 50_000),
          mimeType,
          responseTime: elapsed,
        },
      });

      if (
        item.depth < task.max_depth &&
        (/html|javascript|json/i.test(mimeType) || /<html/i.test(bodyStr.slice(0, 256)))
      ) {
        const links = extractLinksAndForms(bodyStr, item.url);
        for (const nextUrl of links) {
          if (discovered.size >= task.max_links) break;
          if (!urlMatchesCrawlScope(nextUrl, task.scope_included, task.scope_excluded)) {
            continue;
          }
          if (!discovered.has(nextUrl)) {
            discovered.add(nextUrl);
            queue.push({ url: nextUrl, depth: item.depth + 1 });
          }
        }
      }

      task.urls_discovered = Array.from(discovered);
      task.crawl_requests_queued = queue.length;
    }

    task.status = task.stop_requested ? "stopped" : "succeeded";
    task.finished_at = new Date().toISOString();
  } catch (err) {
    task.status = "failed";
    task.error = err instanceof Error ? err.message : String(err);
    task.finished_at = new Date().toISOString();
  }
}

export function getLocalCrawl(taskId: string): LocalCrawlTask | undefined {
  return localCrawls.get(taskId);
}

export function stopLocalCrawl(taskId: string): LocalCrawlTask | undefined {
  const task = localCrawls.get(taskId);
  if (task) {
    task.stop_requested = true;
    task.status = "stopped";
  }
  return task;
}

export function listLocalCrawls(): LocalCrawlTask[] {
  return Array.from(localCrawls.values());
}
