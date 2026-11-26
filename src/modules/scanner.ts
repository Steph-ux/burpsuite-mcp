/**
 * SCANNER MODULE
 * BurpSuite MCP – wraps BurpSuite Pro REST API scanner endpoints.
 * API base: http://BURP_HOST:BURP_API_PORT  (default 127.0.0.1:1337)
 * Auth header: X-Burp-Api-Token
 */

import { getBurpClient, BurpClient } from "../utils/burp-client.js";
import {
  analyzePassiveExchange,
  getLocalPassiveIssues,
  PASSIVE_ISSUE_DEFINITIONS,
} from "../utils/local-store.js";

function communityActiveScannerNotice(toolName: string) {
  return {
    supported: false,
    mode: "community-no-active-scanner",
    tool: toolName,
    message:
      "BurpSuite Active Scanner and its REST API (/v0.1/scan) require BurpSuite Pro. " +
      "When you upgrade to Pro, set BURP_API_KEY in .env to enable native active scanning automatically.",
    community_alternatives: [
      "start_passive_scan (local passive security checks)",
      "get_all_issues / get_issues_for_host (passive findings from MCP traffic)",
      "spider_start_crawl (crawl via Burp Community proxy)",
      "intruder_start_attack (fuzzing via Burp Community proxy)",
      "repeater_send_request (manual request testing via Burp Community proxy)",
    ],
  };
}

function decodeMaybeBase64(input: string): string {
  const trimmed = input.trim();
  if (/^HTTP\/\d\.\d\s+\d{3}/i.test(trimmed)) return input;
  if (/^[A-Za-z0-9+/=]+$/.test(trimmed) && trimmed.length >= 16) {
    try {
      const decoded = Buffer.from(trimmed, "base64").toString("utf8");
      if (/^HTTP\/\d\.\d\s+\d{3}/i.test(decoded) || /<[a-z!]/i.test(decoded)) {
        return decoded;
      }
    } catch {
      /* ignore */
    }
  }
  return input;
}

function parseHttpResponseText(raw: string): {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
} {
  const text = decodeMaybeBase64(raw);
  const sep = text.includes("\r\n\r\n") ? "\r\n\r\n" : "\n\n";
  const lineSep = text.includes("\r\n") ? "\r\n" : "\n";
  const idx = text.indexOf(sep);
  const head = idx >= 0 ? text.slice(0, idx) : text;
  const body = idx >= 0 ? text.slice(idx + sep.length) : "";
  const lines = head.split(lineSep);
  const statusMatch = (lines[0] ?? "").match(/HTTP\/\d\.\d\s+(\d{3})/i);
  const statusCode = statusMatch ? Number(statusMatch[1]) : 200;
  const headers: Record<string, string> = {};
  for (const line of lines.slice(1)) {
    const c = line.indexOf(":");
    if (c > 0) {
      headers[line.slice(0, c).trim().toLowerCase()] = line.slice(c + 1).trim();
    }
  }
  return { statusCode, headers, body };
}

export async function analyzeCommunityLiveSitemap(
  burpClient: BurpClient,
  host?: string
): Promise<{ mode: string; count: number; issues: ReturnType<typeof getLocalPassiveIssues> }> {
  try {
    const query = host ? `?host=${encodeURIComponent(host)}` : "";
    const sitemapRes = await burpClient.get<Array<Record<string, unknown>>>(
      `/v0.1/target/sitemap${query}`
    );
    if (Array.isArray(sitemapRes)) {
      for (const node of sitemapRes) {
        const req = (node.request as Record<string, unknown>) ?? {};
        const res = (node.response as Record<string, unknown>) ?? {};
        const url =
          (req.url as string) ||
          `${(node.protocol as string) ?? "http"}://${(node.host as string) ?? ""}${(node.path as string) ?? "/"}`;
        if (!url || !node.host) continue;
        const headers = (res.headers as Record<string, string>) ?? {};
        const body = (res.body as string) ?? "";
        if (Object.keys(headers).length > 0 || body.length > 0) {
          analyzePassiveExchange({
            url,
            statusCode: (res.statusCode as number) ?? (node.responseCode as number),
            responseHeaders: headers,
            responseBody: body,
          });
        }
      }
      const issues = getLocalPassiveIssues(host);
      return { mode: "community-bridge-passive", count: issues.length, issues };
    }
  } catch {
    /* ignore if sitemap not reachable; return local passive issues below */
  }
  const issues = getLocalPassiveIssues(host);
  return { mode: "community-local-passive", count: issues.length, issues };
}

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ScanIssue {
  name: string;
  severity: "high" | "medium" | "low" | "info" | string;
  confidence: "certain" | "firm" | "tentative" | string;
  host: string;
  path: string;
  description: string;
  remediation: string;
  issue_type?: number;
  serial_number?: string;
}

export interface ScanTask {
  task_id: string;
  status: string;
  scan_status?: string;
  urls?: string[];
  created_at?: string;
}

export interface McpTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  handler: (args: Record<string, unknown>, burpClient: BurpClient) => Promise<unknown>;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Normalise an issue object from the Burp API into our ScanIssue shape.
 * Burp returns snake_case; we keep it consistent and fill missing fields.
 */
function normaliseIssue(raw: Record<string, unknown>): ScanIssue {
  return {
    name: (raw.name ?? raw.issue_type_id ?? "Unknown") as string,
    severity: (raw.severity ?? "info") as string,
    confidence: (raw.confidence ?? "tentative") as string,
    host: (raw.origin ?? raw.host ?? "") as string,
    path: (raw.path ?? "/") as string,
    description: (raw.description ?? raw.detail ?? "") as string,
    remediation: (raw.remediation ?? raw.recommendation ?? "") as string,
    issue_type: raw.type_index as number | undefined,
    serial_number: (raw.serial_number ?? raw.id) as string | undefined,
  };
}

// ─── Tool definitions ─────────────────────────────────────────────────────────

const startScan: McpTool = {
  name: "start_scan",
  description:
    "Launch an active scan against one or more URLs using BurpSuite Pro. " +
    "Returns the task_id that can be used to monitor or stop the scan.",
  inputSchema: {
    type: "object",
    properties: {
      urls: {
        type: "array",
        items: { type: "string" },
        description: "List of URLs to scan.",
      },
      scan_configurations: {
        type: "array",
        items: {
          type: "object",
          properties: {
            name: { type: "string", description: "Name of a saved scan configuration in Burp." },
          },
          required: ["name"],
        },
        description: "Named scan configurations to apply (optional).",
      },
      scope_included: {
        type: "array",
        items: { type: "string" },
        description: "URL prefixes or regexes explicitly included in scope.",
      },
      scope_excluded: {
        type: "array",
        items: { type: "string" },
        description: "URL prefixes or regexes explicitly excluded from scope.",
      },
    },
    required: ["urls"],
  },
  async handler(args, burpClient) {
    const urls = args.urls as string[];
    const scan_configurations = (args.scan_configurations as Array<{ name: string }>) ?? [];
    const scope_included = (args.scope_included as string[]) ?? urls;
    const scope_excluded = (args.scope_excluded as string[]) ?? [];

    const payload: Record<string, unknown> = {
      urls,
      scope: {
        include: scope_included.map((p) => ({ rule: p })),
        exclude: scope_excluded.map((p) => ({ rule: p })),
      },
    };

    if (scan_configurations.length > 0) {
      payload.scan_configurations = scan_configurations;
    }

    return burpClient.withRestFallback(
      async () => {
        const response = await burpClient.postRaw("/v0.1/scan", payload);
        // Burp returns 201 with a Location header; task_id is in the Location path.
        const location: string = (response.headers?.location as string) ?? "";
        const task_id = location.split("/").pop() ?? (response.data as Record<string, unknown>)?.task_id ?? "";

        return {
          mode: "burp-rest-api",
          task_id,
          message: `Scan started. Monitor with get_scan_status task_id="${task_id}".`,
          raw: response.data,
        };
      },
      () => communityActiveScannerNotice("start_scan")
    );
  },
};

// ─────────────────────────────────────────────────────────────────────────────

const getScanStatus: McpTool = {
  name: "get_scan_status",
  description: "Get the current status and progress of a BurpSuite scan by its task_id.",
  inputSchema: {
    type: "object",
    properties: {
      task_id: {
        type: "string",
        description: "The scan task ID returned by start_scan.",
      },
    },
    required: ["task_id"],
  },
  async handler(args, burpClient) {
    const { task_id } = args as { task_id: string };
    return burpClient.withRestFallback(
      () => burpClient.get(`/v0.1/scan/${task_id}`),
      () => communityActiveScannerNotice("get_scan_status")
    );
  },
};

// ─────────────────────────────────────────────────────────────────────────────

const getScanIssues: McpTool = {
  name: "get_scan_issues",
  description:
    "Retrieve all vulnerability issues found by a specific scan. " +
    "Returns a list of ScanIssue objects with name, severity, confidence, host, path, description and remediation.",
  inputSchema: {
    type: "object",
    properties: {
      task_id: {
        type: "string",
        description: "The scan task ID returned by start_scan.",
      },
    },
    required: ["task_id"],
  },
  async handler(args, burpClient) {
    const { task_id } = args as { task_id: string };
    return burpClient.withRestFallback(
      async () => {
        const response = await burpClient.get<Record<string, unknown>>(`/v0.1/scan/${task_id}`);
        const rawIssues: Record<string, unknown>[] = Array.isArray((response as Record<string,unknown>)?.issue_events)
          ? ((response as Record<string,unknown>).issue_events as Record<string,unknown>[]).map(
              (evt: Record<string, unknown>) =>
                (evt.issue as Record<string, unknown>) ?? evt,
            )
          : Array.isArray((response as Record<string,unknown>)?.issues)
          ? (response as Record<string,unknown>).issues as Record<string,unknown>[]
          : [];

        const issues: ScanIssue[] = rawIssues.map(normaliseIssue);
        return { mode: "burp-rest-api", task_id, count: issues.length, issues };
      },
      () => ({
        ...communityActiveScannerNotice("get_scan_issues"),
        passive_issues: getLocalPassiveIssues(),
      })
    );
  },
};

// ─────────────────────────────────────────────────────────────────────────────

const stopScan: McpTool = {
  name: "stop_scan",
  description: "Abort (cancel) a running BurpSuite scan by its task_id.",
  inputSchema: {
    type: "object",
    properties: {
      task_id: {
        type: "string",
        description: "The scan task ID to stop.",
      },
    },
    required: ["task_id"],
  },
  async handler(args, burpClient) {
    const { task_id } = args as { task_id: string };
    return burpClient.withRestFallback(
      async () => {
        await burpClient.delete(`/v0.1/scan/${task_id}`);
        return { task_id, message: `Scan ${task_id} has been stopped.` };
      },
      () => communityActiveScannerNotice("stop_scan")
    );
  },
};

// ─────────────────────────────────────────────────────────────────────────────

const listScans: McpTool = {
  name: "list_scans",
  description: "List all active and completed scans managed by BurpSuite Pro.",
  inputSchema: {
    type: "object",
    properties: {},
  },
  async handler(_args, burpClient) {
    return burpClient.withRestFallback(
      () => burpClient.get("/v0.1/scan"),
      () => ({
        mode: "community-no-active-scanner",
        scans: [],
        message: "No active scans (BurpSuite Pro REST API not reachable).",
      })
    );
  },
};

// ─────────────────────────────────────────────────────────────────────────────

const startPassiveScan: McpTool = {
  name: "start_passive_scan",
  description:
    "Submit a captured HTTP request/response pair for passive scanning. " +
    "Burp will analyse it without sending any additional traffic.",
  inputSchema: {
    type: "object",
    properties: {
      url: {
        type: "string",
        description: "The URL that the request was sent to.",
      },
      request: {
        type: "string",
        description: "Raw HTTP request (base64-encoded or plain text).",
      },
      response: {
        type: "string",
        description: "Raw HTTP response (base64-encoded or plain text).",
      },
    },
    required: ["url", "request", "response"],
  },
  async handler(args, burpClient) {
    const { url, request, response } = args as {
      url: string;
      request: string;
      response: string;
    };

    // Burp passive scan endpoint: POST /v0.1/scan (with scan_configurations pointing to passive)
    // or via the audit queue. We use the documented approach for passive scanning.
    const payload = {
      urls: [url],
      scan_configurations: [{ name: "Crawl limit - 10 requests" }],
      scope: { include: [{ rule: url }], exclude: [] },
      // Attach the request/response as a captured item if the API supports it.
      captured_requests: [
        {
          request: Buffer.from(request).toString("base64"),
          response: Buffer.from(response).toString("base64"),
          url,
        },
      ],
    };

    return burpClient.withRestFallback(
      async () => {
        try {
          const res = await burpClient.postRaw<Record<string,unknown>>("/v0.1/scan", payload);
          const location: string = (res.headers?.location as string) ?? "";
          const task_id = location.split("/").pop() ?? (res.data as Record<string,unknown>)?.task_id ?? "";
          return { mode: "burp-rest-api", task_id, message: "Passive scan started.", url };
        } catch (err) {
          if (BurpClient.isConnectionError(err)) throw err;
          // Fallback: add item to proxy history for passive audit
          const auditRes = await burpClient.post("/v0.1/proxy/history", {
            request: Buffer.from(request).toString("base64"),
            response: Buffer.from(response).toString("base64"),
            url,
          });
          return {
            mode: "burp-rest-api",
            message: "Item submitted for passive analysis via proxy history.",
            data: auditRes,
          };
        }
      },
      () => {
        const parsed = parseHttpResponseText(response);
        const issues = analyzePassiveExchange({
          url,
          statusCode: parsed.statusCode,
          responseHeaders: parsed.headers,
          responseBody: parsed.body,
        });
        return {
          mode: "community-local-passive",
          url,
          issues_found: issues.length,
          issues,
        };
      }
    );
  },
};

// ─────────────────────────────────────────────────────────────────────────────

const getAllIssues: McpTool = {
  name: "get_all_issues",
  description:
    "Retrieve all vulnerability issues site-wide by cross-referencing issue definitions " +
    "with the target sitemap. Returns a combined list with full issue detail.",
  inputSchema: {
    type: "object",
    properties: {},
  },
  async handler(_args, burpClient) {
    return burpClient.withRestFallback(
      async () => {
        // Fetch both in parallel
        const [defsRes, sitemapRes] = await Promise.all([
          burpClient.get("/v0.1/issue-definitions"),
          burpClient.get("/v0.1/target/sitemap"),
        ]);

        // Build a lookup map: type_index -> definition
        const definitions: Record<number, Record<string, unknown>> = {};
        const rawDefs = Array.isArray(defsRes)
          ? defsRes
          : ((defsRes as Record<string,unknown>)?.issue_definitions ?? []);
        for (const def of rawDefs as Record<string, unknown>[]) {
          const idx = def.type_index ?? def.issue_type_id;
          if (idx !== undefined) {
            definitions[idx as number] = def;
          }
        }

        // Collect all issues from sitemap nodes
        const allIssues: ScanIssue[] = [];
        const sitemap: Record<string, unknown>[] = Array.isArray(sitemapRes)
          ? (sitemapRes as Record<string, unknown>[])
          : (((sitemapRes as Record<string,unknown>)?.sitemap as Record<string,unknown>[]) ?? []);

        for (const node of sitemap) {
          const nodeIssues: Record<string, unknown>[] = Array.isArray(node.issues)
            ? (node.issues as Record<string, unknown>[])
            : [];
          for (const issue of nodeIssues) {
            const typeIdx = issue.type_index as number | undefined;
            const def = typeIdx !== undefined ? definitions[typeIdx] : undefined;
            allIssues.push(
              normaliseIssue({
                ...issue,
                description: (issue.description ?? def?.description ?? "") as string,
                remediation: (issue.remediation ?? def?.remediation ?? "") as string,
                name: (issue.name ?? def?.name ?? "Unknown") as string,
              }),
            );
          }
        }

        return { mode: "burp-rest-api", count: allIssues.length, issues: allIssues };
      },
      () => analyzeCommunityLiveSitemap(burpClient)
    );
  },
};

// ─────────────────────────────────────────────────────────────────────────────

const getIssueDefinitions: McpTool = {
  name: "get_issue_definitions",
  description:
    "Retrieve the master list of all vulnerability type definitions known to BurpSuite, " +
    "including their names, descriptions, severities and remediation guidance.",
  inputSchema: {
    type: "object",
    properties: {},
  },
  async handler(_args, burpClient) {
    return burpClient.withRestFallback(
      () => burpClient.get("/v0.1/issue-definitions"),
      () => ({
        mode: "community-local-passive",
        count: PASSIVE_ISSUE_DEFINITIONS.length,
        issue_definitions: PASSIVE_ISSUE_DEFINITIONS,
      })
    );
  },
};

// ─────────────────────────────────────────────────────────────────────────────

const getIssuesForHost: McpTool = {
  name: "get_issues_for_host",
  description:
    "Retrieve all vulnerability issues found for a specific host (origin). " +
    "Searches the sitemap and returns matching issues with full detail.",
  inputSchema: {
    type: "object",
    properties: {
      host: {
        type: "string",
        description:
          "The host to filter by, e.g. 'https://example.com' or 'example.com'. " +
          "Matching is performed on the origin/host field of sitemap nodes.",
      },
    },
    required: ["host"],
  },
  async handler(args, burpClient) {
    const { host } = args as { host: string };

    return burpClient.withRestFallback(
      async () => {
        const [sitemapRes, defsRes] = await Promise.all([
          burpClient.get("/v0.1/target/sitemap", { params: { base_url: host } }),
          burpClient.get("/v0.1/issue-definitions"),
        ]);

        // Build definitions lookup
        const definitions: Record<number, Record<string, unknown>> = {};
        const rawDefs = Array.isArray(defsRes)
          ? defsRes
          : ((defsRes as Record<string,unknown>)?.issue_definitions ?? []);
        for (const def of rawDefs as Record<string, unknown>[]) {
          const idx = def.type_index ?? def.issue_type_id;
          if (idx !== undefined) definitions[idx as number] = def;
        }

        // Collect issues for the given host
        const sitemap: Record<string, unknown>[] = Array.isArray(sitemapRes)
          ? (sitemapRes as Record<string, unknown>[])
          : (((sitemapRes as Record<string,unknown>)?.sitemap as Record<string,unknown>[]) ?? []);

        const normalise = (h: string) => h.replace(/\/$/, "").toLowerCase();
        const targetHost = normalise(host);

        const issues: ScanIssue[] = [];
        for (const node of sitemap) {
          const nodeHost = normalise(
            (node.origin ?? node.host ?? node.url ?? "") as string,
          );
          if (!nodeHost.includes(targetHost) && !targetHost.includes(nodeHost)) continue;

          const nodeIssues: Record<string, unknown>[] = Array.isArray(node.issues)
            ? (node.issues as Record<string, unknown>[])
            : [];
          for (const issue of nodeIssues) {
            const typeIdx = issue.type_index as number | undefined;
            const def = typeIdx !== undefined ? definitions[typeIdx] : undefined;
            issues.push(
              normaliseIssue({
                ...issue,
                host: nodeHost,
                description: (issue.description ?? def?.description ?? "") as string,
                remediation: (issue.remediation ?? def?.remediation ?? "") as string,
                name: (issue.name ?? def?.name ?? "Unknown") as string,
              }),
            );
          }
        }

        return { mode: "burp-rest-api", host, count: issues.length, issues };
      },
      () => analyzeCommunityLiveSitemap(burpClient, host)
    );
  },
};

// ─── Export ───────────────────────────────────────────────────────────────────

export const SCANNER_TOOLS: McpTool[] = [
  startScan,
  getScanStatus,
  getScanIssues,
  stopScan,
  listScans,
  startPassiveScan,
  getAllIssues,
  getIssueDefinitions,
  getIssuesForHost,
];

export default SCANNER_TOOLS;
