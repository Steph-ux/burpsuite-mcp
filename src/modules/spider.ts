// ============================================================
// BurpSuite MCP – Spider / Crawler Module
// ============================================================

import { BurpClient, getBurpClient } from "../utils/burp-client.js";
import { logger } from "../utils/logger.js";
import { SiteMapNode } from "../types/index.js";
import {
  getLocalCrawl,
  getLocalSiteMap,
  listLocalCrawls,
  startLocalCrawl,
  stopLocalCrawl,
} from "../utils/local-store.js";

// ── Internal helpers ─────────────────────────────────────────

interface BurpScanResponse {
  id?: string | number;
  task_id?: string | number;
}

interface BurpScanStatus {
  id?: string | number;
  status?: string;
  scan_status?: string;
  status_message?: string;
  completion_observable?: boolean;
  crawl_requests_made?: number;
  native_crawl_requests_made?: number | null;
  sitemap_delta?: number;
  crawl_requests_queued?: number;
  urls_discovered?: number;
  target_sitemap_urls?: number;
  progress_source?: string;
  warnings?: string[];
  audit_items?: unknown[];
  issue_events?: unknown[];
}

interface BurpScanListItem {
  id?: string | number;
  task_id?: string | number;
  status?: string;
  scan_status?: string;
  status_message?: string;
  completion_observable?: boolean;
  crawl_requests_made?: number;
  sitemap_delta?: number;
  urls_discovered?: number;
  urls?: string[];
  createdAt?: string;
}

type SiteMapItem = SiteMapNode & {
  request?: {
    method?: string;
    url?: string;
    headers?: Record<string, string>;
    body?: string;
  };
  response?: {
    statusCode?: number;
    headers?: Record<string, string>;
    body?: string;
    mimeType?: string;
  };
};

/** Extract all flat nodes from a potentially-nested sitemap tree */
function flattenSiteMap(nodes: SiteMapItem[]): SiteMapItem[] {
  const result: SiteMapItem[] = [];
  for (const node of nodes) {
    result.push(node);
    if (Array.isArray(node.children) && node.children.length > 0) {
      result.push(...flattenSiteMap(node.children as SiteMapItem[]));
    }
  }
  return result;
}

/** Build the full URL string from a sitemap node */
function nodeToUrl(node: SiteMapItem): string {
  const proto = node.protocol ?? "http";
  const host = node.host ?? "";
  const port = node.port;
  const path = node.path ?? "/";
  const hasDefaultPort =
    (proto === "http" && port === 80) ||
    (proto === "https" && port === 443);
  const portStr = port && !hasDefaultPort ? `:${port}` : "";
  return `${proto}://${host}${portStr}${path}`;
}

/** Fetch sitemap nodes via REST API with Community local-store fallback */
async function fetchSiteMapNodes(
  client: BurpClient,
  host?: string
): Promise<{ nodes: SiteMapItem[]; mode: "burp-rest-api" | "community-local" }> {
  return client.withRestFallback(
    async () => {
      const q = host ? `?host=${encodeURIComponent(host)}` : "";
      const siteMap = await client.get<SiteMapItem[]>(`/v0.1/target/sitemap${q}`);
      return {
        mode: "burp-rest-api" as const,
        nodes: flattenSiteMap(Array.isArray(siteMap) ? siteMap : []),
      };
    },
    () => ({
      mode: "community-local" as const,
      nodes: getLocalSiteMap(host) as unknown as SiteMapItem[],
    })
  );
}

/** Extract HTML <form> tags from crawled response bodies in Community mode */
function extractHtmlForms(
  nodes: SiteMapItem[]
): Array<{
  url: string;
  method: string;
  content_type: string | null;
  params_detected: string[];
  response_code: number | null;
}> {
  const results: Array<{
    url: string;
    method: string;
    content_type: string | null;
    params_detected: string[];
    response_code: number | null;
  }> = [];

  for (const n of nodes) {
    const body = n.response?.body ?? "";
    if (!body || !/<form/i.test(body)) continue;
    const baseUrl = nodeToUrl(n);
    const formRegex = /<form([^>]*)>([\s\S]*?)<\/form>/gi;
    let m: RegExpExecArray | null;
    while ((m = formRegex.exec(body)) !== null) {
      const attrs = m[1] ?? "";
      const inner = m[2] ?? "";
      const actionMatch = attrs.match(/action\s*=\s*["']([^"']*)["']/i);
      const methodMatch = attrs.match(/method\s*=\s*["']([^"']*)["']/i);
      let formUrl = baseUrl;
      if (actionMatch?.[1]) {
        try {
          formUrl = new URL(actionMatch[1], baseUrl).toString();
        } catch {
          formUrl = baseUrl;
        }
      }
      const method = (methodMatch?.[1] ?? "GET").toUpperCase();
      const inputNames = new Set<string>();
      const inputRegex = /<(?:input|select|textarea)[^>]+name\s*=\s*["']([^"']+)["']/gi;
      let inp: RegExpExecArray | null;
      while ((inp = inputRegex.exec(inner)) !== null) {
        if (inp[1]) inputNames.add(inp[1]);
      }
      results.push({
        url: formUrl,
        method,
        content_type: "application/x-www-form-urlencoded",
        params_detected: Array.from(inputNames),
        response_code: n.response?.statusCode ?? null,
      });
    }
  }
  return results;
}

// ── Tool: spider_start_crawl ─────────────────────────────────

const spiderStartCrawl = {
  name: "spider_start_crawl",
  description:
    "Start a crawl-only task via the Burp Suite REST API. No active scanning is performed – only link-following and sitemap population. Returns a task_id that can be used with the other spider tools.",
  inputSchema: {
    type: "object",
    properties: {
      urls: {
        type: "array",
        items: { type: "string" },
        description: "Seed URLs for the crawler (e.g. ['https://target.com/'])",
      },
      scope_included: {
        type: "array",
        items: { type: "string" },
        description:
          "URL prefix patterns to include in scope (e.g. ['https://target.com/'])",
        default: [],
      },
      scope_excluded: {
        type: "array",
        items: { type: "string" },
        description: "URL prefix patterns to exclude from scope",
        default: [],
      },
      max_depth: {
        type: "number",
        description: "Maximum crawl depth (default: 10)",
        default: 10,
      },
      max_links: {
        type: "number",
        description: "Maximum number of links to follow (default: 10000)",
        default: 10000,
      },
    },
    required: ["urls"],
  },
  handler: async (
    params: {
      urls: string[];
      scope_included?: string[];
      scope_excluded?: string[];
      max_depth?: number;
      max_links?: number;
    },
    burpClient?: BurpClient
  ) => {
    const client = burpClient ?? getBurpClient();

    const scopeIncluded = (params.scope_included ?? params.urls).map((p) => ({
      rule: p,
    }));
    const scopeExcluded = (params.scope_excluded ?? []).map((p) => ({
      rule: p,
    }));

    const body = {
      urls: params.urls,
      scope: {
        include: scopeIncluded,
        exclude: scopeExcluded,
      },
      // crawl-only: empty scan_configurations means no active audit
      scan_configurations: [],
      crawl_configuration: {
        max_link_depth: params.max_depth ?? 10,
        max_links_crawled: params.max_links ?? 10000,
      },
      resource_pool_id: "default",
    };

    logger.info(`spider_start_crawl: launching crawl for ${params.urls.join(", ")}`);

    return client.withRestFallback(
      async () => {
        const response = await client.post<BurpScanResponse>("/v0.1/scan", body);
        const taskId =
          response?.id ?? response?.task_id ?? (response as unknown as string);

        return {
          mode: "burp-rest-api",
          task_id: String(taskId),
          status: "started",
          urls: params.urls,
        };
      },
      () => {
        const task = startLocalCrawl({
          urls: params.urls,
          scope_included: params.scope_included,
          scope_excluded: params.scope_excluded,
          max_depth: params.max_depth,
          max_links: params.max_links,
          proxyBaseUrl: client.proxyBaseUrl,
          rejectUnauthorized: client.proxyTlsRejectUnauthorized,
        });
        return {
          mode: "community-local-spider",
          task_id: task.task_id,
          status: task.status,
          urls: task.urls,
          proxied_through: client.proxyBaseUrl,
        };
      }
    );
  },
};

// ── Tool: spider_get_crawl_status ────────────────────────────

const spiderGetCrawlStatus = {
  name: "spider_get_crawl_status",
  description:
    "Get the current status of a crawl task, including request counts and URLs discovered.",
  inputSchema: {
    type: "object",
    properties: {
      task_id: {
        type: "string",
        description: "Task ID returned by spider_start_crawl",
      },
    },
    required: ["task_id"],
  },
  handler: async (params: { task_id: string }, burpClient?: BurpClient) => {
    const client = burpClient ?? getBurpClient();

    if (params.task_id.startsWith("local-crawl-")) {
      const local = getLocalCrawl(params.task_id);
      if (!local) {
        throw new Error(`Local crawl task not found: ${params.task_id}`);
      }
      return {
        mode: "community-local-spider",
        task_id: local.task_id,
        status: local.status,
        crawl_requests_made: local.crawl_requests_made,
        crawl_requests_queued: local.crawl_requests_queued,
        urls_discovered: local.urls_discovered.length,
        proxied: local.proxied,
        error: local.error,
      };
    }

    return client.withRestFallback(
      async () => {
        const data = await client.get<BurpScanStatus>(
          `/v0.1/scan/${params.task_id}`
        );

        const status = data?.scan_status ?? data?.status ?? "unknown";
        const crawl_requests_made = data?.crawl_requests_made ?? 0;
        const crawl_requests_queued = data?.crawl_requests_queued ?? 0;

        const urls_discovered =
          data?.urls_discovered ??
          (Array.isArray(data?.audit_items) ? data.audit_items!.length : 0);

        return {
          mode: "burp-rest-api",
          task_id: params.task_id,
          status,
          crawl_requests_made,
          crawl_requests_queued,
          urls_discovered,
          ...(data?.sitemap_delta !== undefined ? { sitemap_delta: data.sitemap_delta } : {}),
          ...(data?.native_crawl_requests_made !== undefined
            ? { native_crawl_requests_made: data.native_crawl_requests_made }
            : {}),
          ...(data?.target_sitemap_urls !== undefined
            ? { target_sitemap_urls: data.target_sitemap_urls }
            : {}),
          ...(data?.progress_source !== undefined ? { progress_source: data.progress_source } : {}),
          ...(data?.completion_observable !== undefined
            ? { completion_observable: data.completion_observable }
            : {}),
          ...(data?.status_message !== undefined ? { status_message: data.status_message } : {}),
          ...(Array.isArray(data?.warnings) && data.warnings.length > 0
            ? { warnings: data.warnings }
            : {}),
        };
      },
      () => {
        const local = getLocalCrawl(params.task_id);
        if (!local) {
          throw new Error(`Crawl task not found: ${params.task_id}`);
        }
        return {
          mode: "community-local-spider",
          task_id: local.task_id,
          status: local.status,
          crawl_requests_made: local.crawl_requests_made,
          crawl_requests_queued: local.crawl_requests_queued,
          urls_discovered: local.urls_discovered.length,
          proxied: local.proxied,
        };
      }
    );
  },
};

// ── Tool: spider_get_discovered_urls ────────────────────────

const spiderGetDiscoveredUrls = {
  name: "spider_get_discovered_urls",
  description:
    "Return every URL discovered by Burp's crawler by reading the target sitemap. Optionally filter by task_id (used to restrict by the seed hosts).",
  inputSchema: {
    type: "object",
    properties: {
      task_id: {
        type: "string",
        description:
          "Task ID returned by spider_start_crawl (used as a hint; actual data comes from the sitemap)",
      },
    },
    required: ["task_id"],
  },
  handler: async (params: { task_id: string }, burpClient?: BurpClient) => {
    const client = burpClient ?? getBurpClient();

    const local = getLocalCrawl(params.task_id);
    if (local) {
      return {
        mode: "community-local-spider",
        task_id: params.task_id,
        count: local.urls_discovered.length,
        urls: local.urls_discovered,
      };
    }

    const { mode, nodes } = await fetchSiteMapNodes(client);

    const urls = nodes
      .filter((n) => n.host)
      .map(nodeToUrl)
      .filter(Boolean);

    const unique = [...new Set(urls)];

    logger.info(
      `spider_get_discovered_urls: ${unique.length} unique URLs in sitemap (task ${params.task_id})`
    );

    return { mode, task_id: params.task_id, count: unique.length, urls: unique };
  },
};

// ── Tool: spider_stop_crawl ──────────────────────────────────

const spiderStopCrawl = {
  name: "spider_stop_crawl",
  description: "Stop an active crawl task.",
  inputSchema: {
    type: "object",
    properties: {
      task_id: {
        type: "string",
        description: "Task ID of the crawl to stop",
      },
    },
    required: ["task_id"],
  },
  handler: async (params: { task_id: string }, burpClient?: BurpClient) => {
    const client = burpClient ?? getBurpClient();

    if (params.task_id.startsWith("local-crawl-")) {
      const stopped = stopLocalCrawl(params.task_id);
      if (!stopped) {
        throw new Error(`Local crawl task not found: ${params.task_id}`);
      }
      return {
        mode: "community-local-spider",
        task_id: params.task_id,
        status: "stopped",
      };
    }

    return client.withRestFallback(
      async () => {
        await client.delete(`/v0.1/scan/${params.task_id}`);
        logger.info(`spider_stop_crawl: crawl ${params.task_id} stopped`);
        return { mode: "burp-rest-api", task_id: params.task_id, status: "stopped" };
      },
      () => {
        const stopped = stopLocalCrawl(params.task_id);
        return {
          mode: "community-local-spider",
          task_id: params.task_id,
          status: stopped ? "stopped" : "not_found",
        };
      }
    );
  },
};

// ── Tool: spider_list_crawls ─────────────────────────────────

const spiderListCrawls = {
  name: "spider_list_crawls",
  description:
    "List all crawl tasks (active and finished) known to Burp Suite.",
  inputSchema: {
    type: "object",
    properties: {},
    required: [],
  },
  handler: async (_params: Record<string, never>, burpClient?: BurpClient) => {
    const client = burpClient ?? getBurpClient();
    const localList = listLocalCrawls().map((c) => ({
      task_id: c.task_id,
      status: c.status,
      urls: c.urls,
      urls_discovered: c.urls_discovered.length,
      created_at: c.created_at,
      mode: "community-local-spider",
    }));

    return client.withRestFallback(
      async () => {
        const data = await client.get<BurpScanListItem[]>("/v0.1/scan");
        const list = Array.isArray(data) ? data : [];

        const crawls = list.map((item) => ({
          task_id: String(item.id ?? item.task_id ?? ""),
          status: item.scan_status ?? item.status ?? "unknown",
          urls: item.urls ?? [],
          created_at: item.createdAt ?? null,
          mode: "burp-rest-api",
          ...(item.crawl_requests_made !== undefined ? { crawl_requests_made: item.crawl_requests_made } : {}),
          ...(item.sitemap_delta !== undefined ? { sitemap_delta: item.sitemap_delta } : {}),
          ...(item.urls_discovered !== undefined ? { urls_discovered: item.urls_discovered } : {}),
          ...(item.completion_observable !== undefined
            ? { completion_observable: item.completion_observable }
            : {}),
          ...(item.status_message !== undefined ? { status_message: item.status_message } : {}),
        }));

        const all = [...crawls, ...localList];
        return { count: all.length, crawls: all };
      },
      () => ({
        mode: "community-local-spider",
        count: localList.length,
        crawls: localList,
      })
    );
  },
};

// ── Tool: spider_get_forms ───────────────────────────────────

const spiderGetForms = {
  name: "spider_get_forms",
  description:
    "Extract form-like endpoints (POST endpoints / endpoints with body parameters) discovered in Burp's sitemap. Optionally filter by host.",
  inputSchema: {
    type: "object",
    properties: {
      host: {
        type: "string",
        description:
          "Optional hostname to filter by (e.g. 'target.com'). If omitted, all hosts are returned.",
      },
    },
    required: [],
  },
  handler: async (params: { host?: string }, burpClient?: BurpClient) => {
    const client = burpClient ?? getBurpClient();
    const { mode, nodes } = await fetchSiteMapNodes(client, params.host);

    // A "form" endpoint is any node where the recorded request is a POST
    // (or PUT/PATCH) and optionally has a body / Content-Type header.
    const forms = nodes
      .filter((n) => {
        if (!n.host || !n.request) return false;
        if (params.host && n.host !== params.host) return false;
        const method = (n.request.method ?? "").toUpperCase();
        return ["POST", "PUT", "PATCH"].includes(method);
      })
      .map((n) => {
        const url = nodeToUrl(n);
        const method = (n.request!.method ?? "POST").toUpperCase();
        const contentType =
          n.request!.headers?.["content-type"] ??
          n.request!.headers?.["Content-Type"] ??
          "";
        const body = n.request!.body ?? "";

        // Parse URL-encoded or JSON body params
        let params_detected: string[] = [];
        if (contentType.includes("application/x-www-form-urlencoded") || contentType === "") {
          try {
            params_detected = Array.from(
              new URLSearchParams(body).keys()
            );
          } catch {
            /* ignore */
          }
        } else if (contentType.includes("application/json")) {
          try {
            const parsed = JSON.parse(body);
            if (parsed && typeof parsed === "object") {
              params_detected = Object.keys(parsed);
            }
          } catch {
            /* ignore */
          }
        }

        return {
          url,
          method,
          content_type: contentType || null,
          params_detected,
          response_code: n.response?.statusCode ?? null,
        };
      });

    const htmlForms = extractHtmlForms(
      params.host ? nodes.filter((n) => n.host === params.host) : nodes
    );
    const combined = [...forms, ...htmlForms];

    return { mode, count: combined.length, forms: combined };
  },
};

// ── Tool: spider_get_endpoints ───────────────────────────────

const spiderGetEndpoints = {
  name: "spider_get_endpoints",
  description:
    "Return all HTTP endpoints discovered by Burp's crawler with their HTTP method, response code, MIME type, and detected parameters. Optionally filter by host and/or HTTP method.",
  inputSchema: {
    type: "object",
    properties: {
      host: {
        type: "string",
        description: "Optional hostname filter (e.g. 'api.target.com')",
      },
      method: {
        type: "string",
        description:
          "Optional HTTP method filter (e.g. 'GET', 'POST'). Case-insensitive.",
      },
    },
    required: [],
  },
  handler: async (
    params: { host?: string; method?: string },
    burpClient?: BurpClient
  ) => {
    const client = burpClient ?? getBurpClient();
    const { mode, nodes } = await fetchSiteMapNodes(client, params.host);

    const methodFilter = params.method?.toUpperCase();

    const endpoints = nodes
      .filter((n) => {
        if (!n.host || !n.path) return false;
        if (params.host && n.host !== params.host) return false;
        if (methodFilter) {
          const m = (n.request?.method ?? "GET").toUpperCase();
          if (m !== methodFilter) return false;
        }
        return true;
      })
      .map((n) => {
        const url = nodeToUrl(n);
        const method = (n.request?.method ?? "GET").toUpperCase();
        const responseCode = n.response?.statusCode ?? null;
        const mimeType = n.response?.mimeType ?? n.mimeType ?? null;

        // Detect query parameters from URL
        let query_params: string[] = [];
        try {
          const urlObj = new URL(url);
          query_params = Array.from(urlObj.searchParams.keys());
        } catch {
          /* ignore malformed URLs */
        }

        // Detect body parameters for non-GET requests
        let body_params: string[] = [];
        const body = n.request?.body ?? "";
        const contentType =
          n.request?.headers?.["content-type"] ??
          n.request?.headers?.["Content-Type"] ??
          "";
        if (body) {
          if (contentType.includes("application/x-www-form-urlencoded")) {
            try {
              body_params = Array.from(new URLSearchParams(body).keys());
            } catch {
              /* ignore */
            }
          } else if (contentType.includes("application/json")) {
            try {
              const parsed = JSON.parse(body);
              if (parsed && typeof parsed === "object") {
                body_params = Object.keys(parsed);
              }
            } catch {
              /* ignore */
            }
          }
        }

        return {
          url,
          method,
          response_code: responseCode,
          mime_type: mimeType,
          query_params,
          body_params,
        };
      });

    // Deduplicate by url+method
    const seen = new Set<string>();
    const unique = endpoints.filter((e) => {
      const key = `${e.method}:${e.url}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    return { mode, count: unique.length, endpoints: unique };
  },
};

// ── Exported tool list ───────────────────────────────────────

export const SPIDER_TOOLS = [
  spiderStartCrawl,
  spiderGetCrawlStatus,
  spiderGetDiscoveredUrls,
  spiderStopCrawl,
  spiderListCrawls,
  spiderGetForms,
  spiderGetEndpoints,
];
