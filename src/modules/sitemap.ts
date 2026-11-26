// ============================================================
// BurpSuite MCP – SITEMAP & TARGET Module
// ============================================================
// Wraps the /v0.1/target/* endpoints of the BurpSuite REST API.
// Each entry in SITEMAP_TOOLS follows the standard MCP tool shape:
//   { name, description, inputSchema, handler }
// ============================================================

import { BurpClient, getBurpClient } from "../utils/burp-client.js";
import { logger } from "../utils/logger.js";
import type { SiteMapNode, ScopeRule } from "../types/index.js";
import {
  addLocalScopeUrl,
  clearLocalSiteMap,
  excludeLocalScopeUrl,
  getLocalScope,
  getLocalSiteMap,
  isLocalUrlInScope,
  setLocalScope,
} from "../utils/local-store.js";

// ── Internal API shapes ─────────────────────────────────────

interface BurpSiteMapEntry {
  host?: string;
  path?: string;
  protocol?: string;
  port?: number;
  responseCode?: number;
  mimeType?: string;
  request?: {
    method?: string;
    url?: string;
    headers?: Record<string, string>;
    body?: string;
  };
  response?: {
    statusCode?: number;
    statusMessage?: string;
    headers?: Record<string, string>;
    body?: string;
    mimeType?: string;
    responseTime?: number;
  };
}

interface BurpScopeConfig {
  include?: BurpScopeEntry[];
  exclude?: BurpScopeEntry[];
}

interface BurpScopeEntry {
  enabled?: boolean;
  host?: string;
  path?: string;
  protocol?: string;
  port?: string;
  file?: string;
}

// ── Helpers ──────────────────────────────────────────────────

/**
 * Extract the technology stack from response headers collected in the sitemap.
 * Returns a de-duplicated map: technology_name → evidence string.
 */
export function detectTechnologies(
  entries: BurpSiteMapEntry[]
): Record<string, string[]> {
  const tech: Record<string, Set<string>> = {};

  const push = (key: string, value: string) => {
    if (!tech[key]) tech[key] = new Set();
    tech[key].add(value);
  };

  for (const entry of entries) {
    const headers = entry.response?.headers ?? {};
    const headerMap = Object.fromEntries(
      Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])
    );

    // Server
    if (headerMap["server"]) push("server", headerMap["server"]);

    // X-Powered-By
    if (headerMap["x-powered-by"]) push("x-powered-by", headerMap["x-powered-by"]);

    // X-Generator / X-Drupal-Cache / X-Joomla-...
    for (const [k, v] of Object.entries(headerMap)) {
      if (k.startsWith("x-") && k !== "x-powered-by") push(k, v);
    }

    // Via
    if (headerMap["via"]) push("via", headerMap["via"]);

    // Set-Cookie fingerprinting
    const rawCookies = headers["Set-Cookie"] ?? headers["set-cookie"] ?? "";
    const cookieStr = Array.isArray(rawCookies)
      ? rawCookies.join("; ")
      : rawCookies;
    if (/PHPSESSID/i.test(cookieStr)) push("language", "PHP");
    if (/JSESSIONID/i.test(cookieStr)) push("language", "Java / JVM");
    if (/ASP\.NET_SessionId|\.ASPXAUTH/i.test(cookieStr))
      push("language", "ASP.NET");
    if (/csrftoken|sessionid/i.test(cookieStr)) push("framework", "Django");
    if (/laravel_session/i.test(cookieStr)) push("framework", "Laravel");
    if (/rack\.session/i.test(cookieStr)) push("framework", "Rack/Ruby");
    if (/connect\.sid/i.test(cookieStr)) push("framework", "Express.js");
    if (/wordpress_/i.test(cookieStr)) push("cms", "WordPress");
    if (/joomla/i.test(cookieStr)) push("cms", "Joomla");

    // Content-Type
    if (headerMap["content-type"]) {
      const ct = headerMap["content-type"];
      if (/application\/json/.test(ct)) push("api-format", "JSON");
      if (/text\/xml|application\/xml|application\/soap/.test(ct))
        push("api-format", "XML/SOAP");
    }
  }

  return Object.fromEntries(
    Object.entries(tech).map(([k, v]) => [k, [...v]])
  );
}

export async function fetchSiteMapEntries(
  client: BurpClient,
  host?: string
): Promise<{ mode: "burp-rest-api" | "community-local"; entries: BurpSiteMapEntry[] }> {
  return client.withRestFallback(
    async () => {
      const query = host ? `?host=${encodeURIComponent(host)}` : "";
      const data = await client.get<BurpSiteMapEntry[]>(
        `/v0.1/target/sitemap${query}`
      );
      return {
        mode: "burp-rest-api" as const,
        entries: Array.isArray(data) ? data : [],
      };
    },
    () => ({
      mode: "community-local" as const,
      entries: getLocalSiteMap(host) as BurpSiteMapEntry[],
    })
  );
}

// ── Tool definitions ─────────────────────────────────────────

export const SITEMAP_TOOLS = [
  // ── 1. sitemap_get ──────────────────────────────────────
  {
    name: "sitemap_get",
    description:
      "Retrieve the full BurpSuite target sitemap. " +
      "Optionally filter results to a specific host. " +
      "Returns a tree of URL nodes with status codes, HTTP methods, and response metadata.",
    inputSchema: {
      type: "object",
      properties: {
        host: {
          type: "string",
          description:
            "Optional hostname to filter results (e.g. 'example.com'). " +
            "When omitted, all hosts in the sitemap are returned.",
        },
      },
      required: [],
    },
    handler: async (params: { host?: string }, burpClient?: BurpClient) => {
      const client = burpClient ?? getBurpClient();
      const { mode, entries: data } = await fetchSiteMapEntries(client, params.host);

      // Group entries by host for a structured response
      const byHost: Record<string, BurpSiteMapEntry[]> = {};
      for (const entry of data) {
        const h = entry.host ?? "unknown";
        if (!byHost[h]) byHost[h] = [];
        byHost[h].push(entry);
      }

      const summary = Object.entries(byHost).map(([h, entries]) => ({
        host: h,
        total_endpoints: entries.length,
        status_codes: [
          ...new Set(entries.map((e) => e.responseCode).filter(Boolean)),
        ],
        methods: [
          ...new Set(
            entries.map((e) => e.request?.method).filter(Boolean)
          ),
        ],
        endpoints: entries.map((e) => ({
          path: e.path,
          method: e.request?.method,
          status: e.responseCode,
          mime: e.mimeType,
        })),
      }));

      return {
        mode,
        total_entries: data.length,
        hosts: Object.keys(byHost),
        sitemap: summary,
      };
    },
  },

  // ── 2. sitemap_get_host_details ─────────────────────────
  {
    name: "sitemap_get_host_details",
    description:
      "Get detailed information for a specific host from the BurpSuite sitemap. " +
      "Returns all discovered endpoints with request/response details, " +
      "detected technologies, and a summary of observed status codes.",
    inputSchema: {
      type: "object",
      properties: {
        host: {
          type: "string",
          description: "The hostname to inspect (e.g. 'api.example.com').",
        },
      },
      required: ["host"],
    },
    handler: async (params: { host: string }, burpClient?: BurpClient) => {
      const client = burpClient ?? getBurpClient();
      const { mode, entries: data } = await fetchSiteMapEntries(client, params.host);

      const technologies = detectTechnologies(data);

      const endpoints = data.map((entry) => ({
        path: entry.path,
        protocol: entry.protocol,
        port: entry.port,
        method: entry.request?.method,
        status: entry.responseCode,
        mime: entry.mimeType ?? entry.response?.mimeType,
        response_time_ms: entry.response?.responseTime,
        request_headers: entry.request?.headers,
        response_headers: entry.response?.headers,
      }));

      const statusCodes: Record<number, number> = {};
      for (const e of data) {
        if (e.responseCode) {
          statusCodes[e.responseCode] = (statusCodes[e.responseCode] ?? 0) + 1;
        }
      }

      return {
        mode,
        host: params.host,
        total_endpoints: data.length,
        status_code_distribution: statusCodes,
        technologies,
        endpoints,
      };
    },
  },

  // ── 3. scope_get ────────────────────────────────────────
  {
    name: "scope_get",
    description:
      "Retrieve the current BurpSuite target scope configuration. " +
      "Returns the included and excluded scope rules.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
    handler: async (_params: Record<string, never>, burpClient?: BurpClient) => {
      const client = burpClient ?? getBurpClient();
      return client.withRestFallback(
        async () => {
          const data = await client.get<BurpScopeConfig>("/v0.1/target/scope");
          return {
            mode: "burp-rest-api",
            included: data.include ?? [],
            excluded: data.exclude ?? [],
            total_included: (data.include ?? []).length,
            total_excluded: (data.exclude ?? []).length,
          };
        },
        () => ({
          mode: "community-local",
          ...getLocalScope(),
        })
      );
    },
  },

  // ── 4. scope_add_url ────────────────────────────────────
  {
    name: "scope_add_url",
    description:
      "Add a URL to the BurpSuite target scope (included list). " +
      "The URL is parsed and a scope rule is created for the matching host/path.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "The URL to include in scope (e.g. 'https://example.com/').",
        },
      },
      required: ["url"],
    },
    handler: async (params: { url: string }, burpClient?: BurpClient) => {
      const client = burpClient ?? getBurpClient();
      return client.withRestFallback(
        async () => {
          await client.put("/v0.1/target/scope", { include: [{ url: params.url }] });
          logger.info(`Scope: added ${params.url}`);
          return {
            mode: "burp-rest-api",
            success: true,
            message: `URL added to scope: ${params.url}`,
          };
        },
        () => {
          addLocalScopeUrl(params.url);
          logger.info(`Scope (local): added ${params.url}`);
          return {
            mode: "community-local",
            success: true,
            message: `URL added to local MCP scope: ${params.url}`,
          };
        }
      );
    },
  },

  // ── 5. scope_remove_url ─────────────────────────────────
  {
    name: "scope_remove_url",
    description:
      "Remove a URL from the BurpSuite target scope (add it to the excluded list). " +
      "Creates an exclusion rule that matches the host and path of the given URL.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "The URL to exclude from scope.",
        },
      },
      required: ["url"],
    },
    handler: async (params: { url: string }, burpClient?: BurpClient) => {
      const client = burpClient ?? getBurpClient();
      return client.withRestFallback(
        async () => {
          await client.put("/v0.1/target/scope", {
            exclude: [{ url: params.url }],
          });
          logger.info(`Scope: excluded ${params.url}`);
          return {
            mode: "burp-rest-api",
            success: true,
            message: `URL added to exclusion list: ${params.url}`,
          };
        },
        () => {
          excludeLocalScopeUrl(params.url);
          logger.info(`Scope (local): excluded ${params.url}`);
          return {
            mode: "community-local",
            success: true,
            message: `URL added to local MCP exclusion list: ${params.url}`,
          };
        }
      );
    },
  },

  // ── 6. scope_set ────────────────────────────────────────
  {
    name: "scope_set",
    description:
      "Replace the entire BurpSuite target scope in one operation. " +
      "All existing rules are overwritten with the provided included/excluded URL lists.",
    inputSchema: {
      type: "object",
      properties: {
        included: {
          type: "array",
          items: { type: "string" },
          description: "List of URLs / prefixes to include in scope.",
        },
        excluded: {
          type: "array",
          items: { type: "string" },
          description: "List of URLs / prefixes to exclude from scope.",
        },
      },
      required: ["included", "excluded"],
    },
    handler: async (
      params: { included: string[]; excluded: string[] },
      burpClient?: BurpClient
    ) => {
      const client = burpClient ?? getBurpClient();
      return client.withRestFallback(
        async () => {
          const body: BurpScopeConfig = {
            include: params.included.map((url) => ({ enabled: true, url } as unknown as BurpScopeEntry)),
            exclude: params.excluded.map((url) => ({ enabled: true, url } as unknown as BurpScopeEntry)),
          };
          await client.put("/v0.1/target/scope", body);
          logger.info(
            `Scope replaced: ${params.included.length} included, ${params.excluded.length} excluded`
          );
          return {
            mode: "burp-rest-api",
            success: true,
            included_count: params.included.length,
            excluded_count: params.excluded.length,
            message: "Scope replaced successfully.",
          };
        },
        () => {
          setLocalScope(params.included, params.excluded);
          return {
            mode: "community-local",
            success: true,
            included_count: params.included.length,
            excluded_count: params.excluded.length,
            message: "Local MCP scope replaced successfully.",
          };
        }
      );
    },
  },

  // ── 7. scope_check_url ──────────────────────────────────
  {
    name: "scope_check_url",
    description:
      "Check whether a given URL falls within the current BurpSuite target scope.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "The URL to check (e.g. 'https://example.com/admin').",
        },
      },
      required: ["url"],
    },
    handler: async (params: { url: string }, burpClient?: BurpClient) => {
      const client = burpClient ?? getBurpClient();
      return client.withRestFallback(
        async () => {
          const data = await client.get<{ inScope: boolean }>(
            `/v0.1/target/scope/check?url=${encodeURIComponent(params.url)}`
          );
          return {
            mode: "burp-rest-api",
            url: params.url,
            in_scope: data.inScope ?? false,
          };
        },
        () => ({
          mode: "community-local",
          url: params.url,
          in_scope: isLocalUrlInScope(params.url),
        })
      );
    },
  },

  // ── 8. sitemap_get_requests_for_host ────────────────────
  {
    name: "sitemap_get_requests_for_host",
    description:
      "Retrieve all recorded HTTP requests for a specific host from the BurpSuite sitemap, " +
      "including full request and response details. Useful for manual analysis of a target.",
    inputSchema: {
      type: "object",
      properties: {
        host: {
          type: "string",
          description: "The hostname to filter on (e.g. 'api.example.com').",
        },
        limit: {
          type: "number",
          description:
            "Maximum number of requests to return (default: 200). " +
            "Increase for exhaustive enumeration.",
          default: 200,
        },
      },
      required: ["host"],
    },
    handler: async (
      params: { host: string; limit?: number },
      burpClient?: BurpClient
    ) => {
      const client = burpClient ?? getBurpClient();
      const limit = params.limit ?? 200;

      const { mode, entries: data } = await fetchSiteMapEntries(client, params.host);

      const sliced = data.slice(0, limit);

      const requests = sliced.map((entry) => ({
        path: entry.path,
        method: entry.request?.method,
        status: entry.responseCode,
        response_size: entry.response?.body?.length ?? 0,
        response_time_ms: entry.response?.responseTime,
        mime: entry.mimeType ?? entry.response?.mimeType,
        request: {
          method: entry.request?.method,
          url: entry.request?.url,
          headers: entry.request?.headers,
          body: entry.request?.body,
        },
        response: {
          status_code: entry.response?.statusCode,
          status_message: entry.response?.statusMessage,
          headers: entry.response?.headers,
          body: entry.response?.body,
        },
      }));

      return {
        mode,
        host: params.host,
        total_available: data.length,
        returned: sliced.length,
        truncated: data.length > limit,
        requests,
      };
    },
  },

  // ── 9. sitemap_clear ────────────────────────────────────
  {
    name: "sitemap_clear",
    description:
      "Attempt to clear the BurpSuite sitemap via DELETE /v0.1/target/sitemap. " +
      "Note: this endpoint may not be available in all BurpSuite versions. " +
      "If the API returns 404 or 405, the sitemap must be cleared manually " +
      "via Burp's GUI (Target > Site map > Right-click > Clear).",
    inputSchema: {
      type: "object",
      properties: {
        host: {
          type: "string",
          description:
            "Optional hostname – if the API supports scoped deletion, only entries " +
            "for this host will be removed.",
        },
      },
      required: [],
    },
    handler: async (params: { host?: string }, burpClient?: BurpClient) => {
      const client = burpClient ?? getBurpClient();
      return client.withRestFallback(
        async () => {
          try {
            const path = params.host
              ? `/v0.1/target/sitemap?host=${encodeURIComponent(params.host)}`
              : "/v0.1/target/sitemap";
            await client.delete(path);
            logger.info("Sitemap cleared via API.");
            return {
              mode: "burp-rest-api",
              success: true,
              message: params.host
                ? `Sitemap entries for ${params.host} cleared.`
                : "Full sitemap cleared.",
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            const isNotSupported =
              msg.includes("404") || msg.includes("405") || msg.includes("501");
            logger.warn(`sitemap_clear: ${msg}`);
            return {
              mode: "burp-rest-api",
              success: false,
              supported: !isNotSupported,
              message: isNotSupported
                ? "The DELETE /v0.1/target/sitemap endpoint is not available in this " +
                  "version of BurpSuite. Clear the sitemap manually via: " +
                  "Target > Site map > Right-click > Clear sitemap."
                : `API error: ${msg}`,
            };
          }
        },
        () => {
          const cleared = clearLocalSiteMap(params.host);
          return {
            mode: "community-local",
            success: true,
            cleared_entries: cleared,
            message: params.host
              ? `Cleared ${cleared} local sitemap entries for ${params.host}.`
              : `Cleared ${cleared} local sitemap entries.`,
          };
        }
      );
    },
  },

  // ── 10. sitemap_get_technologies ────────────────────────
  {
    name: "sitemap_get_technologies",
    description:
      "Detect web technologies (server software, frameworks, languages, CMSes) " +
      "by analysing HTTP response headers recorded in the BurpSuite sitemap. " +
      "Optionally filter to a specific host.",
    inputSchema: {
      type: "object",
      properties: {
        host: {
          type: "string",
          description:
            "Optional hostname to restrict the analysis (e.g. 'example.com'). " +
            "When omitted, the entire sitemap is analysed.",
        },
      },
      required: [],
    },
    handler: async (params: { host?: string }, burpClient?: BurpClient) => {
      const client = burpClient ?? getBurpClient();
      const { mode, entries: data } = await fetchSiteMapEntries(client, params.host);

      // Group by host so we can report per-host
      const byHost: Record<string, BurpSiteMapEntry[]> = {};
      for (const entry of data) {
        const h = entry.host ?? "unknown";
        if (!byHost[h]) byHost[h] = [];
        byHost[h].push(entry);
      }

      const perHost = Object.entries(byHost).map(([h, entries]) => ({
        host: h,
        entries_analysed: entries.length,
        technologies: detectTechnologies(entries),
      }));

      // Global aggregate across all hosts
      const globalTech = detectTechnologies(data);

      return {
        mode,
        total_entries_analysed: data.length,
        hosts_analysed: Object.keys(byHost).length,
        global_technologies: globalTech,
        per_host: perHost,
      };
    },
  },
] as const;

export type SitemapTool = (typeof SITEMAP_TOOLS)[number];
