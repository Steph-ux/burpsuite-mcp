/**
 * BurpSuite MCP – Repeater module
 *
 * The Burp Pro REST API does not expose the Repeater tab directly.
 * This module implements Repeater functionality by:
 *   - Sending HTTP/HTTPS requests directly to the target (optionally routed
 *     through the Burp proxy for interception / logging), and
 *   - Maintaining an in-memory history of every request/response pair so the
 *     AI can inspect, replay, or reference previous interactions.
 */

import { randomUUID } from "node:crypto";
import axios, { type AxiosRequestConfig, type AxiosResponse } from "axios";
import { type BurpClient, getBurpClient } from "../utils/burp-client.js";
import {
  createProxyAgents,
  getLocalHistoryItem,
  recordLocalExchange,
} from "../utils/local-store.js";

// ---------------------------------------------------------------------------
// Env / config helpers
// ---------------------------------------------------------------------------

function resolveProxySettings(client?: BurpClient): {
  proxyUrl: string;
  rejectUnauthorized: boolean;
} {
  if (client) {
    return {
      proxyUrl: client.proxyBaseUrl,
      rejectUnauthorized: client.proxyTlsRejectUnauthorized,
    };
  }
  try {
    const c = getBurpClient();
    return {
      proxyUrl: c.proxyBaseUrl,
      rejectUnauthorized: c.proxyTlsRejectUnauthorized,
    };
  } catch {
    const host = process.env.BURP_HOST ?? "127.0.0.1";
    const port = Number(process.env.BURP_PORT ?? 8080);
    return {
      proxyUrl: `http://${host}:${port}`,
      rejectUnauthorized: process.env.BURP_PROXY_TLS_REJECT_UNAUTHORIZED === "true",
    };
  }
}

// ---------------------------------------------------------------------------
// In-memory history store
// ---------------------------------------------------------------------------

export interface RepeaterEntry {
  id: string;
  name?: string;
  timestamp: string;
  sent: boolean;
  request: {
    host: string;
    port: number;
    use_https: boolean;
    method: string;
    path: string;
    headers: Record<string, string>;
    body?: string;
  };
  response?: {
    status: number;
    status_text: string;
    headers: Record<string, string>;
    body: string;
    timing_ms: number;
  };
  error?: string;
}

const repeaterHistory = new Map<string, RepeaterEntry>();

// ---------------------------------------------------------------------------
// Core send helper
// ---------------------------------------------------------------------------

interface SendOptions {
  host: string;
  port: number;
  use_https: boolean;
  method: string;
  path: string;
  headers: Record<string, string>;
  body?: string;
  follow_redirects?: boolean;
  use_burp_proxy?: boolean;
}

async function sendHttpRequest(
  opts: SendOptions,
  burpClient?: BurpClient
): Promise<{
  status: number;
  status_text: string;
  headers: Record<string, string>;
  body: string;
  timing_ms: number;
  proxied: boolean;
}> {
  const useProxy = opts.use_burp_proxy !== false;
  const { proxyUrl, rejectUnauthorized } = resolveProxySettings(burpClient);
  const agents = useProxy
    ? createProxyAgents(proxyUrl, rejectUnauthorized)
    : undefined;

  const url = `${opts.use_https ? "https" : "http"}://${opts.host}:${opts.port}${opts.path}`;

  const config: AxiosRequestConfig = {
    method: opts.method.toUpperCase(),
    url,
    headers: opts.headers,
    data: opts.body ?? undefined,
    maxRedirects: opts.follow_redirects ? 5 : 0,
    validateStatus: () => true, // accept any HTTP status
    responseType: "text",
    timeout: 30_000,
    ...(agents ?? {}),
    transformResponse: [(data: unknown) => data],
  };

  let proxied = useProxy;
  const start = Date.now();
  let resp: AxiosResponse;
  try {
    resp = await axios(config);
  } catch (err) {
    // If Burp proxy isn't listening and user didn't explicitly forbid fallback,
    // allow direct send? No: only fall back if proxy ECONNREFUSED? Better: surface or fallback?
    // Keep explicit error when proxy explicitly requested unless direct fallback desired;
    // actually for seamless Community experience, retry direct if proxy port is down & mark proxied=false.
    if (useProxy && axios.isAxiosError(err) && err.code === "ECONNREFUSED") {
      proxied = false;
      const directCfg = { ...config };
      delete directCfg.httpAgent;
      delete directCfg.httpsAgent;
      resp = await axios(directCfg);
    } else {
      throw err;
    }
  }
  const timing_ms = Date.now() - start;

  // Flatten response headers (axios stores them as lowercase)
  const responseHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(resp.headers)) {
    if (typeof v === "string") responseHeaders[k] = v;
    else if (Array.isArray(v)) responseHeaders[k] = v.join(", ");
  }

  const bodyStr =
    typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);

  recordLocalExchange({
    source: "repeater",
    proxied,
    protocol: opts.use_https ? "https" : "http",
    host: opts.host,
    port: opts.port,
    path: opts.path,
    request: {
      method: opts.method.toUpperCase(),
      url,
      headers: opts.headers,
      body: opts.body,
    },
    response: {
      statusCode: resp.status,
      statusMessage: resp.statusText,
      headers: responseHeaders,
      body: bodyStr.slice(0, 50_000),
      mimeType: (responseHeaders["content-type"] ?? "").split(";")[0]?.trim() || "text/plain",
      responseTime: timing_ms,
    },
  });

  return {
    status: resp.status,
    status_text: resp.statusText,
    headers: responseHeaders,
    body: bodyStr,
    timing_ms,
    proxied,
  };
}

// ---------------------------------------------------------------------------
// Tool definitions
// ---------------------------------------------------------------------------

export interface McpTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  handler: (
    args: Record<string, unknown>,
    _burpClient?: BurpClient
  ) => Promise<unknown>;
}

// 1. repeater_send_request ---------------------------------------------------

const repeaterSendRequest: McpTool = {
  name: "repeater_send_request",
  description:
    "Send a custom HTTP/HTTPS request to a target host, optionally routing it " +
    "through the Burp proxy for interception and logging. The request and its " +
    "full response (status, headers, body, timing) are stored in the in-memory " +
    "Repeater history and can be retrieved later with repeater_get_item.",
  inputSchema: {
    type: "object",
    required: ["host", "port", "use_https", "method", "path", "headers"],
    properties: {
      host: { type: "string", description: "Target hostname or IP address." },
      port: { type: "number", description: "Target TCP port (e.g. 80 or 443)." },
      use_https: { type: "boolean", description: "Use TLS/HTTPS for the connection." },
      method: {
        type: "string",
        enum: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"],
        description: "HTTP method.",
      },
      path: { type: "string", description: "Request path including query string (e.g. /api/users?page=1)." },
      headers: {
        type: "object",
        additionalProperties: { type: "string" },
        description: "HTTP request headers as key-value pairs.",
      },
      body: { type: "string", description: "Optional request body." },
      follow_redirects: {
        type: "boolean",
        default: false,
        description: "Whether to automatically follow HTTP redirects.",
      },
      use_burp_proxy: {
        type: "boolean",
        default: true,
        description:
          "Route the request through the Burp proxy (127.0.0.1:8080 by default) " +
          "so it appears in the Burp UI. Set to false to send directly.",
      },
      name: {
        type: "string",
        description: "Optional human-readable label for this request in the history.",
      },
    },
  },
  handler: async (args, burpClient) => {
    const id = randomUUID();
    const request: RepeaterEntry["request"] = {
      host: args.host as string,
      port: args.port as number,
      use_https: args.use_https as boolean,
      method: (args.method as string).toUpperCase(),
      path: args.path as string,
      headers: (args.headers as Record<string, string>) ?? {},
      body: args.body as string | undefined,
    };

    const entry: RepeaterEntry = {
      id,
      name: args.name as string | undefined,
      timestamp: new Date().toISOString(),
      sent: false,
      request,
    };

    try {
      const resp = await sendHttpRequest(
        {
          ...request,
          follow_redirects: (args.follow_redirects as boolean | undefined) ?? false,
          use_burp_proxy: (args.use_burp_proxy as boolean | undefined) ?? true,
        },
        burpClient
      );

      entry.sent = true;
      entry.response = resp;
      repeaterHistory.set(id, entry);

      return {
        id,
        proxied: resp.proxied,
        status: resp.status,
        status_text: resp.status_text,
        headers: resp.headers,
        body: resp.body,
        timing_ms: resp.timing_ms,
      };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      entry.error = message;
      repeaterHistory.set(id, entry);
      throw new Error(`repeater_send_request failed: ${message}`);
    }
  },
};

// 2. repeater_get_history ----------------------------------------------------

const repeaterGetHistory: McpTool = {
  name: "repeater_get_history",
  description:
    "Return the in-memory Repeater history (most recent first). Each entry " +
    "contains the request details, the response (if the request was sent), and " +
    "metadata such as id, name, timestamp, and any error.",
  inputSchema: {
    type: "object",
    properties: {
      limit: {
        type: "number",
        default: 50,
        description: "Maximum number of history entries to return.",
      },
    },
  },
  handler: async (args) => {
    const limit = (args.limit as number | undefined) ?? 50;
    const entries = Array.from(repeaterHistory.values())
      .sort((a, b) => b.timestamp.localeCompare(a.timestamp))
      .slice(0, limit);

    return {
      total: repeaterHistory.size,
      returned: entries.length,
      items: entries.map((e) => ({
        id: e.id,
        name: e.name,
        timestamp: e.timestamp,
        sent: e.sent,
        method: e.request.method,
        host: e.request.host,
        port: e.request.port,
        use_https: e.request.use_https,
        path: e.request.path,
        status: e.response?.status,
        timing_ms: e.response?.timing_ms,
        error: e.error,
      })),
    };
  },
};

// 3. repeater_get_item -------------------------------------------------------

const repeaterGetItem: McpTool = {
  name: "repeater_get_item",
  description:
    "Retrieve a full Repeater history entry (request + response) by its ID.",
  inputSchema: {
    type: "object",
    required: ["id"],
    properties: {
      id: { type: "string", description: "The UUID of the Repeater history entry." },
    },
  },
  handler: async (args) => {
    const id = args.id as string;
    const entry = repeaterHistory.get(id);
    if (!entry) {
      throw new Error(`No Repeater history entry found with id: ${id}`);
    }
    return entry;
  },
};

// 4. repeater_replay_from_proxy_history -------------------------------------

const repeaterReplayFromProxyHistory: McpTool = {
  name: "repeater_replay_from_proxy_history",
  description:
    "Fetch a request from the Burp proxy history by its numeric ID and replay " +
    "it through the Repeater. Optional modifications let you add or remove " +
    "headers and override the request body before sending.",
  inputSchema: {
    type: "object",
    required: ["proxy_history_id"],
    properties: {
      proxy_history_id: {
        type: "number",
        description: "The numeric ID of the proxy history item to replay.",
      },
      modifications: {
        type: "object",
        description: "Optional modifications to apply before replaying.",
        properties: {
          headers_to_add: {
            type: "object",
            additionalProperties: { type: "string" },
            description: "Headers to add or override in the replayed request.",
          },
          headers_to_remove: {
            type: "array",
            items: { type: "string" },
            description: "Header names to remove from the replayed request.",
          },
          body_override: {
            type: "string",
            description: "Replace the original request body with this value.",
          },
        },
      },
      follow_redirects: { type: "boolean", default: false },
      use_burp_proxy: { type: "boolean", default: true },
      name: { type: "string", description: "Optional label for this Repeater entry." },
    },
  },
  handler: async (args, burpClient) => {
    const proxyId = args.proxy_history_id as number;
    const client = burpClient ?? getBurpClient();

    interface ProxyItemShape {
      id?: number;
      messageId?: number;
      request: {
        method: string;
        url: string;
        headers?: Array<{ name: string; value: string }> | Record<string, string>;
        body?: string;
      };
    }

    let proxyItem: ProxyItemShape | undefined;

    await client.withRestFallback(
      async () => {
        try {
          proxyItem = await client.get<ProxyItemShape>(`/v0.1/proxy/history/${proxyId}`);
        } catch {
          const hist = await client.get<{ messages?: ProxyItemShape[] }>("/v0.1/proxy/history");
          proxyItem = hist?.messages?.find(
            (m) => m.messageId === proxyId || m.id === proxyId
          );
        }
      },
      () => {
        const local = getLocalHistoryItem(proxyId);
        if (local) {
          proxyItem = {
            id: local.id,
            messageId: local.messageId,
            request: {
              method: local.request.method,
              url: local.request.url,
              headers: local.request.headers,
              body: local.request.body,
            },
          };
        }
      }
    );

    if (!proxyItem) {
      throw new Error(
        `Proxy history item #${proxyId} not found in Burp REST API or local MCP history.`
      );
    }

    // Parse URL to extract host, port, path
    const rawUrl = proxyItem.request.url;
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(rawUrl);
    } catch {
      throw new Error(`Invalid URL in proxy history item: ${rawUrl}`);
    }

    const use_https = parsedUrl.protocol === "https:";
    const host = parsedUrl.hostname;
    const port = parsedUrl.port
      ? Number(parsedUrl.port)
      : use_https
      ? 443
      : 80;
    const path = parsedUrl.pathname + parsedUrl.search;

    // Build headers map (handles both array and key-value object shapes)
    const headers: Record<string, string> = {};
    const rawHeaders = proxyItem.request.headers;
    if (Array.isArray(rawHeaders)) {
      for (const h of rawHeaders) {
        headers[h.name.toLowerCase()] = h.value;
      }
    } else if (rawHeaders && typeof rawHeaders === "object") {
      for (const [k, v] of Object.entries(rawHeaders)) {
        headers[k.toLowerCase()] = String(v);
      }
    }

    // Apply modifications
    const mods = (args.modifications as {
      headers_to_add?: Record<string, string>;
      headers_to_remove?: string[];
      body_override?: string;
    } | undefined) ?? {};

    if (mods.headers_to_add) {
      for (const [k, v] of Object.entries(mods.headers_to_add)) {
        headers[k.toLowerCase()] = v;
      }
    }
    if (mods.headers_to_remove) {
      for (const k of mods.headers_to_remove) {
        delete headers[k.toLowerCase()];
      }
    }

    const body = mods.body_override ?? proxyItem.request.body;

    // Delegate to the send handler
    return repeaterSendRequest.handler(
      {
        host,
        port,
        use_https,
        method: proxyItem.request.method,
        path,
        headers,
        body,
        follow_redirects: args.follow_redirects,
        use_burp_proxy: args.use_burp_proxy,
        name: args.name ?? `Replay of proxy #${proxyId}`,
      },
      client
    );
  },
};

// 5. repeater_save_request ---------------------------------------------------

const repeaterSaveRequest: McpTool = {
  name: "repeater_save_request",
  description:
    "Save a request to the Repeater history without sending it. Useful for " +
    "building a library of requests to send later or to annotate interesting " +
    "requests found elsewhere.",
  inputSchema: {
    type: "object",
    required: ["name", "host", "port", "use_https", "method", "path", "headers"],
    properties: {
      name: { type: "string", description: "Human-readable label for this saved request." },
      host: { type: "string" },
      port: { type: "number" },
      use_https: { type: "boolean" },
      method: { type: "string" },
      path: { type: "string" },
      headers: { type: "object", additionalProperties: { type: "string" } },
      body: { type: "string" },
    },
  },
  handler: async (args) => {
    const id = randomUUID();
    const entry: RepeaterEntry = {
      id,
      name: args.name as string,
      timestamp: new Date().toISOString(),
      sent: false,
      request: {
        host: args.host as string,
        port: args.port as number,
        use_https: args.use_https as boolean,
        method: (args.method as string).toUpperCase(),
        path: args.path as string,
        headers: (args.headers as Record<string, string>) ?? {},
        body: args.body as string | undefined,
      },
    };

    repeaterHistory.set(id, entry);
    return { id, message: "Request saved to Repeater history (not sent)." };
  },
};

// 6. repeater_clear_history --------------------------------------------------

const repeaterClearHistory: McpTool = {
  name: "repeater_clear_history",
  description:
    "Clear all entries from the in-memory Repeater history. This action is " +
    "irreversible within the current session.",
  inputSchema: {
    type: "object",
    properties: {},
  },
  handler: async (_args) => {
    const count = repeaterHistory.size;
    repeaterHistory.clear();
    return { message: `Repeater history cleared. ${count} entries removed.` };
  },
};

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

export const REPEATER_TOOLS: McpTool[] = [
  repeaterSendRequest,
  repeaterGetHistory,
  repeaterGetItem,
  repeaterReplayFromProxyHistory,
  repeaterSaveRequest,
  repeaterClearHistory,
];

export default REPEATER_TOOLS;
