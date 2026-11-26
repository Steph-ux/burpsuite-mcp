#!/usr/bin/env node
/**
 * BurpSuite MCP – Main Entry Point
 *
 * Starts an MCP server over stdio (default) or Streamable HTTP (--http)
 * exposing all BurpSuite tools to any MCP-compatible client.
 */

import "dotenv/config";

import http from "node:http";
import { randomUUID, timingSafeEqual } from "node:crypto";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  McpError,
  ErrorCode,
} from "@modelcontextprotocol/sdk/types.js";

import { ApiKeyMode, BurpConfig, BurpEdition } from "./types/index.js";
import { createBurpClient, BurpClient } from "./utils/burp-client.js";
import { logger } from "./utils/logger.js";

// ── Module imports ────────────────────────────────────────────────────────────
import { PROXY_TOOLS } from "./modules/proxy.js";
import { SCANNER_TOOLS } from "./modules/scanner.js";
import { REPEATER_TOOLS } from "./modules/repeater.js";
import { INTRUDER_TOOLS } from "./modules/intruder.js";
import { SPIDER_TOOLS } from "./modules/spider.js";
import { SITEMAP_TOOLS } from "./modules/sitemap.js";
import { EXTENSIONS_TOOLS } from "./modules/extensions.js";
import { DECODER_TOOLS } from "./modules/decoder.js";
import { COMPARER_TOOLS } from "./modules/comparer.js";
import { REPORT_TOOLS } from "./modules/report.js";

// ── Tool shape ────────────────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
interface McpTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  handler: (args: any, burpClient: BurpClient) => Promise<unknown>;
}

// ── Aggregate all tools ───────────────────────────────────────────────────────

const ALL_TOOLS: McpTool[] = [
  ...PROXY_TOOLS,
  ...SCANNER_TOOLS,
  ...REPEATER_TOOLS,
  ...INTRUDER_TOOLS,
  ...SPIDER_TOOLS,
  ...SITEMAP_TOOLS,
  ...EXTENSIONS_TOOLS,
  ...DECODER_TOOLS,
  ...COMPARER_TOOLS,
  ...REPORT_TOOLS,
];

/** Fast lookup: tool name → handler entry */
const TOOL_MAP = new Map<string, McpTool>(
  ALL_TOOLS.map((t) => [t.name, t])
);

// ── Config & CLI parsing ──────────────────────────────────────────────────────

interface CliOptions {
  transport: "stdio" | "http";
  httpHost: string;
  httpPort: number;
  httpToken: string;
  showHelp: boolean;
}

function parseCliOptions(argv: string[]): CliOptions {
  let transport: "stdio" | "http" =
    process.env.MCP_TRANSPORT === "http" ? "http" : "stdio";
  let httpHost = process.env.MCP_HTTP_HOST ?? "127.0.0.1";
  let httpPort = parseInt(process.env.MCP_HTTP_PORT ?? "3000", 10);
  let httpToken = process.env.MCP_HTTP_TOKEN ?? "";
  let showHelp = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "--http") {
      transport = "http";
    } else if (arg === "--stdio") {
      transport = "stdio";
    } else if (arg === "--host" && argv[i + 1]) {
      httpHost = argv[++i]!;
    } else if (arg.startsWith("--host=")) {
      httpHost = arg.slice("--host=".length);
    } else if (arg === "--port" && argv[i + 1]) {
      httpPort = parseInt(argv[++i]!, 10);
    } else if (arg.startsWith("--port=")) {
      httpPort = parseInt(arg.slice("--port=".length), 10);
    } else if (arg === "--token" && argv[i + 1]) {
      httpToken = argv[++i]!;
    } else if (arg.startsWith("--token=")) {
      httpToken = arg.slice("--token=".length);
    } else if (arg === "--help" || arg === "-h") {
      showHelp = true;
    }
  }

  return { transport, httpHost, httpPort, httpToken, showHelp };
}

function loadConfig(): BurpConfig {
  const apiKeyMode = (process.env.BURP_API_KEY_MODE ?? "auto") as ApiKeyMode;
  const edition = (process.env.BURP_EDITION ?? "auto") as BurpEdition;
  const rejectUnauthorized =
    process.env.BURP_PROXY_TLS_REJECT_UNAUTHORIZED === "true";

  return {
    host: process.env.BURP_HOST ?? "127.0.0.1",
    port: parseInt(process.env.BURP_PORT ?? "8080", 10),
    apiKey: process.env.BURP_API_KEY ?? "",
    apiPort: parseInt(process.env.BURP_API_PORT ?? "1337", 10),
    apiKeyMode: ["auto", "path", "header"].includes(apiKeyMode)
      ? apiKeyMode
      : "auto",
    edition: ["auto", "community", "pro"].includes(edition) ? edition : "auto",
    proxyTlsRejectUnauthorized: rejectUnauthorized,
  };
}

// ── MCP Server factory ────────────────────────────────────────────────────────

function createMcpServer(burpClient: BurpClient): Server {
  const server = new Server(
    { name: "burpsuite-mcp", version: "1.0.0" },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: ALL_TOOLS.map((tool) => ({
      name: tool.name,
      description: tool.description,
      inputSchema: tool.inputSchema,
    })),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    const tool = TOOL_MAP.get(name);
    if (!tool) {
      throw new McpError(
        ErrorCode.MethodNotFound,
        `Unknown tool: ${name}. Available tools: ${[...TOOL_MAP.keys()].join(", ")}`
      );
    }

    logger.info(`Calling tool: ${name}`);

    try {
      const result = await tool.handler(args ?? {}, burpClient);

      if (
        result !== null &&
        typeof result === "object" &&
        Array.isArray((result as { content?: unknown }).content)
      ) {
        return result as {
          content: Array<{ type: string; text: string }>;
          isError?: boolean;
        };
      }

      return {
        content: [
          {
            type: "text",
            text:
              typeof result === "string"
                ? result
                : JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error(`Tool ${name} failed: ${message}`);

      return {
        content: [
          {
            type: "text",
            text: `Error executing ${name}: ${message}`,
          },
        ],
        isError: true,
      };
    }
  });

  server.onerror = (err) => {
    logger.error(`MCP server error: ${err.message}`);
  };

  return server;
}

// ── Streamable HTTP Transport helpers ─────────────────────────────────────────

const MAX_HTTP_BODY_BYTES = 10 * 1024 * 1024;

function readJsonBody(req: http.IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalBytes = 0;
    req.on("data", (chunk: Buffer) => {
      totalBytes += chunk.length;
      if (totalBytes > MAX_HTTP_BODY_BYTES) {
        req.destroy();
        reject(new Error("Request body too large"));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8").trim();
      if (!raw) {
        resolve(undefined);
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error("Invalid JSON request body"));
      }
    });
    req.on("error", reject);
  });
}

function isValidBearerToken(
  authHeader: string | undefined,
  expectedToken: string
): boolean {
  if (!expectedToken) return true;
  if (!authHeader || !authHeader.startsWith("Bearer ")) return false;
  const provided = authHeader.slice("Bearer ".length);
  const a = Buffer.from(provided, "utf8");
  const b = Buffer.from(expectedToken, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

function isInitializeMessage(body: unknown): boolean {
  if (Array.isArray(body)) {
    return body.some(
      (msg) =>
        msg &&
        typeof msg === "object" &&
        (msg as { method?: unknown }).method === "initialize"
    );
  }
  return Boolean(
    body &&
      typeof body === "object" &&
      (body as { method?: unknown }).method === "initialize"
  );
}

function sendJsonError(
  res: http.ServerResponse,
  status: number,
  code: number,
  message: string
): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(
    JSON.stringify({
      jsonrpc: "2.0",
      error: { code, message },
      id: null,
    })
  );
}

async function startHttpServer(
  burpClient: BurpClient,
  opts: CliOptions
): Promise<void> {
  if (
    opts.httpHost !== "127.0.0.1" &&
    opts.httpHost !== "localhost" &&
    opts.httpHost !== "::1" &&
    !opts.httpToken
  ) {
    logger.warn(
      `Binding Streamable HTTP to ${opts.httpHost} without MCP_HTTP_TOKEN (--token). Set a Bearer token when exposing beyond localhost.`
    );
  }

  const sessions = new Map<
    string,
    { server: Server; transport: StreamableHTTPServerTransport }
  >();

  const httpServer = http.createServer(async (req, res) => {
    const reqUrl = new URL(req.url ?? "/", `http://${opts.httpHost}:${opts.httpPort}`);

    if (reqUrl.pathname === "/health" && req.method === "GET") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          status: "ok",
          server: "burpsuite-mcp",
          transport: "streamable-http",
          tools: ALL_TOOLS.length,
          active_sessions: sessions.size,
        })
      );
      return;
    }

    if (reqUrl.pathname !== "/mcp") {
      sendJsonError(res, 404, -32004, "Not found. Use /mcp or /health.");
      return;
    }

    if (!isValidBearerToken(req.headers.authorization, opts.httpToken)) {
      sendJsonError(res, 401, -32001, "Unauthorized: invalid or missing Bearer token");
      return;
    }

    const sessionIdHeader = req.headers["mcp-session-id"];
    const sessionId = Array.isArray(sessionIdHeader)
      ? sessionIdHeader[0]
      : sessionIdHeader;

    try {
      if (req.method === "POST") {
        let parsedBody: unknown;
        try {
          parsedBody = await readJsonBody(req);
        } catch (err) {
          sendJsonError(
            res,
            400,
            -32700,
            err instanceof Error ? err.message : "Invalid request body"
          );
          return;
        }

        if (sessionId) {
          const existing = sessions.get(sessionId);
          if (!existing) {
            sendJsonError(res, 404, -32001, `Unknown session ID: ${sessionId}`);
            return;
          }
          await existing.transport.handleRequest(req, res, parsedBody);
          return;
        }

        if (!isInitializeMessage(parsedBody)) {
          sendJsonError(
            res,
            400,
            -32000,
            "Bad Request: missing mcp-session-id header for non-initialize request"
          );
          return;
        }

        const sessionServer = createMcpServer(burpClient);
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (sid) => {
            sessions.set(sid, { server: sessionServer, transport });
            logger.debug(`MCP HTTP session initialized: ${sid}`);
          },
          onsessionclosed: (sid) => {
            sessions.delete(sid);
            logger.debug(`MCP HTTP session closed: ${sid}`);
          },
        });

        transport.onclose = () => {
          if (transport.sessionId) {
            sessions.delete(transport.sessionId);
          }
        };

        await sessionServer.connect(transport);
        await transport.handleRequest(req, res, parsedBody);
        return;
      }

      if (req.method === "GET" || req.method === "DELETE") {
        if (!sessionId || !sessions.has(sessionId)) {
          sendJsonError(
            res,
            sessionId ? 404 : 400,
            -32001,
            sessionId
              ? `Unknown session ID: ${sessionId}`
              : "Missing mcp-session-id header"
          );
          return;
        }
        const existing = sessions.get(sessionId)!;
        await existing.transport.handleRequest(req, res);
        return;
      }

      res.writeHead(405, { Allow: "GET, POST, DELETE" });
      res.end();
    } catch (err) {
      logger.error(
        `HTTP transport error: ${err instanceof Error ? err.message : String(err)}`
      );
      if (!res.headersSent) {
        sendJsonError(res, 500, -32603, "Internal server error");
      }
    }
  });

  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(opts.httpPort, opts.httpHost, () => {
      httpServer.off("error", reject);
      resolve();
    });
  });

  logger.info(
    `BurpSuite MCP Streamable HTTP server ready – listening on http://${opts.httpHost}:${opts.httpPort}/mcp`
  );

  const shutdown = async () => {
    logger.info("Shutting down BurpSuite MCP HTTP server…");
    for (const { server: s, transport: t } of sessions.values()) {
      await t.close().catch(() => undefined);
      await s.close().catch(() => undefined);
    }
    sessions.clear();
    httpServer.close(() => process.exit(0));
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

// ── Server bootstrap ──────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const cli = parseCliOptions(process.argv.slice(2));
  if (cli.showHelp) {
    process.stderr.write(
      [
        "Usage: burpsuite-mcp [options]",
        "",
        "Options:",
        "  --stdio           Use stdio MCP transport (default)",
        "  --http            Use Streamable HTTP MCP transport (/mcp and /health)",
        "  --host <addr>     HTTP bind host (default: 127.0.0.1 or MCP_HTTP_HOST)",
        "  --port <port>     HTTP listen port (default: 3000 or MCP_HTTP_PORT)",
        "  --token <secret>  Require Authorization: Bearer <secret> on HTTP mode",
        "  -h, --help        Show this help message",
        "",
      ].join("\n")
    );
    process.exit(0);
  }

  const config = loadConfig();
  const burpClient = createBurpClient(config);

  const authLabel = config.apiKey
    ? `API key configured (mode=${config.apiKeyMode})`
    : "no API key (Community / unauthenticated REST mode)";
  logger.info(
    `BurpSuite MCP starting – proxy=${config.host}:${config.port}, rest=${config.host}:${config.apiPort}, edition=${config.edition}, ${authLabel}`
  );
  logger.info(
    `Registered ${ALL_TOOLS.length} tools across 10 modules (proxy:9, scanner:9, repeater:6, intruder:6, spider:7, sitemap:10, extensions:12, decoder:3, comparer:3, report:1)`
  );

  if (cli.transport === "http") {
    await startHttpServer(burpClient, cli);
    return;
  }

  const server = createMcpServer(burpClient);

  process.on("SIGINT", async () => {
    logger.info("Shutting down BurpSuite MCP server…");
    await server.close();
    process.exit(0);
  });

  process.on("SIGTERM", async () => {
    logger.info("SIGTERM received – shutting down…");
    await server.close();
    process.exit(0);
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);

  logger.info("BurpSuite MCP server ready – listening on stdio");
}

main().catch((err) => {
  logger.error(`Fatal: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
