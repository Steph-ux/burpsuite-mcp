/**
 * BurpSuite MCP – Main Entry Point
 *
 * Starts an MCP server over stdio that exposes all BurpSuite Pro tools to
 * any MCP-compatible client (Claude Desktop, Antigravity, …).
 */

import "dotenv/config";

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
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

// ── Tool shape ────────────────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
interface McpTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  // handlers may have narrower arg types in their own modules; we accept any here
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
];

/** Fast lookup: tool name → handler entry */
const TOOL_MAP = new Map<string, McpTool>(
  ALL_TOOLS.map((t) => [t.name, t])
);

// ── Config ────────────────────────────────────────────────────────────────────

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

// ── Server bootstrap ──────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const config = loadConfig();
  const burpClient = createBurpClient(config);

  const authLabel = config.apiKey
    ? `API key configured (mode=${config.apiKeyMode})`
    : "no API key (Community / unauthenticated REST mode)";
  logger.info(
    `BurpSuite MCP starting – proxy=${config.host}:${config.port}, rest=${config.host}:${config.apiPort}, edition=${config.edition}, ${authLabel}`
  );
  logger.info(`Registered ${ALL_TOOLS.length} tools across 7 modules (proxy:9, scanner:9, repeater:6, intruder:6, spider:7, sitemap:10, extensions:12)`);

  // Create MCP server
  const server = new Server(
    { name: "burpsuite-mcp", version: "1.0.0" },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // ── List tools ──────────────────────────────────────────────────────────────

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: ALL_TOOLS.map((tool) => ({
      name: tool.name,
      description: tool.description,
      inputSchema: tool.inputSchema,
    })),
  }));

  // ── Call tool ───────────────────────────────────────────────────────────────

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

      // Guard against double-wrapping if a tool already returns MCP content
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

      // Return error as tool content (not as MCP protocol error) so the
      // client can read the message and decide how to handle it.
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

  // ── Error handling ──────────────────────────────────────────────────────────

  server.onerror = (err) => {
    logger.error(`MCP server error: ${err.message}`);
  };

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

  // ── Transport ───────────────────────────────────────────────────────────────

  const transport = new StdioServerTransport();
  await server.connect(transport);

  logger.info("BurpSuite MCP server ready – listening on stdio");
}

main().catch((err) => {
  logger.error(`Fatal: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
