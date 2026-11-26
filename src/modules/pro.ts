// ============================================================
// BurpSuite MCP – Pro & Montoya Bridge Exclusive Tools
// Wraps Collaborator OAST, Intruder/Organizer UI integration,
// WebSocket proxy history, BChecks, Bambda, and Task Engine.
// ============================================================

import { BurpClient } from "../utils/burp-client.js";
import { getLocalHistoryItem } from "../utils/local-store.js";

interface McpTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  handler: (args: Record<string, unknown>, burpClient: BurpClient) => Promise<unknown>;
}

function proRequiredNotice(toolName: string, detail: string) {
  return {
    supported: false,
    mode: "pro-bridge-required",
    tool: toolName,
    message:
      `${toolName} requires BurpSuite Pro with the Full Pro Bridge extension loaded ` +
      `(burp-extension/burpsuite-mcp-bridge.jar recommended; ${detail}).`,
  };
}

async function withProBridge<T>(
  burpClient: BurpClient,
  toolName: string,
  detail: string,
  fn: () => Promise<T>
): Promise<T | ReturnType<typeof proRequiredNotice>> {
  return burpClient.withRestFallback(
    async () => {
      try {
        return await fn();
      } catch (err) {
        if (err instanceof Error && /^BurpClient \[(404|501)\]/.test(err.message)) {
          return {
            ...proRequiredNotice(toolName, detail),
            bridge_response: err.message,
          };
        }
        throw err;
      }
    },
    () => proRequiredNotice(toolName, detail)
  );
}

const collaboratorGeneratePayload: McpTool = {
  name: "collaborator_generate_payload",
  description:
    "Generate a Burp Collaborator OAST payload domain for out-of-band testing " +
    "(blind SSRF, XXE, OOB SQLi, command injection). Requires Burp Pro + Bridge.",
  inputSchema: {
    type: "object",
    properties: {
      custom_data: {
        type: "string",
        description:
          "Optional identifier encoded into the Montoya Collaborator payload " +
          "(strictly 1-16 ASCII alphanumeric characters [A-Za-z0-9], no hyphens or symbols).",
      },
      secret_key: {
        type: "string",
        description: "Optional Collaborator client secret key to restore an existing polling session.",
      },
    },
    required: [],
  },
  async handler(args, burpClient) {
    if (args.custom_data !== undefined && args.custom_data !== "") {
      const tag = String(args.custom_data);
      if (!/^[A-Za-z0-9]{1,16}$/.test(tag)) {
        throw new Error(
          `Invalid custom_data ("${tag}"): Montoya Collaborator requires strictly 1-16 ASCII alphanumeric characters [A-Za-z0-9] (no hyphens or symbols).`
        );
      }
    }
    return withProBridge(
      burpClient,
      "collaborator_generate_payload",
      "uses /v0.1/collaborator/generate",
      async () => ({
        mode: "burp-pro-bridge",
        ...(await burpClient.post<Record<string, unknown>>("/v0.1/collaborator/generate", {
          custom_data: args.custom_data,
          secret_key: args.secret_key,
        })),
      })
    );
  },
};

const collaboratorPollInteractions: McpTool = {
  name: "collaborator_poll_interactions",
  description:
    "Poll Burp Collaborator for received DNS, HTTP, and SMTP out-of-band interactions.",
  inputSchema: {
    type: "object",
    properties: {
      interaction_id: {
        type: "string",
        description: "Optional Collaborator interaction ID returned by collaborator_generate_payload to filter results.",
      },
      secret_key: {
        type: "string",
        description: "Optional Collaborator client secret key from a previous session.",
      },
    },
    required: [],
  },
  async handler(args, burpClient) {
    return withProBridge(
      burpClient,
      "collaborator_poll_interactions",
      "uses /v0.1/collaborator/interactions",
      async () => ({
        mode: "burp-pro-bridge",
        ...(await burpClient.get<Record<string, unknown>>("/v0.1/collaborator/interactions", {
          params: {
            ...(args.interaction_id ? { interaction_id: String(args.interaction_id) } : {}),
            ...(args.secret_key ? { secret_key: String(args.secret_key) } : {}),
          },
        })),
      })
    );
  },
};

const burpSendToIntruder: McpTool = {
  name: "burp_send_to_intruder",
  description:
    "Send a request to the Burp Intruder UI tab. Supports lookup by proxy_history_id or a raw " +
    "request_template with §marker§ payload insertion positions.",
  inputSchema: {
    type: "object",
    properties: {
      proxy_history_id: {
        type: "number",
        description: "Optional proxy history item ID to send to Intruder.",
      },
      host: { type: "string", description: "Target hostname (required if proxy_history_id omitted and url omitted)." },
      port: { type: "number", description: "Target port (default 443 for https, 80 for http)." },
      protocol: { type: "string", enum: ["http", "https"], description: "Target protocol." },
      url: { type: "string", description: "Target URL (alternative to host/port/protocol)." },
      request_template: {
        type: "string",
        description: "Raw HTTP request, optionally containing §payload§ markers converted to Intruder insertion points.",
      },
      tab_name: { type: "string", description: "Optional Intruder tab title (default 'MCP')." },
    },
    required: [],
  },
  async handler(args, burpClient) {
    return withProBridge(
      burpClient,
      "burp_send_to_intruder",
      "uses /v0.1/intruder",
      async () => {
        let payload: Record<string, unknown> = {
          host: args.host,
          port: args.port,
          protocol: args.protocol,
          url: args.url,
          request_template: args.request_template,
          tab_name: args.tab_name ?? "MCP",
        };
        if (args.proxy_history_id !== undefined && !args.request_template) {
          const id = Number(args.proxy_history_id);
          const item = (await burpClient.get<Record<string, unknown>>(
            `/v0.1/proxy/history/${id}`
          ).catch(() => getLocalHistoryItem(id))) as Record<string, unknown> | undefined;
          if (!item) {
            return { sent: false, error: `Proxy history item ${id} not found` };
          }
          payload = {
            host: item.host,
            port: item.port,
            protocol: item.protocol,
            request: item,
            tab_name: args.tab_name ?? `MCP #${id}`,
          };
        }
        return {
          mode: "burp-pro-bridge",
          ...(await burpClient.post<Record<string, unknown>>("/v0.1/intruder", payload)),
        };
      }
    );
  },
};

const burpSendToOrganizer: McpTool = {
  name: "burp_send_to_organizer",
  description:
    "Send a captured proxy item or custom request/response pair to Burp Suite Organizer (Montoya bridge).",
  inputSchema: {
    type: "object",
    properties: {
      proxy_history_id: { type: "number", description: "Proxy history item ID to send to Organizer." },
      url: { type: "string", description: "Target URL when sending a custom request." },
      host: { type: "string", description: "Target host." },
      port: { type: "number", description: "Target port." },
      protocol: { type: "string", enum: ["http", "https"] },
      request: { type: "string", description: "Raw HTTP request string." },
      response: { type: "string", description: "Optional raw HTTP response string." },
    },
    required: [],
  },
  async handler(args, burpClient) {
    return withProBridge(
      burpClient,
      "burp_send_to_organizer",
      "uses /v0.1/organizer (Montoya JAR bridge)",
      async () => ({
        mode: "burp-montoya-bridge",
        ...(await burpClient.post<Record<string, unknown>>("/v0.1/organizer", args)),
      })
    );
  },
};

const organizerListItems: McpTool = {
  name: "organizer_list_items",
  description:
    "List HTTP items stored in Burp Suite Organizer along with their status and notes (Montoya bridge).",
  inputSchema: {
    type: "object",
    properties: {
      limit: { type: "number", description: "Maximum number of Organizer items to return." },
    },
    required: [],
  },
  async handler(args, burpClient) {
    return withProBridge(
      burpClient,
      "organizer_list_items",
      "uses /v0.1/organizer (Montoya JAR bridge)",
      async () => ({
        mode: "burp-montoya-bridge",
        ...(await burpClient.get<Record<string, unknown>>("/v0.1/organizer", {
          params: args.limit !== undefined ? { limit: Number(args.limit) } : undefined,
        })),
      })
    );
  },
};

const proxyGetWebsockets: McpTool = {
  name: "proxy_get_websockets",
  description:
    "Retrieve captured WebSocket frames from Burp Proxy WebSocket history (Montoya bridge).",
  inputSchema: {
    type: "object",
    properties: {
      limit: { type: "number", description: "Maximum number of WebSocket messages to return." },
      filter: { type: "string", description: "Optional substring filter matched against URL or payload." },
      direction: {
        type: "string",
        enum: ["CLIENT_TO_SERVER", "SERVER_TO_CLIENT"],
        description: "Optional frame direction filter.",
      },
    },
    required: [],
  },
  async handler(args, burpClient) {
    return withProBridge(
      burpClient,
      "proxy_get_websockets",
      "uses /v0.1/proxy/websockets (Montoya JAR bridge)",
      async () => ({
        mode: "burp-montoya-bridge",
        ...(await burpClient.get<Record<string, unknown>>("/v0.1/proxy/websockets", {
          params: {
            ...(args.limit !== undefined ? { limit: Number(args.limit) } : {}),
            ...(args.filter ? { filter: String(args.filter) } : {}),
            ...(args.direction ? { direction: String(args.direction) } : {}),
          },
        })),
      })
    );
  },
};

const scannerImportBcheck: McpTool = {
  name: "scanner_import_bcheck",
  description:
    "Import a custom BCheck scan script directly into Burp Suite Pro's Scanner (Montoya bridge).",
  inputSchema: {
    type: "object",
    properties: {
      script: { type: "string", description: "Full BCheck definition source text." },
      enabled: { type: "boolean", default: true, description: "Whether the imported BCheck is immediately enabled." },
    },
    required: ["script"],
  },
  async handler(args, burpClient) {
    return withProBridge(
      burpClient,
      "scanner_import_bcheck",
      "uses /v0.1/scanner/bchecks (Montoya JAR bridge)",
      async () => ({
        mode: "burp-montoya-bridge",
        ...(await burpClient.post<Record<string, unknown>>("/v0.1/scanner/bchecks", {
          script: args.script,
          enabled: args.enabled ?? true,
        })),
      })
    );
  },
};

const burpImportBambda: McpTool = {
  name: "burp_import_bambda",
  description:
    "Import a Bambda filter/custom-action script directly into Burp Suite via the Montoya bridge.",
  inputSchema: {
    type: "object",
    properties: {
      script: { type: "string", description: "Full Bambda source script." },
    },
    required: ["script"],
  },
  async handler(args, burpClient) {
    return withProBridge(
      burpClient,
      "burp_import_bambda",
      "uses /v0.1/bambda (Montoya JAR bridge)",
      async () => ({
        mode: "burp-montoya-bridge",
        ...(await burpClient.post<Record<string, unknown>>("/v0.1/bambda", {
          script: args.script,
        })),
      })
    );
  },
};

const burpTaskEngine: McpTool = {
  name: "burp_task_engine",
  description:
    "Inspect or set Burp Suite's global Task Execution Engine state (RUNNING or PAUSED) via Montoya bridge.",
  inputSchema: {
    type: "object",
    properties: {
      state: {
        type: "string",
        enum: ["RUNNING", "PAUSED"],
        description: "Omit to read current state; pass RUNNING or PAUSED to update.",
      },
    },
    required: [],
  },
  async handler(args, burpClient) {
    return withProBridge(
      burpClient,
      "burp_task_engine",
      "uses /v0.1/burp/task_engine (Montoya JAR bridge)",
      async () => {
        if (args.state) {
          return {
            mode: "burp-montoya-bridge",
            ...(await burpClient.post<Record<string, unknown>>("/v0.1/burp/task_engine", {
              state: String(args.state),
            })),
          };
        }
        return {
          mode: "burp-montoya-bridge",
          ...(await burpClient.get<Record<string, unknown>>("/v0.1/burp/task_engine")),
        };
      }
    );
  },
};

export const PRO_TOOLS: McpTool[] = [
  collaboratorGeneratePayload,
  collaboratorPollInteractions,
  burpSendToIntruder,
  burpSendToOrganizer,
  organizerListItems,
  proxyGetWebsockets,
  scannerImportBcheck,
  burpImportBambda,
  burpTaskEngine,
];

export default PRO_TOOLS;
