import { BurpClient } from '../utils/burp-client.js';
import { getLocalHistoryItem } from '../utils/local-store.js';

function communityRestNotice(toolName: string, extra?: string) {
  return {
    supported: false,
    mode: 'community-no-rest-api',
    tool: toolName,
    message:
      `${toolName} requires the Burp REST API on port 1337 (native in BurpSuite Pro, or via the optional Community bridge extension burp-extension/burp_mcp_bridge.py).` +
      (extra ? ` ${extra}` : ''),
  };
}

// ============================================================
// BurpSuite MCP – Extensions & Burp Core module
// ============================================================

// ── Shared handler type ──────────────────────────────────────

type ToolHandler = (args: Record<string, unknown>, burpClient: BurpClient) => Promise<unknown>;

interface McpTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  handler: ToolHandler;
}

// ============================================================
// EXTENSIONS TOOLS
// ============================================================

// 1. extensions_list ─────────────────────────────────────────

const extensions_list: McpTool = {
  name: 'extensions_list',
  description:
    'List all extensions currently loaded in BurpSuite. Returns id, name, description, author, version and state (enabled/disabled) for each extension.',
  inputSchema: {
    type: 'object',
    properties: {},
    required: [],
  },
  async handler(_args, burpClient) {
    return burpClient.withRestFallback(
      () => burpClient.get('/v0.1/extensions'),
      () => ({
        ...communityRestNotice('extensions_list'),
        extensions: [],
      }),
    );
  },
};

// 2. extensions_get ──────────────────────────────────────────

const extensions_get: McpTool = {
  name: 'extensions_get',
  description: 'Get detailed information about a specific BurpSuite extension by its ID.',
  inputSchema: {
    type: 'object',
    properties: {
      extension_id: {
        type: 'string',
        description: 'The unique identifier of the extension to retrieve.',
      },
    },
    required: ['extension_id'],
  },
  async handler(args, burpClient) {
    const { extension_id } = args as { extension_id: string };
    return burpClient.withRestFallback(
      () => burpClient.get(`/v0.1/extensions/${encodeURIComponent(extension_id)}`),
      () => communityRestNotice('extensions_get'),
    );
  },
};

// 3. extensions_toggle ───────────────────────────────────────

const extensions_toggle: McpTool = {
  name: 'extensions_toggle',
  description: 'Enable or disable a BurpSuite extension.',
  inputSchema: {
    type: 'object',
    properties: {
      extension_id: {
        type: 'string',
        description: 'The unique identifier of the extension to toggle.',
      },
      enabled: {
        type: 'boolean',
        description: 'Set to true to enable the extension, false to disable it.',
      },
    },
    required: ['extension_id', 'enabled'],
  },
  async handler(args, burpClient) {
    const { extension_id, enabled } = args as { extension_id: string; enabled: boolean };
    return burpClient.withRestFallback(
      async () => {
        const data = await burpClient.put(`/v0.1/extensions/${encodeURIComponent(extension_id)}`, {
          enabled,
        });
        return {
          success: true,
          extension_id,
          enabled,
          response: data,
        };
      },
      () => communityRestNotice('extensions_toggle'),
    );
  },
};

// 4. extensions_get_output ───────────────────────────────────

const extensions_get_output: McpTool = {
  name: 'extensions_get_output',
  description:
    'Retrieve the stdout and stderr output produced by a BurpSuite extension. Useful for debugging extension behaviour.',
  inputSchema: {
    type: 'object',
    properties: {
      extension_id: {
        type: 'string',
        description: 'The unique identifier of the extension whose output to retrieve.',
      },
    },
    required: ['extension_id'],
  },
  async handler(args, burpClient) {
    const { extension_id } = args as { extension_id: string };
    return burpClient.withRestFallback(
      () => burpClient.get(`/v0.1/extensions/${encodeURIComponent(extension_id)}/output`),
      () => communityRestNotice('extensions_get_output'),
    );
  },
};

// 5. extensions_clear_output ─────────────────────────────────

const extensions_clear_output: McpTool = {
  name: 'extensions_clear_output',
  description: "Clear the stdout/stderr output buffer of a BurpSuite extension.",
  inputSchema: {
    type: 'object',
    properties: {
      extension_id: {
        type: 'string',
        description: 'The unique identifier of the extension whose output to clear.',
      },
    },
    required: ['extension_id'],
  },
  async handler(args, burpClient) {
    const { extension_id } = args as { extension_id: string };
    return burpClient.withRestFallback(
      async () => {
        try {
          const data = await burpClient.delete(
            `/v0.1/extensions/${encodeURIComponent(extension_id)}/output`,
          );
          return { success: true, extension_id, response: data };
        } catch (err) {
          if (BurpClient.isConnectionError(err)) throw err;
          const data = await burpClient.post(
            `/v0.1/extensions/${encodeURIComponent(extension_id)}/output/clear`,
          );
          return { success: true, extension_id, response: data };
        }
      },
      () => communityRestNotice('extensions_clear_output'),
    );
  },
};

// 6. extensions_install ──────────────────────────────────────

const extensions_install: McpTool = {
  name: 'extensions_install',
  description:
    'Install a BurpSuite extension from a local .jar or .py file. ' +
    'Note: the BurpSuite REST API v0.1 does not expose a direct installation endpoint. ' +
    'This tool returns step-by-step instructions for manual installation when the API does not support it.',
  inputSchema: {
    type: 'object',
    properties: {
      file_path: {
        type: 'string',
        description:
          'Absolute path to the extension file on the machine running BurpSuite (.jar for Java, .py for Python, .rb for Ruby).',
      },
      extension_type: {
        type: 'string',
        enum: ['java', 'python', 'ruby'],
        description: 'Type of extension: java, python or ruby.',
      },
    },
    required: ['file_path', 'extension_type'],
  },
  async handler(args, burpClient) {
    const { file_path, extension_type } = args as {
      file_path: string;
      extension_type: 'java' | 'python' | 'ruby';
    };

    // Attempt via API first (some custom builds expose a POST endpoint).
    try {
      const data = await burpClient.post('/v0.1/extensions', {
        filename: file_path,
        extension_type,
      });
      return { success: true, file_path, extension_type, response: data };
    } catch {
      // The standard BurpSuite REST API v0.1 does not support installation.
      return {
        success: false,
        message:
          'The BurpSuite REST API v0.1 does not support programmatic extension installation. ' +
          'Please install the extension manually:',
        instructions: [
          `1. Open BurpSuite Pro.`,
          `2. Navigate to the "Extender" (or "Extensions") tab.`,
          `3. Click "Add".`,
          `4. Set "Extension type" to "${extension_type}".`,
          `5. Click "Select file …" and choose: ${file_path}`,
          `6. Click "Next" and wait for the extension to load.`,
          `7. Verify there are no errors in the "Output" and "Errors" tabs.`,
        ],
      };
    }
  },
};

// 7. extensions_unload ───────────────────────────────────────

const extensions_unload: McpTool = {
  name: 'extensions_unload',
  description: 'Unload (remove) an extension from BurpSuite. The extension file is not deleted.',
  inputSchema: {
    type: 'object',
    properties: {
      extension_id: {
        type: 'string',
        description: 'The unique identifier of the extension to unload.',
      },
    },
    required: ['extension_id'],
  },
  async handler(args, burpClient) {
    const { extension_id } = args as { extension_id: string };
    return burpClient.withRestFallback(
      async () => {
        const data = await burpClient.delete(
          `/v0.1/extensions/${encodeURIComponent(extension_id)}`,
        );
        return { success: true, extension_id, response: data };
      },
      () => communityRestNotice('extensions_unload'),
    );
  },
};

// ============================================================
// BURP CORE TOOLS
// ============================================================

// 8. burp_get_version ────────────────────────────────────────

const burp_get_version: McpTool = {
  name: 'burp_get_version',
  description: 'Retrieve the current version information of BurpSuite Pro.',
  inputSchema: {
    type: 'object',
    properties: {},
    required: [],
  },
  async handler(_args, burpClient) {
    return burpClient.withRestFallback(
      async () => ({
        mode: 'burp-rest-api',
        api_key_configured: burpClient.hasApiKey,
        ...(await burpClient.get<Record<string, unknown>>('/v0.1/burp/version')),
      }),
      () => ({
        mode: 'community-no-rest-api',
        edition: 'Community (or Pro without REST API enabled)',
        rest_api_reachable: false,
        rest_api_url: burpClient.apiBaseUrl,
        proxy_url: burpClient.proxyBaseUrl,
        api_key_configured: burpClient.hasApiKey,
      }),
    );
  },
};

// 9. burp_get_configuration ──────────────────────────────────

const burp_get_configuration: McpTool = {
  name: 'burp_get_configuration',
  description:
    'Retrieve the current BurpSuite project configuration as a JSON object. ' +
    'The returned object mirrors the structure of a Burp project options export.',
  inputSchema: {
    type: 'object',
    properties: {},
    required: [],
  },
  async handler(_args, burpClient) {
    return burpClient.withRestFallback(
      () => burpClient.get('/v0.1/burp/configuration'),
      () => communityRestNotice('burp_get_configuration'),
    );
  },
};

// 10. burp_update_configuration ──────────────────────────────

const burp_update_configuration: McpTool = {
  name: 'burp_update_configuration',
  description:
    'Update BurpSuite project configuration. ' +
    'Pass a partial or full configuration object matching the Burp project options schema. ' +
    'Unknown keys are ignored by BurpSuite.',
  inputSchema: {
    type: 'object',
    properties: {
      config: {
        type: 'object',
        description:
          'Configuration object to apply. Follows the BurpSuite project configuration JSON schema. ' +
          'Example: { "scanner": { "active_audit_mode": "audit_forms_in_scope" } }',
        additionalProperties: true,
      },
    },
    required: ['config'],
  },
  async handler(args, burpClient) {
    const { config } = args as { config: Record<string, unknown> };
    return burpClient.withRestFallback(
      async () => {
        const data = await burpClient.put('/v0.1/burp/configuration', config);
        return { success: true, response: data };
      },
      () => communityRestNotice('burp_update_configuration'),
    );
  },
};

// 11. burp_save_state ────────────────────────────────────────

const burp_save_state: McpTool = {
  name: 'burp_save_state',
  description:
    'Save the current BurpSuite project state to a file. ' +
    'The file_path must be accessible to the machine running BurpSuite. ' +
    'Uses GET /v0.1/burp/exportstate when available.',
  inputSchema: {
    type: 'object',
    properties: {
      file_path: {
        type: 'string',
        description:
          'Absolute path on the BurpSuite host where the state file should be saved (e.g. /home/user/project.burp).',
      },
    },
    required: ['file_path'],
  },
  async handler(args, burpClient) {
    const { file_path } = args as { file_path: string };

    return burpClient.withRestFallback(
      async () => {
        try {
          const data = await burpClient.get('/v0.1/burp/exportstate', {
            params: { file_path },
          } as Parameters<BurpClient['get']>[1]);
          return { success: true, file_path, response: data };
        } catch (err) {
          if (BurpClient.isConnectionError(err)) throw err;
          try {
            const data = await burpClient.post('/v0.1/burp/exportstate', { file_path });
            return { success: true, file_path, response: data };
          } catch (postErr) {
            if (BurpClient.isConnectionError(postErr)) throw postErr;
            return {
              success: false,
              message:
                'BurpSuite REST API v0.1 may not support programmatic state export on this build. ' +
                'Please save the project state manually via File → Save Project.',
              file_path,
            };
          }
        }
      },
      () => communityRestNotice('burp_save_state', 'Project state saving is a BurpSuite Pro feature.'),
    );
  },
};

// 12. burp_send_to_repeater ──────────────────────────────────

const burp_send_to_repeater: McpTool = {
  name: 'burp_send_to_repeater',
  description:
    'Send a request from the Proxy history to the Burp Repeater UI for manual editing and re-sending. ' +
    'The request is identified by its proxy history item ID.',
  inputSchema: {
    type: 'object',
    properties: {
      proxy_history_id: {
        type: 'number',
        description: 'The numeric ID of the proxy history item to send to Repeater.',
      },
    },
    required: ['proxy_history_id'],
  },
  async handler(args, burpClient) {
    const { proxy_history_id } = args as { proxy_history_id: number };

    return burpClient.withRestFallback(
      async () => {
        const item = (await burpClient.get(
          `/v0.1/proxy/history/${proxy_history_id}`,
        )) as Record<string, unknown>;

        try {
          const data = await burpClient.post('/v0.1/repeater', {
            request: item,
          });
          return { success: true, proxy_history_id, response: data };
        } catch (err) {
          if (BurpClient.isConnectionError(err)) throw err;
          const request = (item as { request?: unknown }).request ?? item;
          const host = (item as { host?: string }).host ?? '';
          const port = (item as { port?: number }).port ?? 443;
          const protocol = (item as { protocol?: string }).protocol ?? 'https';

          const data = await burpClient.post('/v0.1/repeater', {
            host,
            port,
            protocol,
            request,
          });

          return { success: true, proxy_history_id, response: data };
        }
      },
      () => {
        const local = getLocalHistoryItem(proxy_history_id);
        return {
          ...communityRestNotice(
            'burp_send_to_repeater',
            'Use repeater_replay_from_proxy_history or repeater_send_request to replay requests directly in Community mode.',
          ),
          local_item_found: Boolean(local),
          proxy_history_id,
        };
      },
    );
  },
};

// ============================================================
// Exported tool array
// ============================================================

export const EXTENSIONS_TOOLS: McpTool[] = [
  extensions_list,
  extensions_get,
  extensions_toggle,
  extensions_get_output,
  extensions_clear_output,
  extensions_install,
  extensions_unload,
  burp_get_version,
  burp_get_configuration,
  burp_update_configuration,
  burp_save_state,
  burp_send_to_repeater,
];
