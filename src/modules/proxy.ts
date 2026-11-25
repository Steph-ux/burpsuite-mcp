import { BurpClient, getBurpClient } from '../utils/burp-client.js';
import {
  addLocalMatchReplaceRule,
  deleteLocalMatchReplaceRule,
  getLocalHistory,
  getLocalHistoryItem,
  listLocalMatchReplaceRules,
} from '../utils/local-store.js';

function communityProxyNotice(feature: string) {
  return {
    supported: false,
    mode: 'community-no-rest-api',
    feature,
    message:
      `${feature} via REST API requires BurpSuite Pro (or loading the optional Community bridge extension on port 1337). ` +
      'You can control interception directly in the Burp Community GUI under Proxy > Intercept.',
  };
}

// ---------------------------------------------------------------------------
// Helper: resolve a burpClient argument (falls back to singleton or new client)
// ---------------------------------------------------------------------------
let _defaultClient: BurpClient | null = null;
function resolveClient(burpClient?: BurpClient): BurpClient {
  if (burpClient) return burpClient;
  try {
    return getBurpClient();
  } catch {
    if (!_defaultClient) {
      _defaultClient = new BurpClient({
        host: process.env.BURP_HOST ?? '127.0.0.1',
        port: parseInt(process.env.BURP_PORT ?? '8080', 10),
        apiKey: process.env.BURP_API_KEY ?? '',
        apiPort: parseInt(process.env.BURP_API_PORT ?? '1337', 10),
      });
    }
    return _defaultClient;
  }
}

// ---------------------------------------------------------------------------
// Tool definitions
// ---------------------------------------------------------------------------

/**
 * 1. get_proxy_history
 * GET /v0.1/proxy/history
 */
export function get_proxy_history() {
  return {
    name: 'get_proxy_history',
    description:
      'Retrieve the Burp Proxy HTTP history. Optionally limit the number of items returned and filter by URL substring.',
    inputSchema: {
      type: 'object',
      properties: {
        limit: {
          type: 'number',
          description: 'Maximum number of history items to return (default 100).',
          default: 100,
        },
        filter: {
          type: 'string',
          description: 'Optional URL substring filter. Only items whose URL contains this string are returned.',
        },
      },
      required: [],
    },
    async handler(args: { limit?: number; filter?: string }, burpClient?: BurpClient) {
      const client = resolveClient(burpClient);
      const limit = args.limit ?? 100;

      return client.withRestFallback(
        async () => {
          const data = (await client.get('/v0.1/proxy/history')) as {
            messages?: Array<Record<string, unknown>>;
          };

          let items: Array<Record<string, unknown>> = data?.messages ?? [];

          if (args.filter) {
            const f = args.filter.toLowerCase();
            items = items.filter((item) => {
              const url = String(
                (item.request as Record<string, unknown>)?.url ??
                  (item.request as Record<string, unknown>)?.path ??
                  '',
              ).toLowerCase();
              return url.includes(f);
            });
          }

          if (items.length > limit) {
            items = items.slice(0, limit);
          }

          return { mode: 'burp-rest-api', total: items.length, items };
        },
        () => {
          const items = getLocalHistory(limit, args.filter);
          return {
            mode: 'community-local',
            total: items.length,
            items,
            ...(items.length === 0
              ? {
                  note:
                    'No local history recorded yet. Requests sent via repeater_send_request or spider_start_crawl appear here and in Burp Community Proxy History.',
                }
              : {}),
          };
        },
      );
    },
  };
}

/**
 * 2. get_proxy_history_item
 * GET /v0.1/proxy/history  (filtered by id on client side – Burp REST v0.1
 *   does not expose a /history/{id} endpoint, so we fetch the list and find
 *   the item.)
 */
export function get_proxy_history_item() {
  return {
    name: 'get_proxy_history_item',
    description:
      'Retrieve a specific Burp Proxy history item by its numeric ID, including full request and response with headers, body, and status.',
    inputSchema: {
      type: 'object',
      properties: {
        id: {
          type: 'number',
          description: 'Numeric ID of the proxy history item.',
        },
      },
      required: ['id'],
    },
    async handler(args: { id: number }, burpClient?: BurpClient) {
      const client = resolveClient(burpClient);

      return client.withRestFallback(
        async () => {
          const data = (await client.get('/v0.1/proxy/history')) as {
            messages?: Array<Record<string, unknown>>;
          };

          const items: Array<Record<string, unknown>> = data?.messages ?? [];
          const item = items.find((i) => i.messageId === args.id || (i as Record<string, unknown>).id === args.id);

          if (!item) {
            throw new Error(`No proxy history item found with id ${args.id}`);
          }

          return item;
        },
        () => {
          const item = getLocalHistoryItem(args.id);
          if (!item) {
            throw new Error(`No local proxy history item found with id ${args.id}`);
          }
          return { mode: 'community-local', ...item };
        },
      );
    },
  };
}

/**
 * 3. set_proxy_intercept
 * PUT /v0.1/proxy/intercept_requests
 * PUT /v0.1/proxy/intercept_responses
 */
export function set_proxy_intercept() {
  return {
    name: 'set_proxy_intercept',
    description:
      'Enable or disable Burp Proxy interception for both requests and responses.',
    inputSchema: {
      type: 'object',
      properties: {
        enabled: {
          type: 'boolean',
          description: 'Set to true to enable interception, false to disable.',
        },
      },
      required: ['enabled'],
    },
    async handler(args: { enabled: boolean }, burpClient?: BurpClient) {
      const client = resolveClient(burpClient);

      return client.withRestFallback(
        async () => {
          const payload = { intercept: args.enabled ? 'enabled' : 'disabled' };

          const [reqResult, respResult] = await Promise.all([
            client.put('/v0.1/proxy/intercept_requests', payload),
            client.put('/v0.1/proxy/intercept_responses', payload),
          ]);

          return {
            intercept_enabled: args.enabled,
            intercept_requests: reqResult,
            intercept_responses: respResult,
          };
        },
        () => communityProxyNotice('set_proxy_intercept'),
      );
    },
  };
}

/**
 * 4. get_intercepted_requests
 * GET /v0.1/proxy/intercept_requests
 */
export function get_intercepted_requests() {
  return {
    name: 'get_intercepted_requests',
    description: 'List all currently intercepted (pending) HTTP requests in Burp Proxy.',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
    async handler(_args: Record<string, never>, burpClient?: BurpClient) {
      const client = resolveClient(burpClient);
      return client.withRestFallback(
        () => client.get('/v0.1/proxy/intercept_requests'),
        () => communityProxyNotice('get_intercepted_requests'),
      );
    },
  };
}

/**
 * 5. forward_intercepted_request
 * POST /v0.1/proxy/intercept_requests/{id}/forward  (or equivalent)
 */
export function forward_intercepted_request() {
  return {
    name: 'forward_intercepted_request',
    description:
      'Forward an intercepted request, optionally with a modified version of the raw HTTP request.',
    inputSchema: {
      type: 'object',
      properties: {
        id: {
          type: 'string',
          description: 'ID of the intercepted request to forward.',
        },
        modified_request: {
          type: 'string',
          description:
            'Optional raw HTTP request (as a string) to send in place of the original.',
        },
      },
      required: ['id'],
    },
    async handler(
      args: { id: string; modified_request?: string },
      burpClient?: BurpClient,
    ) {
      const client = resolveClient(burpClient);

      return client.withRestFallback(
        async () => {
          const payload: Record<string, unknown> = {};
          if (args.modified_request !== undefined) {
            payload.request = args.modified_request;
          }

          const data = await client.post(
            `/v0.1/proxy/intercept_requests/${encodeURIComponent(args.id)}/forward`,
            payload,
          );

          return { forwarded: true, id: args.id, result: data };
        },
        () => communityProxyNotice('forward_intercepted_request'),
      );
    },
  };
}

/**
 * 6. drop_intercepted_request
 * POST /v0.1/proxy/intercept_requests/{id}/drop  (or DELETE)
 */
export function drop_intercepted_request() {
  return {
    name: 'drop_intercepted_request',
    description: 'Drop (discard) an intercepted request so it is never forwarded to the server.',
    inputSchema: {
      type: 'object',
      properties: {
        id: {
          type: 'string',
          description: 'ID of the intercepted request to drop.',
        },
      },
      required: ['id'],
    },
    async handler(args: { id: string }, burpClient?: BurpClient) {
      const client = resolveClient(burpClient);

      return client.withRestFallback(
        async () => {
          const data = await client.post(
            `/v0.1/proxy/intercept_requests/${encodeURIComponent(args.id)}/drop`,
            {},
          );

          return { dropped: true, id: args.id, result: data };
        },
        () => communityProxyNotice('drop_intercepted_request'),
      );
    },
  };
}

/**
 * 7. add_proxy_match_replace_rule
 * POST /v0.1/proxy/match_replace_rules
 */

type MatchType =
  | 'request_header'
  | 'response_header'
  | 'request_body'
  | 'response_body'
  | 'request_first_line';

export function add_proxy_match_replace_rule() {
  return {
    name: 'add_proxy_match_replace_rule',
    description:
      'Add a Burp Proxy match-and-replace rule to automatically modify matching requests or responses.',
    inputSchema: {
      type: 'object',
      properties: {
        match_condition: {
          type: 'string',
          description: 'The string or regex to match against.',
        },
        match_type: {
          type: 'string',
          enum: [
            'request_header',
            'response_header',
            'request_body',
            'response_body',
            'request_first_line',
          ],
          description: 'Where to apply the match: request_header, response_header, request_body, response_body, or request_first_line.',
        },
        replace_string: {
          type: 'string',
          description: 'The string to substitute in place of the matched content.',
        },
        enabled: {
          type: 'boolean',
          description: 'Whether the rule is active immediately after creation.',
        },
        is_regex: {
          type: 'boolean',
          description: 'Treat match_condition as a regular expression (default false).',
          default: false,
        },
        comment: {
          type: 'string',
          description: 'Optional comment / label for the rule.',
        },
      },
      required: ['match_condition', 'match_type', 'replace_string', 'enabled'],
    },
    async handler(
      args: {
        match_condition: string;
        match_type: MatchType;
        replace_string: string;
        enabled: boolean;
        is_regex?: boolean;
        comment?: string;
      },
      burpClient?: BurpClient,
    ) {
      const client = resolveClient(burpClient);

      const payload = {
        rule_type: args.match_type,
        match: args.match_condition,
        replace: args.replace_string,
        is_simple_match: !(args.is_regex ?? false),
        enabled: args.enabled,
        comment: args.comment ?? '',
      };

      return client.withRestFallback(
        async () => {
          const data = await client.post('/v0.1/proxy/match_replace_rules', payload);
          return { created: true, rule: data };
        },
        () => {
          const rule = addLocalMatchReplaceRule(payload);
          return { created: true, mode: 'community-local', rule };
        },
      );
    },
  };
}

/**
 * 8. list_proxy_match_replace_rules
 * GET /v0.1/proxy/match_replace_rules
 */
export function list_proxy_match_replace_rules() {
  return {
    name: 'list_proxy_match_replace_rules',
    description: 'List all current Burp Proxy match-and-replace rules.',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
    async handler(_args: Record<string, never>, burpClient?: BurpClient) {
      const client = resolveClient(burpClient);
      return client.withRestFallback(
        () => client.get('/v0.1/proxy/match_replace_rules'),
        () => ({ mode: 'community-local', rules: listLocalMatchReplaceRules() }),
      );
    },
  };
}

/**
 * 9. delete_proxy_match_replace_rule
 * DELETE /v0.1/proxy/match_replace_rules/{id}
 */
export function delete_proxy_match_replace_rule() {
  return {
    name: 'delete_proxy_match_replace_rule',
    description: 'Delete a Burp Proxy match-and-replace rule by its ID.',
    inputSchema: {
      type: 'object',
      properties: {
        id: {
          type: 'string',
          description: 'ID of the match-and-replace rule to delete.',
        },
      },
      required: ['id'],
    },
    async handler(args: { id: string }, burpClient?: BurpClient) {
      const client = resolveClient(burpClient);

      return client.withRestFallback(
        async () => {
          const data = await client.delete(
            `/v0.1/proxy/match_replace_rules/${encodeURIComponent(args.id)}`,
          );

          return { deleted: true, id: args.id, result: data };
        },
        () => ({
          deleted: deleteLocalMatchReplaceRule(args.id),
          mode: 'community-local',
          id: args.id,
        }),
      );
    },
  };
}

// ---------------------------------------------------------------------------
// Aggregate export
// ---------------------------------------------------------------------------
export const PROXY_TOOLS = [
  get_proxy_history(),
  get_proxy_history_item(),
  set_proxy_intercept(),
  get_intercepted_requests(),
  forward_intercepted_request(),
  drop_intercepted_request(),
  add_proxy_match_replace_rule(),
  list_proxy_match_replace_rules(),
  delete_proxy_match_replace_rule(),
];
