// ============================================================
// BurpSuite MCP – Session Persistence Module
// Allows saving and restoring full Community/MCP session state
// (proxy history, scope, match & replace rules, passive issues,
// and Repeater history) to/from a JSON file on disk.
// ============================================================

import fs from "node:fs";
import path from "node:path";
import { type BurpClient, getBurpClient } from "../utils/burp-client.js";
import {
  exportLocalStoreSnapshot,
  getLocalStoreStats,
  importLocalStoreSnapshot,
  type LocalExchangeRecord,
  type LocalMatchReplaceRule,
  type LocalStoreSnapshot,
} from "../utils/local-store.js";
import {
  exportRepeaterHistory,
  importRepeaterHistory,
  type RepeaterEntry,
} from "./repeater.js";

const SESSION_SCHEMA_VERSION = 1;

interface SessionFile {
  version: number;
  saved_at: string;
  local_store: LocalStoreSnapshot;
  repeater_history: RepeaterEntry[];
}

function toStringHeaders(raw: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (raw && typeof raw === "object") {
    for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
      out[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : String(v ?? "");
    }
  }
  return out;
}

async function mergeLiveBurpData(
  client: BurpClient,
  snapshot: LocalStoreSnapshot
): Promise<{ synced_from_burp: boolean }> {
  const reachable = await client.isRestApiAvailable();
  if (!reachable) {
    return { synced_from_burp: false };
  }

  // Merge live Burp Proxy history if local store is empty or missing items
  try {
    const histRes = await client.get<{ messages?: Array<Record<string, unknown>> }>(
      "/v0.1/proxy/history"
    );
    const messages = histRes?.messages ?? [];
    const seenUrls = new Set(
      snapshot.proxy_history.map((h) => `${h.id}:${h.request.method}:${h.request.url}`)
    );
    let nextId =
      snapshot.proxy_history.reduce((m, item) => Math.max(m, item.id), 0) + 1;

    for (const msg of messages) {
      const req = (msg.request as Record<string, unknown>) ?? {};
      const res = (msg.response as Record<string, unknown>) ?? {};
      const url = String(req.url ?? "");
      if (!url) continue;
      let parsed: URL | null = null;
      try {
        parsed = new URL(url);
      } catch {
        parsed = null;
      }
      const id =
        typeof msg.id === "number"
          ? msg.id
          : typeof msg.messageId === "number"
          ? msg.messageId
          : nextId++;
      const method = String(req.method ?? "GET").toUpperCase();
      const key = `${id}:${method}:${url}`;
      if (seenUrls.has(key)) continue;
      seenUrls.add(key);

      const rec: LocalExchangeRecord = {
        id,
        messageId: id,
        timestamp: new Date().toISOString(),
        source: "repeater",
        proxied: true,
        protocol:
          String(msg.protocol ?? (parsed?.protocol === "https:" ? "https" : "http")) === "https"
            ? "https"
            : "http",
        host: String(msg.host ?? parsed?.hostname ?? ""),
        port: Number(msg.port ?? (parsed?.port ? Number(parsed.port) : parsed?.protocol === "https:" ? 443 : 80)),
        path: String(msg.path ?? (parsed ? parsed.pathname + parsed.search : "/")),
        request: {
          method,
          url,
          headers: toStringHeaders(req.headers),
          body: typeof req.body === "string" ? req.body : undefined,
        },
        response: {
          statusCode: Number(res.statusCode ?? msg.responseCode ?? 0),
          statusMessage: String(res.statusMessage ?? ""),
          headers: toStringHeaders(res.headers),
          body: typeof res.body === "string" ? res.body : "",
          mimeType: String(res.mimeType ?? msg.mimeType ?? ""),
          responseTime: Number(res.responseTime ?? 0),
        },
      };
      snapshot.proxy_history.push(rec);
    }
  } catch {
    /* ignore if proxy history endpoint unavailable */
  }

  // Merge live scope rules
  try {
    const scopeRes = await client.get<{
      include?: Array<{ url?: string }>;
      exclude?: Array<{ url?: string }>;
    }>("/v0.1/target/scope");
    for (const item of scopeRes?.include ?? []) {
      if (item?.url && !snapshot.scope.included.includes(item.url)) {
        snapshot.scope.included.push(item.url);
      }
    }
    for (const item of scopeRes?.exclude ?? []) {
      if (item?.url && !snapshot.scope.excluded.includes(item.url)) {
        snapshot.scope.excluded.push(item.url);
      }
    }
  } catch {
    /* ignore if scope endpoint unsupported */
  }

  // Merge live match/replace rules
  try {
    const mrRes = await client.get<{ rules?: LocalMatchReplaceRule[] }>(
      "/v0.1/proxy/match_replace_rules"
    );
    const seenRuleIds = new Set(snapshot.match_replace_rules.map((r) => r.id));
    for (const r of mrRes?.rules ?? []) {
      if (r?.id && !seenRuleIds.has(r.id)) {
        snapshot.match_replace_rules.push(r);
      }
    }
  } catch {
    /* ignore if match/replace endpoint unsupported */
  }

  return { synced_from_burp: true };
}

export const SESSION_TOOLS = [
  {
    name: "session_info",
    description:
      "Inspect current in-memory session statistics (local proxy history, Repeater entries, scope rules, match/replace rules, passive issues, and REST/bridge connectivity).",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
    handler: async (_args: Record<string, never>, burpClient?: BurpClient) => {
      const client = burpClient ?? getBurpClient();
      const [restReachable, localStats] = await Promise.all([
        client.isRestApiAvailable(),
        Promise.resolve(getLocalStoreStats()),
      ]);
      const repeaterCount = exportRepeaterHistory().length;
      return {
        rest_api_reachable: restReachable,
        edition: client.edition,
        proxy_url: client.proxyBaseUrl,
        ...localStats,
        repeater_history_count: repeaterCount,
      };
    },
  },
  {
    name: "session_save",
    description:
      "Save the current MCP/Community session (proxy history, scope, match & replace rules, passive issues, and Repeater history) to a JSON file on disk.",
    inputSchema: {
      type: "object",
      properties: {
        file_path: {
          type: "string",
          description: "Destination JSON file path (e.g. ./burp-session.json).",
        },
        include_live_burp: {
          type: "boolean",
          default: true,
          description:
            "When Burp REST/bridge (:1337) is reachable, include live proxy history, scope, and match/replace rules in the saved snapshot (default: true).",
        },
      },
      required: ["file_path"],
    },
    handler: async (
      args: { file_path: string; include_live_burp?: boolean },
      burpClient?: BurpClient
    ) => {
      const client = burpClient ?? getBurpClient();
      const snapshot = exportLocalStoreSnapshot();
      const repeaterHistory = exportRepeaterHistory();

      let syncedFromBurp = false;
      if (args.include_live_burp !== false) {
        const syncRes = await mergeLiveBurpData(client, snapshot);
        syncedFromBurp = syncRes.synced_from_burp;
      }

      const payload: SessionFile = {
        version: SESSION_SCHEMA_VERSION,
        saved_at: new Date().toISOString(),
        local_store: snapshot,
        repeater_history: repeaterHistory,
      };

      const targetPath = path.resolve(args.file_path);
      fs.mkdirSync(path.dirname(targetPath), { recursive: true });
      const json = JSON.stringify(payload, null, 2);
      fs.writeFileSync(targetPath, json, "utf8");

      return {
        saved: true,
        file_path: targetPath,
        bytes_written: Buffer.byteLength(json, "utf8"),
        synced_from_burp: syncedFromBurp,
        counts: {
          proxy_history: snapshot.proxy_history.length,
          scope_included: snapshot.scope.included.length,
          scope_excluded: snapshot.scope.excluded.length,
          match_replace_rules: snapshot.match_replace_rules.length,
          passive_issues: snapshot.passive_issues.length,
          repeater_history: repeaterHistory.length,
        },
      };
    },
  },
  {
    name: "session_load",
    description:
      "Load a previously saved JSON session file into memory (proxy history, scope, match & replace rules, passive issues, and Repeater history), optionally syncing scope and rules to a live Burp REST/bridge instance.",
    inputSchema: {
      type: "object",
      properties: {
        file_path: {
          type: "string",
          description: "Path to the saved JSON session file.",
        },
        merge: {
          type: "boolean",
          default: false,
          description:
            "Merge with existing in-memory session instead of replacing it (default: false).",
        },
        sync_to_burp: {
          type: "boolean",
          default: true,
          description:
            "If Burp REST/bridge (:1337) is reachable, push loaded scope and match/replace rules to Burp (default: true).",
        },
      },
      required: ["file_path"],
    },
    handler: async (
      args: { file_path: string; merge?: boolean; sync_to_burp?: boolean },
      burpClient?: BurpClient
    ) => {
      const client = burpClient ?? getBurpClient();
      const targetPath = path.resolve(args.file_path);
      if (!fs.existsSync(targetPath)) {
        throw new Error(`Session file not found: ${targetPath}`);
      }

      let parsed: SessionFile;
      try {
        parsed = JSON.parse(fs.readFileSync(targetPath, "utf8")) as SessionFile;
      } catch (err) {
        throw new Error(
          `Invalid session JSON file: ${err instanceof Error ? err.message : String(err)}`
        );
      }

      if (
        !parsed ||
        typeof parsed !== "object" ||
        parsed.version !== SESSION_SCHEMA_VERSION ||
        !parsed.local_store
      ) {
        throw new Error(
          `Unsupported session file format (expected version=${SESSION_SCHEMA_VERSION} with local_store).`
        );
      }

      const merge = args.merge === true;
      const storeResult = importLocalStoreSnapshot(parsed.local_store, merge);
      const repeaterLoaded = Array.isArray(parsed.repeater_history)
        ? importRepeaterHistory(parsed.repeater_history, merge)
        : 0;

      let syncedToBurp = false;
      if (args.sync_to_burp !== false && (await client.isRestApiAvailable())) {
        try {
          const scope = parsed.local_store.scope;
          if (scope && (scope.included?.length || scope.excluded?.length)) {
            await client.put("/v0.1/target/scope", {
              include: (scope.included ?? []).map((url) => ({ url })),
              exclude: (scope.excluded ?? []).map((url) => ({ url })),
            });
          }
          for (const rule of parsed.local_store.match_replace_rules ?? []) {
            await client.post("/v0.1/proxy/match_replace_rules", {
              rule_type: rule.rule_type,
              match: rule.match,
              replace: rule.replace,
              is_simple_match: rule.is_simple_match,
              enabled: rule.enabled,
              comment: rule.comment,
            });
          }
          syncedToBurp = true;
        } catch {
          /* partial or unsupported endpoint on bridge/Pro */
        }
      }

      return {
        loaded: true,
        file_path: targetPath,
        saved_at: parsed.saved_at,
        merge,
        synced_to_burp: syncedToBurp,
        ...storeResult,
        repeater_history_loaded: repeaterLoaded,
      };
    },
  },
];
