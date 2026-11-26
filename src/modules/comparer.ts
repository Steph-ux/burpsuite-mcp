// ============================================================
// BurpSuite MCP – Comparer Module
// Mirrors BurpSuite's Comparer tab for text, Proxy History items,
// and in-memory Repeater items.
// ============================================================

import { type BurpClient, getBurpClient } from "../utils/burp-client.js";
import { getLocalHistoryItem } from "../utils/local-store.js";
import { getRepeaterEntry } from "./repeater.js";

export type DiffMode = "lines" | "words" | "chars";

interface DiffChunk {
  op: "equal" | "removed" | "added";
  value: string;
}

interface HttpMessageComparable {
  label: string;
  statusCode: number | null;
  headers: Record<string, string>;
  body: string;
}

const MAX_LCS_TOKENS = 1_500;

function tokenize(text: string, mode: DiffMode): string[] {
  if (mode === "lines") return text.split(/\r?\n/);
  if (mode === "words") return text.split(/(\s+)/).filter((t) => t.length > 0);
  return Array.from(text);
}

function joinTokens(tokens: string[], mode: DiffMode): string {
  return mode === "lines" ? tokens.join("\n") : tokens.join("");
}

function computeTokenDiff(left: string, right: string, mode: DiffMode): {
  identical: boolean;
  added_count: number;
  removed_count: number;
  equal_count: number;
  truncated: boolean;
  changes: Array<{ op: "removed" | "added"; left_index?: number; right_index?: number; value: string }>;
  unified_preview: string;
} {
  if (left === right) {
    return {
      identical: true,
      added_count: 0,
      removed_count: 0,
      equal_count: tokenize(left, mode).length,
      truncated: false,
      changes: [],
      unified_preview: "(identical)",
    };
  }

  const a = tokenize(left, mode);
  const b = tokenize(right, mode);

  // Trim identical prefix and suffix to shrink DP matrix
  let prefix = 0;
  while (prefix < a.length && prefix < b.length && a[prefix] === b[prefix]) {
    prefix++;
  }
  let suffix = 0;
  while (
    suffix < a.length - prefix &&
    suffix < b.length - prefix &&
    a[a.length - 1 - suffix] === b[b.length - 1 - suffix]
  ) {
    suffix++;
  }

  const midA = a.slice(prefix, a.length - suffix);
  const midB = b.slice(prefix, b.length - suffix);
  const truncated = midA.length > MAX_LCS_TOKENS || midB.length > MAX_LCS_TOKENS;
  const sliceA = truncated ? midA.slice(0, MAX_LCS_TOKENS) : midA;
  const sliceB = truncated ? midB.slice(0, MAX_LCS_TOKENS) : midB;

  const m = sliceA.length;
  const n = sliceB.length;
  const dp: Uint32Array[] = Array.from({ length: m + 1 }, () => new Uint32Array(n + 1));

  for (let i = m - 1; i >= 0; i--) {
    const row = dp[i]!;
    const nextRow = dp[i + 1]!;
    for (let j = n - 1; j >= 0; j--) {
      if (sliceA[i] === sliceB[j]) {
        row[j] = 1 + nextRow[j + 1]!;
      } else {
        row[j] = Math.max(nextRow[j]!, row[j + 1]!);
      }
    }
  }

  const chunks: DiffChunk[] = [];
  let i = 0;
  let j = 0;
  let added = 0;
  let removed = 0;
  let equal = prefix + suffix;

  const changes: Array<{
    op: "removed" | "added";
    left_index?: number;
    right_index?: number;
    value: string;
  }> = [];

  while (i < m && j < n) {
    if (sliceA[i] === sliceB[j]) {
      chunks.push({ op: "equal", value: sliceA[i]! });
      equal++;
      i++;
      j++;
    } else if (dp[i + 1]![j]! >= dp[i]![j + 1]!) {
      const val = sliceA[i]!;
      chunks.push({ op: "removed", value: val });
      changes.push({ op: "removed", left_index: prefix + i, value: val });
      removed++;
      i++;
    } else {
      const val = sliceB[j]!;
      chunks.push({ op: "added", value: val });
      changes.push({ op: "added", right_index: prefix + j, value: val });
      added++;
      j++;
    }
  }
  while (i < m) {
    const val = sliceA[i]!;
    chunks.push({ op: "removed", value: val });
    changes.push({ op: "removed", left_index: prefix + i, value: val });
    removed++;
    i++;
  }
  while (j < n) {
    const val = sliceB[j]!;
    chunks.push({ op: "added", value: val });
    changes.push({ op: "added", right_index: prefix + j, value: val });
    added++;
    j++;
  }

  let unifiedPreview: string;
  if (mode === "lines") {
    unifiedPreview = chunks
      .map((c) => {
        const prefixChar = c.op === "added" ? "+ " : c.op === "removed" ? "- " : "  ";
        return prefixChar + c.value;
      })
      .slice(0, 200)
      .join("\n");
  } else {
    const remTokens = chunks.filter((c) => c.op === "removed").map((c) => c.value);
    const addTokens = chunks.filter((c) => c.op === "added").map((c) => c.value);
    unifiedPreview = `- ${joinTokens(remTokens, mode)}\n+ ${joinTokens(addTokens, mode)}`;
  }

  return {
    identical: false,
    added_count: added,
    removed_count: removed,
    equal_count: equal,
    truncated,
    changes: changes.slice(0, 300),
    unified_preview: unifiedPreview,
  };
}

function normalizeHeaderRecord(raw: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (Array.isArray(raw)) {
    for (const h of raw) {
      if (h && typeof h === "object" && "name" in h && "value" in h) {
        out[String((h as { name: unknown }).name).toLowerCase()] = String(
          (h as { value: unknown }).value
        );
      }
    }
  } else if (raw && typeof raw === "object") {
    for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
      out[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : String(v ?? "");
    }
  }
  return out;
}

function compareHttpMessages(
  left: HttpMessageComparable,
  right: HttpMessageComparable,
  mode: DiffMode
) {
  const allHeaderKeys = new Set([
    ...Object.keys(left.headers),
    ...Object.keys(right.headers),
  ]);
  const headersDiff: {
    added: Record<string, string>;
    removed: Record<string, string>;
    changed: Record<string, { left: string; right: string }>;
  } = { added: {}, removed: {}, changed: {} };

  for (const key of Array.from(allHeaderKeys).sort()) {
    const lv = left.headers[key];
    const rv = right.headers[key];
    if (lv === undefined && rv !== undefined) {
      headersDiff.added[key] = rv;
    } else if (lv !== undefined && rv === undefined) {
      headersDiff.removed[key] = lv;
    } else if (lv !== rv) {
      headersDiff.changed[key] = { left: lv ?? "", right: rv ?? "" };
    }
  }

  const bodyDiff = computeTokenDiff(left.body, right.body, mode);

  return {
    left: { label: left.label, status_code: left.statusCode, body_length: left.body.length },
    right: { label: right.label, status_code: right.statusCode, body_length: right.body.length },
    status_changed: left.statusCode !== right.statusCode,
    headers_diff: headersDiff,
    body_diff: bodyDiff,
  };
}

async function fetchProxyMessage(
  client: BurpClient,
  id: number
): Promise<HttpMessageComparable> {
  return client.withRestFallback(
    async () => {
      let item: Record<string, unknown> | undefined;
      try {
        item = await client.get<Record<string, unknown>>(`/v0.1/proxy/history/${id}`);
      } catch {
        const hist = await client.get<{ messages?: Array<Record<string, unknown>> }>(
          "/v0.1/proxy/history"
        );
        item = hist?.messages?.find((m) => m.messageId === id || m.id === id);
      }
      if (!item) {
        throw new Error(`No proxy history item found with id ${id}`);
      }
      const req = (item.request as Record<string, unknown>) ?? {};
      const res = (item.response as Record<string, unknown>) ?? {};
      return {
        label: `proxy#${id} ${String(req.method ?? "")} ${String(req.url ?? req.path ?? "")}`.trim(),
        statusCode:
          typeof res.statusCode === "number"
            ? res.statusCode
            : typeof item.responseCode === "number"
            ? item.responseCode
            : null,
        headers: normalizeHeaderRecord(res.headers),
        body: typeof res.body === "string" ? res.body : "",
      };
    },
    () => {
      const local = getLocalHistoryItem(id);
      if (!local) {
        throw new Error(`No local proxy history item found with id ${id}`);
      }
      return {
        label: `local-proxy#${id} ${local.request.method} ${local.request.url}`,
        statusCode: local.response.statusCode,
        headers: normalizeHeaderRecord(local.response.headers),
        body: local.response.body,
      };
    }
  );
}

export const COMPARER_TOOLS = [
  {
    name: "comparer_diff_text",
    description:
      "Compare two strings (lines, words, or chars) and return structured diff chunks and a unified preview, similar to BurpSuite Comparer.",
    inputSchema: {
      type: "object",
      properties: {
        left: { type: "string", description: "Baseline / left text." },
        right: { type: "string", description: "Modified / right text." },
        mode: {
          type: "string",
          enum: ["lines", "words", "chars"],
          default: "lines",
          description: "Comparison granularity (default: lines).",
        },
      },
      required: ["left", "right"],
    },
    handler: async (
      args: { left: string; right: string; mode?: DiffMode },
      _burpClient?: BurpClient
    ) => {
      const mode = args.mode ?? "lines";
      return {
        mode,
        left_length: args.left.length,
        right_length: args.right.length,
        ...computeTokenDiff(args.left, args.right, mode),
      };
    },
  },
  {
    name: "comparer_diff_proxy_items",
    description:
      "Compare two Burp Proxy history items by ID (status code, response headers added/removed/changed, and response body diff).",
    inputSchema: {
      type: "object",
      properties: {
        left_id: { type: "number", description: "Numeric ID of the baseline proxy history item." },
        right_id: { type: "number", description: "Numeric ID of the second proxy history item." },
        mode: {
          type: "string",
          enum: ["lines", "words", "chars"],
          default: "lines",
          description: "Body diff granularity (default: lines).",
        },
      },
      required: ["left_id", "right_id"],
    },
    handler: async (
      args: { left_id: number; right_id: number; mode?: DiffMode },
      burpClient?: BurpClient
    ) => {
      const client = burpClient ?? getBurpClient();
      const mode = args.mode ?? "lines";
      const [left, right] = await Promise.all([
        fetchProxyMessage(client, args.left_id),
        fetchProxyMessage(client, args.right_id),
      ]);
      return compareHttpMessages(left, right, mode);
    },
  },
  {
    name: "comparer_diff_repeater_items",
    description:
      "Compare two in-memory Repeater history entries by UUID (status code, response headers, and response body diff).",
    inputSchema: {
      type: "object",
      properties: {
        left_id: { type: "string", description: "UUID of the baseline Repeater item." },
        right_id: { type: "string", description: "UUID of the second Repeater item." },
        mode: {
          type: "string",
          enum: ["lines", "words", "chars"],
          default: "lines",
          description: "Body diff granularity (default: lines).",
        },
      },
      required: ["left_id", "right_id"],
    },
    handler: async (
      args: { left_id: string; right_id: string; mode?: DiffMode },
      _burpClient?: BurpClient
    ) => {
      const leftEntry = getRepeaterEntry(args.left_id);
      if (!leftEntry) {
        throw new Error(`Repeater history item not found: ${args.left_id}`);
      }
      const rightEntry = getRepeaterEntry(args.right_id);
      if (!rightEntry) {
        throw new Error(`Repeater history item not found: ${args.right_id}`);
      }

      const toComparable = (entry: NonNullable<typeof leftEntry>): HttpMessageComparable => ({
        label: entry.name ?? `${entry.request.method} ${entry.request.path}`,
        statusCode: entry.response?.status ?? null,
        headers: normalizeHeaderRecord(entry.response?.headers ?? {}),
        body: entry.response?.body ?? "",
      });

      return compareHttpMessages(
        toComparable(leftEntry),
        toComparable(rightEntry),
        args.mode ?? "lines"
      );
    },
  },
];
