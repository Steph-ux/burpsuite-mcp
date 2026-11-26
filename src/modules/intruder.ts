// ============================================================
// BurpSuite MCP – Intruder Module
// Implements Burp Intruder attack types by sending HTTP
// requests directly through the Burp proxy using Node.js
// http/https (no Burp REST endpoint needed for Intruder).
// ============================================================

import http from "node:http";
import https from "node:https";
import { randomUUID } from "node:crypto";
import { BurpClient, getBurpClient } from "../utils/burp-client.js";
import { logger } from "../utils/logger.js";

// ── Types ────────────────────────────────────────────────────

export type AttackType = "sniper" | "battering_ram" | "pitchfork" | "cluster_bomb";
export type AttackStatus = "pending" | "running" | "stopped" | "finished" | "error";

export interface IntruderResult {
  index: number;
  payloads: string[];          // one entry per position
  position_index: number;      // primary position index (0-based)
  status_code: number;
  response_length: number;
  response_time_ms: number;
  response_headers: Record<string, string>;
  response_body: string;       // first 5000 chars
  error?: string;
}

export interface AttackRecord {
  attack_id: string;
  attack_type: AttackType;
  host: string;
  port: number;
  use_https: boolean;
  request_template: string;
  payload_sets: string[][];
  max_concurrent: number;
  request_timeout_ms: number;
  status: AttackStatus;
  total_requests: number;
  completed_requests: number;
  results: IntruderResult[];
  created_at: string;
  started_at?: string;
  finished_at?: string;
  stop_requested: boolean;
}

// ── In-memory store ──────────────────────────────────────────

const attacks = new Map<string, AttackRecord>();

// ── Payload generation ───────────────────────────────────────

/**
 * Parses a marked template with §baseline§ delimiters, returning static text
 * segments (`segments.length === baselines.length + 1`) and the baseline values.
 */
function parseMarkedTemplate(template: string): { segments: string[]; baselines: string[] } {
  const segments: string[] = [];
  const baselines: string[] = [];
  let cursor = 0;
  let literalStart = 0;

  while (cursor < template.length) {
    if (template[cursor] === "§") {
      const end = template.indexOf("§", cursor + 1);
      if (end === -1) {
        cursor++;
        continue;
      }
      segments.push(template.slice(literalStart, cursor));
      baselines.push(template.slice(cursor + 1, end));
      cursor = end + 1;
      literalStart = cursor;
    } else {
      cursor++;
    }
  }
  segments.push(template.slice(literalStart));
  return { segments, baselines };
}

/**
 * Builds a request string by substituting payload values into §marker§ slots.
 */
function buildRequest(template: string, payloads: string[]): string {
  const { segments, baselines } = parseMarkedTemplate(template);
  let result = segments[0] ?? "";
  for (let i = 0; i < baselines.length; i++) {
    result += (payloads[i] ?? baselines[i] ?? "") + (segments[i + 1] ?? "");
  }
  return result;
}

/**
 * Generates the list of payload tuples for each attack type.
 * Returns an array of { payloads: string[], positionIndex: number }
 */
function generatePayloadCombinations(
  attackType: AttackType,
  payloadSets: string[][],
  baselines: string[]
): Array<{ payloads: string[]; positionIndex: number }> {
  const positionCount = baselines.length;
  const combos: Array<{ payloads: string[]; positionIndex: number }> = [];

  if (attackType === "sniper") {
    // Single payload set, iterated over each position while other positions keep their baseline values
    const set = payloadSets[0] ?? [];
    for (let posIdx = 0; posIdx < positionCount; posIdx++) {
      for (const payload of set) {
        const payloads: string[] = [];
        for (let p = 0; p < positionCount; p++) {
          payloads.push(p === posIdx ? payload : (baselines[p] ?? ""));
        }
        combos.push({ payloads, positionIndex: posIdx });
      }
    }
  } else if (attackType === "battering_ram") {
    // Single payload set, same value in every position
    const set = payloadSets[0] ?? [];
    for (const payload of set) {
      const payloads = Array(positionCount).fill(payload) as string[];
      combos.push({ payloads, positionIndex: 0 });
    }
  } else if (attackType === "pitchfork") {
    // Multiple payload sets, each set maps to its position in lockstep
    const minLen = Math.min(...payloadSets.map((s) => s.length));
    for (let i = 0; i < minLen; i++) {
      const payloads = payloadSets.map((set) => set[i] ?? "");
      combos.push({ payloads, positionIndex: 0 });
    }
  } else if (attackType === "cluster_bomb") {
    // Cartesian product of all payload sets
    function cartesian(sets: string[][]): string[][] {
      return sets.reduce<string[][]>(
        (acc, set) => acc.flatMap((prefix) => set.map((v) => [...prefix, v])),
        [[]]
      );
    }
    const product = cartesian(payloadSets);
    for (const payloads of product) {
      combos.push({ payloads, positionIndex: 0 });
    }
  }

  return combos;
}

// ── HTTP request sender ──────────────────────────────────────

interface RawResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  responseTimeMs: number;
}

function sendRawRequest(
  host: string,
  port: number,
  useHttps: boolean,
  rawRequest: string,
  timeoutMs: number,
  burpProxyHost: string,
  burpProxyPort: number,
  rejectUnauthorized = false
): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const start = Date.now();

    // Parse the raw HTTP request
    const [headerSection, ...bodyParts] = rawRequest.split("\r\n\r\n");
    const bodyStr = bodyParts.join("\r\n\r\n");
    const headerLines = (headerSection ?? "").split("\r\n");
    const requestLine = headerLines[0] ?? "";
    const [method, path] = requestLine.split(" ");
    const headerMap: Record<string, string> = {};
    for (const line of headerLines.slice(1)) {
      const colonIdx = line.indexOf(":");
      if (colonIdx === -1) continue;
      const key = line.slice(0, colonIdx).trim().toLowerCase();
      const val = line.slice(colonIdx + 1).trim();
      headerMap[key] = val;
    }

    // Send through Burp proxy using CONNECT tunnel
    const proxyOptions: http.RequestOptions = {
      host: burpProxyHost,
      port: burpProxyPort,
      method: "CONNECT",
      path: `${host}:${port}`,
    };

    const connectReq = http.request(proxyOptions);
    connectReq.setTimeout(timeoutMs);

    connectReq.on("error", reject);
    connectReq.on("timeout", () => {
      connectReq.destroy();
      reject(new Error(`CONNECT timeout to ${host}:${port}`));
    });

    connectReq.on("connect", (_res, socket, _head) => {
      // Now send the actual request over the tunnel (or directly for http)
      const transport = useHttps ? https : http;
      const reqOptions: https.RequestOptions = {
        host,
        port,
        method: method ?? "GET",
        path: path ?? "/",
        headers: { ...headerMap, host: headerMap.host ?? `${host}:${port}` },
        // For HTTPS we provide the socket directly and respect Burp MITM cert setting
        ...(useHttps
          ? {
              socket,
              createConnection: () => socket,
              rejectUnauthorized,
            }
          : {}),
      };

      const req = transport.request(reqOptions, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          const responseTimeMs = Date.now() - start;
          const body = Buffer.concat(chunks).toString("utf8");
          const headers: Record<string, string> = {};
          for (const [k, v] of Object.entries(res.headers)) {
            headers[k] = Array.isArray(v) ? v.join(", ") : (v ?? "");
          }
          resolve({
            statusCode: res.statusCode ?? 0,
            headers,
            body,
            responseTimeMs,
          });
        });
        res.on("error", reject);
      });

      req.setTimeout(timeoutMs, () => {
        req.destroy();
        reject(new Error(`Request timeout for ${host}:${port}${path}`));
      });
      req.on("error", reject);

      if (bodyStr) req.write(bodyStr);
      req.end();
    });

    connectReq.end();
  });
}

/** Fallback for plain HTTP (no CONNECT needed) */
function sendDirectHttpRequest(
  host: string,
  port: number,
  rawRequest: string,
  timeoutMs: number,
  burpProxyHost: string,
  burpProxyPort: number
): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const start = Date.now();

    const [headerSection, ...bodyParts] = rawRequest.split("\r\n\r\n");
    const bodyStr = bodyParts.join("\r\n\r\n");
    const headerLines = (headerSection ?? "").split("\r\n");
    const requestLine = headerLines[0] ?? "";
    const [method, path] = requestLine.split(" ");
    const headers: Record<string, string> = {
      host: `${host}:${port}`,
    };
    for (const line of headerLines.slice(1)) {
      const colonIdx = line.indexOf(":");
      if (colonIdx === -1) continue;
      const key = line.slice(0, colonIdx).trim().toLowerCase();
      const val = line.slice(colonIdx + 1).trim();
      headers[key] = val;
    }

    const options: http.RequestOptions = {
      host: burpProxyHost,
      port: burpProxyPort,
      method: method ?? "GET",
      path: `http://${host}:${port}${path ?? "/"}`,
      headers,
    };

    const req = http.request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => {
        const responseTimeMs = Date.now() - start;
        const body = Buffer.concat(chunks).toString("utf8");
        const resHeaders: Record<string, string> = {};
        for (const [k, v] of Object.entries(res.headers)) {
          resHeaders[k] = Array.isArray(v) ? v.join(", ") : (v ?? "");
        }
        resolve({
          statusCode: res.statusCode ?? 0,
          headers: resHeaders,
          body,
          responseTimeMs,
        });
      });
      res.on("error", reject);
    });

    req.setTimeout(timeoutMs, () => {
      req.destroy();
      reject(new Error("Request timeout"));
    });
    req.on("error", reject);
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

// ── Concurrency pool ─────────────────────────────────────────

async function runWithConcurrency<T>(
  tasks: Array<() => Promise<T>>,
  maxConcurrent: number,
  shouldStop: () => boolean
): Promise<T[]> {
  const results: T[] = [];
  let idx = 0;

  async function runNext(): Promise<void> {
    while (idx < tasks.length) {
      if (shouldStop()) break;
      const currentIdx = idx++;
      const result = await tasks[currentIdx]!();
      results[currentIdx] = result;
    }
  }

  const workers = Array.from({ length: maxConcurrent }, () => runNext());
  await Promise.all(workers);
  return results;
}

// ── Attack runner ─────────────────────────────────────────────

async function runAttack(
  attack: AttackRecord,
  burpClient?: BurpClient
): Promise<void> {
  attack.status = "running";
  attack.started_at = new Date().toISOString();

  const { baselines } = parseMarkedTemplate(attack.request_template);
  const combos = generatePayloadCombinations(
    attack.attack_type,
    attack.payload_sets,
    baselines
  );

  attack.total_requests = combos.length;

  // Get proxy config from burp client
  const client = burpClient ?? getBurpClient();
  // Extract proxy host/port from proxyBaseUrl
  const proxyUrl = new URL(client.proxyBaseUrl);
  const burpProxyHost = proxyUrl.hostname;
  const burpProxyPort = parseInt(proxyUrl.port || "8080", 10);

  logger.info(`[Intruder] Attack ${attack.attack_id}: ${combos.length} requests, type=${attack.attack_type}`);

  const tasks = combos.map((combo, idx) => async (): Promise<IntruderResult> => {
    if (attack.stop_requested) {
      attack.completed_requests++;
      const result: IntruderResult = {
        index: idx,
        payloads: combo.payloads,
        position_index: combo.positionIndex,
        status_code: 0,
        response_length: 0,
        response_time_ms: 0,
        response_headers: {},
        response_body: "",
        error: "Attack stopped",
      };
      attack.results.push(result);
      return result;
    }

    const rawRequest = buildRequest(attack.request_template, combo.payloads);
    let result: IntruderResult;

    try {
      let raw: RawResponse;
      if (attack.use_https) {
        raw = await sendRawRequest(
          attack.host,
          attack.port,
          true,
          rawRequest,
          attack.request_timeout_ms,
          burpProxyHost,
          burpProxyPort,
          client.proxyTlsRejectUnauthorized
        );
      } else {
        raw = await sendDirectHttpRequest(
          attack.host,
          attack.port,
          rawRequest,
          attack.request_timeout_ms,
          burpProxyHost,
          burpProxyPort
        );
      }

      result = {
        index: idx,
        payloads: combo.payloads,
        position_index: combo.positionIndex,
        status_code: raw.statusCode,
        response_length: raw.body.length,
        response_time_ms: raw.responseTimeMs,
        response_headers: raw.headers,
        response_body: raw.body.slice(0, 5000),
      };
    } catch (err) {
      result = {
        index: idx,
        payloads: combo.payloads,
        position_index: combo.positionIndex,
        status_code: 0,
        response_length: 0,
        response_time_ms: 0,
        response_headers: {},
        response_body: "",
        error: err instanceof Error ? err.message : String(err),
      };
    }

    attack.completed_requests++;
    attack.results.push(result);
    return result;
  });

  try {
    await runWithConcurrency(tasks, attack.max_concurrent, () => attack.stop_requested);
  } catch (err) {
    logger.error(`[Intruder] Attack ${attack.attack_id} error: ${String(err)}`);
    attack.status = "error";
    attack.finished_at = new Date().toISOString();
    return;
  }

  attack.status = attack.stop_requested ? "stopped" : "finished";
  attack.finished_at = new Date().toISOString();
  logger.info(`[Intruder] Attack ${attack.attack_id} ${attack.status} – ${attack.completed_requests}/${attack.total_requests} requests`);
}

// ── MCP Tool definitions ─────────────────────────────────────

export const INTRUDER_TOOLS = [
  {
    name: "intruder_start_attack",
    description:
      "Launch a Burp Intruder-style attack. Sends HTTP requests through the Burp proxy with payloads substituted into §marker§ positions in the request template.",
    inputSchema: {
      type: "object",
      properties: {
        host: { type: "string", description: "Target host" },
        port: { type: "number", description: "Target port" },
        use_https: { type: "boolean", description: "Whether to use HTTPS" },
        request_template: {
          type: "string",
          description: "Raw HTTP request with §marker§ positions for payload injection",
        },
        attack_type: {
          type: "string",
          enum: ["sniper", "battering_ram", "pitchfork", "cluster_bomb"],
          description:
            "Attack type: sniper (1 position, all payloads), battering_ram (all positions same payload), pitchfork (lockstep), cluster_bomb (cartesian product)",
        },
        payload_sets: {
          type: "array",
          items: { type: "array", items: { type: "string" } },
          description: "Array of payload lists, one per position (sniper/battering_ram use payload_sets[0])",
        },
        max_concurrent: {
          type: "number",
          description: "Max concurrent requests (default: 10)",
        },
        request_timeout_ms: {
          type: "number",
          description: "Per-request timeout in ms (default: 10000)",
        },
      },
      required: ["host", "port", "use_https", "request_template", "attack_type", "payload_sets"],
    },
    handler: async (
      params: {
        host: string;
        port: number;
        use_https: boolean;
        request_template: string;
        attack_type: AttackType;
        payload_sets: string[][];
        max_concurrent?: number;
        request_timeout_ms?: number;
      },
      burpClient?: BurpClient
    ) => {
      const client = burpClient ?? getBurpClient();
      const maxConcurrent = params.max_concurrent ?? 10;
      if (!Number.isInteger(maxConcurrent) || maxConcurrent < 1) {
        throw new Error(
          `Invalid max_concurrent (${String(params.max_concurrent)}): must be a positive integer >= 1.`
        );
      }
      const timeoutMs = params.request_timeout_ms ?? 10_000;
      if (!Number.isFinite(timeoutMs) || timeoutMs < 1) {
        throw new Error(
          `Invalid request_timeout_ms (${String(params.request_timeout_ms)}): must be a positive number.`
        );
      }
      const { baselines } = parseMarkedTemplate(params.request_template);
      if (baselines.length === 0) {
        throw new Error(
          "Invalid request_template: no §marker§ insertion points found."
        );
      }

      const attack_id = randomUUID();
      const record: AttackRecord = {
        attack_id,
        attack_type: params.attack_type,
        host: params.host,
        port: params.port,
        use_https: params.use_https,
        request_template: params.request_template,
        payload_sets: params.payload_sets,
        max_concurrent: maxConcurrent,
        request_timeout_ms: timeoutMs,
        status: "pending",
        total_requests: 0,
        completed_requests: 0,
        results: [],
        created_at: new Date().toISOString(),
        stop_requested: false,
      };

      attacks.set(attack_id, record);

      // Run asynchronously – don't await
      void runAttack(record, client).catch((err) => {
        record.status = "error";
        record.finished_at = new Date().toISOString();
        logger.error(`[Intruder] Unhandled error in attack ${attack_id}: ${String(err)}`);
      });

      return {
        attack_id,
        attack_type: params.attack_type,
        message: `Attack started. Use intruder_get_attack_status to monitor progress.`,
      };
    },
  },

  {
    name: "intruder_get_attack_status",
    description: "Get the current status and progress of an Intruder attack.",
    inputSchema: {
      type: "object",
      properties: {
        attack_id: { type: "string", description: "Attack ID returned by intruder_start_attack" },
      },
      required: ["attack_id"],
    },
    handler: async (params: { attack_id: string }, _burpClient?: BurpClient) => {
      const attack = attacks.get(params.attack_id);
      if (!attack) {
        throw new Error(`Attack not found: ${params.attack_id}`);
      }
      return {
        attack_id: attack.attack_id,
        attack_type: attack.attack_type,
        status: attack.status,
        total_requests: attack.total_requests,
        completed_requests: attack.completed_requests,
        results_count: attack.results.length,
        created_at: attack.created_at,
        started_at: attack.started_at,
        finished_at: attack.finished_at,
      };
    },
  },

  {
    name: "intruder_get_results",
    description:
      "Retrieve results from an Intruder attack with optional filtering and pagination.",
    inputSchema: {
      type: "object",
      properties: {
        attack_id: { type: "string", description: "Attack ID" },
        limit: { type: "number", description: "Max results to return (default: 100)" },
        offset: { type: "number", description: "Pagination offset (default: 0)" },
        filter_status_codes: {
          type: "array",
          items: { type: "number" },
          description: "Only return results with these HTTP status codes",
        },
        min_response_length: {
          type: "number",
          description: "Filter results with response body >= this length",
        },
        max_response_length: {
          type: "number",
          description: "Filter results with response body <= this length",
        },
      },
      required: ["attack_id"],
    },
    handler: async (
      params: {
        attack_id: string;
        limit?: number;
        offset?: number;
        filter_status_codes?: number[];
        min_response_length?: number;
        max_response_length?: number;
      },
      _burpClient?: BurpClient
    ) => {
      const attack = attacks.get(params.attack_id);
      if (!attack) {
        throw new Error(`Attack not found: ${params.attack_id}`);
      }

      let results = [...attack.results];

      if (params.filter_status_codes?.length) {
        const allowed = new Set(params.filter_status_codes);
        results = results.filter((r) => allowed.has(r.status_code));
      }
      if (params.min_response_length !== undefined) {
        results = results.filter((r) => r.response_length >= params.min_response_length!);
      }
      if (params.max_response_length !== undefined) {
        results = results.filter((r) => r.response_length <= params.max_response_length!);
      }

      const offset = params.offset ?? 0;
      const limit = params.limit ?? 100;
      const page = results.slice(offset, offset + limit);

      return {
        attack_id: attack.attack_id,
        total_filtered: results.length,
        offset,
        limit,
        results: page,
      };
    },
  },

  {
    name: "intruder_stop_attack",
    description: "Stop a running Intruder attack. Already-sent requests will complete.",
    inputSchema: {
      type: "object",
      properties: {
        attack_id: { type: "string", description: "Attack ID to stop" },
      },
      required: ["attack_id"],
    },
    handler: async (params: { attack_id: string }, _burpClient?: BurpClient) => {
      const attack = attacks.get(params.attack_id);
      if (!attack) {
        throw new Error(`Attack not found: ${params.attack_id}`);
      }
      if (attack.status !== "running" && attack.status !== "pending") {
        return { attack_id: attack.attack_id, message: `Attack is already ${attack.status}` };
      }
      attack.stop_requested = true;
      return { attack_id: attack.attack_id, message: "Stop requested. In-flight requests will complete." };
    },
  },

  {
    name: "intruder_list_attacks",
    description: "List all Intruder attacks (running and finished).",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
    handler: async (_params?: Record<string, never>, _burpClient?: BurpClient) => {
      const list = Array.from(attacks.values()).map((a) => ({
        attack_id: a.attack_id,
        attack_type: a.attack_type,
        host: a.host,
        port: a.port,
        status: a.status,
        total_requests: a.total_requests,
        completed_requests: a.completed_requests,
        results_count: a.results.length,
        created_at: a.created_at,
        started_at: a.started_at,
        finished_at: a.finished_at,
      }));
      return { attacks: list, count: list.length };
    },
  },

  {
    name: "intruder_clear_attack",
    description: "Remove an attack record from memory (frees resources).",
    inputSchema: {
      type: "object",
      properties: {
        attack_id: { type: "string", description: "Attack ID to remove" },
      },
      required: ["attack_id"],
    },
    handler: async (params: { attack_id: string }, _burpClient?: BurpClient) => {
      const attack = attacks.get(params.attack_id);
      if (!attack) {
        throw new Error(`Attack not found: ${params.attack_id}`);
      }
      if (attack.status === "running") {
        attack.stop_requested = true;
      }
      attacks.delete(params.attack_id);
      return { attack_id: params.attack_id, message: "Attack cleared from memory." };
    },
  },
];
