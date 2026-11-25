// ============================================================
// BurpSuite MCP – Shared Types
// ============================================================

// ── Configuration ────────────────────────────────────────────

export type ApiKeyMode = "auto" | "path" | "header";
export type BurpEdition = "auto" | "community" | "pro";

export interface BurpConfig {
  host: string;
  port: number;
  apiKey: string;
  apiPort: number;
  apiKeyMode?: ApiKeyMode;
  edition?: BurpEdition;
  /** Verify TLS certs when proxying HTTPS through Burp MITM (default: false) */
  proxyTlsRejectUnauthorized?: boolean;
}

// ── HTTP Primitives ──────────────────────────────────────────

export interface HttpRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
  raw?: string;
}

export interface HttpResponse {
  statusCode: number;
  statusMessage: string;
  headers: Record<string, string>;
  body?: string;
  raw?: string;
  mimeType?: string;
  responseTime?: number;
}

// ── Proxy ────────────────────────────────────────────────────

export interface ProxyHistoryItem {
  id: number;
  request: HttpRequest;
  response?: HttpResponse;
  host: string;
  port: number;
  protocol: string;
  timestamp: string;
  highlight?: string;
  comment?: string;
  edited: boolean;
}

// ── Scanner ──────────────────────────────────────────────────

export type ScanStatus =
  | "pending"
  | "crawling"
  | "auditing"
  | "succeeded"
  | "failed"
  | "paused"
  | "cancelled";

export interface ScanIssue {
  serialNumber: string;
  name: string;
  severity: "High" | "Medium" | "Low" | "Information";
  confidence: "Certain" | "Firm" | "Tentative";
  host: string;
  path: string;
  issueBackground?: string;
  remediationBackground?: string;
  issueDetail?: string;
  remediationDetail?: string;
  request?: HttpRequest;
  response?: HttpResponse;
}

export interface ScanTask {
  taskId: string;
  status: ScanStatus;
  urls: string[];
  issueCount: number;
  requestCount: number;
  errorCount: number;
  createdAt: string;
  completedAt?: string;
  issues?: ScanIssue[];
}

// ── Site Map ─────────────────────────────────────────────────

export interface SiteMapNode {
  host: string;
  path: string;
  protocol: string;
  port: number;
  responseCode?: number;
  mimeType?: string;
  request?: HttpRequest;
  response?: HttpResponse;
  children?: SiteMapNode[];
}

export interface ScopeRule {
  enabled: boolean;
  host?: string;
  path?: string;
  protocol?: "http" | "https" | "any";
  port?: string;
  file?: string;
}

// ── Intruder ─────────────────────────────────────────────────

export enum IntruderAttackType {
  Sniper = "sniper",
  BatteringRam = "battering ram",
  Pitchfork = "pitchfork",
  ClusterBomb = "cluster bomb",
}

export interface IntruderPayload {
  position: number;
  type: "simple list" | "runtime file" | "numbers" | "dates" | "brute forcer" | "null payloads" | "username generator" | "custom iterator";
  values?: string[];
  min?: number;
  max?: number;
  step?: number;
}

export interface IntruderAttack {
  attackId?: string;
  request: HttpRequest;
  attackType: IntruderAttackType;
  payloads: IntruderPayload[];
  threadCount?: number;
  status?: "running" | "paused" | "finished" | "stopped";
  resultCount?: number;
}

// ── Spider ───────────────────────────────────────────────────

export interface SpiderTask {
  taskId: string;
  targetUrl: string;
  status: "running" | "paused" | "finished" | "stopped";
  requestCount: number;
  itemCount: number;
  createdAt: string;
  completedAt?: string;
}

export interface SpiderResult {
  url: string;
  method: string;
  statusCode?: number;
  mimeType?: string;
  request?: HttpRequest;
  response?: HttpResponse;
}

// ── Extensions ───────────────────────────────────────────────

export interface BurpExtension {
  id: string;
  name: string;
  description?: string;
  version?: string;
  author?: string;
  loaded: boolean;
  errors?: string[];
  type: "java" | "python" | "ruby";
}

// ── Repeater ─────────────────────────────────────────────────

export interface RepeaterRequest {
  id?: string;
  name?: string;
  request: HttpRequest;
  host: string;
  port: number;
  protocol: string;
}

export interface RepeaterResponse {
  request: RepeaterRequest;
  response: HttpResponse;
  timestamp: string;
}
