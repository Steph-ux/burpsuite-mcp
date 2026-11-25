import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from "axios";
import { ApiKeyMode, BurpConfig, BurpEdition } from "../types/index.js";
import { logger } from "./logger.js";

const REST_AVAILABILITY_TTL_MS = 5_000;

export class BurpClient {
  private http: AxiosInstance;
  private config: BurpConfig;
  private resolvedKeyMode: Exclude<ApiKeyMode, "auto"> | null = null;
  private restAvailabilityCache: { available: boolean; checkedAt: number } | null = null;

  constructor(config: BurpConfig) {
    this.config = {
      ...config,
      apiKeyMode: config.apiKeyMode ?? "auto",
      edition: config.edition ?? "auto",
    };

    this.http = axios.create({
      baseURL: `http://${config.host}:${config.apiPort}`,
      headers: {
        "Content-Type": "application/json",
      },
      timeout: 30_000,
    });

    this.http.interceptors.request.use((req) => {
      logger.debug(`→ ${req.method?.toUpperCase()} ${req.url}`);
      return req;
    });

    this.http.interceptors.response.use(
      (res) => {
        logger.debug(`← ${res.status} ${res.config.url}`);
        return res;
      },
      (err) => {
        const status = err.response?.status ?? "network error";
        const url = err.config?.url ?? "unknown";
        logger.debug(`← ${status} ${url}: ${err.message}`);
        return Promise.reject(this.normalizeError(err));
      }
    );
  }

  // ── API Key mode resolution (no key, Pro path key, or header key) ──

  private getEffectiveKeyMode(): Exclude<ApiKeyMode, "auto"> {
    if (this.config.apiKeyMode === "header") return "header";
    if (this.config.apiKeyMode === "path") return "path";
    // In "auto" mode, PortSwigger's native Burp Pro REST API uses URL-path keys
    return this.resolvedKeyMode ?? "path";
  }

  private buildPath(path: string, mode: Exclude<ApiKeyMode, "auto">): string {
    const cleanPath = path.startsWith("/") ? path : `/${path}`;
    if (!this.config.apiKey || mode !== "path") {
      return cleanPath;
    }
    // Official Burp Pro REST API mounts endpoints under /<API_KEY>/v0.1/...
    if (cleanPath.startsWith("/v0.1")) {
      return `/${encodeURIComponent(this.config.apiKey)}${cleanPath}`;
    }
    return cleanPath;
  }

  private buildRequestConfig(
    mode: Exclude<ApiKeyMode, "auto">,
    config?: AxiosRequestConfig
  ): AxiosRequestConfig {
    if (!this.config.apiKey || mode === "path") {
      return config ?? {};
    }
    // Header auth for third-party REST API extensions (burp-rest-api, custom bridges)
    return {
      ...config,
      headers: {
        ...(config?.headers ?? {}),
        Authorization: this.config.apiKey,
        "X-Burp-Api-Token": this.config.apiKey,
        "API-KEY": this.config.apiKey,
      },
    };
  }

  private isAuthOrPathMismatch(err: unknown): boolean {
    if (!(err instanceof Error)) return false;
    return /^BurpClient \[(401|403|404)\]/.test(err.message);
  }

  private async requestWithKeyFallback<T>(
    exec: (mode: Exclude<ApiKeyMode, "auto">) => Promise<AxiosResponse<T>>
  ): Promise<AxiosResponse<T>> {
    const primaryMode = this.getEffectiveKeyMode();
    try {
      const res = await exec(primaryMode);
      if (this.config.apiKey && this.config.apiKeyMode === "auto") {
        this.resolvedKeyMode = primaryMode;
      }
      this.restAvailabilityCache = { available: true, checkedAt: Date.now() };
      return res;
    } catch (err) {
      if (
        this.config.apiKey &&
        this.config.apiKeyMode === "auto" &&
        this.resolvedKeyMode === null &&
        this.isAuthOrPathMismatch(err)
      ) {
        const secondaryMode = primaryMode === "path" ? "header" : "path";
        logger.debug(`API key mode "${primaryMode}" returned auth/404, retrying "${secondaryMode}"`);
        const res = await exec(secondaryMode);
        this.resolvedKeyMode = secondaryMode;
        this.restAvailabilityCache = { available: true, checkedAt: Date.now() };
        return res;
      }
      if (BurpClient.isConnectionError(err)) {
        this.restAvailabilityCache = { available: false, checkedAt: Date.now() };
      }
      throw err;
    }
  }

  // ── Core request helpers ─────────────────────────────────

  async get<T = unknown>(
    path: string,
    config?: AxiosRequestConfig
  ): Promise<T> {
    const res = await this.requestWithKeyFallback<T>((mode) =>
      this.http.get<T>(this.buildPath(path, mode), this.buildRequestConfig(mode, config))
    );
    return res.data;
  }

  async post<T = unknown>(
    path: string,
    data?: unknown,
    config?: AxiosRequestConfig
  ): Promise<T> {
    const res = await this.postRaw<T>(path, data, config);
    return res.data;
  }

  /** Like post() but returns the full AxiosResponse (headers, status, data). */
  async postRaw<T = unknown>(
    path: string,
    data?: unknown,
    config?: AxiosRequestConfig
  ): Promise<AxiosResponse<T>> {
    return this.requestWithKeyFallback<T>((mode) =>
      this.http.post<T>(this.buildPath(path, mode), data, this.buildRequestConfig(mode, config))
    );
  }

  async put<T = unknown>(
    path: string,
    data?: unknown,
    config?: AxiosRequestConfig
  ): Promise<T> {
    const res = await this.requestWithKeyFallback<T>((mode) =>
      this.http.put<T>(this.buildPath(path, mode), data, this.buildRequestConfig(mode, config))
    );
    return res.data;
  }

  async delete<T = unknown>(
    path: string,
    config?: AxiosRequestConfig
  ): Promise<T> {
    const res = await this.requestWithKeyFallback<T>((mode) =>
      this.http.delete<T>(this.buildPath(path, mode), this.buildRequestConfig(mode, config))
    );
    return res.data;
  }

  // ── Edition & REST API availability ──────────────────────

  static isConnectionError(err: unknown): boolean {
    if (!(err instanceof Error)) return false;
    return /ECONNREFUSED|ECONNRESET|ETIMEDOUT|ENOTFOUND|EHOSTUNREACH|BurpClient \[net\]/.test(
      err.message
    );
  }

  static isCommunityBridgeUnsupported(err: unknown): boolean {
    if (!(err instanceof Error)) return false;
    return /Endpoint not supported by Community Bridge/i.test(err.message);
  }

  async isRestApiAvailable(forceRefresh = false): Promise<boolean> {
    const now = Date.now();
    if (
      !forceRefresh &&
      this.restAvailabilityCache &&
      now - this.restAvailabilityCache.checkedAt < REST_AVAILABILITY_TTL_MS
    ) {
      return this.restAvailabilityCache.available;
    }

    const probeCfg: AxiosRequestConfig = { timeout: 1_500 };
    for (const probePath of ["/v0.1/", "/v0.1/burp/version", "/burp/versions"]) {
      try {
        await this.get(probePath, probeCfg);
        this.restAvailabilityCache = { available: true, checkedAt: Date.now() };
        return true;
      } catch (err) {
        if (!BurpClient.isConnectionError(err)) {
          // Non-connection HTTP responses (e.g. 401 invalid API key, 404 on one probe route)
          // indicate the REST daemon is actually reachable on apiPort.
          this.restAvailabilityCache = { available: true, checkedAt: Date.now() };
          return true;
        }
        this.restAvailabilityCache = { available: false, checkedAt: Date.now() };
        return false;
      }
    }

    this.restAvailabilityCache = { available: false, checkedAt: Date.now() };
    return false;
  }

  /**
   * Executes a Burp REST API call when available (Burp Pro or Community + bridge).
   * In "auto" or "community" edition, transparently falls back to `fallbackFn`
   * when the REST API port (:1337) is unreachable (standard Burp Community).
   */
  async withRestFallback<T, F = T>(
    apiFn: () => Promise<T>,
    fallbackFn: () => F | Promise<F>
  ): Promise<T | F> {
    if (this.config.edition === "community") {
      // Even in community mode, allow a quick check if REST bridge is running unless unavailable
      const available = await this.isRestApiAvailable();
      if (!available) {
        return fallbackFn();
      }
    }

    if (this.config.edition === "auto") {
      const available = await this.isRestApiAvailable();
      if (!available) {
        return fallbackFn();
      }
    }

    try {
      return await apiFn();
    } catch (err) {
      if (
        this.config.edition !== "pro" &&
        (BurpClient.isConnectionError(err) ||
          BurpClient.isCommunityBridgeUnsupported(err))
      ) {
        if (BurpClient.isConnectionError(err)) {
          this.restAvailabilityCache = { available: false, checkedAt: Date.now() };
        }
        return fallbackFn();
      }
      throw err;
    }
  }

  async isReachable(): Promise<boolean> {
    return this.isRestApiAvailable(true);
  }

  // ── Config accessors ─────────────────────────────────────

  get proxyBaseUrl(): string {
    return `http://${this.config.host}:${this.config.port}`;
  }

  get apiBaseUrl(): string {
    return `http://${this.config.host}:${this.config.apiPort}`;
  }

  get hasApiKey(): boolean {
    return Boolean(this.config.apiKey);
  }

  get edition(): BurpEdition {
    return this.config.edition ?? "auto";
  }

  get proxyTlsRejectUnauthorized(): boolean {
    return this.config.proxyTlsRejectUnauthorized ?? false;
  }

  // ── Error normalisation ──────────────────────────────────

  private normalizeError(err: unknown): Error {
    if (axios.isAxiosError(err)) {
      const status = err.response?.status;
      const detail =
        err.response?.data != null
          ? JSON.stringify(err.response.data)
          : err.message;
      const code = err.code ? ` (${err.code})` : "";
      return new Error(`BurpClient [${status ?? "net"}]${code}: ${detail}`);
    }
    if (err instanceof Error) return err;
    return new Error(String(err));
  }
}

// ── Singleton factory ────────────────────────────────────────

let _client: BurpClient | null = null;

export function createBurpClient(config: BurpConfig): BurpClient {
  _client = new BurpClient(config);
  return _client;
}

export function getBurpClient(): BurpClient {
  if (!_client) {
    throw new Error(
      "BurpClient not initialised – call createBurpClient() first."
    );
  }
  return _client;
}
