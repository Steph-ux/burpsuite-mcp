// ── Log levels ───────────────────────────────────────────────

export type LogLevel = "debug" | "info" | "warn" | "error";

const LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

const COLORS: Record<LogLevel, string> = {
  debug: "\x1b[36m", // cyan
  info: "\x1b[32m",  // green
  warn: "\x1b[33m",  // yellow
  error: "\x1b[31m", // red
};

const RESET = "\x1b[0m";

// ── Logger class ─────────────────────────────────────────────

class Logger {
  private minLevel: number;
  private useColors: boolean;

  constructor(minLevel: LogLevel = "info", useColors = true) {
    this.minLevel = LEVELS[minLevel];
    this.useColors = useColors;
  }

  setLevel(level: LogLevel): void {
    this.minLevel = LEVELS[level];
  }

  private format(level: LogLevel, message: string, meta?: unknown): string {
    const ts = new Date().toISOString();
    const tag = level.toUpperCase().padEnd(5);
    const metaStr = meta !== undefined ? ` ${JSON.stringify(meta)}` : "";

    if (this.useColors) {
      const color = COLORS[level];
      return `${RESET}\x1b[90m${ts}${RESET} ${color}${tag}${RESET} ${message}${metaStr}`;
    }

    return `${ts} ${tag} ${message}${metaStr}`;
  }

  private write(level: LogLevel, message: string, meta?: unknown): void {
    if (LEVELS[level] < this.minLevel) return;

    const line = this.format(level, message, meta);
    // MCP stdio uses stdout strictly for JSON-RPC; all logs must go to stderr.
    process.stderr.write(line + "\n");
  }

  debug(message: string, meta?: unknown): void {
    this.write("debug", message, meta);
  }

  info(message: string, meta?: unknown): void {
    this.write("info", message, meta);
  }

  warn(message: string, meta?: unknown): void {
    this.write("warn", message, meta);
  }

  error(message: string, meta?: unknown): void {
    this.write("error", message, meta);
  }
}

// ── Singleton ────────────────────────────────────────────────

const rawLevel = process.env["LOG_LEVEL"]?.toLowerCase() as LogLevel | undefined;
const minLevel: LogLevel = rawLevel && rawLevel in LEVELS ? rawLevel : "info";
export const logger = new Logger(minLevel, Boolean(process.stderr.isTTY));

export { Logger };
