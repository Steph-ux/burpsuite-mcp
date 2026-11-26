// ============================================================
// BurpSuite MCP – Decoder Module
// Mirrors BurpSuite's Decoder tab (encode, decode, smart auto-detect,
// JWT inspection, gzip+base64, and cryptographic hashes).
// ============================================================

import { createHash } from "node:crypto";
import { gunzipSync, gzipSync } from "node:zlib";
import type { BurpClient } from "../utils/burp-client.js";

export type EncodeFormat =
  | "base64"
  | "base64url"
  | "url"
  | "url_all"
  | "html"
  | "hex"
  | "unicode_escape"
  | "gzip_base64";

export type DecodeFormat = EncodeFormat | "jwt" | "auto";
export type HashAlgorithm = "md5" | "sha1" | "sha256" | "sha512";

const HTML_ENCODE_MAP: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

const HTML_NAMED_DECODE: Record<string, string> = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
  nbsp: "\u00a0",
};

function encodeBase64Url(buf: Buffer): string {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function decodeBase64Url(input: string): Buffer {
  const normalized = input.trim().replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (normalized.length % 4)) % 4;
  return Buffer.from(normalized + "=".repeat(padLen), "base64");
}

function encodeValue(input: string, format: EncodeFormat): string {
  switch (format) {
    case "base64":
      return Buffer.from(input, "utf8").toString("base64");
    case "base64url":
      return encodeBase64Url(Buffer.from(input, "utf8"));
    case "url":
      return encodeURIComponent(input);
    case "url_all":
      return Array.from(Buffer.from(input, "utf8"))
        .map((b) => `%${b.toString(16).padStart(2, "0")}`)
        .join("");
    case "html":
      return input.replace(/[&<>"']/g, (ch) => HTML_ENCODE_MAP[ch] ?? ch);
    case "hex":
      return Buffer.from(input, "utf8").toString("hex");
    case "unicode_escape":
      return Array.from(input)
        .map((ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, "0")}`)
        .join("");
    case "gzip_base64":
      return gzipSync(Buffer.from(input, "utf8")).toString("base64");
  }
}

function decodeHtmlEntities(input: string): string {
  return input.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z]+);/g, (full, entity: string) => {
    if (entity.startsWith("#x") || entity.startsWith("#X")) {
      const cp = parseInt(entity.slice(2), 16);
      return Number.isFinite(cp) ? String.fromCodePoint(cp) : full;
    }
    if (entity.startsWith("#")) {
      const cp = parseInt(entity.slice(1), 10);
      return Number.isFinite(cp) ? String.fromCodePoint(cp) : full;
    }
    return HTML_NAMED_DECODE[entity.toLowerCase()] ?? full;
  });
}

function decodeJwt(token: string): Record<string, unknown> {
  const parts = token.trim().split(".");
  if (parts.length < 2 || parts.length > 3) {
    throw new Error("Invalid JWT format: expected 2 or 3 dot-separated segments.");
  }
  const headerRaw = decodeBase64Url(parts[0]!).toString("utf8");
  const payloadRaw = decodeBase64Url(parts[1]!).toString("utf8");

  let header: unknown;
  let payload: unknown;
  try {
    header = JSON.parse(headerRaw);
    payload = JSON.parse(payloadRaw);
  } catch {
    throw new Error("JWT header or payload is not valid JSON.");
  }

  const exp =
    payload && typeof payload === "object" && typeof (payload as Record<string, unknown>).exp === "number"
      ? new Date(((payload as Record<string, unknown>).exp as number) * 1000).toISOString()
      : undefined;

  return {
    header,
    payload,
    signature_present: Boolean(parts[2]),
    ...(exp ? { expires_at: exp } : {}),
  };
}

function detectFormat(input: string): Exclude<DecodeFormat, "auto" | "url_all"> {
  const trimmed = input.trim();
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(trimmed)) {
    try {
      decodeJwt(trimmed);
      return "jwt";
    } catch {
      /* not a valid JWT */
    }
  }
  if (/^H4sI[A-Za-z0-9+/=]+$/.test(trimmed)) return "gzip_base64";
  if (/%[0-9a-fA-F]{2}/.test(trimmed)) return "url";
  if (/\\u[0-9a-fA-F]{4}/.test(trimmed)) return "unicode_escape";
  if (/&(?:#x[0-9a-fA-F]+|#[0-9]+|amp|lt|gt|quot|apos|nbsp);/i.test(trimmed)) return "html";
  const cleanedHex = trimmed.replace(/(?:0x|\\x|\s+)/gi, "");
  if (cleanedHex.length >= 4 && cleanedHex.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(cleanedHex)) {
    return "hex";
  }
  if (/^[A-Za-z0-9_-]{8,}$/.test(trimmed) && (trimmed.includes("-") || trimmed.includes("_"))) {
    return "base64url";
  }
  return "base64";
}

function decodeValue(
  input: string,
  format: DecodeFormat
): { detected_format: string; output: unknown } {
  const effective = format === "auto" ? detectFormat(input) : format;

  switch (effective) {
    case "jwt":
      return { detected_format: "jwt", output: decodeJwt(input) };
    case "base64":
      return {
        detected_format: "base64",
        output: Buffer.from(input.trim(), "base64").toString("utf8"),
      };
    case "base64url":
      return {
        detected_format: "base64url",
        output: decodeBase64Url(input).toString("utf8"),
      };
    case "url":
    case "url_all":
      return {
        detected_format: effective,
        output: decodeURIComponent(input.replace(/\+/g, " ")),
      };
    case "html":
      return { detected_format: "html", output: decodeHtmlEntities(input) };
    case "hex": {
      const clean = input.replace(/(?:0x|\\x|\s+)/gi, "");
      if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
        throw new Error("Invalid hex input.");
      }
      return {
        detected_format: "hex",
        output: Buffer.from(clean, "hex").toString("utf8"),
      };
    }
    case "unicode_escape":
      return {
        detected_format: "unicode_escape",
        output: input.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex: string) =>
          String.fromCharCode(parseInt(hex, 16))
        ),
      };
    case "gzip_base64": {
      const raw = Buffer.from(input.trim(), "base64");
      return {
        detected_format: "gzip_base64",
        output: gunzipSync(raw).toString("utf8"),
      };
    }
  }
}

export const DECODER_TOOLS = [
  {
    name: "decoder_encode",
    description:
      "Encode a string using Burp Decoder formats: base64, base64url, url, url_all (hex-encode every byte), html, hex, unicode_escape, or gzip_base64.",
    inputSchema: {
      type: "object",
      properties: {
        input: { type: "string", description: "Plain text input to encode." },
        format: {
          type: "string",
          enum: [
            "base64",
            "base64url",
            "url",
            "url_all",
            "html",
            "hex",
            "unicode_escape",
            "gzip_base64",
          ],
          description: "Target encoding format.",
        },
      },
      required: ["input", "format"],
    },
    handler: async (
      args: { input: string; format: EncodeFormat },
      _burpClient?: BurpClient
    ) => {
      const output = encodeValue(args.input, args.format);
      return {
        format: args.format,
        input_length: args.input.length,
        output_length: output.length,
        output,
      };
    },
  },
  {
    name: "decoder_decode",
    description:
      "Decode an encoded string (base64, base64url, url, html, hex, unicode_escape, gzip_base64, jwt, or auto-detect).",
    inputSchema: {
      type: "object",
      properties: {
        input: { type: "string", description: "Encoded string or JWT token to decode." },
        format: {
          type: "string",
          enum: [
            "auto",
            "base64",
            "base64url",
            "url",
            "url_all",
            "html",
            "hex",
            "unicode_escape",
            "gzip_base64",
            "jwt",
          ],
          default: "auto",
          description: "Decoding format (default: auto).",
        },
      },
      required: ["input"],
    },
    handler: async (
      args: { input: string; format?: DecodeFormat },
      _burpClient?: BurpClient
    ) => {
      const format = args.format ?? "auto";
      const { detected_format, output } = decodeValue(args.input, format);
      return {
        requested_format: format,
        detected_format,
        output,
      };
    },
  },
  {
    name: "decoder_hash",
    description:
      "Compute a cryptographic hash digest (md5, sha1, sha256, sha512) of an input string.",
    inputSchema: {
      type: "object",
      properties: {
        input: { type: "string", description: "Input text to hash (UTF-8)." },
        algorithm: {
          type: "string",
          enum: ["md5", "sha1", "sha256", "sha512"],
          default: "sha256",
          description: "Hash algorithm (default: sha256).",
        },
      },
      required: ["input"],
    },
    handler: async (
      args: { input: string; algorithm?: HashAlgorithm },
      _burpClient?: BurpClient
    ) => {
      const algorithm = args.algorithm ?? "sha256";
      const digest = createHash(algorithm).update(args.input, "utf8").digest("hex");
      return {
        algorithm,
        input_length: args.input.length,
        digest_hex: digest,
      };
    },
  },
];
