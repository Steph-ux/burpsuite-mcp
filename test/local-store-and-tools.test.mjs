import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { DECODER_TOOLS } from "../dist/modules/decoder.js";
import { COMPARER_TOOLS } from "../dist/modules/comparer.js";
import {
  addLocalMatchReplaceRule,
  addLocalScopeUrl,
  analyzePassiveExchange,
  clearLocalSiteMap,
  deleteLocalMatchReplaceRule,
  excludeLocalScopeUrl,
  getLocalHistory,
  getLocalHistoryItem,
  getLocalScope,
  getLocalSiteMap,
  isLocalUrlInScope,
  listLocalMatchReplaceRules,
  recordLocalExchange,
  setLocalScope,
} from "../dist/utils/local-store.js";

const toolMap = new Map(
  [...DECODER_TOOLS, ...COMPARER_TOOLS].map((t) => [t.name, t])
);

describe("Decoder tools", () => {
  it("encodes and decodes across supported formats including auto-detect and JWT", async () => {
    const encode = toolMap.get("decoder_encode").handler;
    const decode = toolMap.get("decoder_decode").handler;
    const hash = toolMap.get("decoder_hash").handler;

    for (const format of [
      "base64",
      "base64url",
      "url",
      "url_all",
      "html",
      "hex",
      "unicode_escape",
      "gzip_base64",
    ]) {
      const text = '<hello "burp" & 100%?>';
      const enc = await encode({ input: text, format });
      const dec = await decode({ input: enc.output, format });
      assert.equal(dec.output, text, `Roundtrip failed for ${format}`);
    }

    const gzipEnc = await encode({ input: "compress me", format: "gzip_base64" });
    const autoGzip = await decode({ input: gzipEnc.output, format: "auto" });
    assert.equal(autoGzip.detected_format, "gzip_base64");
    assert.equal(autoGzip.output, "compress me");

    const jwt =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MiIsInJvbGUiOiJhdWRpdG9yIn0.sig";
    const decJwt = await decode({ input: jwt, format: "auto" });
    assert.equal(decJwt.detected_format, "jwt");
    assert.equal(decJwt.output.payload.role, "auditor");

    const sha = await hash({ input: "burpsuite-mcp", algorithm: "sha256" });
    assert.equal(sha.digest_hex.length, 64);
    const md5 = await hash({ input: "burpsuite-mcp", algorithm: "md5" });
    assert.equal(md5.digest_hex.length, 32);
  });
});

describe("Comparer tools", () => {
  it("diffs text lines, words, and chars cleanly", async () => {
    const diffText = toolMap.get("comparer_diff_text").handler;

    const same = await diffText({ left: "abc", right: "abc", mode: "lines" });
    assert.equal(same.identical, true);

    const lineDiff = await diffText({
      left: "one\ntwo\nthree",
      right: "one\nTWO\nthree\nfour",
      mode: "lines",
    });
    assert.equal(lineDiff.identical, false);
    assert.equal(lineDiff.removed_count, 1);
    assert.equal(lineDiff.added_count, 2);

    const wordDiff = await diffText({
      left: "hello world",
      right: "hello burp",
      mode: "words",
    });
    assert.equal(wordDiff.added_count, 1);
    assert.equal(wordDiff.removed_count, 1);
  });
});

describe("Local Community store & passive analyzer", () => {
  it("records exchanges, manages scope/rules, and detects passive security issues", () => {
    clearLocalSiteMap();

    const ex = recordLocalExchange({
      source: "repeater",
      proxied: false,
      protocol: "https",
      host: "unit.local",
      port: 443,
      path: "/login",
      request: {
        method: "GET",
        url: "https://unit.local/login",
        headers: {},
      },
      response: {
        statusCode: 200,
        statusMessage: "OK",
        headers: {
          "content-type": "text/html",
          server: "Apache/2.4.57",
          "set-cookie": "sid=abc; Path=/",
          "access-control-allow-origin": "*",
          "access-control-allow-credentials": "true",
        },
        body: '<html><body><form action="http://unit.local/auth" method="POST"></form></body></html>',
        mimeType: "text/html",
        responseTime: 12,
      },
    });

    assert.ok(ex.id >= 1);
    assert.equal(getLocalHistory(10, "unit.local").length, 1);
    assert.equal(getLocalHistoryItem(ex.id)?.host, "unit.local");
    assert.equal(getLocalSiteMap("unit.local").length, 1);

    // Passive analyzer should flag HSTS, CSP, XFO, nosniff, cookie flags, CORS, Server, cleartext form
    const passive = analyzePassiveExchange({
      url: "https://unit.local/login",
      statusCode: 200,
      responseHeaders: ex.response.headers,
      responseBody: ex.response.body,
    });
    const names = new Set(passive.map((p) => p.name));
    assert.ok(names.has("Missing Strict-Transport-Security Header"));
    assert.ok(names.has("Missing Content-Security-Policy Header"));
    assert.ok(names.has("Cookie Without HttpOnly Flag"));
    assert.ok(names.has("Cookie Without Secure Flag on HTTPS"));
    assert.ok(names.has("Permissive Cross-Origin Resource Sharing (CORS)"));
    assert.ok(names.has("Cleartext Form Submission Target"));

    // Scope management
    setLocalScope([], []);
    addLocalScopeUrl("https://unit.local/");
    excludeLocalScopeUrl("https://unit.local/logout");
    assert.equal(getLocalScope().total_included, 1);
    assert.equal(isLocalUrlInScope("https://unit.local/login"), true);
    assert.equal(isLocalUrlInScope("https://unit.local/logout"), false);
    assert.equal(isLocalUrlInScope("https://other.local/"), false);

    // Match & replace rules
    const rule = addLocalMatchReplaceRule({
      rule_type: "request_header",
      match: "X-A: 1",
      replace: "X-A: 2",
      is_simple_match: true,
      enabled: true,
      comment: "test",
    });
    assert.ok(listLocalMatchReplaceRules().some((r) => r.id === rule.id));
    assert.equal(deleteLocalMatchReplaceRule(rule.id), true);

    clearLocalSiteMap("unit.local");
    assert.equal(getLocalSiteMap("unit.local").length, 0);
  });
});
