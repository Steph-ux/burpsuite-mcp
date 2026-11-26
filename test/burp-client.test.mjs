import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { BurpClient } from "../dist/utils/burp-client.js";

const servers = [];

function listen(server) {
  servers.push(server);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });
}

afterEach(async () => {
  while (servers.length > 0) {
    const srv = servers.pop();
    await new Promise((resolve) => srv.close(() => resolve()));
  }
});

describe("BurpClient authentication & fallback modes", () => {
  it("connects without API key and sends no auth headers or path prefix", async () => {
    let seenUrl = "";
    let seenAuth;
    let seenToken;
    const srv = http.createServer((req, res) => {
      seenUrl = req.url;
      seenAuth = req.headers["authorization"];
      seenToken = req.headers["x-burp-api-token"];
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ edition: "Pro-NoKey", ok: true }));
    });
    const apiPort = await listen(srv);

    const client = new BurpClient({
      host: "127.0.0.1",
      port: 8080,
      apiPort,
      apiKey: "",
    });
    const res = await client.get("/v0.1/burp/version");
    assert.equal(res.edition, "Pro-NoKey");
    assert.equal(seenUrl, "/v0.1/burp/version");
    assert.equal(seenAuth, undefined);
    assert.equal(seenToken, undefined);
  });

  it("uses native Burp Pro URL-path API key mode and preserves headers via postRaw", async () => {
    const srv = http.createServer((req, res) => {
      if (!req.url.startsWith("/pro-key-123/v0.1/")) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "API key required in URL path" }));
        return;
      }
      if (req.method === "POST" && req.url === "/pro-key-123/v0.1/scan") {
        res.writeHead(201, {
          "Content-Type": "application/json",
          Location: "/pro-key-123/v0.1/scan/task-77",
        });
        res.end(JSON.stringify({ task_id: "task-77" }));
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ edition: "Professional", path: req.url }));
    });
    const apiPort = await listen(srv);

    const client = new BurpClient({
      host: "127.0.0.1",
      port: 8080,
      apiPort,
      apiKey: "pro-key-123",
      apiKeyMode: "auto",
    });

    const ver = await client.get("/v0.1/burp/version");
    assert.equal(ver.edition, "Professional");

    const scanRes = await client.postRaw("/v0.1/scan", { urls: ["https://example.com"] });
    assert.equal(scanRes.status, 201);
    assert.equal(scanRes.headers.location, "/pro-key-123/v0.1/scan/task-77");
  });

  it("auto-falls back from path mode to header mode on 404/401", async () => {
    let headerHits = 0;
    const srv = http.createServer((req, res) => {
      if (req.url.startsWith("/hdr-key-456/")) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Not found" }));
        return;
      }
      if (req.headers["x-burp-api-token"] !== "hdr-key-456") {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Missing header" }));
        return;
      }
      headerHits++;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, mode: "header" }));
    });
    const apiPort = await listen(srv);

    const client = new BurpClient({
      host: "127.0.0.1",
      port: 8080,
      apiPort,
      apiKey: "hdr-key-456",
      apiKeyMode: "auto",
    });

    const r1 = await client.get("/v0.1/burp/version");
    const r2 = await client.get("/v0.1/extensions");
    assert.equal(r1.mode, "header");
    assert.equal(r2.mode, "header");
    assert.equal(headerHits, 2);
  });

  it("handles withRestFallback in auto vs pro mode and Community Bridge 404", async () => {
    // Closed port
    const probe = http.createServer();
    const closedPort = await listen(probe);
    await new Promise((r) => probe.close(r));
    servers.pop();

    const autoClient = new BurpClient({
      host: "127.0.0.1",
      port: 8080,
      apiPort: closedPort,
      apiKey: "",
      edition: "auto",
    });

    const fallbackResult = await autoClient.withRestFallback(
      () => autoClient.get("/v0.1/burp/version"),
      () => ({ mode: "community-local" })
    );
    assert.equal(fallbackResult.mode, "community-local");

    const proClient = new BurpClient({
      host: "127.0.0.1",
      port: 8080,
      apiPort: closedPort,
      apiKey: "",
      edition: "pro",
    });

    await assert.rejects(
      proClient.withRestFallback(
        () => proClient.get("/v0.1/burp/version"),
        () => ({ mode: "should-not-run" })
      ),
      /BurpClient/
    );

    // Community Bridge 404 unsupported endpoint triggers fallback
    const bridgeSrv = http.createServer((req, res) => {
      if (req.url === "/v0.1/" || req.url === "/v0.1/burp/version") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ bridge: true }));
        return;
      }
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Endpoint not supported by Community Bridge" }));
    });
    const bridgePort = await listen(bridgeSrv);

    const bridgeClient = new BurpClient({
      host: "127.0.0.1",
      port: 8080,
      apiPort: bridgePort,
      apiKey: "",
      edition: "auto",
    });

    const bridgeFallback = await bridgeClient.withRestFallback(
      () => bridgeClient.get("/v0.1/issue-definitions"),
      () => ({ mode: "community-bridge-passive" })
    );
    assert.equal(bridgeFallback.mode, "community-bridge-passive");
  });
});
