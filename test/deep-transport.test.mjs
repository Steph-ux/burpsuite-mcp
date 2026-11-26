import { it } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import http from "node:http";
import { once } from "node:events";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

it("deep: isolated HTTP transport error paths and MCP contracts", async t => {
  const probe = http.createServer();
  probe.listen(0, "127.0.0.1");
  await once(probe, "listening");
  const port = probe.address().port;
  await new Promise(resolve => probe.close(resolve));
  const proc = spawn(process.execPath, [
    "dist/index.js", "--http", "--host", "127.0.0.1", "--port", String(port),
    "--token", "deep-test-disposable-token",
  ], {
    env: {
      ...process.env, BURP_HOST: "127.0.0.1", BURP_PORT: "1", BURP_API_PORT: "1",
      BURP_API_KEY: "", BURP_EDITION: "community",
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  t.after(() => {
    if (!proc.killed) proc.kill("SIGTERM");
  });
  await new Promise((resolve, reject) => {
    let log = "";
    const timer = setTimeout(() => reject(new Error("HTTP fixture startup timed out")), 5000);
    proc.once("error", err => { clearTimeout(timer); reject(err); });
    proc.once("exit", code => { clearTimeout(timer); reject(new Error(`HTTP fixture exited ${code}: ${log}`)); });
    proc.stderr.on("data", chunk => {
      log += chunk;
      if (log.includes("Streamable HTTP server ready")) {
        clearTimeout(timer);
        resolve();
      }
    });
  });
  const url = `http://127.0.0.1:${port}/mcp`;
  const headers = {
    Authorization: "Bearer deep-test-disposable-token",
    "Content-Type": "application/json", Accept: "application/json, text/event-stream",
  };
  const request = (options = {}) => fetch(url, {
    method: "POST", headers, body: "{}", signal: AbortSignal.timeout(3000), ...options,
  });

  await t.test("missing and wrong tokens reject before JSON parsing", async () => {
    for (const auth of [undefined, "Bearer wrong", "Basic irrelevant"]) {
      const h = { ...headers };
      if (auth) h.Authorization = auth;
      else delete h.Authorization;
      const res = await request({ headers: h, body: "{bad-json" });
      assert.equal(res.status, 401);
    }
  });
  await t.test("authenticated malformed JSON is a parse error", async () => {
    const res = await request({ body: "{bad-json" });
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error.code, -32700);
  });
  await t.test("non-initialize request requires session id", async () => {
    const res = await request({
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
    });
    assert.equal(res.status, 400);
  });
  await t.test("unknown session ids return 404", async () => {
    const res = await request({ headers: { ...headers, "mcp-session-id": "does-not-exist" } });
    assert.equal(res.status, 404);
  });
  await t.test("unsupported HTTP method returns 405", async () => {
    const res = await request({ method: "PUT" });
    assert.equal(res.status, 405);
  });

  const transport = new StreamableHTTPClientTransport(new URL(url), {
    requestInit: { headers: { Authorization: headers.Authorization } },
  });
  const client = new Client({ name: "deep-contract", version: "1.0" }, { capabilities: {} });
  t.after(async () => {
    await transport.terminateSession().catch(() => {});
    await client.close();
  });
  await client.connect(transport);
  await t.test("all 78 tools have unique names and object schemas", async () => {
    const { tools } = await client.listTools();
    assert.equal(tools.length, 78);
    assert.equal(new Set(tools.map(tool => tool.name)).size, 78);
    assert.ok(tools.every(tool => tool.inputSchema.type === "object"));
  });
  await t.test("unknown tool returns JSON-RPC error", async () => {
    await assert.rejects(client.callTool({ name: "deep_nonexistent", arguments: {} }), /Unknown tool/);
  });
  await t.test("required Repeater request name is enforced at MCP boundary", async () => {
    const result = await client.callTool({
      name: "repeater_save_request",
      arguments: {
        host: "127.0.0.1", port: 80, use_https: false,
        method: "GET", path: "/", headers: {},
      },
    });
    assert.equal(result.isError, true, JSON.stringify(result));
  });
});
