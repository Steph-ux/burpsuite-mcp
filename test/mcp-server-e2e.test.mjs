import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const cleanupCallbacks = [];

function listen(server) {
  cleanupCallbacks.push(
    () => new Promise((resolve) => server.close(() => resolve()))
  );
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });
}

async function startStdioMcp(envOverrides) {
  const proc = spawn("./dist/index.js", [], {
    env: { ...process.env, ...envOverrides },
    stdio: ["pipe", "pipe", "pipe"],
  });
  cleanupCallbacks.push(async () => {
    if (!proc.killed) proc.kill();
  });

  let out = "";
  let err = "";
  const pending = new Map();
  let nextId = 1;

  proc.stdout.on("data", (d) => {
    out += d.toString();
    const lines = out.split("\n");
    out = lines.pop() ?? "";
    for (const line of lines) {
      if (!line.trim()) continue;
      const msg = JSON.parse(line);
      if (msg.id !== undefined && pending.has(msg.id)) {
        pending.get(msg.id)(msg);
        pending.delete(msg.id);
      }
    }
  });
  proc.stderr.on("data", (d) => {
    err += d.toString();
  });

  const rpc = (method, params) => {
    const id = nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`Timeout waiting for ${method} (id=${id})`)),
        10_000
      );
      pending.set(id, (msg) => {
        clearTimeout(timer);
        resolve(msg);
      });
      proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  };

  await rpc("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "e2e-test", version: "1.0" },
  });

  return { proc, rpc, getOut: () => out, getErr: () => err };
}

function parseTool(msg) {
  assert.ok(!msg.result?.isError, `MCP tool returned error: ${JSON.stringify(msg)}`);
  return JSON.parse(msg.result.content[0].text);
}

afterEach(async () => {
  while (cleanupCallbacks.length > 0) {
    const fn = cleanupCallbacks.pop();
    await fn();
  }
});

describe("MCP server end-to-end (stdio & Streamable HTTP)", () => {
  it("exposes 66 valid unique tools and runs full Community workflow over stdio", async () => {
    const target = http.createServer((req, res) => {
      if (req.url === "/login") {
        res.writeHead(200, {
          "Content-Type": "text/html",
          Server: "Express/4.19.0",
          "Set-Cookie": "sid=test; Path=/",
        });
        res.end(
          '<html><body><form action="/auth" method="POST"><input name="user"/><input name="pass"/></form></body></html>'
        );
      } else if (req.url.startsWith("/fuzz")) {
        res.writeHead(req.url.includes("ok") ? 200 : 403, {
          "Content-Type": "text/plain",
        });
        res.end("fuzz=" + req.url);
      } else {
        res.writeHead(200, {
          "Content-Type": "text/html",
          Server: "Express/4.19.0",
        });
        res.end('<html><body><a href="/login">Login</a></body></html>');
      }
    });
    const targetPort = await listen(target);

    let proxyHits = 0;
    const proxy = http.createServer((req, res) => {
      proxyHits++;
      const u = new URL(req.url);
      const fwd = http.request(
        {
          host: u.hostname,
          port: u.port,
          path: u.pathname + u.search,
          method: req.method,
          headers: req.headers,
        },
        (up) => {
          res.writeHead(up.statusCode, up.headers);
          up.pipe(res);
        }
      );
      req.pipe(fwd);
    });
    const proxyPort = await listen(proxy);

    const probe = http.createServer();
    const closedRestPort = await listen(probe);
    await new Promise((r) => probe.close(r));
    cleanupCallbacks.pop();

    const mcp = await startStdioMcp({
      BURP_HOST: "127.0.0.1",
      BURP_PORT: String(proxyPort),
      BURP_API_PORT: String(closedRestPort),
      BURP_API_KEY: "",
      BURP_EDITION: "auto",
    });

    const list = await mcp.rpc("tools/list", {});
    const tools = list.result.tools;
    assert.equal(tools.length, 69);
    assert.equal(new Set(tools.map((t) => t.name)).size, 69);
    for (const t of tools) {
      assert.equal(t.inputSchema.type, "object", `${t.name} must have object schema`);
    }

    const ver = parseTool(await mcp.rpc("tools/call", { name: "burp_get_version", arguments: {} }));
    assert.equal(ver.mode, "community-no-rest-api");

    const r1 = parseTool(
      await mcp.rpc("tools/call", {
        name: "repeater_send_request",
        arguments: {
          host: "127.0.0.1",
          port: targetPort,
          use_https: false,
          method: "GET",
          path: "/login",
          headers: {},
          use_burp_proxy: true,
        },
      })
    );
    assert.equal(r1.status, 200);
    assert.equal(r1.proxied, true);

    const r2 = parseTool(
      await mcp.rpc("tools/call", {
        name: "repeater_replay_from_proxy_history",
        arguments: { proxy_history_id: 1, modifications: { headers_to_add: { "X-Test": "1" } } },
      })
    );
    assert.equal(r2.status, 200);

    const diffRep = parseTool(
      await mcp.rpc("tools/call", {
        name: "comparer_diff_repeater_items",
        arguments: { left_id: r1.id, right_id: r2.id },
      })
    );
    assert.equal(diffRep.body_diff.identical, true);

    const histMeta = parseTool(
      await mcp.rpc("tools/call", {
        name: "get_proxy_history",
        arguments: { include_body: false },
      })
    );
    assert.equal(histMeta.total, 2);
    assert.equal(histMeta.items[0].response.body, undefined);

    const crawl = parseTool(
      await mcp.rpc("tools/call", {
        name: "spider_start_crawl",
        arguments: { urls: [`http://127.0.0.1:${targetPort}/`], max_depth: 2, max_links: 10 },
      })
    );
    for (let i = 0; i < 30; i++) {
      const st = parseTool(
        await mcp.rpc("tools/call", {
          name: "spider_get_crawl_status",
          arguments: { task_id: crawl.task_id },
        })
      );
      if (st.status === "succeeded") break;
      await new Promise((r) => setTimeout(r, 40));
    }

    const forms = parseTool(await mcp.rpc("tools/call", { name: "spider_get_forms", arguments: {} }));
    assert.ok(forms.forms.some((f) => f.url.endsWith("/auth") && f.params_detected.includes("user")));

    const atk = parseTool(
      await mcp.rpc("tools/call", {
        name: "intruder_start_attack",
        arguments: {
          host: "127.0.0.1",
          port: targetPort,
          use_https: false,
          request_template: "GET /fuzz?v=§FUZZ§ HTTP/1.1\r\n\r\n",
          attack_type: "sniper",
          payload_sets: [["ok", "nope"]],
        },
      })
    );
    for (let i = 0; i < 30; i++) {
      const st = parseTool(
        await mcp.rpc("tools/call", {
          name: "intruder_get_attack_status",
          arguments: { attack_id: atk.attack_id },
        })
      );
      if (st.status === "finished") break;
      await new Promise((r) => setTimeout(r, 40));
    }
    const atkRes = parseTool(
      await mcp.rpc("tools/call", {
        name: "intruder_get_results",
        arguments: { attack_id: atk.attack_id },
      })
    );
    assert.equal(atkRes.total_filtered, 2);

    const tmpOut = path.join(os.tmpdir(), `burp-mcp-e2e-${Date.now()}.md`);
    const tmpSession = path.join(os.tmpdir(), `burp-mcp-session-${Date.now()}.json`);
    try {
      const rep = parseTool(
        await mcp.rpc("tools/call", {
          name: "report_export",
          arguments: { format: "markdown", output_path: tmpOut },
        })
      );
      assert.ok(rep.summary.findings >= 3);
      assert.ok(fs.existsSync(tmpOut));

      await mcp.rpc("tools/call", {
        name: "scope_add_url",
        arguments: { url: `http://127.0.0.1:${targetPort}/` },
      });
      const info1 = parseTool(
        await mcp.rpc("tools/call", { name: "session_info", arguments: {} })
      );
      assert.ok(info1.proxy_history_count >= 2);
      assert.equal(info1.repeater_history_count, 2);

      const saved = parseTool(
        await mcp.rpc("tools/call", {
          name: "session_save",
          arguments: { file_path: tmpSession },
        })
      );
      assert.equal(saved.saved, true);
      assert.ok(fs.existsSync(tmpSession));

      // Load into a brand-new MCP stdio process and confirm state survives restart
      const mcp2 = await startStdioMcp({
        BURP_HOST: "127.0.0.1",
        BURP_PORT: String(proxyPort),
        BURP_API_PORT: String(closedRestPort),
        BURP_API_KEY: "",
        BURP_EDITION: "auto",
      });
      const loaded = parseTool(
        await mcp2.rpc("tools/call", {
          name: "session_load",
          arguments: { file_path: tmpSession },
        })
      );
      assert.equal(loaded.loaded, true);
      assert.equal(loaded.repeater_history_loaded, 2);
      const info2 = parseTool(
        await mcp2.rpc("tools/call", { name: "session_info", arguments: {} })
      );
      assert.equal(info2.proxy_history_count, info1.proxy_history_count);
      assert.equal(info2.scope_included_count, 1);
      assert.ok(info2.passive_issues_count >= 3);
    } finally {
      if (fs.existsSync(tmpOut)) fs.unlinkSync(tmpOut);
      if (fs.existsSync(tmpSession)) fs.unlinkSync(tmpSession);
    }

    assert.ok(proxyHits >= 4);
    assert.equal(mcp.getOut().trim(), "");
    assert.ok(mcp.getErr().includes("Registered 69 tools"));
  });

  it("supports Burp Pro path API key mode over stdio", async () => {
    const proApi = http.createServer((req, res) => {
      if (!req.url.startsWith("/secret-pro/v0.1/")) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "API key required" }));
        return;
      }
      if (req.url === "/secret-pro/v0.1/" || req.url === "/secret-pro/v0.1/burp/version") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ edition: "Professional", version: "2026.9" }));
        return;
      }
      if (req.url === "/secret-pro/v0.1/scan" && req.method === "POST") {
        res.writeHead(201, {
          "Content-Type": "application/json",
          Location: "/secret-pro/v0.1/scan/55",
        });
        res.end(JSON.stringify({ task_id: "55" }));
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({}));
    });
    const proPort = await listen(proApi);

    const mcp = await startStdioMcp({
      BURP_HOST: "127.0.0.1",
      BURP_PORT: "8080",
      BURP_API_PORT: String(proPort),
      BURP_API_KEY: "secret-pro",
      BURP_API_KEY_MODE: "auto",
      BURP_EDITION: "auto",
    });

    const ver = parseTool(await mcp.rpc("tools/call", { name: "burp_get_version", arguments: {} }));
    assert.equal(ver.mode, "burp-rest-api");
    assert.equal(ver.edition, "Professional");
    assert.equal(ver.api_key_configured, true);

    const scan = parseTool(
      await mcp.rpc("tools/call", {
        name: "start_scan",
        arguments: { urls: ["https://example.com/"] },
      })
    );
    assert.equal(scan.mode, "burp-rest-api");
    assert.equal(scan.task_id, "55");
  });

  it("serves Streamable HTTP transport (--http) with Bearer auth and session lifecycle", async () => {
    const probe = http.createServer();
    const httpPort = await listen(probe);
    await new Promise((r) => probe.close(r));
    cleanupCallbacks.pop();

    const httpProc = spawn(
      "./dist/index.js",
      ["--http", "--host", "127.0.0.1", "--port", String(httpPort), "--token", "tok-xyz"],
      {
        env: {
          ...process.env,
          BURP_HOST: "127.0.0.1",
          BURP_PORT: "59996",
          BURP_API_PORT: "59997",
          BURP_API_KEY: "",
          BURP_EDITION: "community",
        },
        stdio: ["ignore", "pipe", "pipe"],
      }
    );
    cleanupCallbacks.push(async () => {
      if (!httpProc.killed) httpProc.kill();
    });

    await new Promise((resolve, reject) => {
      let stderr = "";
      const timer = setTimeout(
        () => reject(new Error("HTTP MCP failed to start: " + stderr)),
        10_000
      );
      httpProc.stderr.on("data", (d) => {
        stderr += d.toString();
        if (stderr.includes("Streamable HTTP server ready")) {
          clearTimeout(timer);
          resolve();
        }
      });
    });

    const health = await fetch(`http://127.0.0.1:${httpPort}/health`);
    assert.equal(health.status, 200);
    const healthJson = await health.json();
    assert.equal(healthJson.tools, 69);

    const unauth = await fetch(`http://127.0.0.1:${httpPort}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
    });
    assert.equal(unauth.status, 401);

    const transport = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${httpPort}/mcp`),
      { requestInit: { headers: { Authorization: "Bearer tok-xyz" } } }
    );
    const client = new Client(
      { name: "streamable-http-test", version: "1.0.0" },
      { capabilities: {} }
    );
    await client.connect(transport);

    const list = await client.listTools();
    assert.equal(list.tools.length, 69);

    const hashRes = await client.callTool({
      name: "decoder_hash",
      arguments: { input: "test", algorithm: "sha256" },
    });
    const parsedHash = JSON.parse(hashRes.content[0].text);
    assert.equal(
      parsedHash.digest_hex,
      "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    );

    await transport.terminateSession();
    await client.close();
  });
});
