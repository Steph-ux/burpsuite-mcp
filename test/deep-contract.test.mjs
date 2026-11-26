import { it } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import { DECODER_TOOLS } from "../dist/modules/decoder.js";
import { INTRUDER_TOOLS } from "../dist/modules/intruder.js";
import { BurpClient } from "../dist/utils/burp-client.js";

// Contract tests verifying decoder and intruder edge cases.
const decoder = Object.fromEntries(DECODER_TOOLS.map(t => [t.name, t.handler]));
const intruder = Object.fromEntries(INTRUDER_TOOLS.map(t => [t.name, t.handler]));

for (const format of [
  "base64", "base64url", "url", "url_all", "html", "hex",
  "unicode_escape", "gzip_base64",
]) {
  it(`deep: ${format} preserves non-BMP Unicode and NUL`, async () => {
    const input = "été 漢字 \u{1f52c}\0<&";
    const encoded = await decoder.decoder_encode({ input, format });
    const decoded = await decoder.decoder_decode({ input: encoded.output, format });
    assert.equal(decoded.output, input);
  });
}

it("deep: HTML hexadecimal entities accept uppercase X", async () => {
  const decoded = await decoder.decoder_decode({ input: "&#X1F52C;", format: "html" });
  assert.equal(decoded.output, "\u{1f52c}");
});

it("deep: empty strings roundtrip through every encoding", async () => {
  for (const format of ["base64", "base64url", "url", "url_all", "html",
    "hex", "unicode_escape", "gzip_base64"]) {
    const enc = await decoder.decoder_encode({ input: "", format });
    const dec = await decoder.decoder_decode({ input: enc.output, format });
    assert.equal(dec.output, "");
  }
});

it("deep: hash known-answer vectors include the empty input", async () => {
  const expected = {
    md5: "d41d8cd98f00b204e9800998ecf8427e",
    sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    sha512: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
      "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
  };
  for (const [algorithm, digest] of Object.entries(expected)) {
    const result = await decoder.decoder_hash({ input: "", algorithm });
    assert.equal(result.digest_hex, digest);
  }
});

it("deep: invalid hex, URL and gzip fail explicitly", async () => {
  for (const [format, input] of [["hex", "zz"], ["url", "%ZZ"], ["gzip_base64", "eA=="]]) {
    await assert.rejects(decoder.decoder_decode({ input, format }));
  }
});

async function fixture(t) {
  const requests = [];
  const proxy = http.createServer((req, res) => {
    requests.push(req.url);
    res.writeHead(200, { "Content-Type": "application/json", Connection: "close" });
    res.end(JSON.stringify({ url: req.url }));
  });
  proxy.listen(0, "127.0.0.1");
  await once(proxy, "listening");
  t.after(() => new Promise(resolve => {
    proxy.close(resolve);
    proxy.closeAllConnections();
  }));
  const client = new BurpClient({
    host: "127.0.0.1", port: proxy.address().port, apiPort: 1,
    apiKey: "", edition: "community", apiKeyMode: "auto",
  });
  const params = {
    host: "127.0.0.1", port: 18743, use_https: false,
    request_template: "GET /echo?a=§originalA§&b=§originalB§ HTTP/1.1\r\n\r\n",
    attack_type: "sniper", payload_sets: [["probe"]],
    max_concurrent: 1, request_timeout_ms: 1000,
  };
  return { client, params, requests };
}

async function finished(id) {
  // Await event-loop progress, with an explicit deadline rather than fixed sleeps.
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    const status = await intruder.intruder_get_attack_status({ attack_id: id });
    if (!["pending", "running"].includes(status.status)) return status;
    await new Promise(resolve => setImmediate(resolve));
  }
  throw new Error(`Attack ${id} did not finish within 3 seconds`);
}

for (const [attack_type, sets, count] of [
  ["sniper", [["1", "2"]], 4],
  ["battering_ram", [["1", "2"]], 2],
  ["pitchfork", [["1", "2"], ["x", "y"]], 2],
  ["cluster_bomb", [["1", "2"], ["x", "y"]], 4],
]) {
  it(`deep: ${attack_type} emits the expected request count`, async t => {
    const f = await fixture(t);
    const a = await intruder.intruder_start_attack({
      ...f.params, attack_type, payload_sets: sets,
    }, f.client);
    t.after(() => intruder.intruder_clear_attack({ attack_id: a.attack_id }));
    const status = await finished(a.attack_id);
    assert.equal(status.status, "finished");
    assert.equal(status.completed_requests, count);
    assert.equal(f.requests.length, count);
    const results = await intruder.intruder_get_results({ attack_id: a.attack_id });
    assert.ok(results.results.every(r => r.status_code === 200));
  });
}

it("deep: Sniper preserves the unmodified insertion-point value", async t => {
  const f = await fixture(t);
  const a = await intruder.intruder_start_attack(f.params, f.client);
  t.after(() => intruder.intruder_clear_attack({ attack_id: a.attack_id }));
  await finished(a.attack_id);
  assert.deepEqual(f.requests, [
    "http://127.0.0.1:18743/echo?a=probe&b=originalB",
    "http://127.0.0.1:18743/echo?a=originalA&b=probe",
  ]);
});

for (const max_concurrent of [0, -1, 0.5]) {
  it(`deep: Intruder rejects invalid concurrency ${max_concurrent}`, async t => {
    const f = await fixture(t);
    let started;
    t.after(async () => {
      if (started) await intruder.intruder_clear_attack({ attack_id: started.attack_id });
    });
    await assert.rejects(async () => {
      started = await intruder.intruder_start_attack({
        ...f.params, max_concurrent,
      }, f.client);
    }, /concurr|positive|integer|invalid/i);
  });
}

it("deep: Intruder rejects a request without insertion points", async t => {
  const f = await fixture(t);
  let started;
  t.after(async () => {
    if (started) await intruder.intruder_clear_attack({ attack_id: started.attack_id });
  });
  await assert.rejects(async () => {
    started = await intruder.intruder_start_attack({
      ...f.params, request_template: "GET / HTTP/1.1\r\n\r\n",
    }, f.client);
  }, /marker|position|insertion|invalid/i);
});

it("deep: Intruder handles sequential proxy requests when proxy drops sockets after response", async t => {
  const net = await import("node:net");
  let hits = 0;
  const droppingProxy = net.createServer((socket) => {
    socket.on("data", () => {
      hits++;
      // Simulate Burp forwarding a keep-alive HTTP/1.1 response (no Connection: close)
      // and closing its proxy-side client socket immediately afterward.
      socket.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
      socket.end();
    });
  });
  droppingProxy.listen(0, "127.0.0.1");
  await once(droppingProxy, "listening");
  t.after(() => new Promise((resolve) => droppingProxy.close(resolve)));

  const client = new BurpClient({
    host: "127.0.0.1", port: droppingProxy.address().port, apiPort: 1,
    apiKey: "", edition: "community", apiKeyMode: "auto",
  });
  const a = await intruder.intruder_start_attack({
    host: "127.0.0.1", port: 80, use_https: false,
    request_template: "GET /item?id=§1§ HTTP/1.1\r\n\r\n",
    attack_type: "sniper",
    payload_sets: [["1", "2", "3", "4"]],
    max_concurrent: 1,
    request_timeout_ms: 1000,
  }, client);
  t.after(() => intruder.intruder_clear_attack({ attack_id: a.attack_id }));

  const st = await finished(a.attack_id);
  assert.equal(st.status, "finished");
  assert.equal(hits, 4);
  const res = await intruder.intruder_get_results({ attack_id: a.attack_id });
  assert.equal(res.results.filter((r) => r.status_code === 200).length, 4);
  assert.equal(res.results.filter((r) => r.error).length, 0);
});
