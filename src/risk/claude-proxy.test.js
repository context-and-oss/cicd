// Loopback tests for claude-proxy.js. Each starts the real proxy as a child
// process on 127.0.0.1 with a fixture-only PATH — no model, no subscription,
// no network beyond loopback, and no host-CLI fallback when the fake is removed. Run: node --test src/risk/
// (scripts/tests/test_claude_proxy.py runs it in the script suite and CI).
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");

const PROXY = path.join(__dirname, "claude-proxy.js");
const FAKE_SRC = path.join(__dirname, "testdata", "fake-claude", "claude");
// Synthetic, test-only value; it authorises nothing anywhere.
const TOKEN = "fake-proxy-token-" + "0123456789abcdef0123456789abcdef";

function sandbox() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "proxy-test-"));
  const bin = path.join(root, "bin");
  const log = path.join(root, "log");
  const tmp = path.join(root, "tmp");
  for (const d of [bin, log, tmp]) fs.mkdirSync(d);
  fs.copyFileSync(FAKE_SRC, path.join(bin, "claude"));
  fs.chmodSync(path.join(bin, "claude"), 0o755);
  // The fake's /usr/bin/env node shebang needs Node, not the host's CLI path.
  fs.symlinkSync(process.execPath, path.join(bin, "node"));
  return { root, bin, log, tmp };
}

// startProxy resolves once the proxy prints its address, or rejects with its
// exit code and output if it refuses to start.
function startProxy(box, { args = [], env = {} } = {}) {
  const fullEnv = {
    ...process.env,
    TMPDIR: box.tmp,
    FAKE_CLAUDE_LOG: box.log,
    FAKE_CLAUDE_SECRET_PROBE: crypto.createHash("sha256").update(TOKEN).digest("hex"),
    CICD_RISK_PROXY_TOKEN: TOKEN,
    ...env,
    PATH: box.bin,
  };
  for (const [k, v] of Object.entries(fullEnv)) if (v === undefined) delete fullEnv[k];
  const child = spawn(process.execPath, [PROXY, "--port", "0", ...args], { env: fullEnv });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (d) => (stdout += d));
  child.stderr.on("data", (d) => (stderr += d));
  const output = () => ({ stdout, stderr });
  return new Promise((resolve, reject) => {
    child.stdout.on("data", () => {
      const m = /listening on http:\/\/127\.0\.0\.1:(\d+)/.exec(stdout);
      if (m) resolve({ child, port: Number(m[1]), output });
    });
    child.on("exit", (code) => reject(Object.assign(new Error(`proxy exited ${code}`), { code, stdout, stderr })));
  });
}

async function stopProxy(p) {
  if (p.child.exitCode !== null) return;
  const exited = new Promise((r) => p.child.once("exit", r));
  p.child.kill("SIGTERM");
  await exited;
}

function request(port, { method = "POST", urlPath = "/v1/chat/completions", headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const h = {
      Host: `127.0.0.1:${port}`,
      "Content-Type": "application/json",
      Authorization: `Bearer ${TOKEN}`,
      ...headers,
    };
    for (const [k, v] of Object.entries(h)) if (v === undefined) delete h[k];
    const req = http.request({ host: "127.0.0.1", port, method, path: urlPath, headers: h }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    if (body !== undefined) req.write(typeof body === "string" ? body : JSON.stringify(body));
    req.end();
  });
}

const chat = (text) => ({ model: "m", messages: [{ role: "user", content: text }] });
const records = (box) => fs.readdirSync(box.log).map((f) => JSON.parse(fs.readFileSync(path.join(box.log, f), "utf8")));
const leftovers = (box) => fs.readdirSync(box.tmp).filter((f) => f.startsWith("claude-proxy-"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function waitFor(pred, ms = 5000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (pred()) return true;
    await sleep(25);
  }
  return pred();
}

test("refuses to start without a token, with a short one, or with a CLI that cannot disable its tools", async () => {
  const box = sandbox();
  for (const env of [{ CICD_RISK_PROXY_TOKEN: undefined }, { CICD_RISK_PROXY_TOKEN: "short" }]) {
    await assert.rejects(startProxy(box, { env }), (e) => e.code === 1 && /CICD_RISK_PROXY_TOKEN/.test(e.stderr));
  }
  await assert.rejects(
    startProxy(box, { env: { FAKE_CLAUDE_HELP: "old" } }),
    (e) => e.code === 1 && /--tools/.test(e.stderr) && /--no-session-persistence/.test(e.stderr),
  );
  fs.rmSync(path.join(box.bin, "claude"));
  await assert.rejects(
    startProxy(box, { env: { PATH: box.bin } }),
    (e) => e.code === 1 && /could not be run/.test(e.stderr),
  );
  await assert.rejects(startProxy(sandbox(), { args: ["--no-auth"] }), (e) => e.code === 2);
  assert.deepEqual(records(box), []);
});

test("an authenticated request reaches the CLI with tools off, no session, no token", async () => {
  const box = sandbox();
  const p = await startProxy(box);
  try {
    const res = await request(p.port, { body: chat("review this repository") });
    assert.equal(res.status, 200);
    const reply = JSON.parse(res.body);
    assert.equal(reply.choices[0].message.role, "assistant");
    assert.deepEqual(JSON.parse(reply.choices[0].message.content).findings, []);

    const [rec] = records(box);
    assert.deepEqual(rec.argv, ["--print", "--tools", "", "--no-session-persistence", "--strict-mcp-config", "--disable-slash-commands"]);
    assert.ok(!rec.argv.some((a) => /dangerously|bypass|permission/i.test(a)));
    assert.equal(rec.prompt, "review this repository");
    assert.ok(!rec.envKeys.includes("CICD_RISK_PROXY_TOKEN"));
    assert.equal(rec.envHoldsProbe, false);
    assert.ok(path.dirname(rec.cwd) === fs.realpathSync(box.tmp) || path.dirname(rec.cwd) === box.tmp);
    assert.ok(await waitFor(() => leftovers(box).length === 0));
  } finally {
    await stopProxy(p);
  }
});

test("refuses unauthenticated, foreign and malformed requests before the CLI, and keeps serving", async () => {
  const box = sandbox();
  const p = await startProxy(box);
  try {
    const port = p.port;
    const cases = [
      [401, { headers: { Authorization: undefined }, body: chat("x") }],
      [401, { headers: { Authorization: `Bearer ${TOKEN}x` }, body: chat("x") }],
      [401, { headers: { Authorization: TOKEN }, body: chat("x") }],
      [403, { headers: { Origin: "https://attacker.example" }, body: chat("x") }],
      [403, { headers: { Origin: "null" }, body: chat("x") }],
      [403, { headers: { Host: `attacker.example:${port}` }, body: chat("x") }],
      [403, { headers: { Host: "127.0.0.1:1" }, body: chat("x") }],
      [415, { headers: { "Content-Type": "text/plain" }, body: chat("x") }],
      [415, { headers: { "Content-Type": undefined }, body: chat("x") }],
      [404, { urlPath: "/chat/completions", body: chat("x") }],
      [404, { urlPath: "/v1/chat/completions/x", body: chat("x") }],
      [404, { urlPath: "/v1/chat/completions?x=1", body: chat("x") }],
      [405, { method: "GET" }],
      [400, { body: "{not json" }],
      [400, { body: "null" }],
      [400, { body: [] }],
      [400, { body: { messages: {} } }],
      [400, { body: { messages: [] } }],
      [400, { body: { messages: "hello" } }],
      [400, { body: { messages: [null] } }],
      [400, { body: { messages: [{ role: "root", content: "x" }] } }],
      [400, { body: { messages: [{ role: "user", content: 42 }] } }],
      [400, { body: { messages: [{ role: "user", content: [{ type: "image", url: "x" }] }] } }],
      [400, { body: { messages: [{ role: "assistant", content: "only" }] } }],
      [400, { body: { messages: [{ role: "user", content: "   " }] } }],
      [400, { body: { model: 7, messages: [{ role: "user", content: "x" }] } }],
      [400, { body: { stream: true, messages: [{ role: "user", content: "x" }] } }],
      [400, { body: { messages: Array.from({ length: 65 }, () => ({ role: "user", content: "x" })) } }],
    ];
    for (const [want, opts] of cases) {
      const res = await request(port, opts);
      assert.equal(res.status, want, JSON.stringify(opts).slice(0, 160));
      assert.ok(!res.body.includes(TOKEN));
    }
    assert.deepEqual(records(box), [], "a refused request must never start the CLI");
    assert.equal(p.child.exitCode, null, "a malformed request must not kill the proxy");

    const ok = await request(port, {
      body: { messages: [{ role: "user", content: [{ type: "text", text: "a" }, { type: "text", text: "b" }] }] },
    });
    assert.equal(ok.status, 200);
    assert.equal(records(box)[0].prompt, "a\nb");
  } finally {
    await stopProxy(p);
  }
});

test("bounds the request body", async () => {
  const box = sandbox();
  const p = await startProxy(box, { args: ["--max-body-bytes", "2048"] });
  try {
    const big = await request(p.port, { body: chat("y".repeat(4096)) }).catch((e) => ({ status: "reset", e }));
    assert.ok(big.status === 413 || big.status === "reset");
    // Chunked, with no Content-Length to refuse up front.
    const chunked = await new Promise((resolve) => {
      const req = http.request(
        {
          host: "127.0.0.1",
          port: p.port,
          method: "POST",
          path: "/v1/chat/completions",
          headers: { Host: `127.0.0.1:${p.port}`, "Content-Type": "application/json", Authorization: `Bearer ${TOKEN}` },
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve(res.statusCode));
        },
      );
      req.on("error", () => resolve("reset"));
      req.write(JSON.stringify(chat("z".repeat(8192))));
      req.end();
    });
    assert.ok(chunked === 413 || chunked === "reset");
    assert.deepEqual(records(box), []);
    assert.equal((await request(p.port, { body: chat("small") })).status, 200);
  } finally {
    await stopProxy(p);
  }
});

test("caps concurrent CLI processes", async () => {
  const box = sandbox();
  const p = await startProxy(box, { args: ["--max-concurrent", "1", "--timeout-ms", "1500"] });
  try {
    const first = request(p.port, { body: chat("FAKE:sleep") });
    assert.ok(await waitFor(() => records(box).length === 1));
    const second = await request(p.port, { body: chat("hello") });
    assert.equal(second.status, 429);
    assert.equal(records(box).length, 1, "the refused request must not start a second CLI");
    assert.equal((await first).status, 504);
    assert.equal((await request(p.port, { body: chat("hello") })).status, 200);
  } finally {
    await stopProxy(p);
  }
});

test("stops a CLI that runs too long, and cleans up after it", async () => {
  const box = sandbox();
  const p = await startProxy(box, { args: ["--timeout-ms", "300"] });
  try {
    const res = await request(p.port, { body: chat("FAKE:sleep") });
    assert.equal(res.status, 504);
    const [rec] = records(box);
    assert.ok(await waitFor(() => !alive(rec.pid)), "the timed-out CLI must be killed");
    assert.ok(await waitFor(() => leftovers(box).length === 0));
  } finally {
    await stopProxy(p);
  }
});

test("stops a CLI whose output passes the cap", async () => {
  const box = sandbox();
  const p = await startProxy(box, { args: ["--max-output-bytes", "4096"] });
  try {
    const res = await request(p.port, { body: chat("FAKE:flood") });
    assert.equal(res.status, 502);
    assert.ok(res.body.length < 1024);
    const [rec] = records(box);
    assert.ok(await waitFor(() => !alive(rec.pid)));
    assert.ok(await waitFor(() => leftovers(box).length === 0));
  } finally {
    await stopProxy(p);
  }
});

test("stops the CLI when the client disconnects", async () => {
  const box = sandbox();
  const p = await startProxy(box);
  try {
    const body = JSON.stringify(chat("FAKE:sleep"));
    const sock = net.connect(p.port, "127.0.0.1");
    await new Promise((r) => sock.once("connect", r));
    sock.write(
      "POST /v1/chat/completions HTTP/1.1\r\n" +
        `Host: 127.0.0.1:${p.port}\r\nContent-Type: application/json\r\n` +
        `Authorization: Bearer ${TOKEN}\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n` +
        body,
    );
    assert.ok(await waitFor(() => records(box).length === 1));
    const [rec] = records(box);
    assert.ok(alive(rec.pid));
    sock.destroy();
    assert.ok(await waitFor(() => !alive(rec.pid)), "the CLI of a vanished client must be killed");
    assert.ok(await waitFor(() => leftovers(box).length === 0));
    assert.equal((await request(p.port, { body: chat("again") })).status, 200);
  } finally {
    await stopProxy(p);
  }
});

test("a CLI failure or a CLI that cannot start returns a fixed error, never its stderr", async () => {
  const box = sandbox();
  const p = await startProxy(box);
  try {
    const failed = await request(p.port, { body: chat("FAKE:fail") });
    assert.equal(failed.status, 502);
    assert.ok(!failed.body.includes("FAKE-STDERR-SENTINEL"));

    fs.renameSync(path.join(box.bin, "claude"), path.join(box.bin, "claude.gone"));
    const missing = await request(p.port, { body: chat("hello") });
    assert.equal(missing.status, 502);
    assert.ok(await waitFor(() => leftovers(box).length === 0));
    assert.equal(p.child.exitCode, null);

    fs.renameSync(path.join(box.bin, "claude.gone"), path.join(box.bin, "claude"));
    assert.equal((await request(p.port, { body: chat("hello") })).status, 200);
    const { stdout, stderr } = p.output();
    assert.ok(!stdout.includes("FAKE-STDERR-SENTINEL") && !stderr.includes("FAKE-STDERR-SENTINEL"));
  } finally {
    await stopProxy(p);
  }
});

test("a missing fake CLI never falls through to a host executable", async () => {
  const box = sandbox();
  const fallback = sandbox();
  const previousPath = process.env.PATH;
  let p;
  try {
    // A second controlled fake models a host installation without contacting it.
    process.env.PATH = fallback.bin;
    p = await startProxy(box);
  } finally {
    process.env.PATH = previousPath;
  }
  try {
    fs.renameSync(path.join(box.bin, "claude"), path.join(box.bin, "claude.gone"));
    const res = await request(p.port, { body: chat("isolation fixture") });
    assert.equal(res.status, 502);
    assert.deepEqual(records(box), []);
  } finally {
    await stopProxy(p);
  }
});

test("the token never appears in the proxy's output, its responses or the CLI's environment", async () => {
  const box = sandbox();
  const p = await startProxy(box);
  const bodies = [];
  try {
    bodies.push((await request(p.port, { body: chat("hello") })).body);
    bodies.push((await request(p.port, { headers: { Authorization: "Bearer wrong-token-value" }, body: chat("x") })).body);
    bodies.push((await request(p.port, { body: chat("FAKE:fail") })).body);
  } finally {
    await stopProxy(p);
  }
  const { stdout, stderr } = p.output();
  for (const bytes of [...bodies, stdout, stderr, ...fs.readdirSync(box.log).map((f) => fs.readFileSync(path.join(box.log, f), "utf8"))]) {
    assert.ok(!bytes.includes(TOKEN));
    assert.ok(!bytes.includes("wrong-token-value"));
  }
  for (const rec of records(box)) assert.equal(rec.envHoldsProbe, false);
});
