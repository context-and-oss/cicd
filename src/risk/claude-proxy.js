#!/usr/bin/env node
// Local proxy for `risk scan --use-claude-cli`: wraps `claude --print` behind an
// OpenAI-compatible POST /v1/chat/completions, so a scan can use the Claude CLI's
// own login (subscription/OAuth) instead of an API key.
//
// Deliberate setup, no compatibility bypass:
//
//   export CICD_RISK_PROXY_TOKEN="$(openssl rand -hex 32)"
//   node claude-proxy.js [--port 4000]
//   dagger -m <risk> call scan --source . --use-claude-cli \
//     --llm-token env:CICD_RISK_PROXY_TOKEN export --path .
//
// Loopback is not isolation: any process of any OS user on this machine, and any
// web page the browser opens, can reach 127.0.0.1. So every request must carry
// the bearer token, name an expected Host, carry no Origin and be
// application/json, or it is refused before the CLI is started. The token is
// read from the environment only — a command-line flag would show in `ps` to
// every user — and is removed from the CLI's environment.
//
// The CLI runs with every tool disabled, no MCP servers, no skills and no
// session saved to disk, in an empty private working directory. Those flags are
// checked against the installed CLI's own --help at startup; a CLI that does not
// offer all of them is refused rather than run without them. Request bytes,
// concurrent CLI processes, CLI output and CLI runtime are bounded, and a CLI
// process is killed when its client disconnects or its time runs out.

"use strict";

const http = require("http");
const crypto = require("crypto");
const { spawn, spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const TOKEN_ENV = "CICD_RISK_PROXY_TOKEN";
const MIN_TOKEN_LENGTH = 32;
const ROUTE = "/v1/chat/completions";

// The CLI's argv: print mode, no tools, no MCP servers, no skills, no saved
// session. Never a permission-bypass flag.
const CLAUDE_ARGS = [
  "--print",
  "--tools", "",
  "--no-session-persistence",
  "--strict-mcp-config",
  "--disable-slash-commands",
];
const REQUIRED_CLI_FLAGS = [
  "--print",
  "--tools",
  "--no-session-persistence",
  "--strict-mcp-config",
  "--disable-slash-commands",
];

const MAX_MESSAGES = 64;
const KILL_GRACE_MS = 2000;

function usage(msg) {
  process.stderr.write(`claude-proxy: ${msg}\n`);
  process.exit(2);
}

function parseArgs(argv) {
  const opts = {
    port: 4000,
    maxBodyBytes: 2 * 1024 * 1024,
    maxConcurrent: 2,
    maxOutputBytes: 1024 * 1024,
    timeoutMs: 300_000,
    allowHosts: [],
  };
  const ints = {
    "--port": ["port", 0, 65535],
    "--max-body-bytes": ["maxBodyBytes", 1024, 64 * 1024 * 1024],
    "--max-concurrent": ["maxConcurrent", 1, 16],
    "--max-output-bytes": ["maxOutputBytes", 1024, 64 * 1024 * 1024],
    "--timeout-ms": ["timeoutMs", 100, 3_600_000],
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    const value = argv[i + 1];
    if (ints[flag]) {
      const [key, min, max] = ints[flag];
      if (value === undefined || !/^[0-9]+$/.test(value)) usage(`${flag} needs a whole number`);
      const n = Number(value);
      if (n < min || n > max) usage(`${flag} must be between ${min} and ${max}`);
      opts[key] = n;
      i++;
    } else if (flag === "--allow-host") {
      if (value === undefined || !/^[A-Za-z0-9.-]+$/.test(value)) usage("--allow-host needs a host name");
      opts.allowHosts.push(value.toLowerCase());
      i++;
    } else {
      usage(`unknown argument ${JSON.stringify(flag)}`);
    }
  }
  return opts;
}

function readToken() {
  const token = process.env[TOKEN_ENV] || "";
  if (token.length < MIN_TOKEN_LENGTH || /\s/.test(token)) {
    process.stderr.write(
      `claude-proxy: refusing to start: ${TOKEN_ENV} must hold a random token of at least ` +
        `${MIN_TOKEN_LENGTH} characters with no whitespace.\n` +
        `  export ${TOKEN_ENV}="$(openssl rand -hex 32)"\n` +
        `then start the proxy, and pass --llm-token env:${TOKEN_ENV} to the scan from a shell that has it.\n`,
    );
    process.exit(1);
  }
  return token;
}

// The environment the CLI runs with: the proxy's own, minus the token.
function childEnvironment() {
  const env = { ...process.env };
  delete env[TOKEN_ENV];
  return env;
}

// Ask the installed CLI which flags it has; refuse to run one without the
// flags that disable its tools and its session persistence.
function verifyCli(env) {
  const help = spawnSync("claude", ["--help"], { env, encoding: "utf8", timeout: 30_000 });
  if (help.error) {
    process.stderr.write(
      "claude-proxy: refusing to start: the Claude CLI could not be run (" + help.error.code + ").\n" +
        "  Install it and log in once: npm install -g @anthropic-ai/claude-code && claude\n",
    );
    process.exit(1);
  }
  const text = `${help.stdout || ""}\n${help.stderr || ""}`;
  const missing = REQUIRED_CLI_FLAGS.filter((f) => !new RegExp(`(^|[\\s,])${f}([\\s,=<]|$)`, "m").test(text));
  if (help.status !== 0 || missing.length > 0) {
    process.stderr.write(
      "claude-proxy: refusing to start: this Claude CLI does not offer " +
        (missing.length ? missing.join(", ") : "a readable --help") +
        ", so its tools and session persistence cannot be switched off. Upgrade it: " +
        "npm install -g @anthropic-ai/claude-code\n",
    );
    process.exit(1);
  }
}

// removeDir never throws: a directory the CLI left behind must not take the
// proxy, and every other request's CLI, down with it.
function removeDir(dir) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (err) {
    process.stderr.write(`claude-proxy: could not remove a working directory (${err.code || "error"})\n`);
  }
}

function digest(s) {
  return crypto.createHash("sha256").update(s, "utf8").digest();
}

function authorised(header, tokenDigest) {
  if (typeof header !== "string" || !header.startsWith("Bearer ")) return false;
  return crypto.timingSafeEqual(digest(header.slice("Bearer ".length)), tokenDigest);
}

function send(res, status, error, extraHeaders) {
  if (res.headersSent || res.destroyed) return;
  const body = JSON.stringify({ error });
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
    ...(extraHeaders || {}),
  });
  res.end(body);
}

// validatePrompt returns the prompt text, or an error string. Only the shape
// the scan client sends is accepted: a non-empty messages array of
// {role, content} with string or text-block content.
function validatePrompt(parsed) {
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { error: "body must be a JSON object" };
  }
  if (parsed.model !== undefined && (typeof parsed.model !== "string" || parsed.model.length > 128)) {
    return { error: "model must be a short string" };
  }
  if (parsed.stream !== undefined && parsed.stream !== false) {
    return { error: "streaming is not supported" };
  }
  const messages = parsed.messages;
  if (!Array.isArray(messages) || messages.length === 0 || messages.length > MAX_MESSAGES) {
    return { error: `messages must be an array of 1 to ${MAX_MESSAGES} entries` };
  }
  const texts = [];
  for (const m of messages) {
    if (m === null || typeof m !== "object" || Array.isArray(m)) return { error: "each message must be an object" };
    if (!["system", "user", "assistant"].includes(m.role)) return { error: "message role must be system, user or assistant" };
    let text;
    if (typeof m.content === "string") {
      text = m.content;
    } else if (Array.isArray(m.content)) {
      const parts = [];
      for (const b of m.content) {
        if (b === null || typeof b !== "object" || b.type !== "text" || typeof b.text !== "string") {
          return { error: "message content blocks must be {type: \"text\", text: string}" };
        }
        parts.push(b.text);
      }
      text = parts.join("\n");
    } else {
      return { error: "message content must be a string or an array of text blocks" };
    }
    texts.push({ role: m.role, text });
  }
  // The last user message is the prompt (the scan client's conversation).
  const last = [...texts].reverse().find((m) => m.role === "user");
  if (!last || last.text.trim() === "") return { error: "a non-empty user message is required" };
  return { prompt: last.text, model: parsed.model };
}

function startServer(opts, token) {
  const tokenDigest = digest(token);
  const allowedHosts = new Set(
    ["127.0.0.1", "localhost", "[::1]", "host.docker.internal", ...opts.allowHosts].map((h) => h.toLowerCase()),
  );
  const env = childEnvironment();
  const active = new Map(); // CLI process -> its private working directory

  const server = http.createServer((req, res) => {
    const reqPath = (req.url || "").split("?")[0];
    if (reqPath !== ROUTE || (req.url || "") !== ROUTE) return send(res, 404, "not found");
    if (req.method !== "POST") return send(res, 405, "method not allowed", { Allow: "POST" });

    const port = server.address().port;
    const host = String(req.headers.host || "").toLowerCase();
    const hostOK = [...allowedHosts].some((h) => host === `${h}:${port}`);
    if (!hostOK) return send(res, 403, "unexpected Host header");
    if (req.headers.origin !== undefined) return send(res, 403, "browser-originated requests are refused");
    if (!authorised(req.headers.authorization, tokenDigest)) {
      return send(res, 401, "missing or wrong bearer token", { "WWW-Authenticate": "Bearer" });
    }
    const ctype = String(req.headers["content-type"] || "").toLowerCase();
    if (!/^application\/json\s*(;\s*charset=utf-8\s*)?$/.test(ctype)) {
      return send(res, 415, "content type must be application/json");
    }
    const declared = Number(req.headers["content-length"]);
    if (Number.isFinite(declared) && declared > opts.maxBodyBytes) {
      send(res, 413, "request body too large", { Connection: "close" });
      req.destroy();
      return;
    }

    const chunks = [];
    let bodyBytes = 0;
    let tooLarge = false;
    req.on("data", (chunk) => {
      if (tooLarge) return;
      bodyBytes += chunk.length;
      if (bodyBytes > opts.maxBodyBytes) {
        tooLarge = true;
        send(res, 413, "request body too large", { Connection: "close" });
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("error", () => {});
    req.on("end", () => {
      if (tooLarge) return;
      let parsed;
      try {
        parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch {
        return send(res, 400, "invalid JSON");
      }
      const v = validatePrompt(parsed);
      if (v.error) return send(res, 400, v.error);
      if (active.size >= opts.maxConcurrent) {
        return send(res, 429, "too many concurrent requests", { "Retry-After": "5" });
      }
      runClaude(v, res);
    });
  });

  function runClaude(v, res) {
    let workDir;
    try {
      workDir = fs.mkdtempSync(path.join(os.tmpdir(), "claude-proxy-"));
      fs.chmodSync(workDir, 0o700);
    } catch {
      return send(res, 500, "could not create a private working directory");
    }

    const posix = process.platform !== "win32";
    let child;
    try {
      child = spawn("claude", CLAUDE_ARGS, {
        cwd: workDir,
        env,
        stdio: ["pipe", "pipe", "pipe"],
        detached: posix, // own process group, so a kill reaches its children too
        windowsHide: true,
      });
    } catch {
      removeDir(workDir);
      return send(res, 502, "the Claude CLI could not be started");
    }
    active.set(child, workDir);

    let finished = false;
    let killTimer;
    let outcome = null; // set once: "timeout" | "output" | "disconnect"
    const out = [];
    let outBytes = 0;
    let errBytes = 0;

    const kill = (why) => {
      if (outcome !== null) return; // one kill sequence per CLI process
      outcome = why;
      const signal = (sig) => {
        try {
          if (posix && child.pid) process.kill(-child.pid, sig);
          else child.kill(sig);
        } catch {}
      };
      signal("SIGTERM");
      killTimer = setTimeout(() => signal("SIGKILL"), KILL_GRACE_MS);
      killTimer.unref();
    };
    const timer = setTimeout(() => kill("timeout"), opts.timeoutMs);

    const finish = (status, body) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      active.delete(child);
      removeDir(workDir);
      if (status === 200) {
        const payload = JSON.stringify(body);
        res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) });
        res.end(payload);
      } else if (status) {
        send(res, status, body);
      }
    };

    res.on("close", () => {
      if (!res.writableFinished && !finished) kill("disconnect");
    });

    child.stdout.on("data", (d) => {
      outBytes += d.length;
      if (outBytes > opts.maxOutputBytes) {
        kill("output");
        return;
      }
      out.push(d);
    });
    // stderr is counted, never returned or logged: it is the CLI's business.
    child.stderr.on("data", (d) => {
      errBytes += d.length;
    });
    child.stdin.on("error", () => {});
    child.stdin.end(v.prompt);

    child.on("error", (err) => {
      process.stderr.write(`claude-proxy: the Claude CLI could not be started (${err.code || "error"})\n`);
      finish(502, "the Claude CLI could not be started");
    });
    child.on("close", (code, signal) => {
      clearTimeout(killTimer);
      if (outcome === "disconnect") {
        process.stderr.write("claude-proxy: client disconnected; the Claude CLI was stopped\n");
        return finish(0);
      }
      if (outcome === "timeout") {
        process.stderr.write(`claude-proxy: the Claude CLI ran past ${opts.timeoutMs} ms and was stopped\n`);
        return finish(504, "the Claude CLI timed out");
      }
      if (outcome === "output") {
        process.stderr.write(`claude-proxy: the Claude CLI wrote more than ${opts.maxOutputBytes} bytes and was stopped\n`);
        return finish(502, "the Claude CLI output exceeded the proxy's limit");
      }
      if (code !== 0) {
        process.stderr.write(
          `claude-proxy: the Claude CLI exited with ${signal ? `signal ${signal}` : `code ${code}`} ` +
            `(${errBytes} bytes on stderr, not forwarded)\n`,
        );
        return finish(502, "the Claude CLI failed; run `claude --print` by hand to see why");
      }
      finish(200, {
        id: "chatcmpl-proxy",
        object: "chat.completion",
        created: Math.floor(Date.now() / 1000),
        model: v.model || "claude-cli",
        choices: [
          {
            index: 0,
            message: { role: "assistant", content: Buffer.concat(out).toString("utf8").trim() },
            finish_reason: "stop",
          },
        ],
        usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
      });
    });
  }

  // Connections beyond this are closed on arrival, so authenticated uploads
  // cannot multiply the body cap without bound.
  server.maxConnections = 4 * opts.maxConcurrent + 8;
  server.headersTimeout = 10_000;
  server.requestTimeout = 60_000;

  const stop = () => {
    for (const [child, workDir] of active) {
      try {
        if (process.platform !== "win32" && child.pid) process.kill(-child.pid, "SIGKILL");
        else child.kill("SIGKILL");
      } catch {}
      removeDir(workDir);
    }
    process.exit(0);
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);

  // Loopback only. This keeps other machines out; the token keeps out other
  // users and browser pages on this one.
  server.listen(opts.port, "127.0.0.1", () => {
    const port = server.address().port;
    console.log(`claude-proxy listening on http://127.0.0.1:${port}`);
    console.log(`Route: POST ${ROUTE} -> claude ${CLAUDE_ARGS.map((a) => (a === "" ? '""' : a)).join(" ")}`);
    console.log(`Requests need: Authorization: Bearer $${TOKEN_ENV}`);
    console.log("Press Ctrl+C to stop.");
  });
}

const opts = parseArgs(process.argv.slice(2));
const token = readToken();
verifyCli(childEnvironment());
startServer(opts, token);
