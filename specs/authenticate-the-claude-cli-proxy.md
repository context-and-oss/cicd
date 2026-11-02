# Authenticate the Claude CLI proxy

## Intent

`src/risk/claude-proxy.js` lets `risk scan --use-claude-cli` use a developer's
Claude CLI login. It bound to `127.0.0.1`, accepted any POST whose URL contained
`chat/completions`, and started `claude --print` with the last user message. It
had no authentication, no `Origin`, `Host` or content-type check, and no
validation of the message shape. Measured with a fake `claude` on `PATH`: a
foreign-`Origin` `text/plain` POST reached the CLI and returned 200, and
`{"messages":{}}` threw `messages is not iterable` and stopped the process.

Loopback is not isolation: every local OS user, and any page a local browser
opens, can reach it. No browser exploit was demonstrated; the gap is that the
CLI was reachable by anything that could open a socket.

## Chosen approach

- **A token, set up on purpose.** The proxy refuses to start without
  `CICD_RISK_PROXY_TOKEN` (32+ characters) in its environment — never a flag,
  because argv is visible to other users — and removes it from the CLI's
  environment. `risk scan` takes `--llm-token` as a Dagger secret, and
  `--use-claude-cli` without it is refused before any file is collected
  (`resolveLLMEndpoint`, `src/risk/scanner.go`). The client sends it only in
  the `Authorization` header. There is no bypass flag, since a compatibility
  switch would be the default within a week.
- **Refuse before the CLI starts.** Only `POST /v1/chat/completions`, with the
  bearer token (compared in constant time), `Content-Type: application/json`,
  no `Origin`, and a `Host` of `127.0.0.1`, `localhost` or
  `host.docker.internal` on its own port (`--allow-host` adds a name). The body
  must be a JSON object with 1–64 messages of known roles and string or text-
  block content, and a non-empty user message.
- **Bounds.** Body (2 MiB), concurrent CLI processes (2, then 429), CLI output
  (1 MiB) and runtime (5 min), each a flag. A disconnect, timeout or output
  overrun kills the CLI's process group; each request runs in its own private
  temporary directory, removed on every exit path. The prompt goes to stdin, so
  no prompt file exists.
- **The CLI runs with nothing to act with.** `claude --print --tools ""
  --no-session-persistence --strict-mcp-config --disable-slash-commands`, never
  a permission-bypass flag. The proxy asks the installed CLI's `--help` for
  those flags at startup and refuses to run one that lacks any of them, instead
  of running it without.
- **No credential in failure feedback.** Proxy errors are fixed strings; the
  CLI's stderr is counted and neither returned nor logged. The Go client also
  removes the bearer token from a custom gateway's error body before limiting
  its length, because truncating first could expose a token prefix that a
  full-value scrub no longer recognises.

## Rejected

- *Rely on the `127.0.0.1` bind.* It stops other machines only.
- *A token in the URL or a flag.* URLs reach logs; flags reach `ps`.
- *Keep the stdin temp file.* Writing the prompt to stdin removes a file that
  had to be cleaned on every path.

## Proof

`src/risk/claude-proxy.test.js` starts the real proxy on loopback with
`src/risk/testdata/fake-claude/claude` first on `PATH` and covers: refusal to
start without a token or with a CLI lacking the flags; the exact CLI argv; 401,
403, 404, 405, 415, 400 and 413 refusals that never start the CLI and leave
the proxy serving; the concurrency, output and time caps; disconnect and
spawn-failure cleanup; stderr withheld; and the token absent from every
response, log line and the CLI's environment. `scripts/tests/test_claude_proxy.py`
runs it inside `make test-scripts`, which CI's lint-repo job runs.
`claude_proxy_client_test.go` drives the production Go client through the same
proxy, with and without the token. A local gateway that echoes Authorization
on an HTTP failure verifies that neither a whole token nor its truncated
prefix reaches the serialised error. The test failed before the client scrub
was added.

A real Dagger scan through `host.docker.internal` reached the authenticated
proxy and fake CLI, exported the findings and manifest, retained safe source,
and withheld ignored files and credential sentinels. No real model was called.

## Residue

The fake CLI stands in for the real one; whether `--tools ""` disables every
tool is the CLI's contract, checked by flag presence, not by behaviour. The
Dagger/proxy proof uses a fake CLI and does not establish a real model's
behaviour or its provider's retention policy.
