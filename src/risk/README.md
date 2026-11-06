# risk

AI-driven repository risk analysis with OPA policy enforcement. Scans source files with an
LLM to surface identity, data, integration, infrastructure, and automation risks.
Returns findings as committed JSON artifacts; Validate gates CI against them.

## Install

Public modules support anonymous fetching; private copies require read-only
source access. Verify the referenced release, or use `-m ./src/risk` from a
separate source checkout's root. Source credentials are separate from
model/proxy authentication.

```bash
dagger -m github.com/context-and-oss/cicd/src/risk@v5.1.6
```

## Usage

Before using the CLI proxy, install Node.js and the Claude CLI, authenticate the
CLI through its supported login flow, and confirm it supports the restricted
flags listed below. Export the proxy, generate the token and start it in a
separate terminal; run the scan with the same token in its environment only after
the proxy is ready. The default CLI endpoint uses Docker Desktop's
`host.docker.internal:4000`; Linux setups must configure a reachable proxy URL
through `--llm-url` instead. The model receives source contents: review the
collection policy below before scanning. The explicit URL must be reachable
from the Dagger module container: its `localhost` is not the host terminal's.
Choose one scan option, not all three.

```bash
# Step 1 — scan (run locally, commit the output)
# Option A: Claude CLI proxy (no API key needed — uses your CLI subscription)
dagger -m github.com/context-and-oss/cicd/src/risk@v5.1.6 call proxy export --path ./claude-proxy.js
export CICD_RISK_PROXY_TOKEN="$(openssl rand -hex 32)"   # the proxy refuses to start without it
node claude-proxy.js     # keep running; use a second terminal for the scan
# In that second terminal, with the same token in the environment:
dagger -m github.com/context-and-oss/cicd/src/risk@v5.1.6 call scan --source . --use-claude-cli \
  --llm-token env:CICD_RISK_PROXY_TOKEN export --path .

# Option B: native dag.LLM() (requires ANTHROPIC_API_KEY)
# Set ANTHROPIC_API_KEY securely in the environment, not in shell arguments.
dagger -m github.com/context-and-oss/cicd/src/risk@v5.1.6 call scan --source . export --path .

# Option C: explicit OpenAI-compatible URL (Docker Desktop; same running proxy/token)
dagger -m github.com/context-and-oss/cicd/src/risk@v5.1.6 call scan --source . --llm-url http://host.docker.internal:4000 \
  --llm-token env:CICD_RISK_PROXY_TOKEN export --path .

```

Review all generated files for accuracy and sensitive content, then commit
`findings.json`, `decisions.json` and `scan-manifest.json`. An authorized human
owns the decisions (`approved`, `accepted_risk` or `rejected`); generation is
not review or approval.

```bash
# Validate in CI (set SHA and REPO_URL; requires Dagger and jq)
set -eu
rm -f ./evidence.json
dagger -m github.com/context-and-oss/cicd/src/risk@v5.1.6 call validate \
  --source=. --fail-on=HIGH \
  --commit-sha="$SHA" --branch=main --repo-url="$REPO_URL" \
  export --path=./evidence.json || exit 1
jq -e '.passed == true' ./evidence.json >/dev/null || exit 1

# Render a markdown report (inspection, not a gate)
dagger -m github.com/context-and-oss/cicd/src/risk@v5.1.6 call report --source . export --path risk-report.md
```

Export success alone does not enforce `validate`'s verdict; missing/malformed
JSON must fail, as above. Retain warnings, errors, accepted-risk records and
examined/scope metadata. `passed` does not prove that all source, infrastructure
or risks were assessed, or that human review occurred.

## Functions

| Function   | Returns              | Description |
|------------|----------------------|-------------|
| `scan`     | `*Directory`         | AI analysis → `findings.json` + `decisions.json` + `scan-manifest.json` (commit all three) |
| `validate` | `(*File, error)`     | OPA gate: reads committed files, returns evidence envelope |
| `check`    | `error`              | Dagger check directive — wraps `validate` with `--fail-on HIGH` |
| `report`   | `*File`              | Markdown summary from committed findings and decisions |
| `proxy`    | `*File`              | Exports `claude-proxy.js` for the `--use-claude-cli` workflow |

## What the AI looks for

The scan targets four areas that OPA and SAST tools cannot reason about:

| Category          | Examples                                                                         |
|-------------------|----------------------------------------------------------------------------------|
| `compliance`      | GDPR consent path missing, no audit trail for privileged ops, ISO 27001 gaps    |
| `data_governance` | PII in log statements, personal data in API payloads without a DPA, unclassified fields |
| `trust_boundary`  | Internal services called without token/mTLS, user input crossing validation boundaries, missing tenant isolation |
| `lifecycle_risk`  | EOL runtimes, many-major-version debt, deprecated crypto (MD5/SHA-1/ECB), missing runbooks |

OPA deterministically covers GitHub Actions SHA pinning, Dockerfile security, and Azure resource
configuration — the AI scan explicitly skips those to avoid duplicate findings.

## What the scan sends to the model

`scan` sends file **contents** to the model you choose — to Anthropic through the
Claude CLI or `dag.LLM()`, or to whatever `--llm-url` names. Which files:

- **Git decides which files exist.** In a checkout (`.git` is a directory), the
  tracked files plus untracked files your `.gitignore`, `.git/info/exclude` and
  repository config do not exclude. A worktree or submodule (`.git` is a file)
  is refused unless its repository metadata is inside `--source` — it usually
  is not, because the pointer names a host path Dagger does not mount; scan the
  main checkout, or `git archive --format=tar HEAD | tar -x -C <empty-dir>` and
  scan that. A tree with no `.git` at all is filtered by the `.gitignore` files
  inside it only — an exclude kept in another clone's `.git/info/exclude` or a
  global excludes file is not visible there.
- **Credential and metadata classes never leave, tracked or not.** `.git`, `.hg`
  and `.svn` contents; `.npmrc`, `.yarnrc(.yml)`, `.netrc`, `.pypirc`, `pip.conf`,
  `NuGet.Config`, `.git-credentials`, `.gitconfig`, `credentials.*`/`secrets.*`
  config files; `.ssh`, `.gnupg`, `.aws`, `.azure`, `.kube` and gcloud
  directories, kubeconfigs, SSH keys, CI-written `gha-creds-*.json` and
  `.vault-token`; key/certificate/keystore/keytab files; `.env*`; Terraform
  state and variables. Symlinks — a file or any directory above it — are never
  followed. The list is
  `sensitivePathParts` in [`collect.go`](collect.go), applied in the container
  and again in Go.
- **Everything else that fits.** Up to 100 KB in total, 16 KB per file, binary
  and generated/vendored noise skipped. A secret written into an ordinary source
  file *is* sent; this is a path policy, not a secrets scanner — run
  `security scan-source` for that.

`scan-manifest.json` lists every path that was sent and records which ignore
rules applied (`ignore_rules`: `git` or `tree-gitignore`). The collector also
refuses a `.git` that is a symlink, a repository whose config moves its work
tree away from `--source`, and a path filter that could not run, and switches
off the repository-config keys git would otherwise run commands from while it
lists files. A collection with no file to send is an error, never an empty
review.

### The Claude CLI proxy

`claude-proxy.js` binds to `127.0.0.1` only, but loopback is reachable by every
OS user on the machine and by any web page your browser opens, so it also:

- refuses to start without `CICD_RISK_PROXY_TOKEN` (32+ characters), read from
  the environment — never a flag, which other users could read in `ps` — and
  removed from the CLI's environment;
- answers only `POST /v1/chat/completions` with `Authorization: Bearer <token>`,
  `Content-Type: application/json`, no `Origin` header, and a `Host` of
  `127.0.0.1`, `localhost` or `host.docker.internal` on its port (add a name
  with `--allow-host`); everything else is refused before the CLI starts;
- validates the message shape, caps the body (2 MiB), concurrent CLI processes
  (2), CLI output (1 MiB) and runtime (5 min) — see `--max-body-bytes`,
  `--max-concurrent`, `--max-output-bytes`, `--timeout-ms` — and kills the CLI
  when the client disconnects or the time runs out;
- runs `claude --print --tools "" --no-session-persistence --strict-mcp-config
  --disable-slash-commands` in an empty private directory: no tools, no MCP
  servers, no skills, no saved session, no permission bypass. It checks the
  installed CLI's `--help` for those flags at startup and refuses to run a CLI
  that lacks any of them;
- never returns or logs the CLI's stderr; a failure says to run `claude --print`
  by hand.

`scan --use-claude-cli` requires `--llm-token`, passed as a Dagger secret
(`env:CICD_RISK_PROXY_TOKEN`), and sends it only in the `Authorization` header.

## Workflow

Scan produces three files you commit to the repo:

- **`findings.json`** — AI-identified risks with category, severity, confidence, and evidence
- **`decisions.json`** — scaffold for human review: accept, reject, or suppress each finding
- **`scan-manifest.json`** — audit trail: which files were sent to the LLM, their sizes, and the LLM mode used. Paths only, no content.

CI reads `findings.json` + `decisions.json` via `validate`; the manifest is for human/incident-response review. Missing files pass with a warning for bootstrap; that is not proof of an AI scan or human review.

### Deterministic OPA policy overrides

`validate` also runs deterministic OPA checks for infrastructure and pipeline files. These findings normally fail according to `--fail-on`, but a precise finding can be accepted in `decisions.json` with a synthetic key:

```json
{
  "policy:PIPE-003:.github/workflows/triage.yml:example-org/triage-action@v1": {
    "status": "accepted_risk",
    "justification": "Internal action owned by our org; v1 is the supported package channel.",
    "reviewed_by": "security-lead",
    "reviewed_at": "2026-06-23",
    "expires_at": "2026-09-23"
  }
}
```

`--infra-scope` selects which infrastructure files the deterministic checks read: `changed`
(the default — only the files named in `--diff`) or `tree` (every parseable file in the checkout).
The precommit composite uses `changed`, because a pull request gate scans the pull request; the
commit composite uses `tree`, because a file is not correct merely because nobody touched it. The
evidence states both numbers — `examined.count` is what was scanned, `examined.total` is how many
files the scanner has a parser for — and a scope that excluded anything says so in `warnings[]`.
Conftest has no Bicep parser, so `.bicep` files are counted in neither number.

Every non-overridden policy violation is also emitted in the envelope's SARIF report, with the
policy id as `ruleId` and the repository-relative file as its physical location. The composite
evidence bundle merges that run into `findings.sarif`, so the same findings reach GitHub Code
Scanning instead of existing only in the risk-specific JSON payload.

The key must match the exact policy id, repo-relative input file path, and resource/action string emitted by the OPA finding. Broad suppressions such as `policy:PIPE-003` are ignored. Only `accepted_risk` suppresses a deterministic finding, and `justification`, `reviewed_by`, and `reviewed_at` are required. Dates use `YYYY-MM-DD` or RFC3339. `expires_at` is optional; expired or invalid expiry dates do not suppress. Accepted deterministic findings are still recorded in the validation evidence under `genericReport.overriddenViolations`.

## Docs

→ Full documentation at [docs/](../../docs/index.md)
