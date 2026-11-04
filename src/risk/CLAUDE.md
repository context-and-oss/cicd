# risk module

Domain module: AI-driven repository risk analysis with OPA policy gate enforcement.

## Workflows

| Function | Returns | When |
|---|---|---|
| `Scan` | `(*dagger.Directory, error)` | Developer runs locally; output committed to repo |
| `Validate` | `(*dagger.File, error)` | CI gate; reads committed findings+decisions |
| `Check` | `error` | Dagger check directive; wraps Validate |
| `Report` | `(*dagger.File, error)` | Renders markdown from committed files |
| `Proxy` | `*dagger.File` | Exports claude-proxy.js for manual proxy use |

## Entry functions

```go
// AI scan — output is committed source artifacts (not pipeline evidence)
func (m *Risk) Scan(
    ctx context.Context,
    source *dagger.Directory,
    useClaudeCLI bool,             // +optional
    llmURL string,                 // +optional: custom proxy URL, mutually exclusive with useClaudeCLI
    maxLLMRetries int,             // +optional, +default=2
    llmToken *dagger.Secret,       // +optional: bearer token; required with useClaudeCLI
) (*dagger.Directory, error)       // findings.json + decisions.json + scan-manifest.json

// CI gate — evidence envelope
func (m *Risk) Validate(
    ctx context.Context,
    source *dagger.Directory,
    failOn string,                 // +default="HIGH"
    commitSha, branch, repoUrl string,
    diff *dagger.File,             // +optional: git diff <base>...HEAD; supplies
                                   // the change set infraScope "changed" narrows by
    infraScope string,             // +default="changed" | "tree"
) (*dagger.File, error)            // evidence.json
```

## Run locally

Use an authorized checkout's repository root. These are local inspection and
artifact-authoring examples, not CI enforcement. See the
[fresh validate-and-verdict recipe](README.md#usage) for CI. Before proxy use,
install and authenticate a supported Claude CLI; start the proxy separately
and wait for readiness before scanning with the same token environment.

```sh
(cd src/risk && dagger develop)   # once, generates internal SDK

# Validate (no risk files — passes with warning)
dagger -m ./src/risk call validate \
  --source ./testdata/go-app \
  --fail-on NONE \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path /tmp/risk-evidence.json

# Scan — Claude CLI auth (subscription/OAuth, no API key needed).
# Step 1: export the proxy and keep it running in a separate terminal:
dagger -m ./src/risk call proxy export --path ./claude-proxy.js
npm install -g @anthropic-ai/claude-code                 # once
export CICD_RISK_PROXY_TOKEN="$(openssl rand -hex 32)"   # required
node claude-proxy.js                                     # keep running

# Step 2: run the scan from a shell with the same token (connects to the
# running proxy on port 4000). Export to the repo root — findings.json and
# decisions.json appear there.
dagger -m ./src/risk call scan \
  --source . \
  --use-claude-cli \
  --llm-token env:CICD_RISK_PROXY_TOKEN \
  export --path .

# Scan — raw API key via dag.LLM() native mode
# Set ANTHROPIC_API_KEY securely in the environment first.
dagger -m ./src/risk call scan \
  --source . \
  export --path .

# Scan — enterprise OpenAI-compatible gateway
dagger -m ./src/risk call scan \
  --source . \
  --llm-url http://my-proxy:4000 \
  export --path .
```

> **Linux note:** `--use-claude-cli` connects to `host.docker.internal:4000` (Docker Desktop).
> On Linux, start the proxy on localhost and pass `--llm-url http://localhost:4000
> --llm-token env:CICD_RISK_PROXY_TOKEN` instead.

## Unit tests

```sh
(cd src/risk && GOWORK=off go test -tags unit_test ./...)
```

The `-tags unit_test` flag excludes the three dagger-dependent files (`scan.go`, `opa.go`,
`scanner_native.go`) that import `internal/dagger` — the generated SDK panics outside a Dagger
session. Pure helper functions (parsing, scoring, rendering) are tested without Dagger.

Requires `dagger develop` to have been run first (generates `internal/dagger/`).

`collect_test.go` runs the production collector script with `sh` and `git`;
`claude_proxy_client_test.go` starts `claude-proxy.js` with `node`. Both tools
are required — a missing one fails the suite, it never skips. The proxy's own
loopback suite is `claude-proxy.test.js` (`node --test`), run by
`scripts/tests/test_claude_proxy.py` in `make test-scripts` and CI.

## Key files

- `main.go` — `Risk` struct, `parseConftestViolations`, `shouldFail`
- `opa.go` — `Validate()` (the dag wiring only), `findRiskFiles()`, `errNoRiskFiles`, `execStderr()`
- `gating.go` — `gatedPassed()`: the verdict rule, byte-identical with
  `src/quality/gating.go` and `src/security/gating.go` (a `synced_files` group
  in `scripts/repo-inventory.json` fails `make check-surface` when a copy diverges)
- `validatereport.go` — **untagged**: `validateFold` (what the two conftest
  passes fold into; unparseable output is a non-run in `errors[]`, never zero
  violations), `buildValidateEnvelope()`, and `scanOutcome()` /
  `skippedIfNothingExamined()`, the outcome a `Validate` run states before the gate
- `riskinputs.go` — **untagged**: `parseRiskInputs()`, the findings/decisions
  pair parsed and merged into the one document the findings policy pass reads
- `conftestplan.go` — **untagged**: `conftestGroupPlan()`, the command line and
  the `/inputs/fNNNN` mount each infra file gets, so a repository path never
  reaches conftest's argv and a violation's filename resolves back to the tree
- `conftestrun.go` — `conftestFailureMessage()`/`boundedStderr()`: the `errors[]` entry for a conftest that could not run
- `scan.go` — `Scan()`, `Check()`, `Report()`, `Proxy()` (the dag wiring only)
- `collect.go` — **untagged**: `collectScript` (which files reach the model),
  `sensitivePathParts` (credential and Git-metadata classes withheld in the
  container and again in `parseCollected`), `buildScanManifest()`. Driven over
  real checkouts, worktrees and exports by `collect_test.go`
- `scanner.go` — LLM conversation interfaces and pure helpers (testable), and
  `resolveLLMEndpoint()`, which refuses `--use-claude-cli` without `--llm-token`
- `scanner_native.go` — `nativeConversation` (dag.LLM())
- `findings.go` — `Finding`/`Evidence`/`Decision`/`FindingsFile` types
- `report.go` — markdown report renderer
- `diffpaths.go` — **untagged**: `parseDiffPaths()`, byte-identical with `src/cross-cutting/intent/diffpaths.go` (and its `_test.go` with intent's), enforced by `synced_files`. A diff it cannot read (no `diff --git` header, no a/ and b/ prefixes) is refused before the scan, never read as a change that touched no infrastructure. See [specs/read-a-diff-with-one-parser.md](../../specs/read-a-diff-with-one-parser.md)
- `validate.go` — **untagged**: `infraFileType()`, `isTerraform()`, `diffChangeScope()`, `resolveInfraScope()`, `planInfraScan()`, and `infraPlanWarnings()` (`infraScopeWarnings()` plus `terraformNotAssessedWarning()`). The scoping rules live here, and not in `opa.go`, so `go test -tags unit_test` can drive them without a Dagger session — `opa.go` is `//go:build !unit_test` and the scoping decision inside it was unreachable from any test for as long as it was wrong
- `infrascope_test.go` — what the infra scan looked at, and what it could have
- `terraform_test.go` — Terraform is never handed to the ARM rules and is named as not assessed
- `schema.go` — verbatim copy of `src/internal/evidence/schema.go`
- `claude-proxy.js` — bundled Node.js OpenAI-compatible proxy wrapper: token,
  Host/Origin/content-type/route/schema checks, body/concurrency/output/runtime
  caps, CLI tools and session persistence off (verified from the CLI's `--help`).
  `claude-proxy.test.js` and `testdata/fake-claude/claude` are its tests and fake CLI
- `policy/findings/` — OPA rules for findings+decisions review enforcement
- `policy/infra/` — OPA rules for Azure ARM templates, Dockerfile, CI/CD pipeline files (no HCL2 rules: Terraform is not assessed)

## Exception: Scan returns *dagger.Directory

`Scan()` returns `(*dagger.Directory, error)` — a directory rather than a single file. The output — `findings.json` + `decisions.json` + `scan-manifest.json` — are committed source artifacts for human review (and audit), not pipeline evidence. `Validate()` is the CI-path function that returns the evidence envelope. All entry functions return proper Go errors; there are no `error.txt` files.

## Finding categories

The AI scan targets four areas that deterministic OPA policies cannot cover:

| Category          | Focus |
|-------------------|-------|
| `compliance`      | GDPR, ISO 27001, SOC 2, PCI DSS gaps requiring semantic understanding |
| `data_governance` | PII in logs/errors/configs, unclassified personal data, missing DPAs |
| `trust_boundary`  | Implicit service-to-service trust, missing tenant isolation, user input crossing boundaries |
| `lifecycle_risk`  | EOL runtimes, major version debt, deprecated crypto, missing runbooks |

OPA-covered territory (SHA pinning, Dockerfile USER, Azure ARM settings, etc.) is explicitly
excluded from the AI prompt to avoid duplication.

## Constraints

- `--use-claude-cli` and `--llm-url` are mutually exclusive, and
  `--use-claude-cli` needs `--llm-token` (a Dagger secret, sent only as a bearer
  header — never in a URL, error, log or the manifest).
- **The collector never guesses which files exist.** Git lists them: a checkout
  through its own metadata, an export through a scratch repository outside the
  tree (so its `.gitignore` files apply and nothing is written into it). A
  worktree or submodule whose `.git` file points outside the mount is refused
  with the remedy, never walked with `find` — that fallback is what sent a
  worktree's ignored `.npmrc` and `credentials.json` to the model. No git in the
  image is a refusal too. The image is the pinned gitleaks image, for its git;
  nothing is installed at run time.
- **The infra scope is named by the caller, never inferred.** `--infra-scope
  changed` evaluates only the files the supplied diff touched; `tree` evaluates
  every parseable file in the checkout and ignores the diff. An unrecognised
  value is a hard error before anything runs — falling back to `tree` would turn
  a typo into a scan nobody asked for, and falling back to `changed` into a scan
  that looks at almost nothing. The switch has no `default:` arm. Precommit takes
  `changed` (a pull request owns the infra it changes); commit takes `tree`.
- **`examined` states both numbers.** `Count` is what conftest read, `Total` is
  what it could have read — same unit, which is the one shape `Examined` allows a
  total to take. A candidate is a file this scanner has a *parser* for, counted
  before the scope narrows anything, so a repository of Bicep does not carry a
  denominator no change can move. Without `Total`, SKIPPED with `count: 0` is
  byte-for-byte what a repository with no infrastructure reports, and a consumer
  read their own board as "nothing to scan here" for weeks.
- Missing risk files: `Validate` passes with a warning in `errors[]`.
- Findings below 0.6 confidence are dropped before output.
- OPA `*_test.rego` files are excluded from conftest runs.
- **A conftest that could not run is never a violation.** It used to be: an exec
  failure in the infra pass was appended to the report as a synthetic HIGH
  `conftest exec failed`, counted in `findingsCount`, and then *suppressed* by
  `--fail-on NONE` — so a policy engine that never started reported clean, having
  first invented a policy failure. Failures now go to `errors[]` with `ran=false`,
  and `parseConftestViolations` returns an error rather than fabricating a finding.
  See [specs/prove-the-policy-engine-ran.md](../../specs/prove-the-policy-engine-ran.md).
- **An empty conftest result is not an empty verdict.** conftest v0.58.0 writes
  one result per input file, even one no namespace matched (measured), so `[]`
  or `null` is refused as output that evaluated nothing, and an infra group whose
  output never names one of its mounted files is a non-run naming that file —
  the violations conftest did report are still counted. `findings.json` must
  carry a `findings` array and `decisions.json` must be an object: `null` and
  `{}` used to pass as a review that found nothing. `nonrun_matrix_test.go`
  holds all three.
- **A result that evaluated no rule is not clean.** conftest names a file and
  writes `successes: 0` with nothing else when the namespace it was asked for
  has no package (measured, v0.58.0), and that read CLEAN at every threshold.
  `conftestRulesEvaluated` sums successes, failures, warnings and exceptions
  per file across namespaces (`--all-namespaces` writes one row per namespace,
  the `*_test` packages at 0); a file that sums to 0 is a non-run naming it, in
  both passes. `policynamespace_test.go` fails a package rename before it
  reaches a run. See
  [specs/a-policy-that-evaluated-no-rule-is-not-clean.md](../../specs/a-policy-that-evaluated-no-rule-is-not-clean.md).
- **Terraform is reported as not assessed, never as clean.** Every `risk.azure`
  rule iterates `input.resources`, the ARM array, and HCL2 parses to
  `input.resource`, so a `.tf` file handed to them passed every rule vacuously (a
  one-resource `main.tf` measured `successes: 24`) and the rule count above
  could not see it. `.tf`, `.tf.json` and `.hcl` are now routed to no conftest
  group and are not candidates; `planInfraScan` lists the ones in scope as
  `NotAssessed`, and `risk: TERRAFORM NOT ASSESSED` names them in `warnings[]`
  (the payload carries `infraFilesNotAssessed`). A Terraform-only tree reads
  SKIPPED and passes at every threshold; a mixed tree stays graded on what
  conftest read. Assessing Terraform needs HCL2 rules, which do not exist yet.
  See [specs/report-terraform-as-not-assessed.md](../../specs/report-terraform-as-not-assessed.md).
- **The verdict is `gatedPassed(ran, severityOK, threshold)`, never `!shouldFail`
  alone.** `ran=false` fails at every threshold including `NONE`; `NONE` suppresses
  only the severity half. Any new gate leg in this module must be folded into `ran`,
  not into the severity counts.
- **The two passes fail differently, on purpose.** The findings/decisions pass
  (`opa.go`) returns a hard Go error, because it fails before there is an envelope to
  put anything in. The infra group loop reports into `errors[]` and fails the gate,
  because it can still emit evidence naming the group that broke. A failure that can
  be described as evidence is; one that cannot stays an error.
- **`Tool.Version` is the hardcoded pin `conftest:v0.58.0`, not what ran.** Known
  residue — do not read it as an observation.
