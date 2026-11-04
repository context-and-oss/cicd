# AI Risk Analysis

The `risk` module adds a layer of AI-driven holistic risk analysis on top of traditional
tool-based scanning. Where SAST and secrets scanners match known patterns, the risk module
uses an LLM to reason across the whole repository — surfacing risks that rule-based tools
miss, such as architectural identity access issues, implicit data exposure in configuration,
and unreviewed third-party integration contracts.

---

## How It Differs from SAST and OPA

| Dimension           | SAST / OPA policies                      | AI Risk Analysis                              |
| ------------------- | ---------------------------------------- | --------------------------------------------- |
| Detection method    | Pattern matching, rule evaluation        | Semantic reasoning across multiple files      |
| False positive rate | Very low (deterministic)                 | Higher (mitigated by 0.6 confidence threshold)|
| Novel risk coverage | Limited to known patterns and rules      | Can surface contextual and regulatory risks   |
| Scope               | Single file at a time                    | Cross-file reasoning, intent understanding    |
| Output              | Violations with IDs and remediation      | Findings with human review required           |

The OPA policies (`policy/infra/`) deterministically gate GitHub Actions SHA pinning, Dockerfile
security, and Azure resource configuration. The AI scan explicitly skips those areas — it focuses
on what deterministic tools cannot reason about.

---

## Risk Categories

The module targets four categories that require semantic understanding:

| Category          | What it finds                                                                         |
| ----------------- | ------------------------------------------------------------------------------------- |
| `compliance`      | GDPR, ISO 27001, SOC 2, PCI DSS gaps: missing consent paths, no audit trail, personal data without legal basis |
| `data_governance` | PII in logs/errors/configs, personal data in API payloads without DPA, unclassified sensitive fields |
| `trust_boundary`  | Service-to-service implicit trust, user input crossing validation boundaries, missing tenant isolation |
| `lifecycle_risk`  | EOL runtimes, major version debt, deprecated cryptography, missing operational runbooks |

---

## Workflow

The risk module has a **commit-then-gate** design: findings are generated locally, reviewed by
a human, and then gated in CI. This keeps AI output under human control.

```text
Developer                           CI
─────────                           ──
dagger call risk scan               dagger call risk validate
  → findings.json                     reads findings.json
  → decisions.json  ←── review ──→    reads decisions.json
  (commit both)                       returns evidence.json
```

**`findings.json`** — AI output. Each finding has severity, confidence (0–1), category,
and evidence (file, line range, snippet). Findings below 0.6 confidence are dropped automatically.

**`decisions.json`** — Human review scaffold. For each finding, record a `status` of `approved`, `accepted_risk`, or `rejected` with a reason. Findings default to `needs_review`. CI fails if any high/critical finding still has `needs_review` status.

---

## OPA Policy Enforcement

Validate runs two OPA passes via conftest:

1. **findings+decisions review** — enforces that every finding has been reviewed
   (policy in `risk/policy/findings/`)
2. **infra file scanning** — runs OPA rules against Dockerfiles, ARM templates, and
   pipeline YAML files directly (policy in `risk/policy/infra/`)

The `--fail-on` threshold controls which finding severities fail the evidence
verdict (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `NONE`). `NONE` suppresses failures
over findings, never a non-run. A CI caller must grade the fresh envelope's
`passed` value rather than assume exporting it enforced a gate. Deterministic
validation of recorded decisions supplies no human identity verification or
release approval.

Deterministic infra findings can be accepted only with exact synthetic keys in
`decisions.json`: `policy:<policy-id>:<repo-relative-file>:<resource>`. For example:

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

The override must match the policy id, file path, and resource/action exactly. It
requires `accepted_risk`, `justification`, `reviewed_by`, and `reviewed_at`; dates
use `YYYY-MM-DD` or RFC3339. An optional expired or invalid `expires_at` makes the
override inactive. Accepted deterministic findings are included in
`genericReport.overriddenViolations` so they remain visible in validation evidence.
Non-overridden violations are also emitted as SARIF, using the policy id as the
rule id and the repository-relative file as the physical location, so composite
runs publish the infrastructure-policy findings to GitHub Code Scanning.

---

## LLM Options

The scan function supports three authentication modes — no vendor lock-in:

| Mode | Flag | Auth |
| ---- | ---- | ---- |
| Claude CLI proxy | `--use-claude-cli --llm-token env:CICD_RISK_PROXY_TOKEN` | CLI subscription (no API key); the local proxy only answers requests carrying its token |
| OpenAI-compatible gateway | `--llm-url http://host:port` (optional `--llm-token`) | Gateway-specific |
| Native `dag.LLM()` | _(neither flag)_ | `ANTHROPIC_API_KEY` env var |

Every mode sends repository file **contents** to the model. Git decides which
files exist (a worktree whose metadata is not mounted is refused rather than
walked), credential and Git-metadata files are withheld whether tracked or not,
and `scan-manifest.json` lists every path that was sent. A secret pasted into an
ordinary source file is not withheld — the path policy is not a secrets
scanner. The full boundary, and what the Claude CLI proxy refuses, is in the
[risk module README](../../../../src/risk/README.md#what-the-scan-sends-to-the-model).

---

## Stage Integration

| CD Stage | Role |
| -------- | ---- |
| **Stage 2 (pre-commit)** | `dagger check` runs validate automatically |
| **Stage 3 (PR gate)** | CI calls validate, blocks on unreviewed high/critical findings |
| **Stage 9 (release)** | Evidence envelope included in release audit trail |

Findings are generated once (by the developer) and committed. CI only validates — it does
not regenerate findings, keeping CI times predictable and LLM calls off the hot path.

---

## Related

- [risk module README](../../../../src/risk/README.md) — install and usage
- [Shift-Left Security](shift-left.md) — where risk analysis fits in the CD Model
- [AI-Assisted Defect Detection](../quality-gates/defect-prevention/ai-detection.md) — broader AI strategy
- [SAST](sast.md) — complementary tool-based scanning
