# Vulnerability Remediation

Workflow for handling security findings from detection to resolution.

## Remediation Workflow

```text
Detection → Triage → Prioritize → Remediate → Verify → Document
```

### 1. Detection

- Automated scanning finds vulnerability
- Alert sent to team
- Issue created in tracking system

### 2. Triage (within 24 hours)

- Assess severity and impact
- Determine exploitability
- Identify affected systems

### 3. Prioritize

| Priority | Severity | Fix Timeline examples |
| -------- | -------- | --------------------- |
| P0       | Critical | 24 hours              |
| P1       | High     | 7 days                |
| P2       | Medium   | 30 days               |
| P3       | Low      | Next sprint           |

### 4. Remediate

- Update dependency to patched version
- Apply security patch
- Implement workaround if patch unavailable
- Add compensating controls

### 5. Verify

- Re-run security scans
- Validate fix is effective
- Ensure no regression

### 6. Document

- Record in vulnerability tracking system
- Update knowledge base
- Share learnings with team

## Blocking Strategy

Configure pipelines to block on security findings based on severity.

| Severity      | Action          | Pipeline Impact   |
| ------------- | --------------- | ----------------- |
| Critical/High | Block pipeline  | Deployment halted |
| Medium        | Warn and review | Requires approval |
| Low           | Informational   | Track in backlog  |

Configure your security scanner to enforce severity thresholds and control pipeline behavior.

## Accepting a Vulnerability

Some findings are real, unfixable today, and not worth blocking on — an
unpatched upstream, a code path the deployment never reaches. Accept them where
the acceptance stays visible.

### `--vuln-accept` (recommended)

```yaml
vuln-accept: |
  CVE-2026-81871=the otel log exporter only reaches the build engine's own telemetry endpoint on the runner, never a peer we do not control
  CVE-2026-39882=same exporter, same endpoint, same reasoning
```

The `vuln-accept` input takes one acceptance per line as `<id>=<reason>`. A
reason is mandatory and patterns are refused, so an acceptance always names one
identifier a human has read.

**One acceptance per line, and a reason cannot wrap.** The line break is the
separator, so a reason continued on the next line is read as a second
acceptance and refused for naming no identifier. Write the reason on one long
line — a YAML literal block (`|`) takes any length — and do not indent it into
a shape that looks like a continuation. Commas inside a reason are safe and are
the reason the separator is not a comma; `license-allow`, which takes
identifiers rather than prose, is comma-separated.

What it does to the scan: the finding still happens. The row leaves the severity
counts, `findings[]` and the gate, and arrives in the evidence as a
`security: VULN ACCEPTED` warning quoting the identifier, the number of findings
it covered and the reason as written. It stays in the CycloneDX report attached
to the evidence. When the upstream fix lands and the finding stops appearing,
the acceptance reports `VULN ACCEPTANCE UNUSED` — which is the signal to delete
it rather than renew it.

### `.trivyignore` (still honoured, no longer recommended)

Trivy auto-loads a `.trivyignore` from the root of the scanned repository, and
cicd does not neutralise it. But it drops rows *before the report is written*,
so the acceptance and its reasoning never reach the evidence: the counts are
simply lower, and nothing distinguishes that from a repository where the
vulnerability was never present. cicd emits a
`security: SCAN NARROWED BY .trivyignore` warning when it sees one, naming the
file — it cannot name what the file suppressed.

Note `.trivyignore.yaml` (the richer form with `statement`/`expired_at`) is not
auto-loaded at all and suppresses nothing.

### Best Practices

- Write the reason where the reader of the evidence will see it
- Name one identifier per acceptance, never a pattern
- Give every acceptance a removal condition, and delete it when the acceptance
  reports itself unused

## Security Metrics

Track these metrics to measure security posture:

| Metric              | Description                  |
| ------------------- | ---------------------------- |
| MTTD                | Mean Time To Detect          |
| MTTR                | Mean Time To Remediate       |
| Vulnerability Count | Open issues by severity      |
| Scan Coverage       | % of code/containers scanned |

## Evidence Collection

For compliance and audit:

- Store scan reports as artifacts
- Link findings to commits
- Maintain audit trail
- Generate compliance reports

## Best Practices

### Tool Maintenance

- Update Trivy vulnerability database daily
- Keep OWASP ZAP updated
- Enable Dependabot for all repositories and all modules

### Developer Education

- Secure coding training
- Understanding OWASP Top 10
- How to interpret scan results
- How to remediate vulnerabilities

### Continuous Improvement

- Review blocking thresholds quarterly
- Analyze false positive rates
- Update scan configurations
- Share learnings across teams
