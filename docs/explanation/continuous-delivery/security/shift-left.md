# Shift-Left Security

Security integrated throughout all stages of the CD Model, not bolted on at the end.

## What is Shift-Left Security

The following diagram illustrates the cost of fixing security vulnerabilities at different stages,
from IDE ($1x) through Production ($1000x+).

The earlier issues are caught, the cheaper they are to fix.

![Shift-Left Security Cost Timeline](../../../assets/assisted/14-shift-left-security.drawio.png)

Traditional security tests late in the cycle:

- Security testing after development complete
- Vulnerabilities discovered near release
- Expensive to fix, delays release

Shift-left moves testing earlier:

- Security integrated from Stage 2 (Pre-commit)
- Vulnerabilities caught during development
- Fast feedback, cheap fixes

**Cost of fixing vulnerabilities:**

| Stage Found | Relative Cost |
| ----------- | ------------- |
| Development | 1x            |
| Testing     | 10x           |
| Production  | 100x          |

## Defense in Depth

Multiple security layers protect against different threat vectors:

| Layer                                  | Description                             | Tool              |
| -------------------------------------- | --------------------------------------- | ----------------- |
| [SAST](sast.md)                        | Static analysis before code runs        | Opengrep          |
| [DAST](dast.md)                        | Dynamic testing of running applications | OWASP ZAP         |
| [Dependency Scanning](supply-chain.md) | Identifying vulnerable libraries        | Trivy, Dependabot |
| [Container Security](supply-chain.md)  | Multi-layer image scanning              | Trivy             |

No single layer is perfect - overlapping layers provide comprehensive coverage.

## Security by Stage

| Stage                 | Security Activities                   | Tools             | Duration   |
| --------------------- | ------------------------------------- | ----------------- | ---------- |
| **Pre-commit (2)**    | Full fast suite: lint/test, SAST, secret scan, dependency scan, risk gate (light configs), plus the opt-in change-intent gate | Opengrep, Gitleaks, Trivy | < 2 min    |
| **Pull Request (3)** | SAST, dependency scan, container scan | Opengrep, Trivy, Dependabot | < 5 min |
| **Commit (4)**        | Heavy code + artifact gate: full source suite plus artifact SBOM/scan per shape (`--artifact container\|archive\|none`) | Opengrep, Gitleaks, Trivy | < 10 min   |
| **Acceptance (5)**    | DAST baseline scan                    | OWASP ZAP         | < 15 min   |
| **Extended (6)**      | DAST full scan                        | OWASP ZAP         | 1-4 hours  |
| **Deployment (10)**   | Final container scan                  | Trivy             | < 5 min    |
| **Production (11)**   | Continuous DAST monitoring            | OWASP ZAP         | Continuous |

## Why Open-Source Tools

The stack includes open-source engines, but that does not license every runtime
input. The default SAST rules come from the Semgrep rules repository and are fetched under the restrictive, non-Apache
Semgrep Rules License: review [internal-use, hosted-service and redistribution limits](../../../../THIRD_PARTY_NOTICES.md#default-semgrep-rules--semgrep-rules-license-v10-not-apache-20).
The stage matrix above is conceptual beyond cicd's implemented source/artifact
and separately scheduled DAST pipelines, not an automatic deployment workflow.

| Tool           | Purpose               | Why                                 |
| -------------- | --------------------- | ----------------------------------- |
| **Trivy**      | Multi-purpose scanner | Dependency and image scanning   |
| **OWASP ZAP**  | DAST                  | Industry standard, active community |
| **Dependabot** | Dependency updates    | GitHub-native, zero setup           |

Review each engine, rule pack and service's terms for your intended use; a free
engine does not imply unrestricted rules or legal clearance.

## Benefits

- **10-100x cheaper** to fix vulnerabilities early
- **Faster releases** - no last-minute security blocks
- **Developer education** - learn secure coding practices
- **Better posture** - proactive, continuous validation
