# Security

Security concepts across the CD Model and the tools used by cicd's implemented
source, artifact and running-app scans. The model is broader than the runtime.

Default Semgrep rules are fetched at runtime under the restrictive Semgrep Rules
License, not Apache-2.0. Internal use, hosted-service use and redistribution have
different limits; read [the licensing boundary](../../../../THIRD_PARTY_NOTICES.md#default-semgrep-rules--semgrep-rules-license-v10-not-apache-20).

## In This Section

| Topic                                | Description                                                         |
| ------------------------------------ | ------------------------------------------------------------------- |
| [Shift-Left Security](shift-left.md) | Philosophy, defense in depth, and stage integration matrix          |
| [SAST](sast.md)                      | Static Application Security Testing with Semgrep                      |
| [DAST](dast.md)                      | Dynamic Application Security Testing with OWASP ZAP                 |
| [Supply Chain](supply-chain.md)      | Dependency scanning, Dependabot, and container security             |
| [Remediation](remediation.md)        | Vulnerability workflow, blocking strategy, and best practices       |
| [AI Risk Analysis](risk-analysis.md) | LLM-driven repository risk scanning with OPA policy enforcement     |

## Tools

| Tool                                                              | Purpose                        | Cost |
| ----------------------------------------------------------------- | ------------------------------ | ---- |
| [Semgrep](https://semgrep.dev/) | SAST | Engine and rules have separate licence terms |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Source/output secrets | Free |
| [Trivy](https://aquasecurity.github.io/trivy/) | Dependency vulnerabilities, licences, containers | Free |
| [OWASP ZAP](https://www.zaproxy.org/)                             | DAST for web applications      | Free |
| [Dependabot](https://docs.github.com/en/code-security/dependabot) | Automated dependency updates   | Free |
| [risk module](../../../../src/risk/README.md)                         | AI-driven risk analysis + OPA gate | Claude API / CLI |
