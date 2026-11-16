# SAST (Static Application Security Testing)

Static analysis examines source code without executing it (white-box testing).

cicd uses Opengrep (the LGPL-2.1 fork of the Semgrep engine, reading the same
rule language) for SAST, Gitleaks for source secrets and Trivy for dependency
vulnerabilities. The default SAST rules are fetched at runtime, not bundled or
relicensed as Apache-2.0. The restrictive Semgrep Rules License distinguishes
internal use from hosted-service operation and redistribution: read
[the licensing boundary](../../../../THIRD_PARTY_NOTICES.md#default-semgrep-rules--semgrep-rules-license-v10-not-apache-20)
and the [upstream terms](https://semgrep.dev/legal/rules-license). A checked-in
custom rules config must have terms suitable for your use.

---

## Overview

SAST analyzes code structure and patterns to identify potential vulnerabilities before the code runs.

### What It Detects

| Vulnerability              | Description                          |
| -------------------------- | ------------------------------------ |
| SQL Injection              | Unsanitized database queries         |
| Cross-Site Scripting (XSS) | Unescaped user input in HTML         |
| Hardcoded Secrets          | API keys, passwords in code          |
| Insecure Cryptography      | Weak algorithms, bad implementations |
| Path Traversal             | Unsafe file path handling            |
| Command Injection          | Unsafe system command execution      |

### Benefits

- Catches issues before code runs
- Fast feedback (seconds to minutes)
- Identifies exact code location
- No runtime environment needed

### Limitations

- False positives require tuning
- Can't detect runtime-only issues
- Requires language-specific analyzers
- May miss business logic flaws

---

## Related Documentation

- [DAST](./dast.md) - Dynamic Application Security Testing
- [Supply Chain Security](./supply-chain.md) - Dependency and container scanning
- [Shift-Left Security](./shift-left.md) - Security integration principles
