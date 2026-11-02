# Supply Chain Security

Protecting against vulnerabilities in dependencies and container images.

---

## Overview

Supply chain security focuses on managing risks from third-party code and container images that your application depends on.

### Key Risks

| Risk                  | Description                               |
| --------------------- | ----------------------------------------- |
| Known CVEs            | Published vulnerabilities in dependencies |
| Outdated Dependencies | Old versions with known issues            |
| License Compliance    | Incompatible or problematic licenses      |
| Supply Chain Attacks  | Compromised or malicious packages         |

### Defense Strategy

1. **Scan dependencies** - Identify known vulnerabilities
2. **Generate SBOM** - Track all components in your software
3. **Check licenses** - Ensure compliance with licensing requirements
4. **Scan containers** - Multi-layer image vulnerability analysis

The SBOM and the license check answer different questions and are not
interchangeable. The SBOM is an inventory: it records the license each component
declares. The license check is a verdict: it classifies those licenses and
compares them against a policy. A repository can hold a complete SBOM and still
have no idea whether anything in it is allowed to ship.

In cicd, the license check runs as its own step in the source gate
(`security.scanLicenses`) with its own evidence envelope, so a copyleft
dependency cannot consume the finding budget of the gate that exists to stop
exploitable code shipping. It defaults to `warn`: the findings and the policy
that produced them are recorded on every run, and a consumer opts into blocking
by setting `license-gate: gate`. There is no way to switch it off, because a
license verdict that can vanish is a license verdict nobody can rely on.

A license check can only judge the licenses it can read. A lockfile names
package versions, not licenses; Trivy reads a dependency's license from its
installed package metadata. For .NET, cicd restores the NuGet graph so each
package's `.nuspec` is there to read. For Go, it downloads every required
module from the Go module proxy so each module's licence file is there to read,
and names the modules the proxy does not serve (private modules) as not read.
For every other ecosystem it does not install the project, so a scan that read no declaration at all reports
`SKIPPED` and names the dependency inputs it could not read, rather than a
`CLEAN` that judged nothing.

### Allowing a license without allowing its category

`license-allow` takes Trivy's categories — `permissive`, `notice`,
`unencumbered`, `reciprocal`, `restricted`, `forbidden` — and individual
license names, in one comma-separated list. The distinction is the whole point.
A category is a cliff: `restricted` holds GPL-1.0, 2.0 and 3.0 *and* LGPL-2.0,
2.1 and 3.0, so a repository that needs one LGPL dependency cannot accept it
without accepting GPL everywhere. A name narrows the policy by exactly one
declaration:

```yaml
license-allow: permissive,notice,unencumbered,BlueOak-1.0.0
```

A name is matched against the **whole** declared string, normalised for case
and for runs of whitespace. cicd does not evaluate the operands of an
expression: an allowance for `MIT` does not cover `MIT OR GPL-3.0`, because
deciding that it should would require cicd to keep its own license table and
that table would be a second, quieter policy.

`unknown` is deliberately **not** an allowable category. It is not a class of
license; it is Trivy reporting that it could not classify a declaration, and
allowing it accepts every future unclassifiable declaration along with the one
in front of you. That is an off switch wearing a policy's clothes. Allow those
by name instead, one at a time.

Two kinds of name reach that case, and they are treated differently:

| Declared string | How to allow it | Why |
|---|---|---|
| `BlueOak-1.0.0` | `license-allow: …,BlueOak-1.0.0` | Shaped like an SPDX expression. It identifies a license, so it means the same thing wherever it appears. |
| `SEE LICENSE IN LICENSE` | `license-allow: …,example-sdk=SEE LICENSE IN LICENSE` | Not a license name — an instruction to open a file. The identical sentence appears in unrelated packages, so a global allowance would silence packages nobody has read. |

The residue is documented rather than hidden: a single token such as
`UNLICENSED` is indistinguishable from an identifier, so it is accepted
globally. And a bare all-lowercase word is refused outright, because
`permisive` is far more likely a misspelled category than a license nobody has
ever declared — which means a genuinely lowercase identifier such as `curl`
has to be scoped to its package.

Nothing is allowed silently. Every named allowance and its hit count is written
into the evidence, and an allowance that covered nothing is a warning. A policy
still carrying an exception for a package that stopped declaring it otherwise
looks exactly like a clean tree.

---

## Related Documentation

- [SAST](./sast.md) - Static Application Security Testing
- [DAST](./dast.md) - Dynamic Application Security Testing
- [Shift-Left Security](./shift-left.md) - Security integration principles
- [Remediation](./remediation.md) - Handling security findings
