# Stop silently passing gates that never scanned

## Intent

A shadow run of the source gate against a large real repository returned
`passed=true` while five of its legs had not actually scanned anything. Every leg
here reports zero findings both on a clean tree and on a tool that never
executed, and nothing in the repository distinguished the two. The trust story of
this repository is that a green verdict is evidence; that was false, so the
verdict had to be made falsifiable.

## Chosen approach

Each leg now proves it ran, and a leg that cannot prove it fails the gate:

- Trivy is given `--scanners vuln`, because `--format cyclonedx` alone switches
  it into SBOM-only mode and disables security scanning entirely.
- Semgrep's `auto` ruleset is rejected outright — it cannot coexist with the
  `--metrics=off` this repository always sets — and the default becomes
  `p/security-audit`. The `|| echo '{"runs":[]}'` fallback that turned that
  refusal into a clean report is gone; `semgrepRunError` classifies the exit
  status, stderr and report shape instead.
- SARIF levels resolve through `rules[].defaultConfiguration.level` per SARIF
  2.1.0 §3.27.10, because Semgrep OSS sets no level on any result.
- The Node lint leg records ESLint's exit status rather than swallowing it, so a
  linter that could not run lands in `errors[]`.

The non-run logic lives in untagged Go files (`semgreprun.go`, `eslintreport.go`,
`findings.go`) so the module unit suites can drive it without a Dagger session,
and CI asserts on the evidence — a loaded rule count and a non-zero
vulnerability count — rather than on `passed`.

## Expected result

A scanner that does not execute produces `passed=false` with a reason in
`errors[]`. Vulnerability and SAST findings that were previously invisible now
appear and can fail a `--fail-on HIGH` gate, which is the gate working. The
regression suites pin the specific failure shapes that were observed, including
the exact semgrep refusal message and the fabricated empty SARIF document.
