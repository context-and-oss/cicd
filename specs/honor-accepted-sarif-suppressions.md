# Honor accepted SARIF suppressions

Semgrep retains findings marked with `nosemgrep` in its SARIF output and records
the review decision in `result.suppressions`. The pipeline previously counted
those rows as active findings because `src/security/findings.go` did not read
the suppression status. This made a reviewed false positive contribute to
`fail-on` and appear again in the normalized findings table.

The security reader now excludes a result when any suppression has no status or
has status `accepted`, because SARIF 2.1.0 defines both forms as accepted.
Suppressions with status `underReview` or `rejected` remain active. The same
rule is applied by `src/cross-cutting/evidence/main.go`, so the gate counts and
the table cannot disagree.

The native SARIF remains unchanged in order to preserve the rule, location, and
suppression metadata for review. `src/security/main.go` instead adds a warning
with the number of accepted suppressions. Tests in
`src/security/findings_test.go` and
`src/cross-cutting/evidence/findings_test.go` cover implicit acceptance,
explicit acceptance, review in progress, rejection, and multiple suppression
records on one result. `CHANGELOG.md` records the consumer-visible behavior.

## The Code Scanning upload omits accepted results

`findings.sarif` exists to be uploaded to GitHub Code Scanning, and Code
Scanning ignores `result.suppressions` on a third-party upload. Every accepted
result — a `nosemgrep`, or a gitleaks finding the shadow scan put back with
`status: accepted` — became an open alert there, and the code scanning check
failed on any pull request that touched its file. A consumer could clear it
only by dismissing alerts by hand, which is a gate the consumer cannot clear.

`mergeSARIF` in `src/cross-cutting/evidence/main.go` therefore drops every
result an accepted suppression covers before the run reaches `findings.sarif`,
by the same rule the counters use. `underReview` and `rejected` results still
upload. The disclosure is not lost: it stays in the producing module's
`warnings[]` and in its native SARIF, which `parts/` keeps byte for byte. A run
whose results were all accepted still uploads with `results: []`, so the alerts
an earlier upload opened are closed. A run that keeps every result keeps its
bytes, and a run that cannot be parsed passes through unfiltered.
`src/cross-cutting/evidence/sarifruns_test.go` covers each status, the
untouched bytes and the emptied run.
