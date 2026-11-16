# Finding metadata fixture

First-party synthetic JavaScript and Semgrep rules. The input is scanned, never
executed. No upstream rule bodies, customer source, credentials or private data
are included.

`native.json` and `native.sarif` are byte-exact output from Semgrep OSS 1.162.0,
using cicd's pinned image digest
`sha256:9349edbadf90c3f3c0c3f55867625354e89680e6fa10d9034042af52fdb0e0d0`.
The capture predates the engine swap to Opengrep
([specs/swap-semgrep-for-opengrep.md](../../specs/swap-semgrep-for-opengrep.md))
and was not re-captured: it fixes the native metadata shape the projector reads,
not the output of the engine cicd runs today. The command was run with network disabled, this directory mounted at `/src`, an
empty output directory mounted at `/out`, and working directory `/src`:

```sh
semgrep scan --disable-version-check --metrics=off --no-git-ignore \
  --no-rewrite-rule-ids --config rules.yml \
  --json-output=/out/report.json --sarif-output=/out/report.sarif example.js
```

The outputs were renamed to `native.json` and `native.sarif` without modifying
their contents. All three findings have severity ERROR; the native JSON states
security/audit/LOW confidence, style/HIGH confidence, or no classification.
SARIF emits `precision: very-high` for all three, retains confidence and CWE tags,
and omits category/subcategory. This demonstrates why classification must use
native metadata rather than severity or SARIF precision.

The native SARIF intentionally contains harmless first-party source snippets.
Security unit tests prove those snippets are removed before evidence publication,
while the allowlisted finding metadata survives. Aggregator tests prove the
metadata survives combined-evidence serialization without changing counts/gates.
