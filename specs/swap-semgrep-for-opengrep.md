# Swap Semgrep OSS for Opengrep

## Why

A consumer's scheduled run on a C# repository read SAST as clean while the
parser had rejected most of the tree
([mark-a-partly-read-scan](mark-a-partly-read-scan.md) made that visible).
Visible is not read. Probes written for the purpose, run on both engines:

| C# construct | Semgrep OSS 1.162 / 1.185 | Opengrep 2.0.0 |
|---|---|---|
| primary constructor (C# 12) | `Syntax error`, file partly read | parsed |
| null-conditional assignment (C# 14) | `Syntax error` | parsed |
| `record` declaration | skipped, **no notification at all** | parsed |

The record gap is the one the doctrine cannot tolerate: a file read less than
its count said, with nothing anywhere in the report to say so
([doctrine](../docs/explanation/doctrine.md#a-tool-that-ran-on-part-of-the-input-must-not-read-as-having-run-on-all-of-it)).
No newer Semgrep OSS release fixed it. Opengrep is the LGPL-2.1 fork of the
same engine, reads the same rule language, `.semgrepignore` and `nosemgrep`
(and `noopengrep`), and emits the same SARIF notification shape, so the rest
of cicd's SAST path — pinned packs, rule floor, redaction, notification reader,
inline adapter — runs unchanged on it.

Opengrep 1.x is **not** a substitute: it drops a file it cannot parse without
a notification, the exact failure this swap closes. 2.0.0 is the floor.

## What changed

- **The engine is a pinned binary, not an image.** Opengrep publishes release
  binaries, no container image. `src/security/opengrep.go` pins the version and
  the per-architecture sha256 GitHub publishes for each asset; `sast.go` fetches
  the asset with `dag.HTTP` onto the digest-pinned `python:3.12-slim` base that
  `quality.Check` already uses. `opengrepVerifyScript` checks the digest in the
  container **before** the binary runs; a mismatch is a non-run
  (`PINNED DOWNLOAD REJECTED`), never a scan by an unverified engine. Dagger's
  `File.Digest` is documented as unstable across engine releases, so it is not
  the pin; `sha256sum` is.
- **Called by absolute path.** `/usr/local/bin/opengrep`, the path the verify
  step checked. A `PATH` lookup could resolve to something else.
- **PyYAML is pinned beside it.** The Semgrep image bundled PyYAML; the slim
  base does not, and the two helpers that read upstream rule YAML
  (`semgrep_gha.py`, `semgrep_inline.py`) need it. Without it the GitHub
  Actions fallback and inline JavaScript would fail while every other scan
  stayed green. The cp312 wheel is pinned by PyPI's sha256 and installed with
  `pip --no-index` from the verified file: nothing is resolved or fetched.
- **Two flags are gone.** Opengrep has no telemetry and no version probe, and
  it *refuses* `--metrics` and `--disable-version-check` (unknown option, empty
  report) rather than ignoring them. Both scan commands drop them. See the
  amendment in [keep-local-semgrep-time-for-analysis](keep-local-semgrep-time-for-analysis.md).
- **`--time` is gone from the inline pass.** Opengrep's timing payload carries
  no convergence field; see "What Opengrep does not say" and the amendment in
  [report-inline-taint-convergence-limits](report-inline-taint-convergence-limits.md).
- **The evidence names the engine.** The SAST tool row is `opengrep`, and every
  message prefix that said `semgrep:` says `opengrep:`. The SARIF driver is
  `Opengrep`, with rule ids unchanged. **This is a consumer-visible rename**: a
  filter, dashboard or `jq` query keyed on `name == "semgrep"` matches nothing
  after the upgrade. The release note must say so.
- **The engine never sees `.git`.** In a git project Opengrep lists its
  targets with `git ls-files`, and the slim base carries no git, so every scan
  of a checkout with a `.git` — every consumer's, since the reusable workflows
  clone with full history — was `SAST did not run`. A worktree's `.git`
  pointer file, which names a path outside the container, failed the same way.
  `withoutGitMetadata` drops either shape from the engine's mount only; the
  gitleaks history leg still gets the object store.
- **Renovate** proposes the Opengrep version from GitHub releases. It cannot
  produce the digests, so a version-only bump fails every scan on the
  architecture whose digest was not replaced — loudly, by design.

Unchanged: the rule packs and their commit pin, `--sast-rulesets`, the rule
floor, `.semgrepignore`, `nosemgrep`, redaction, the partial-scan warning
policy, the inline adapter, `--fail-on`. Internal Go identifiers keep their
`semgrep` names; renaming them is churn with no reader.

## Measured equivalence

On the same probes and pinned rules, both engines:

- load every pinned C# rule, and produce identical results on every file both
  parse;
- report SARIF columns in the same unit (byte offsets measured identical on a
  multi-byte line), so the inline adapter's UTF-16 remap is unchanged;
- emit `Syntax error` / `Timeout` notifications with the same descriptor ids,
  level and path-in-message shape that `semgrepnotifications.go` reads.

`opengrep test` on the pinned C# rule tests passes all but two:
`use_ecb_mode` and `use_weak_rng_for_keygeneration`. Every line they "fail" on
carries a `deeptodoruleid:` annotation, the upstream marker for a true
positive only Semgrep's commercial engine is expected to find. Opengrep finds
them. These are **new true positives, not noise**: real ECB-mode use and a key
from a non-cryptographic RNG. The second is severity `ERROR`, which cicd maps
to HIGH, so a C# consumer that was green at the default `--fail-on HIGH` can
go red on upgrade over code that was always vulnerable. The release note must
say so.

## What gets worse

- **An unbalanced brace widens the rejected region to the whole file.** A bad
  statement or member is still skipped alone, and findings before and after it
  are kept; an unbalanced brace makes the notification span the entire file,
  which then yields nothing. Semgrep recovered more of such a file. The
  notification still fires, so the partial-scan warning and `Examined.Partial`
  still say so; the warning's last sentence names both cases.
- **`.gitignore` no longer scopes the scan.** Semgrep's image had git, so it
  scanned what `git ls-files` listed: tracked files and untracked ones git does
  not ignore. Opengrep now walks the tree it is handed, and a gitignored file
  that is present is scanned. A fresh CI checkout holds none, so the scope
  there is unchanged; a local run over a working tree with build output or
  dependencies on disk scans more, never less. `.semgrepignore` still applies.
  cicd does not re-derive git's ignore rules: that would be a second resolver
  for a question git answers, and git is what the image lacks.
- **Loop-carried taint is bounded silently.** See next section.
- **`--config auto` still cannot work.** Semgrep refused it with metrics off.
  Opengrep exits 7: the registry's answer is rejected as invalid YAML, while
  the SARIF invocation still says `executionSuccessful: true` with zero rules.
  `semgrepConfigFlags` keeps rejecting it before any container runs; were it to
  work, it would still be a rule set the registry chooses at scan time, which
  the evidence could not name.

## What Opengrep does not say

Opengrep 2.0.0's intrafile taint fixpoint caps each dataflow node at a fixed
number of visits and skips the node past that cap. The result is still
reported as a successful analysis. Nothing reports it: no SARIF notification,
no JSON `errors[]`, no `--time` field (the payload has no `fixpoint_timeouts`
key), no debug-log line even with tainting log sources enabled. Its separate
timeout arm, which would be reported, was not reached by any probe, including
a switch-in-loop of several hundred cases.

The measured effect: taint that needs several loop iterations to reach its
sink — a chain of assignments written in reverse order inside a loop — is lost
past the cap. Semgrep found every such probe and reported its own time-based
limit through `fixpoint_timeouts`. Realistic loop shapes — nested-loop
accumulators, triple nesting, swaps, retry blocks, a state machine — gave
identical results on both engines.

**Decision.** There is no signal, so cicd reads none and claims none. A
per-scan warning would fire on every scan and carry no information, which
trains readers to skip the line that matters. The bound is documented here
and in the module guide as a measured property of the pinned engine. If a
later release emits a convergence notification, its unknown descriptor falls
into the reader's unclassified bucket and still renders `PARTIAL SCAN`
(`TestAnUnmeasuredConvergenceNoticeStillReadsAsPartial`), so the disclosure
arrives without a code change.

The trade is deliberate: a whole-file C# parse gap that was silent and common,
against a taint bound that is silent and rare. A bump re-runs the loop probes.

## Licence

Opengrep is LGPL-2.1. cicd does not redistribute it: the scan container
downloads the unmodified release binary from the project's own release page at
run time. Recorded in `THIRD_PARTY_NOTICES.md` beside PyYAML (MIT). The rules
are unchanged and remain under the Semgrep Rules License, fetched at run time,
never committed ([pin-the-default-sast-rules](pin-the-default-sast-rules.md)).

## Checks

- `src/security`: `opengrep_test.go` (asset selection per platform, verify
  vocabulary, the script refusing an unverified binary),
  `semgrepnotifications_test.go` (the whole-file clause, the unmeasured
  convergence notice), `semgreprun_test.go`
  (`TestTheScanRunsOpengrepWithoutSemgrepOnlyFlags`: the verified absolute
  path, verification before the scan, no Semgrep-only flag; `auto` rejected).
- `src/security/semgrep_inline_test.py`: no `--time`, no Semgrep-only flag,
  a profile without `paths.scanned` is a non-run.
- `scripts/smoke/opengrep-github-actions.sh` scans a real `git init` clone of
  its fixture; with the `.git` handed to the engine it fails on `git ls-files`
  (measured by reverting `withoutGitMetadata`).
- `scripts/smoke/semgrep-inline.sh`, `scripts/smoke/semgrep-redaction.sh`,
  `scripts/smoke/commit-shapes.sh` and the `module-test` cell run the real
  pinned binary.

## Residue

- Only the arm64 binary was exercised locally; amd64 is exercised by CI.
- Upstream issue for the silent visit cap: not filed from here.
- The GitHub Actions fallback is now dormant. Opengrep 2.0.0 parses the
  `${{ ... }}`, command-substitution and multiline-Markdown run blocks that
  Semgrep rejected, with no notification, and the upstream
  `gha-curl-pipe-shell` rule found both curl-pipe-shell steps in the probe. The
  live-pack rerun therefore does not fire; the pinned plan still runs the
  adapted rule in the upstream one's place. Putting the upstream rule back in
  the manifests is a rule-set change for its own review.
