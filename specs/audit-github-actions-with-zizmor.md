# Audit GitHub Actions with zizmor

## Why

A workflow is code that runs with the repository's token, and its attack
surface is not the shape a general-purpose pattern scanner reads well:
`${{ }}` expansion into a shell, `pull_request_target` and `workflow_run`
triggers, a token left in `.git/config` for later steps, unpinned third-party
actions. Opengrep carries a handful of GitHub Actions rules and finds what a
pattern can name in one file. It has no model of triggers, permissions,
persisted credentials or action references.

[zizmor](https://github.com/zizmorcore/zizmor) is a static analyser built for
exactly that: about forty audits over workflows, composite actions and
Dependabot files, SARIF 2.1.0 out, MIT, a digest-pinnable image. It covers the
workflow class that GitHub's own code scanning covers with its Actions
analysis, so a consumer that drops that scan does not drop the class.

## What changed

- **A `zizmor` row** in `ScanSource`, concern `sast`, beside `opengrep` and
  `roslyn-analyzers`. It runs on every scan, `--code-only` included, and has
  no row when zizmor collected no input (exit 3, nothing registered, "no
  inputs collected"): a tree with no workflows is not a scan that found
  nothing. Its SARIF run is merged into the report under its own driver name
  and `automationDetails.id`.
- **zizmor decides what it collects.** `--collect all`, so a committed
  workflow a `.gitignore` pattern happens to match is still audited: GitHub
  runs it. zizmor's own walk decides which paths are workflows (a nested
  repository's `.github/workflows/` yes, `.github/workflows/nested/` no, as
  GitHub does). cicd does not re-derive it.
- **What was audited is read from zizmor, not inferred.** With `-v`, zizmor
  logs every input it registers and every input it completes; the difference
  is the set it could not parse. An unparseable workflow is a WARN on stderr
  and the run still exits 0, so without this a tree whose only risky workflow
  has a YAML error reads exactly like a clean one. `Examined` reads
  `{unit: "workflow, action and Dependabot files", count, total}` and a
  `PARTIAL SCAN` warning names each file not audited.
- **A non-run is an error**, never a clean row: inputs registered and none
  completed; a fatal exit; unreadable SARIF; a SARIF result whose file the log
  never completed; files completed and no audit scheduled (the log grammar
  changed under cicd). `--fail-on NONE` does not cover any of them.
- **The offline narrowing is named.** The scan runs `--offline`: it contacts
  no GitHub API and needs no token. The audits that need the API
  (`impostor-commit`, `known-vulnerable-actions`, `ref-confusion`,
  `ref-version-mismatch`, `stale-action-refs`) do not run, and a
  `NARROWED AUDITS` warning lists them from zizmor's own log line.
- **What an ignore removed is named.** A `# zizmor: ignore[...]` comment or
  the repository's `zizmor.yml` drops a finding without a trace in the SARIF.
  A second run with `--no-config --no-ignores` (the shadow) reports what zizmor
  finds on its own defaults; a finding only the shadow has goes back into the
  report with an accepted suppression, uncounted, and a warning names each one
  with its severity and location, highest first. The diff is a multiset on
  (rule, file, line, column), so two identical findings with one ignored
  still disclose one. The same mechanism as the gitleaks shadow.
- **One grade changes.** zizmor rates `unpinned-uses` High for an action
  referenced by tag (`actions/checkout@v4`). That is how GitHub's own
  documentation and most of the ecosystem reference actions, so at the default
  `--fail-on HIGH` the gate would go red for nearly every consumer on day one,
  over a policy choice rather than a defect: a gate a consumer cannot clear
  gets switched off. cicd grades it MEDIUM; the projected SARIF carries the
  cicd level. Every other audit keeps zizmor's severity (High → HIGH, Medium →
  MEDIUM, Low and informational → LOW).
- **The rule count is a measurement.** `rules.count` is the number of distinct
  audits zizmor's log says it scheduled; `rules.pinned` names the version and
  persona.

## Measured

On `testdata/zizmor-workflows` with the pinned 1.32.0 image: 7 of 9 inputs
audited, the broken YAML and the schema-invalid workflow named as not audited;
two template injections HIGH, `unpinned-uses` MEDIUM, `dependabot-cooldown`
MEDIUM; the ignore comment and the two `zizmor.yml` removals disclosed and not
counted; the gitignored workflow audited; the nested-repository workflow
found. 36 audits scheduled offline, 5 named as skipped.

On this repository's own tree, before any change: 24 findings, 10 at or above
the dogfood's MEDIUM gate. Seven checkouts that run no credentialed git
command now set `persist-credentials: false`. Three are accepted with a
reason in an ignore comment, each disclosed in the evidence: the CD
`workflow_run` trigger (every job requires a same-repository push),
`$GITHUB_ENV` written from a caller literal in the install-Dagger action, and
the reusable precommit workflow's checkout, whose base-branch fetch needs the
token on a privately hosted consumer. The remaining 14 are LOW
(`self-repository`).

## What gets worse

- **Low-confidence findings gate at their severity.** zizmor attaches a
  confidence to each finding (`github-env` in a composite action is Low
  confidence, High severity, because zizmor cannot see the caller's trigger).
  cicd does not grade by confidence: that would be a second severity model
  cicd invents. The lever is an ignore comment with a reason, which the
  evidence discloses.
- **`.semgrepignore` does not scope it**, nor does any path exclusion flag:
  zizmor has none. A directory of intentionally unsafe workflows is either
  excluded through `ScanSource`'s `exclude`, which the evidence names, or
  stored under a name GitHub and zizmor do not read. This repository's own
  fixtures are stored as `*.fixture` and materialised by their smokes
  (`scripts/smoke/materialise-fixtures.py`).
- **Every scan costs two zizmor runs.** The shadow is the price of naming what
  an ignore removed. Both are offline and read only YAML.
- **No online audits.** A tag that moved to an impostor commit, or an action
  with a published advisory, is not found. Running them needs a token in the
  scan container and makes the result depend on the API's answer at scan
  time; the narrowing is named instead.

## Licence

zizmor is MIT, run from its digest-pinned image
(`ghcr.io/zizmorcore/zizmor`), not redistributed. The capture under
`src/security/testdata/zizmor-1.32.0/` is zizmor's output over cicd's own
fixture.

## Checks

- `src/security/zizmor_test.go`, over the verbatim capture: the collection
  log read, the row and SARIF agreeing, no inputs as no row, nothing parsed
  as a non-run, a fatal exit, a failed shadow, a changed log grammar, an
  unreadable SARIF, the multiset diff, the severity override, the capped file
  list, and the script running both scans.
- `scripts/smoke/zizmor.sh`, run by the `module-test` security cell and
  `make smoke`: the real image over the fixture, asserting every row value,
  result, level, suppression and warning above, no container path in the
  SARIF, and that the default gate fails.
- `scripts/smoke/opengrep-github-actions.sh`: a workflow-only tree is audited
  in full (4 of 4) beside the Opengrep assertions.

## Residue

- Only the arm64 image was exercised locally; amd64 is exercised by CI.
- The workflow templates cicd ships reference its own actions by tag, which
  `unpinned-uses` reports at MEDIUM in a consumer's scan. SHA-pinned templates
  are a separate change.
- The pedantic and auditor personas are not run; their extra audits are
  advisory by zizmor's own description.
