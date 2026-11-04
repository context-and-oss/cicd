# composites/precommit

Full pre-commit pipeline: runs the stage-2 source gate (quality, security, risk, and — with `--require-intent` — the change-intent gate) via a single `dag.Stage2().Run` call, aggregates evidence, and optionally posts a Teams notification. This is the primary consumer entry point for stage-2 checks.

## Entry function

Abridged below — and abridged without a parameter count on purpose, because the
count in this file had already drifted from the signature twice. Every
`stage-2.Run` option is exposed here and forwarded through
`dagger.Stage2RunOpts{}` (coverage ratchet, BYO test command, toolchain image,
feed credentials, the intent opt-in, …), plus precommit's own notification
inputs. `scripts/smoke/stage-orchestrators.sh` fails if any
stage-2 option stops being exposed or forwarded, so read `main.go` for the
authoritative list.

```go
func (m *Precommit) Run(
    ctx context.Context,
    src *dagger.Directory,
    commitSha, branch, repoUrl string,
    failOn string,          // default HIGH
    include []string,       // optional language override
    sastRulesets string,    // default "p/security-audit" ("auto" is refused)
    teamsWebhook *dagger.Secret, // optional; notification skipped if nil
    runUrl string,          // optional CI run URL for Teams card
    npmFeedUrl string,      // optional
    npmFeedRouting string,  // optional: registry (default) | npmrc
    npmToken *dagger.Secret,
    nugetFeedUrl string,    // optional
    nugetToken *dagger.Secret,
    dependabotActionsPin bool, // optional — see intent's machine-origin path below
    requireIntent bool,        // optional — opt in to the change-intent gate
) (*dagger.Directory, error)
// Returns directory with: combined-evidence.json, findings.sarif, sbom.cdx.json,
// plus <tool>-output.txt for any failed step that captured raw output (e.g.
// byo-test-output.txt) — absent on green runs.
```

## Dependencies (dagger.json)

- `stage-2` (the source gate), `cross-cutting/evidence`, `notify`

## Run locally

This is a local inspection/shadow run from an authorized checkout's root, not a
CI gate. Default SAST uses restrictively licensed runtime rules; review the
[rule notice](../../../THIRD_PARTY_NOTICES.md#default-semgrep-rules--semgrep-rules-license-v10-not-apache-20).
For enforcement, use the [fresh export-and-verdict recipe](README.md#usage).

```sh
(cd src/composites/precommit && dagger develop)   # once

dagger -m ./src/composites/precommit call run \
  --src ./testdata/go-app \
  --fail-on NONE \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path ./audit-out
```

## Output

The exported directory contains:
- `combined-evidence.json` — merged envelope (overall pass/fail + finding counts)
- `findings.sarif` — concatenated SARIF from all scanning modules
- `sbom.cdx.json` — merged CycloneDX document

## Key files

- `main.go` — `Run()`: the single `dag.Stage2().Run` call, then `finishAudit`
- `audittail.go` — `finishAudit()`: aggregation, the Teams delivery as evidence, the PR comment; tagged, byte-identical to the commit, precommit and dast copies apart from the SDK import (`synced_files` in `scripts/repo-inventory.json`)
- `precommitinputs.go` — `validatePrecommitInputs()` (untagged, unit-tested)
- `concurrency.go` — generated copy of `src/internal/concurrency/concurrency.go`

## Constraints

- Teams notification failure is non-fatal, and no longer silent: `notify.Teams` returns an evidence envelope that is merged into `combined-evidence.json` by a second `Evidence().Wrap` call, so a webhook that was never configured or a card that was lost is a `warnings[]` line in the pull request comment rather than a transport error inside a twenty-minute log.
- `Run` returns a nil error on a tripped gate. The verdict is `passed` in
  `combined-evidence.json` and the exit status carries no gate signal at all, so
  a caller that checks only the exit status is fail-open. Since v1.16.1 this is
  the contract, not a bug — a producer that aborts cannot hand back the evidence
  explaining the abort — but it means the gate lives in every caller, and a new
  caller that forgets it looks identical to one that passed. The GitHub reusable
  workflow and `templates/local/scripts/cicd-prepush` read the verdict, and so does
  each `templates/azure-devops/` template's gate step.
- The source gate runs via a single `dag.Stage2().Run` call — precommit does
  not compose quality/security/risk/intent directly, so it cannot silently
  drift from stage-2's own composition (see
  `scripts/smoke/stage-orchestrators.sh`'s equivalence guard).
- `requireIntent` on precommit or stage-2 enables the change-intent gate;
  `commit.Run` deliberately exposes no equivalent. It defaults off because
  the gate checks a team practice (did the author write down why this change
  exists?) rather than a property of the code. Off, the intent envelope is still
  in the audit reporting `required: false` plus an `intent-gate: NOT REQUIRED …`
  warning — notify renders warnings verbatim, so a run with the gate switched
  off cannot be mistaken for a run where it passed.
- `infraScope` chooses which infrastructure files `risk.Validate` evaluates and
  defaults to `"changed"` — the files in `--diff`. That default is right for a
  pull request gate: the scan judges the change under review, and debt in a file
  the author did not touch is the previous run's problem. It is exposed rather
  than pinned because a team whose infrastructure is edited rarely enough that
  the diff scope means it is effectively never scanned can ask for `"tree"`
  here. `commit.Run` offers no equivalent and pins `"tree"`: a push that has
  already merged has no author left to hold responsible for one file.
  The string is forwarded unvalidated — `risk` owns the accepted set, and a
  second copy here would drift out of agreement with it.
- `dependabotActionsPin` only ever satisfies `intent.Check`'s presence tier
  via its independent diff re-validation
  ([specs/harden-workflow-supply-chain.md](../../../specs/harden-workflow-supply-chain.md)) — the caller (precommit's reusable/dogfood workflows) must
  verify the PR actor is exactly `dependabot[bot]` before setting it; a
  human/mixed/structural diff still fails presence normally. Never set it
  for commit/push execution.
