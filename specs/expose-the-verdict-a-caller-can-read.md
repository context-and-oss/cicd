# Expose the verdict a caller can read

## The problem

A consumer ships per-release SBOM, SCA and SAST reports to its customers from
a CDN. The commit pipeline already produces every one of those documents —
`sbom.cdx.json`, `findings.sarif`, `combined-evidence.json`, `comment.md` —
and uploads them as the `commit-evidence-<sha>` workflow artifact. But nothing
made that consumable from outside: neither reusable workflow declared a single
`workflow_call` output, so a caller wanting the artifact name, the verdict, or
the finding counts had to read cicd's workflow source and hard-code what it
found there. A rename inside cicd would break every such consumer with no
signal — the consumer's download step would fail on an artifact name that no
longer exists, one release later.

Underneath that sat a second gap in the evidence itself. `buildCombined` in
[src/cross-cutting/evidence/main.go](../src/cross-cutting/evidence/main.go)
merges every source envelope into one `passed` AND and drops module identity on
the way: the combined envelope could say the run failed but not which gate
failed. A caller distinguishing a SAST failure from a coverage regression had
to parse per-tool payloads out of `sarifReport`, which is the source-diving
this change exists to end.

## The change

Three additive pieces, delivered together because each is the seam the next one
reads through:

1. **`sources[]` on the combined envelope.**
   [src/internal/evidence/schema.go](../src/internal/evidence/schema.go) gains
   `SourceStatus` — moduleName, stage, tool, passed, findingsCount,
   errorsCount, warningsCount — and `buildCombined` appends one per input
   envelope, in input order. The counts carry no `omitempty` because an absent
   count and a zero count are different claims: "no errors" must stay
   distinguishable from "nobody counted". Populated by the aggregator only,
   like `Findings`; absent on individual module envelopes, so the presence-only
   CI validator and every synced schema copy are untouched by it.

2. **`workflow_call: outputs:`** on
   [.github/workflows/commit.yml](../.github/workflows/commit.yml) and
   [.github/workflows/precommit.yml](../.github/workflows/precommit.yml):
   `evidence-artifact`, `passed`, `findings-count`, `findings-by-severity`,
   `coverage-ratchet`, and `gates` (the `sources[]` array, compact). The gate
   step writes pessimistic defaults to `$GITHUB_OUTPUT` before either of its
   `exit 1` paths — a missing evidence file or a tripped gate still reports
   `passed=false`, never an empty string — and the jq read of `.passed` is a
   plain assignment on purpose: under `set -e` a document jq cannot parse exits
   the step there, before any real value is written, so the defaults are what
   the caller reads. `evidence-artifact` is a pure expression
   (`commit-evidence-${{ github.sha }}`), immune to every exit path.

3. **`check_workflow_output_chain`** in
   [scripts/repo_surface.py](../scripts/repo_surface.py). A reusable
   workflow's outputs are a three-link chain — workflow_call output → job
   output → step write into `$GITHUB_OUTPUT` — and GitHub validates none of
   it: a typo'd name at any link resolves to the empty string at run time,
   inside a caller's gate, where `'' != 'false'` in a notify condition reads
   as "not failed". actionlint accepts unknown output names and the workflow
   runs green, so nothing else looks. The checker walks every declared
   workflow surface that contains a `workflow_call:` trigger — scoped by
   content, not a second manifest list, so a new reusable workflow cannot
   dodge it by being forgotten — and requires each link to resolve, down to
   the literal `name=` write in the producing step's run body. Which is why
   the gate steps write explicit `echo "passed=..."` lines rather than going
   through a helper function: `out passed false` contains no `passed=` token,
   so a helper would hide the one string the checker can verify.

[docs/decisions/ADR-006-the-consumer-publishes-release-reports.md](../docs/decisions/ADR-006-the-consumer-publishes-release-reports.md)
records the contract this creates: cicd builds the reports, the consumer
publishes them, the artifact and file names are now API, and the current
vulnerability posture is a separate mutable document regenerated from the
frozen SBOM — never an in-place rewrite of the release-time record.

## What was verified

Every mutation class the checker exists for was exercised against the real
tree before the fixture tests pinned them: a typo'd job output name, a typo'd
step id, a typo'd step output name, a step that writes a different key, and a
reference to a job that does not exist each produced exactly one named problem
in the mutated file, and the unmutated tree produced zero — with a probe
confirming both commit.yml and precommit.yml are in scope, because a zero from
a checker that skipped both files is the vacuous pass this repository refuses
everywhere else. `TestBuildCombinedSources` asserts the `sources[]` list is
complete, ordered, and truthful about a failed source; the all-green companion
asserts a zero count is a claim, not an omission.

## What this does not do

`--fail-on` semantics, gating, and every individual module envelope are
unchanged — `sources[]` is aggregator-only. The Azure DevOps templates have no
gate step reading the combined evidence, so they get no outputs analogue here;
ADR-006 names that asymmetry rather than hiding it. And the scheduled rescan
that keeps `vuln-current.json` honest is a separate function on the security
module, delivered in its own change.
