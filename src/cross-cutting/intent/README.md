# cross-cutting/intent

The change-intent gate: a change must carry a written record of why it was made,
and that record must be written for a reader. The module discovers intent
artifacts (a spec under `specs/`, a capsule under `.capsules/`, any
`*.intent.md`), scopes them to the files a pull request touches, and applies
deterministic prose rules to each one. No containers, no network, no model:
pure Go over the source directory and a diff.

The gate is opt-in through `--require-intent` on `stage-2` and
`composites/precommit`. `composites/commit` has no input to enable intent.
Switched off, it still reports an envelope saying so, because
an opt-in gate that is off produces exactly what a gate that passed produces.

## Install

Remote references require authorized read access while the repository is private; anonymous fetch is conditional on an explicitly approved public distribution. An authorized read-only source checkout can use `-m ./src/cross-cutting/intent` from its root.

```
dagger -m github.com/context-and-oss/cicd/src/cross-cutting/intent@v5.1.4
```

## Functions

| Function | Description |
|----------|-------------|
| `check` | Discover the intent artifacts a change touches, apply the rules, and return an evidence envelope |

## Usage

```bash
# Gate one pull request: scope to its diff, fail on any error-severity finding
set -eu
rm -f ./intent-evidence.json /tmp/change.diff
git diff --no-color --no-ext-diff --src-prefix=a/ --dst-prefix=b/ origin/main...HEAD > /tmp/change.diff
dagger -m github.com/context-and-oss/cicd/src/cross-cutting/intent@v5.1.4 call check \
  --src . \
  --diff /tmp/change.diff \
  --commit-sha "$(git rev-parse HEAD)" \
  --branch "$(git branch --show-current)" \
  --repo-url https://github.com/example/repo \
  export --path=./intent-evidence.json || exit 1
jq -e '.passed == true' ./intent-evidence.json >/dev/null || exit 1

# Inspection only, not a CI gate: audit every artifact without a diff
dagger -m github.com/context-and-oss/cicd/src/cross-cutting/intent@v5.1.4 call check \
  --src . \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path=./intent-evidence.json
```

## Parameters

| Param | Type | Description |
|-------|------|-------------|
| `src` | Directory | Repository source |
| `diff` | File (optional) | Output of `git diff <base>...HEAD`. Present and non-empty, it scopes the gate to the artifacts this change touches and enables `refs-infer-coupling`; absent or empty, every discovered artifact is audited. A git diff that touches no surviving file (deletions, binaries or modes only) is still a change set, so presence is judged against it. Text that is not a git diff, or file headers without the `a/`/`b/` prefixes, is refused rather than read as no change set: generate it with `git diff --no-color --no-ext-diff --src-prefix=a/ --dst-prefix=b/`, as the shipped workflows do |
| `commit-sha`, `branch`, `repo-url` | string | Evidence provenance |
| `fail-on` | `error` \| `warn` \| `never` | Lowest finding severity that fails the gate (default `error`) |
| `globs` | []string (optional) | Artifact discovery patterns; the defaults are `.capsules/*.yaml`, `.capsules/*.yml`, `specs/*.md`, `docs/specs/*.md`, `*.intent.md`, `.changes/*.md`, `changes/*.md`. `specs/*.md` is top-level on purpose: nested `specs/<feature>/` trees are planning material, not per-change artifacts |
| `dependabot-actions-pin` | bool (optional) | Asserts the diff is a Dependabot pull request limited to GitHub Actions pin bumps. The module re-validates every hunk before accepting that shape in place of a human artifact; a caller sets it only after checking the PR actor itself, and never on a post-merge run |
| `not-required` | bool (optional) | Declares the gate was not asked for: nothing is discovered or read, and the envelope says `required: false` with a warning. The orchestrators set it when `--require-intent` is absent |

## Rules

Presence first, then one pass of prose rules over each artifact in scope. The
rule ids are what the envelope's findings carry.

| Rule | Severity | What it refuses |
|------|----------|-----------------|
| `presence` | error | A change that touches no intent artifact (with a diff), or a tree with none (without) |
| `no-tbd` | error | `TBD`, `TODO`, `FIXME` or `???` in the artifact |
| `no-weasel-words` | error | Unmeasurable qualifiers as whole words of the author's own prose (`robust`, `simple`, `comprehensive`, …; the list is `weaselWords` in `rules.go`). Fenced blocks and code spans are quotations and are not judged |
| `min-causal-language` | error | No causal phrase at all (`because`, `since`, `instead of`, `we chose`, …), since the artifact exists to record *why* |
| `min-length` | error | Fewer than 30 words |
| `refs-infer-coupling` | error | The judged references name files, none of them is in the diff, and no changed filename appears among them: the artifact may describe a different change. New/copied/renamed artifacts are judged in full; for an artifact edited in place, only newly introduced references are judged |

The text the rules see is extracted, not raw: YAML capsules contribute their
scalar values, Markdown contributes its body and frontmatter values. `extract.go`
holds both extractors. All prose rules read the entire current artifact. Only
file-reference coupling distinguishes historical references from new ones: a
validated textual patch reconstructs the previous document, then references in
the new extracted text but not the old are judged. Repeated references on
replacement lines, numerical redactions, reflow and removed references therefore
do not assert the historical implementation is part of this change. Neither does
a rename of one segment of a reference that keeps the file it names, such as an
org slug in a URL: each removed reference explains at most one such rename. New
unrelated references still fail; an inherited changed filename cannot clear them.

New/copied/renamed artifacts retain whole-artifact coupling. Header-only or
binary patches also retain the full check, since they supply no previous text.
Malformed, truncated or overlapping textual hunks, or hunks inconsistent with
the supplied current artifact, are refused rather than treated as an empty edit
(even with the standalone threshold `--fail-on never`). Repeating a historical reference while changing its
claims remains a human review responsibility. See
[Couple the edit, not the artifact's history](../../../specs/couple-the-edit-not-the-artifacts-history.md).

## Evidence

The envelope's `genericReport` (format `intent-gate`) carries `required`, the
tool version and the findings list; `findingsBySeverity` maps rule severities
onto the shared scale (`error` → HIGH, `warn` → MEDIUM). `passed` is false
when any finding reaches `fail-on`. The pull-request comment that `notify`
renders prints the findings and warnings verbatim, including a scope warning
when coupling judged newly introduced references in modified artifacts. This
narrowing applies to coupling only, not to presence or the other prose rules.

## Development

- `check.go` — `Check()`: discovery, diff scoping, the presence rule and the envelope write (`//go:build !unit_test`)
- `main.go` — the default globs, `buildEnvelope`, `buildNotRequiredEnvelope` and the severity mapping
- `rules.go` — the five prose rules and the path tokeniser behind `refs-infer-coupling`
- `coupling.go` — `runArtifactRules`, the production rule boundary; strict reverse-hunk reconstruction and introduced-reference coupling for modified artifacts
- `extract.go` — YAML and Markdown text extraction; `changeScope()` (the surviving paths a diff names) and `extractDiffPaths()` (every path it touched, for coupling)
- `diffpaths.go` — `parseDiffPaths()`, the one reader of a git diff's file headers: quoted (including Git's tab delimiter), binary, mode-only, renamed and copied paths, headers only between `diff --git` and the first hunk, and the refusal of a diff with no git header or no a/ and b/ prefixes. It also retains resolved file sections for the coupling hunk reader. Byte-identical with `src/risk/diffpaths.go`, with its test table beside each copy; a `synced_files` group in `scripts/repo-inventory.json` enforces both. See [specs/read-a-diff-with-one-parser.md](../../../specs/read-a-diff-with-one-parser.md)
- `machine_origin.go` — the Dependabot Actions pin-bump shape, validated hunk by hunk
- `*_test.go` — one file per concern: rules, extraction, scope, fail-on, not-required, machine origin; `nonrun_matrix_test.go` holds the diffs and artifact searches that must never pass

```sh
(cd src/cross-cutting/intent && GOWORK=off go test -tags unit_test ./...)
```
