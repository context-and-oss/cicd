# Heavy commit stage — scan code and artifact, any repo shape

## Problem
The commit stage (`src/composites/commit`) scans only the built artifact — it
builds an OCI image, SBOMs it, and scans the image. It runs **no checks against
source code**: no lint/test, no SAST, no source-secrets, no dependency-vuln, no
risk, no intent gate. So code defects reach `main` ungated at the authoritative
stage, inverting the documented shift-left tier model (pre-commit is meant to be
the fast loop, commit the heavy authoritative gate). The commit stage is also
container-only via `Run`, with a bolted-on `RunArchive`; repos that build no
deployable artifact (libraries, infra/config repos) have no commit path at all.

## Outcome
The commit stage scans code *and* artifact for any repo shape — container,
archive, or none — through one `commit.Run` with an explicit `--artifact`
selector.

## Users
The platform team owning cicd, and every consumer repo that runs the commit
pipeline. The sole current consumers are the maintainers' own repositories, which is why the
cutover is hard (no back-compat). Ownership split from ADR-001 holds: consumers
own definitions (Dockerfile, build command), cicd owns execution + the evidence
plane.

## Success signal
Running the commit composite on all three artifact shapes — container
(`testdata/go-app`), archive (`testdata/node-app`), and none
(`testdata/python-app`) — each produces a valid `combined-evidence.json`
containing findings from all six source-gate checks (quality, SAST, secrets,
dependency-vuln, risk, intent) plus the correct artifact evidence for that shape
(image scan / built-output secrets scan / source-lockfile SBOM only).

## Non-goals
- Thinning pre-commit — it stays full (fast PR feedback with light configs).
- Auto-detecting the artifact shape — the selector is always explicit (ADR-001).
- Wiring DAST/ZAP into commit — that belongs at the acceptance stage.
- New scanning tooling (e.g. Grype) — "heavier" is config on the same tools.
- Proving TruffleHog live verification in CI — the flag is opt-in plumbing only.
- A coverage-ratchet gate at commit — the ratchet stays a pre-commit/PR concern.
- Bumping version pins — the release process does the major bump out-of-band.

## Glossary
- **Source gate** — the six artifact-agnostic checks run on `src` for every
  shape, via one `dag.Stage2().Run()` call.
- **Artifact tail** — the shape-specific scan appended after the source gate.
- **Shape** — `container` (Dockerfile → image), `archive` (build command →
  output dir), or `none` (no build; SBOM from source lockfiles).
- **Heavy tier** — commit's configs cranked up vs pre-commit (full Semgrep
  rulesets, opt-in TruffleHog verify, lower fail-on) plus the artifact scan.
- **before..after diff** — the incremental change range for a push
  (`github.event.before..after`), fed to the diff-scoped risk/intent gates.

## Reversibility
Hard cutover with long-lived consequences: `RunArchive` and the four
`commit-archive` templates are deleted, and `commit.Run`'s signature changes
(new `--artifact` selector). Back-out = revert the series and re-point pins to
the prior major. Safe because this repo is the sole consumer and re-points its
own pins; the version-pin coherence gate keeps the tree consistent.
