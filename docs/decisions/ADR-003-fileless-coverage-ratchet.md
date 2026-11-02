# ADR-003: File-less coverage ratchet

## Status
Accepted

## Context
"Coverage must go up" as a strict monotonic gate is a footgun: deleting
dead-but-tested code or refactoring blocks legitimate work, and teams learn to
game it with assertion-free tests. A ratchet-with-tolerance needs a baseline —
but a repo-committed baseline file was explicitly rejected ("no CI-specific
files in consumer repos"), and a central coverage store is new infrastructure.
Meanwhile the reusable precommit workflow already uploads
`precommit-evidence-<sha>` artifacts on every run.

## Decision
The baseline is the **previous successful default-branch run's evidence
artifact**. The workflow layer fetches it (gh api + artifact download, `|| true`)
and passes it to `Quality.Test` as an optional `baseline *File`; Test reads
`coverageByLanguage` from it (accepting a full evidence envelope or a bare
`{"coverageByLanguage": {...}}` map — sniffed).

Gate rule, per language present in both maps:
`measured < baseline − tolerance` → fail (gate mode) or warn (warn mode).
Boundary equality passes. Tolerance (default 1.0 pct-point) and mode
(`gate|warn`) are workflow inputs. Missing baseline or missing coverage output
→ ratchet skipped with a warning — **fails open**, never red. Beating the
baseline emits an advisory; the baseline advances automatically on the next
main-branch run. cicd never writes to consumer repos.

## Consequences
Easier: zero consumer files; the baseline is a cicd-produced artifact
(tamper-resistant vs a hand-editable file); the Dagger layer stays
source-agnostic and locally testable (`--baseline ./some.json`).
Harder: default 90-day artifact retention means a repo dormant longer
re-bootstraps silently — the first PR back has no ratchet and re-seeds the
baseline (accepted: only bites parked repos); the fetch step is per-CI-platform
(GH-first; ADO fetch is a documented TODO).
Committed to: strictly-monotonic gates stay rejected; warn-mode is the only
escape hatch for deliberate coverage drops; fail-open semantics on missing
baseline are by design, not a bug.

## Alternatives rejected
- Repo-committed baseline file: rejected by the consumer-files constraint;
  hand-editable evidence.
- Central coverage store: new infrastructure for one number per repo.
- Strict "must go up": blocks legitimate deletions, incentivizes junk tests.
