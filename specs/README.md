# specs/

The written record of why the code is the way it is. A spec is a document written
before or alongside a change: the defect as it was measured, the mechanism that
closes it, the alternatives that were rejected and why, and the traps that would
reopen the door. The [doctrine](../docs/explanation/doctrine.md) is the rulebook
distilled from these; each rule there links the spec that earned it.

Specs are historical by construction. Each one records the intent at the time it
was written and is never rewritten to match today's surface, because a record
that is edited to agree with the present stops being evidence of anything. The
inventory lists `specs/` as a historical exclusion for that reason, so a new spec
needs no declaration anywhere. This index, `specs/README.md`, is the one file in
the directory that is kept current.

## Pre-import context

These retained narratives describe decisions made before the planned fresh
import. They do not establish destination settings, credentials, tags or
releases. Old Git and GitHub state, including issue and pull-request histories,
is not part of the import. Destination verification remains a separate step.

## Layout

| Path | What it holds |
|------|---------------|
| `*.md` | One spec per change, named for the behaviour it establishes (`refuse-a-commit-git-cliff-cannot-release.md`, `prove-the-bump-matches-its-history.md`). Most of the directory. |
| `heavy-commit-stage/` | The commit-stage campaign (ADR-005): `purpose.md` and `design.md` |
| `non-container-artifacts/` | The archive and `none` artifact shapes (ADR-001): the same purpose and design structure |
| `release-latest.md` | Import intent in this candidate; future release automation can overwrite it with release-pins intent. It is not inherited tag or pull-request history. |

Feature trees are planning material: a purpose and a design. They are kept so that a reader of a change can find the larger
decision it was part of.

## Writing one

The intent gate (`src/cross-cutting/intent`) reads every top-level `specs/*.md`
that a pull request touches, so a spec is also the artifact that lets a change
into `main`. The gate applies prose rules that a spec written for a reader satisfies without
effort: no placeholder markers, at least one causal phrase, no
unmeasurable qualifiers, a minimum length, and at least one file path that the
change really touches. [CONTRIBUTING](../CONTRIBUTING.md#every-change-carries-an-intent-artifact)
lists them and names the word list.

A useful shape, used by most of the files here:

1. **Why** — what was measured, with the commit, run or output that showed it.
2. **The mechanism** — what closes the door, and where it lives.
3. **Rejected** — the alternatives and what each one would have cost.
4. **Traps** — the change that would reopen the door, so a reviewer can recognise it.

The spec records a decision; the capsule under [`.capsules/`](../.capsules/README.md)
was the earlier, structured form of the same record.
