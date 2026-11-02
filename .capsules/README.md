# .capsules/

Structured change records from the project's first year, one YAML file per
change. A capsule is the predecessor of a [spec](../specs/README.md): the same
questions (what is this change for, what does it affect, what was decided and
what was rejected) in a fixed schema instead of prose. New changes write a spec;
the capsules stay because they are the provenance of the decisions they record,
and a decision record that is edited after the fact is no longer a record.

## Pre-import context

These capsules record pre-import engineering decisions, not proof of
configuration or release state in a future destination. The planned fresh
import excludes old Git and GitHub state, including issue and pull-request
histories. Required settings, credentials, tags and releases must be verified
separately in that destination.

## Format

`CAPS-<NNN>-<slug>.capsule.yaml`, numbered in order of authoring. Every file is
`kind: change-capsule`, `schema: 1` and `status: sealed`, with these fields:

| Field | What it holds |
|-------|---------------|
| `intent` | What the change is for, in a sentence or two |
| `impact` | `visibility`, `benefit`, `compatibility` and the `risk` list a reader should weigh |
| `decisions` | The choices made, each with its id, the `choice`, the alternatives and the reason |
| `tags` | Free-form labels |

## What reads them

- `scripts/check-capsules.py` (`make check-capsules`) refuses a capsule whose
  YAML the policy engine cannot parse, or whose number is claimed by two files.
  It is a typo check for the two mistakes prose in YAML actually makes, not a
  schema validator; its module docstring says exactly what it covers.
- The intent gate (`src/cross-cutting/intent`) discovers `.capsules/*.yaml` as
  intent artifacts, so a capsule still satisfies the gate for a change that
  touches it.
- The risk module's policy scan reads the directory as infrastructure input,
  which is why a YAML typo here once surfaced as a scanner failure four minutes
  into a pipeline run. The capsule check exists to report that typo by filename
  before any pipeline starts.
