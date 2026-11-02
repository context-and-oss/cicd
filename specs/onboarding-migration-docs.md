# Intent: onboarding entry point + migration guides

## Why

Teams adopting cicd landed on the module reference table and the `templates/`
starters with no narrative from *what they have* — a hand-rolled GitHub Actions
or Azure DevOps pipeline — to *what cicd expects*. They had to reverse-engineer
the step mapping themselves, and the two hardest ADO auth details (the `oauth2`
PAT username and the PR-comment OAuth grant) were buried in inline template
comments where first-timers reliably got stuck. We add the missing map and the
do-it-now onboarding so a newcomer, or their coding agent, can migrate a real
pipeline stage by stage instead of guessing.

## What changed

Docs only — no module or workflow behaviour changes. Three related issues
(migration map, ADO auth, README onboarding) slot into the existing
Diátaxis layout:

- `docs/reference/step-mapping.md` — the canonical "I run X today → it's Y in
  cicd" lookup, with a replace / feed-in / keep verdict per step. Both the
  migration explanation and the incremental how-to link here so the table
  lives in exactly one place.
- `docs/explanation/migrating-to-cicd.md` — the mental-model shift and
  before→after map for both source platforms.
- `docs/how-to-guides/adopt-incrementally.md` — an agent-drivable, one-stage-
  at-a-time adoption procedure that coexists with the legacy pipeline.
- `docs/how-to-guides/set-up-azure-devops-auth.md` — the authoritative ADO auth
  walkthrough, with a troubleshooting table.
- `README.md` — leads with intro, the consumer knowledge-base deeplink, and the
  getting-started paths; the module reference table moves below the fold.
- The ADO templates now deeplink to the auth guide instead of duplicating
  inline setup notes.

## Decisions

We placed the incremental onboarding under `how-to-guides/` rather than
`tutorials/`, because it runs against the user's own real pipeline file with
messy inputs — that is the how-to test in Diátaxis terms, whereas the existing
`getting-started` tutorial is the guaranteed-success first-check lesson.

We kept the step-mapping table as a single reference doc that both the migration map and the README onboarding
link to, rather than embedding a copy in each, because two copies of the same
lookup would drift apart the moment either doc is edited. That drift risk was
the whole reason to decide the structure before writing.
