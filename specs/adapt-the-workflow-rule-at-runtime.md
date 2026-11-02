# Adapt the workflow rule at runtime

## Why

The workflow compatibility check previously embedded a YAML rule alongside
first-party code. Rewriting its explanation did not establish redistribution
rights for retained upstream structure. Because the upstream rules are already
fetched for internal scanning under their own terms, obtain that structure at
runtime rather than distribute it under an assumed Apache-2.0 grant.

## Boundary and mechanism

`src/security/semgrep_gha.py` is a first-party adapter, not a vendored rule. It
reads the workflow rule and LICENSE from the pinned source, validates one
expected YAML rule with one Bash matcher, preserves its structural selectors
and upstream metadata, and replaces only that matcher with the existing
parser-safe compatibility regex. The finding identifier and first-party
explanation remain stable. The old embedded YAML body is removed.

Parsing YAML would discard comments, including possible notices. Instead the
runtime copy retains the complete original source, LICENSE and any root NOTICE
as comments beneath a prominent modification notice. The generated rule stays
under the Semgrep Rules License v1.0, not cicd's Apache-2.0 licence. This does
not authorise redistribution of generated rules/caches or scanning as a service.

`src/security/semgreprules.go` embeds the adapter only.
`src/security/sast.go` reuses the already-fetched pinned checkout for default
packs. A live-only scan fetches that checkout only after the measured upstream
rule's parser notification requires a rerun. Ordinary custom-only scans do not
fetch it, and secrets-only scans generate no workflow rule. No rule source or
engine pin, selected-file scope, severity threshold or exclusion changes.

`src/security/semgreprun.go` generates the selected config before the scanner
starts. Missing source/licence, an unexpected matcher, or an adapter failure
writes a non-run status rather than a partial clean result; a stale generated
config cannot survive failed regeneration. `src/security/semgreppack.go`
requires the generated rule's loaded identity, even on a live-only rerun.
The ordinary pinned-rule floor and separately required DOM rule remain intact.

## Verification

`src/security/semgrep_gha_test.py` uses invented upstream-shaped controls,
not copied upstream bodies. It exercises input preservation, retained notices,
invalid identity/language/severity/matcher contracts and stale-output refusal.
`src/security/semgreprules_test.go` runs that suite, requires the loaded identity,
and drives the production shell script to prove generation failure prevents
scanner execution while an ordinary custom config needs no adapter source.

A real pinned-image regression must compare the previous and generated
matching behaviour over positive, negative and parser-fragile workflow cases,
and a production source scan must prove the full default rule set still loads.
Upstream metadata is now retained, rather than stripped to the former minimal
subset; this is intentional notice/provenance preservation, not a change to
matching or finding severity. A rule-set count alone is not equivalence proof.

## Publication scope

Only the adapter and synthetic unit controls are distributed. Upstream rule
bodies, runtime-generated copies and private validation evidence are not added
to this tree. This boundary correction is not an independent legal certificate
or proof of destination repository settings, release availability or public
visibility. Existing own-code-use and raster-inclusion decisions are unchanged.
