---
name: Bug report
about: cicd reported something other than what it measured, or a module or template did not run
title: ""
labels: bug
assignees: ""
---

## What happened

<!-- One paragraph. If a gate passed when it should not have, or failed when
nothing was wrong, say which: the founding doctrine here is that a tool that
could not run must never read as "clean", so a false pass is the bug we most
want to hear about. -->

## Where

- Module or workflow: <!-- e.g. src/security ScanSource, .github/workflows/precommit.yml, templates/azure-devops/commit.yml -->
- Pin: <!-- @vX.Y.Z -->
- Runner: <!-- GitHub Actions / Azure DevOps / local `dagger call` -->
- Language(s) the module detected: <!-- go, node, python, dotnet -->

## Evidence

<!-- Attach or paste the relevant part of the evidence envelope
(`combined-evidence.json`, or the module's own `evidence.json`): the row's
`passed`, `errors[]`, `warnings[]` and `examined`. Strip anything private
first; a redacted envelope is still more useful than a prose description. -->

## How to reproduce

<!-- A command against a public repository or one of the fixture apps under
testdata/ if you can; the pipeline YAML or `dagger call` line otherwise. -->

## What you expected
