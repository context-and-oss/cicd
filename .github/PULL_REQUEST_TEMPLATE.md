## What this changes

<!-- One paragraph: the defect or gap, and what a reader of the evidence or
the pipeline output sees differently after this change. -->

## Intent artifact

<!-- The change-intent gate reads this pull request's diff and expects a
document that names the files it changes: a spec under specs/ for a behaviour
change, a capsule under .capsules/ for a decision. Link it here, or say why the
change needs none (a typo, a comment, a dependency bump). -->

## Checklist

- [ ] Nothing private: no consumer, customer, organisation or person names, no private issue/PR/SHA/run references, no unlicensed third-party material ([REVIEW.md](../REVIEW.md))
- [ ] Every commit subject parses as a conventional commit (`fix(scope):`, `docs:`, `chore:`, `refactor(scope):`, `ci:`, `test:`); `scripts/check-commit-subjects.py` refuses the rest
- [ ] `make check-surface` passes (declared paths, links, pins and documented commands)
- [ ] `make test-module-units` passes for every module this touches
- [ ] A tool that could not run still reports `passed=false` with an `errors[]` entry; nothing here ends in `|| true` or fabricates an empty report
- [ ] Any new container image is digest-pinned in the module's `images.go` and declared in `scripts/runtime-images.json`
