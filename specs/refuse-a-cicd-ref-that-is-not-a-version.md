# Refuse a cicd reference that is not a version

## What shipped

`v3.8.4` tagged a `.github/workflows/dast.yml` whose two module references read

```
dagger --progress=plain -m github.com/context-and-oss/cicd/src/composites/dast@fix/dast-evidence-write call scan
dagger --progress=plain -m github.com/context-and-oss/cicd/src/composites/dast@fix/dast-evidence-write call package
```

`fix/dast-evidence-write` was the development branch of a merged pull request. It was deleted
the moment that PR merged, four commits before the tag. Every consumer of
`dast.yml@v3.8.4` therefore asks the Dagger CLI for a module reference that
resolves to nothing, and the DAST pipeline cannot start.

Both pin gates reported OK on the commit that was tagged:

```
$ python3 scripts/check-workflow-pins.py   # 0
$ python3 scripts/check-repo-surface.py    # 0
```

This is the founding doctrine at the pin layer. The reference could not run,
and it read as clean.

## Why every existing mechanism was blind

There are three, and all three key on the same shape.

| Mechanism | Where | Pattern |
|---|---|---|
| release bumper rewrite | `CICD_PIN_PATTERNS`, `scripts/repo_surface.py` | `@v\d+\.\d+\.\d+` |
| version skew | `VERSION_SCAN` → `check_pin_consistency` | `@v\d+\.\d+\.\d+` |
| command exists | `DAGGER_CALL_RE` → `check_dagger_commands_exist` | `@v\d+\.\d+\.\d+` |

A reference in any other shape matches none of them. It is not reported as
disagreeing with the others; it is **not seen**. So the branch ref was

- never rewritten by `scripts/bump-version.py`, at v3.8.4 or at any later
  release — it would have outlived every version bump silently;
- never compared against the repository's version, so no skew was possible;
- never resolved to a module, so `call scan` and `call package` were never
  checked against the composite's source either. A second check went quiet as a
  side effect of the first one's blindness.

The three patterns agreeing is what made this a single point of failure rather
than three independent chances to notice.

## The check

`check_cicd_refs_are_versions` (`scripts/repo_surface.py`) asks the question
prior to consistency: *is this reference a version at all?* It walks the same
active surfaces `check_pin_consistency` walks, and refuses any
`context-and-oss/cicd/<path>@<ref>` whose ref is not `vX.Y.Z`.

Refused, with the reason each is refused for:

- **a branch** (`@fix/dast-evidence-write`, `@main`) — outlives its branch;
- **a moving major** (`@v1`) — this repository publishes no moving major tag.
  All 83 of its tags are full `vX.Y.Z`, so `@v1` resolves to nothing at all.
  It is refused precisely because it *looks* like idiomatic GitHub Actions;
- **a commit sha** — immutable, and therefore tempting. Still refused: the
  bumper cannot rewrite it, so it silently outlives every release.

Not refused:

- **another project's reference.** Scoped to `context-and-oss/cicd`, like every
  other pin pattern here. `github.com/acme/shared-models@some-branch` in a
  document is that project's business.
- **a historical document.** The check walks active surfaces only, so a spec or
  dated note recording what was true when it was written is out of scope by
  construction — including this spec, which quotes the broken ref twice above.

## Where it runs

Both gates, and the release-blocking one is the load-bearing placement.

`scripts/check-workflow-pins.py` is deliberately narrower than
`check-repo-surface.py`: it carries only failures a *release commit* could
repair. This one qualifies exactly — the repair is a pin rewrite, the same
repair skew needs, on the same line by the same script. Leaving it to the wider
gate is what let a broken reference reach a tag, because the wider gate's
verdict is not what the release pipeline consults.

`pin_guard.pending_repairs` does **not** excuse it. That tolerance exists for a
pin that *lags* — correct in shape, behind in value, repaired by the next bump.
A reference that is not a version does not lag. No bump makes it correct, so the
tolerance must not reach it, and `test_a_pending_repair_entry_does_not_excuse_it`
holds that open.

## Residue

- **The tag stays broken.** A git tag is immutable and moving it would be worse
  than the bug. `v3.8.4` consumers must move to the next release; nothing in
  this change repairs a published tag.
- **The check reads shape, not existence.** `@v9.9.9` is a well-formed version
  that this repository has never published, and this check accepts it.
  `check_pin_consistency` catches it by disagreeing with the repository version,
  which is the division of labour on purpose — but a reference to a *plausible
  but unpublished* version in a document nothing else pins would still pass.
- **Only `.github/workflows/dast.yml` was wrong.** `templates/azure-devops/dast.yml`
  and `docs/how-to-guides/scan-a-running-app.md` already read `@v3.8.4`,
  because they were in a shape the bumper could rewrite. The two workflow lines
  were the only ones the bumper could not see — which is the argument for this
  check in one sentence.
