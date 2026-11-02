# Refuse a language set that scans nothing, and name what `--include` left out

Two issues — the false pass and the disclosure gap — are one change because they are one code path: the branch in
`detectLanguages` that handled `--include` both dropped names it did not
recognise and returned before it could learn what it was dropping.

## The two silences

`--include` is the only way a consumer can reduce what cicd looks at, and until
this change it was the only reduction in this repository that left no trace.

**One — a name cicd did not recognise was dropped, and a list that dropped to
nothing passed.** `detectLanguages` mapped caller names onto languages with a
`switch` carrying no `default` arm. So `--include golang` resolved to an empty
language set, the per-language leg loop in `quality.Check` never iterated,
`allRan` stayed vacuously `true` because the loop that would have cleared it
never ran, and `gatedPassed(true, true, threshold)` returned `passed=true`. A
one-character typo produced a green quality gate over a repository where nothing
was linted and no test ran. Nothing errored and nothing warned.

That is this repository's founding doctrine — *a tool that could not run must
never read as "clean"* — arriving through a config value rather than a crashed
tool. It is worse than a crashed tool: no tool was even asked, so there is no
exit status to classify and no stderr to put in `errors[]`.

**Two — an exclusion was invisible.** The `--include` branch returned before
probing for marker files, so it never knew which languages were present. An
envelope from `--include go` on a repository containing `package.json` was
byte-identical to one from a repository that only contains Go. The narrowing was
recorded nowhere a reviewer looks.

CAPS-007 had already patched the first hole at one entry point, in shell, in
`.github/workflows/precommit.yml`. That guard is per-workflow: `commit.yml` had
carried the same input for longer with no guard at all, and every direct
`dagger call` was unguarded. And the second path into the false pass involves no
consumer mistake whatsoever — auto-detection legitimately returns nothing on a
tree with no marker file inside `-maxdepth 4`.

## What now happens

Pure resolution and diffing logic moved into a new **untagged** file,
`src/quality/include.go`, so it can be driven by a test: `lint.go`, where this
lived, carries `//go:build !unit_test` and none of it was reachable from the unit
suite. `src/quality/include_test.go` holds sixteen tests over it.

- **An unrecognised `--include` name is an error at the module boundary**
  (`resolveIncludeNames`). Every unrecognised name in the list is named in one
  message, together with the accepted set rendered from the alias map itself, so
  the error cannot fall out of step with what is accepted. The empty string
  lands here too: `--include ""` asks for a language whose name is nothing.
- **A non-empty `--include` therefore always resolves to at least one
  language**, which closes the caller-mistake half of the false pass — and
  closes it harder than `passed=false` would, because no envelope is produced at
  all and there is nothing to mistake for a gate verdict.
- **An excluded language says so.** `quality.Check` now probes for markers even
  when `--include` was given, purely to compute the difference, and emits one
  warning per language it found and skipped:
  `quality: NOT SCANNED — node detected (web/package.json) but excluded by --include go`.
  The marker path is quoted because "node detected" is a claim a reader must take
  on trust while "node detected (web/package.json)" can be checked — and a marker
  four directories down is exactly the case where a consumer's model of their own
  repository is wrong.
- **If the probe itself fails**, the run does not fall back to silence: it
  reports `quality: EXCLUSION NOT CHECKED` rather than implying nothing was
  excluded.
- **Zero languages from auto-detection is a warned pass**, carrying
  `quality: NO LANGUAGE DETECTED — nothing was linted and no unit tests ran, so
  this gate passed over no work`, which quotes the search depth and the marker
  filenames it looked for and names the `--include` values that would reach
  deeper. `notify` renders warnings verbatim into the Teams card and the PR
  comment, so the disclosure reaches a reviewer rather than a log.

## Why zero auto-detected languages is a warned pass and not a failure

The false-pass issue asked for this to be argued rather than decided by implementation
accident, and the argument is the reason the caller mistake above is an error
instead.

After `resolveIncludeNames`, a non-empty `--include` can no longer produce an
empty language set. The only remaining way to reach zero languages is
auto-detection on a tree carrying no marker file — a documentation-only
repository, or one written in a language this module does not lint. Both are
legitimate, and both consume the composites for the security scan, the SBOM and
the intent gate, which all still run.

Failing them would be a permanent red with no remedy available to the consumer.
`--fail-on NONE` deliberately does not suppress a non-run, so the one knob a
consumer reaches for cannot clear this either; there would be no configuration
in which such a repository could go green. The precedent is `intent.Check`, which
runs when it was not required and returns `intent-gate: NOT REQUIRED …` rather
than either failing or staying silent — an off gate that says so.

The property the doctrine actually demands is preserved: the envelope must not
render identically to a repository where every leg ran and passed. It does not.

## The alias set is one set held in two places, so it is checked

The accepted spellings are deliberately **not** one name wider than
`detectLanguages` has always taken. Obvious synonyms (`golang`, `javascript`,
`js`, `cs`, `.net`) were added during this change and reverted: the same list is
carried by a shell `case` guard in `.github/workflows/precommit.yml` and
documented in `templates/azure-devops/precommit.yml` and
`docs/reference/index.md`, so a name accepted by the module and refused by the
guard is a contradiction between two gates on the same input — a worse consumer
experience than a clear error naming the accepted set.

Both halves are wanted. The guard fails in a second and names the accepted set
without provisioning a Dagger engine; the module error covers `commit.yml` and
every direct `dagger call`. That makes it two copies of one set, which is a drift
this repository has already been bitten by, so
`check_include_language_set` in `scripts/repo_surface.py` fails CI when the
`languageAliases` map in `src/quality/include.go` and that `case` arm stop
agreeing — in either direction, with the offending name and the file that lacks
it printed. It normalises the guard's lowercasing and its quoting of `'c#'`
(`#` starts a comment in shell), because neither is a difference in the accepted
set. A missing file, a renamed map, an empty map or a removed `case` arm are all
refusals rather than passes, since each would otherwise compare against an empty
set and report agreement with nothing.

## The search depth stopped being a magic number

`noLanguageDetectedWarning` has to tell a consumer how deep cicd looked, which
means the depth has to be readable from Go rather than embedded in a `find`
string. `markerSearchDepth = 4` and `markerFindArgs()` now live in
`src/quality/markers.go` and `src/build/markers.go` — the two copies stay
byte-identical, as they already had to — and the three `find` call sites
(`src/quality/lint.go`, `src/build/archive.go`) build their arguments from it.
`TestMarkerFindArgs_CarriesTheSearchDepth` asserts the warning and the command
cannot disagree.

## What was proven

Through real `dagger call` runs against the fixtures in `testdata/`:

- `--include golang` fails at the module boundary naming `"golang"` and the
  accepted set; no envelope is produced.
- `--include go` on a tree containing `package.json` produces the `NOT SCANNED`
  warning with the marker path in it.
- A tree with no marker file produces `passed=true` with the
  `NO LANGUAGE DETECTED` warning, and the two envelopes are distinguishable.
- The `quality.Test` path reports the same exclusion disclosure.
- go-app, node-app and dotnet-app all still pass with zero spurious warnings.

And `scripts/tests/test_repo_surface.py` covers the new surface check in both
drift directions plus every refusal case, with the baseline fixture carrying a
coherent `include.go` and guard so that a passing baseline means something.
