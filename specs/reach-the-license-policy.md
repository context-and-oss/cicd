# Reach the license policy, and say which license you allowed

A knob nobody can reach and a knob nobody needs look identical from outside.
`security.ScanLicenses` has carried `--license-gate`, `--license-allow` and
`--license-exclude` for several releases, and `commit.yml` — the workflow every
consumer of the commit stage calls — exposed none of them for five releases. A
consumer received license findings and had no input that could act on them.

Behind that, two classification defects made the knob less useful than it looks
even once it is wired: a rationale comment that described a taxonomy Trivy does
not have, and a policy whose only unit was the category — which for the case
that actually arrives is the same as no policy at all.

## Why

The historical workflow surface at `v3.8.5` showed the mismatch directly:

| Surface | `license-gate` | `license-allow` | `license-exclude` |
|---|---|---|---|
| `.github/workflows/precommit.yml` | exposed, forwarded | exposed, forwarded | exposed, forwarded |
| `.github/workflows/commit.yml` | **absent** | **absent** | **absent** |
| `.github/workflows/commit-monorepo.yml` | **absent** | **absent** | **absent** |
| `templates/azure-devops/commit.yml` | **absent** | **absent** | **absent** |
| `templates/azure-devops/precommit.yml` | **absent** | **absent** | **absent** |

The consumer report named the first two rows and asserted the third was fine. It was
not: precommit *is* wired on the GitHub side, and neither Azure DevOps starter
forwarded a license flag at all. The issue's own reading of the surface was
wrong in both directions, which is the shape of the problem — nothing in the
repository could answer the question, so everyone guessed.

Nothing detected the drift because nothing asked. `check-repo-surface.py`
verifies that every documented Dagger command exists, that pins agree and that
no active document is undeclared. It had no check for the inverse: a parameter
that exists and that no starter surface can set.

## What was wired

`license-gate`, `license-allow` and `license-exclude` are now inputs on
`.github/workflows/commit.yml`, `.github/workflows/precommit.yml` and
`.github/workflows/commit-monorepo.yml`, and are built into the call line by
the same `extra=()` pattern the other optional flags use, with a `_trim()`
helper rather than `xargs` — `xargs` interprets quotes and backslashes, and a
license string is exactly the place a quote arrives.

The four Azure DevOps starters (`commit.yml`, `precommit.yml` and their
`shared/` forms) forward the same three through the step's `env:` mapping and a
`case "${VAR:-}" in ''|'$('*) ;;` guard. The guard is not decoration: ADO
expands `$(VAR)` textually before the shell parses the line, so an undefined
variable arrives as the literal string `$(LICENSE_ALLOW)` and would otherwise be
passed to the module as a policy.

## The check that refuses the next one

`check_composite_params_reachable` (`scripts/repo_surface.py`, check 19) reads
each composite's exported `Run` signature from Go source, mangles each
parameter to its Dagger flag (`licenseAllow` → `--license-allow`), and requires
every starter surface that calls that composite to name it — or to carry a
written reason in `composite_reach.unreachable`.

Four things make it safe to run against a repository this size.

**It reads source, not `dagger functions`.** An engine, a network and a
generated SDK are three things a surface check cannot require, and a check that
cannot run is the failure mode this repository is built around.

**It refuses a signature it cannot read rather than passing it.** The parse
handles one parameter per line and gofmt's grouped form. A single-line
signature, or one that parses to no parameters, is reported as the check's own
blindness. A composite call whose module reference it cannot resolve has to be
declared in `unreadable_sites` with a reason — there is exactly one, the local
pre-push helper, which resolves its module into a shell variable so it can fall
back to a working tree.

**Prose is never read as a command.** Reachability is judged only over
`run:`/`bash:`/`script:` block bodies and inline script lines, with comment-only
lines removed. This is the `check_cross_module_develop` precedent: its first
version read a `dagger` invocation out of a header comment and reported a module
that does not exist. A flag documented in a comment block and not passed on the
call line does not count, which is the whole point — `templates/azure-devops`
documents `--include` in prose precisely because routing it through a pipeline
variable is refused.

**A stale exemption is itself a problem.** `unreachable` currently holds 27
entries covering 89 parameter/site pairs, each with a reason. An entry for a
parameter a surface now *does* name is reported, so the list cannot rot into a
blanket suppression — the same rule the inert-pattern warnings apply to license
excludes, one level up.

## The taxonomy the comment described

`licensereport.go` explained the default allowlist with:

> reciprocal is deliberately NOT here. MPL, EPL and LGPL carry source-sharing
> obligations …

LGPL is not in Trivy's `reciprocal`. Verified against `v0.70.0`'s
`pkg/licensing/expression/category.go`:

| Category | Members that matter here |
|---|---|
| `forbidden` | AGPL-1.0, AGPL-3.0, the CC-BY-NC family, WTFPL |
| `restricted` | GPL-1.0/2.0/3.0, **LGPL-2.0/2.1/3.0**, OSL, QPL-1.0, Sleepycat, CC-BY-SA, CC-BY-ND |
| `reciprocal` | MPL-1.0/1.1/2.0, EPL-1.0/2.0, CDDL-1.0/1.1, CPL-1.0, APSL, IPL-1.0, FreeImage, Ruby |
| `unencumbered` | CC0-1.0, Unlicense, 0BSD |

The error mattered in a specific way. It made `--license-allow reciprocal` read
as "accept the weak-copyleft tier", when it accepts neither LGPL nor GPL — and
it hid the real cliff, which is that the single category between `reciprocal`
and `forbidden` is `restricted`, and allowing it accepts GPL. The issue made the
mirror-image mistake, claiming that allowing `restricted` accepts AGPL. It does
not; AGPL is `forbidden`. Both readings are wrong and both are the kind of wrong
a comment cannot be trusted to fix.

`licensecategories_test.go` pins it against
`testdata/trivy-0.70.0-license-categories.json`, captured from that source and
carrying the recapture instruction in its own `$comment`. The fixture's
`trivyVersion` must equal the version constant in `images.go`, so bumping the
scanner without re-reading the taxonomy fails rather than drifts. The test also
checks cicd's `licenseSeverity` against Trivy's own `categoryToSeverity`
projection and asserts the one deliberate divergence: Trivy maps an
unrecognised category to UNKNOWN severity, cicd maps `unknown` to HIGH, because
a declaration nobody could classify is not a low-severity fact.

## Allowing a license without allowing its category

The findings the consumer could not act on are the reason the category is the wrong
unit. Both of the declarations behind them land in `unknown`:

- `BlueOak-1.0.0` — a permissive license simply absent from Trivy's table at
  `0.70.0` and on upstream main.
- `SEE LICENSE IN LICENSE` — npm's marker for "read the file", with no entry in
  Trivy's `normalize.go` (which maps only `LPGL, SEE LICENSE FILE.`).

Before this change the only remedies were `--license-allow unknown`, which
accepts every unclassifiable declaration forever, and `--license-exclude`,
which drops the path from the scan entirely. Both are off switches.

`--license-allow` now accepts declared license *names* beside categories, under
three rules.

**It narrows, never widens.** A name is matched against the **whole** declared
string, normalised for case and for runs of whitespace. The operands of an
expression are not evaluated: an allowance for `MIT` does not cover
`MIT OR GPL-3.0`. Evaluating operands would require cicd to keep its own
license table, and that table would be a second policy, quieter than the first
and answering the same question — the "two resolvers for one question" failure
this repository has already paid for once.

**`unknown` is no longer an allowable category.** That is a deliberate breaking
change. A consumer who had allowed it gets a hard error naming the route that
replaces it, rather than a silent reinterpretation, because a pipeline
reporting a policy nobody wrote is the thing being fixed.

**An unclassifiable declaration is allowable by name, and an ambiguous name
must be scoped.** A name shaped like an SPDX expression — identifiers separated
by `AND`, `OR` or `WITH`, parentheses stripped — identifies a license and means
the same thing wherever it appears, so it is allowed globally. Anything else
must be written `<package>=<declared string>`: `SEE LICENSE IN LICENSE` is not a
name but an instruction, and the identical sentence appears in unrelated
packages, so a global allowance for it would silence packages nobody has read.

**Nothing is allowed silently.** Every allowance and its hit count reaches
`genericReport.allowedNameHits`, zeroes included, and the run-level count is
`allowedByName`. An allowance that covered nothing is a warning, with a
scope-specific hint for the `pkg=name` form. A policy still carrying an
exception for a package that stopped declaring it otherwise looks exactly like
a clean tree.

## Traps

**A named allowance is checked after the category check, not before.** If it ran
first, an allowance covering only declarations the category policy already
admits would record hits and never warn — a stale entry that looks live.
`TestACategoryAllowedDeclarationDoesNotConsumeAnAllowance` is that ordering,
asserted.

**A bare all-lowercase word is refused.** This is a regression the feature could
have introduced and nearly did. Before names were accepted, every non-category
entry was an error, so `--license-allow permisive` was caught as a typo. Once
names are accepted it would have become a global allowance for a license nobody
has ever declared — silently. `looksLikeCategoryTypo` refuses it with a message
naming both readings. The documented cost: a genuinely lowercase SPDX
identifier such as `curl` has to be scoped to its package.

**A single token cannot be told from an identifier.** `UNLICENSED` is npm's
marker for "deliberately not licensed" and is shaped exactly like an SPDX id, so
it is accepted globally. Stated in the tests rather than left to be discovered.

**A declaration with no name is never allowed.** A row carrying no license text
cannot be the declaration a consumer read and accepted, so matching it on a
guess would drop a finding nobody asked to drop.

**The flag-name mangling is the check's own, and is asserted against Dagger's.**
`dagger_flag_name` is a five-character regex, and a wrong one would make the
check report every parameter as unreachable or none.

## Residue

`templates/local/scripts/cicd-prepush` is not graded, by declaration. It runs
the same composite `precommit.yml` runs, and that workflow is the surface a
consumer configures.

A declared license string containing a comma cannot be passed through any
starter surface, because every one of them splits the input on commas. The
module accepts repeated `--license-allow`, so the case is reachable by calling
it directly, and the templates say so.

`build.BuildArchive` and the other composite parameters listed in
`composite_reach.unreachable` stay unreachable with reasons. The check makes the
list a decision rather than an accident; it does not make the decisions.
