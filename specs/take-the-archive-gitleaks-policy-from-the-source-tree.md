# Take the archive gitleaks policy from the source tree

## Why

`ScanArchive` runs gitleaks over the build output, and a Vite/React consumer's
hashed bundles trip `generic-api-key` on minified UI-library code. Measured on
gitleaks 8.30.1, a minified line in `wwwroot/assets/index-<hash>.js` that
assigns to an identifier ending in `Key` a chained assignment from a prop read
such as `r.ariaDescribedBy` is one HIGH finding: the keyword, the assignment,
and a value long and varied enough to pass the entropy floor. The consumer
could not clear it. The only accepted places for a gitleaks policy were the output root's own `.gitleaks.toml` and `.gitleaksignore`, and
those are files a deployable would have to ship, written by the build being
graded, regenerated on every build, and keyed to a content hash that changes
with every dependency bump. A gate the consumer cannot clear gets switched off
([doctrine](../docs/explanation/doctrine.md#a-gate-the-consumer-cannot-clear-gets-switched-off-so-cicd-clears-it)),
so cicd has to offer a policy source that is reviewable and does not ship.

## The mechanism

**Two optional arguments**, `--archive-gitleaks-config` and
`--archive-gitleaks-ignore`, on `security.ScanArchive` and on the commit
composite's `Run`, named the same in both places so an error message reads the
same wherever it is raised. They are forwarded by `.github/workflows/commit.yml`,
`.github/workflows/commit-monorepo.yml` and both Azure DevOps commit templates
(through `env:`, never a spliced macro).

**Both are read from the source tree, never from the output.** Validation runs
in two places because the spelling and the filesystem answer different
questions:

- `gitleaksPolicyPath` (`src/security/gitleakspolicy.go`) refuses the spelling
  before any container runs: an absolute path, a drive letter, a backslash, a
  `..`, an empty or `.` segment, or a control character. Each refusal names the
  flag and the reason.
- `gitleaksPolicyResolveScript` runs in the gitleaks image against the mounted
  source tree and writes one status word: `ok`, `missing`, `dangling`,
  `notfile`, `escape` or `unreadable`. It resolves the root and the target with
  `realpath` and requires containment, so a symlink that reaches outside the
  tree is refused however it is spelt (absolute target, `../` target, or a
  symlinked directory component). Under Dagger an out-of-tree link usually
  arrives `dangling`, because the host directory is uploaded with the link and
  without its target; that status says so rather than calling the file
  missing. Every status but `ok` is a non-run in `errors[]` that says the
  output was not scanned, because a policy the consumer asked for and cicd
  could not apply must never read as a scan under the defaults.

The accepted file is copied out and mounted at `/cicd-gitleaks/`, outside the
scanned `/src`, so the policy is never itself scanned as part of the output and
the output cannot overwrite it. The primary leg gets `--config` and
`--gitleaks-ignore-path`; the shadow leg gets neither.

**Unset is unchanged.** With neither flag the scan is the scan it was: no extra
container, no extra argument, and the output root's own `.gitleaks.toml` and
`.gitleaksignore` honoured and disclosed as before. `TestParseGitleaksPolicyUnset`
holds the zero policy and its empty argument list.

**Set, the output root must carry neither file.** Measured on 8.30.1:
`--config` does take precedence over a root `.gitleaks.toml`, but a root
`.gitleaksignore` is loaded whether or not `--gitleaks-ignore-path` is given — a
run with the supplied config and an output-root ignore entry dropped the
finding that entry named. Ignoring the output's file is therefore not something
cicd can do without deleting a file from the deployable it is grading, and
honouring both would make two sources of acceptance read as one. So
`gitleaksPolicyCollision` refuses the scan, naming the file and both ways out.
A directory that happens to be called `.gitleaks.toml` is not the file and is
not refused.

**A config that extends a path is refused.** gitleaks resolves `[extend] path`
against its working directory, which is the scanned output, so the output would
supply part of its own policy. `gitleaksConfigExtendsPath` detects the table
form, the dotted key and the inline table; `useDefault = true` is the form to
use instead.

**Disclosure reuses the source scan's code.** The shadow scan, the accepted
SARIF suppressions and the `SUPPRESSED` and `NARROWED RULES` warnings in
`src/security/gitleakssuppress.go` are the same functions; what changed is the
name they print. A `gitleaksOrigin` carries where the policy came from, and for
a supplied policy every line names the source-tree file and says it was
supplied for this scan:

```
gitleaks: SUPPLIED POLICY — the build output was scanned with the config .gitleaks.archive.toml (sha256:…), read from the source tree and not from the build output; what it removed is listed as SUPPRESSED, and a default rule it does not load as NARROWED RULES
gitleaks: SUPPRESSED — 1 finding in the build output was removed by the source tree's .gitleaks.archive.toml, the config supplied for this scan (an [allowlist] entry, or a default rule it disables, narrows or does not load) and is not counted: "wwwroot/assets/index-Cx9aB2kQ.js:1 generic-api-key"
```

The first line is the record of which policy graded the run: the path and a
truncated sha256 of the bytes gitleaks read, so a reviewer can tell two runs
under different versions of the same file apart. The evidence schema is
unchanged; the record lives in `warnings[]` beside the disclosure it explains.

**The composite refuses the flags on the other shapes.** `validateCommitInputs`
errors when either is set and `--artifact` is `container` or `none`, because no
build-output secrets scan runs there and a flag nothing reads is a knob that
looks reachable and is not.

## Writing the allowlist

gitleaks 8.30.1 ORs the conditions of an `[[allowlists]]` entry by default.
Measured against an output holding the prop read above, a real-shaped key in a
sibling bundle in the same directory, and one at the root: an entry with
`paths` and `regexes` and no `condition` removed both bundle findings,
including the real-shaped key. With `condition = "AND"` it removed only the
prop read, and the regex-only form did the same. The how-to recommends the AND
form, scoped to the one rule:

```toml
[extend]
useDefault = true

[[allowlists]]
description = "minified UI-library prop reads in hashed bundles"
condition = "AND"
targetRules = ["generic-api-key"]
paths = ['''^wwwroot/assets/[^/]+-[A-Za-z0-9_-]{8}\.js$''']
regexTarget = "match"
regexes = ['''=[a-z]\.aria[A-Z][A-Za-z]+[;,)}]?$''']
```

The match gitleaks tests includes the terminating character, so a regex
anchored on the identifier alone with `$` matched nothing; the optional
trailing class is what makes it apply.

## Rejected

- **Ignore the output-root files when a policy is supplied, and say so.**
  Preferred upstream, because a file in the shipped output is not a trustworthy
  policy source. It cannot be done for `.gitleaksignore` without removing the
  file from the scanned copy, which changes what was graded, and half-honouring
  the root (config ignored, ignore file not) is harder to read than refusing.
  Refusal is loud and has two one-line fixes.
- **Read the policy from the output with a different name.** Still written by
  the build being graded, and still shipped.
- **Accept a path into the checkout outside the source view.** In the
  monorepo fan-out each application's scan sees only its `source-paths`; a
  file outside them is refused as missing rather than reached around the view,
  so one application's policy cannot be another's by accident.
- **Parse the config to report what it allows.** A second resolver for one
  question. The shadow asks gitleaks itself, as the source scan already does.

## Traps

- Mounting the supplied file under `/src` puts it inside the scanned output and
  lets an output file of the same name replace it.
- Passing `--config` to the shadow leg makes the disclosure compare the policy
  with itself and report nothing removed.
- A future gitleaks that stops auto-loading a root `.gitleaksignore` makes the
  collision refusal stricter than it needs to be, never weaker; re-measure
  before relaxing it.
- Changing the status words in the resolve script without the Go switch in
  `gitleaksPolicyStatusError` lands in its "could not be checked" arm, which is
  still a non-run.
