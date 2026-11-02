# Name the version file cicd could not use

`ResolveToolchain`
returned a bare image string, so a version file cicd read and rejected produced
byte-identical output to a repository that committed no version file at all.

## The mechanism

ADR-004 resolves the container a consumer's own command runs in at three levels:
an explicit `--toolchain-image`, then a version file (`.nvmrc`, `global.json`),
then a pinned per-language default. Level 2's two readers each returned
`(string, bool)`, and `false` meant one of two very different things:

- there is no such file, or
- there is a file, cicd read it, and it did not yield a version.

The caller could not tell them apart, because the only thing it received back
was the image — and the image is the *same* in both cases. That is the whole
defect. `mcr.microsoft.com/dotnet/sdk:8.0` is both the band a `global.json` can
legitimately ask for and the band a repository gets for asking nothing, so the
answer carries no trace of the question.

Measured against the real resolver:

```
| version file             | lang   | image                             | from        | note
| no global.json           | dotnet | mcr.microsoft.com/dotnet/sdk:8.0  | default     | (none)
| runner-only global.json  | dotnet | mcr.microsoft.com/dotnet/sdk:8.0  | default     | global.json declares no sdk.version, …
| sdk.version "10"         | dotnet | mcr.microsoft.com/dotnet/sdk:8.0  | default     | … "10", which is not a major.minor version, …
| malformed global.json    | dotnet | mcr.microsoft.com/dotnet/sdk:8.0  | default     | global.json is not valid JSON, …
| sdk.version "10.0.100"   | dotnet | mcr.microsoft.com/dotnet/sdk:10.0 | global-json | (none)
| no .nvmrc                | node   | node:20-alpine                    | default     | (none)
| .nvmrc "lts/iron"        | node   | node:20-alpine                    | default     | .nvmrc declares "lts/iron", which is not a version number, …
| .nvmrc "" (whitespace)   | node   | node:20-alpine                    | default     | .nvmrc is empty, …
| .nvmrc "22"              | node   | node:22-alpine                    | nvmrc       | (none)
| .nvmrc "lts/iron", go leg| go     | golang:1.26-alpine                | default     | (none)
```

The first four rows are one image and four different facts. Before this change
they were one image and nothing else.

## Why this is not merely untidy

Two of those rows are things a careful consumer does on purpose.

`lts/iron` is idiomatic nvm. It is not a typo and not a malformed file; it is the
documented way to say "the current LTS line", and cicd cannot turn it into a tag
because the mapping from alias to release lives in nvm. So the consumer writes a
correct `.nvmrc`, cicd silently ignores it, and the tests run on node 20
regardless of which release `iron` names this year.

A runner-only `global.json` is worse, because **this repository's own guidance
tells the consumer to write it**. `detect-the-dotnet-test-runner` establishes
that `"test": {"runner": "Microsoft.Testing.Platform"}` in the repository-root
`global.json` is the only mechanism that selects the MTP command line. A
consumer who follows that and adds nothing else has a `global.json` with no
`sdk` key, which resolves to the pinned 8.0 band — and 8.0 predates the opt-in,
cannot honour it, and routes the invocation through VSTest. The two documents a
consumer reads about the toolchain chain now say so (CAPS-029), but a document
is not the run, and nothing in the evidence of the run said anything at all.

## Why the trigger is "present but not decisive"

The first issue is naturally read as *"a version file cicd could not parse should say so"*,
which suggests a discriminator at the key level: `sdk.version` was declared and
was unusable. That reading is wrong in a way worth recording, because it is the
first design I settled on and it is silent on the second issue's measured case.

A runner-only `global.json` has **no `sdk.version` at all**. It is absent, not
unusable. A "declared but unparseable" trigger fires on `"10"` and on malformed
JSON and stays quiet on precisely the file that motivated the report.

So the trigger is the disjunction of both: a note is produced when a version file
was **present and did not determine the image**. That covers no-`sdk.version`,
unparseable `sdk.version`, malformed JSON, an nvm alias and an empty file, with
one rule and no list of cases to keep extending.

## Why the silence is kept where it is kept

A note fires only on that anomaly. A repository with no `.nvmrc` and no
`global.json` produces no warning and no note.

That is deliberately the opposite call from `dotnetLegScopeWarning`, which fires
on **every** .NET leg, and the difference is where the information sits. There,
every run is in the same epistemic position — cicd counted projects and cannot
know how many the consumer's command should have run — so an absence would carry
no information and the line has to be unconditional. Here the absence *is* the
answer: no line means this tree pins no toolchain version. An unconditional line
would destroy the only thing that makes the conditional one worth reading, which
is `say-what-no-artifact-left-unattested`'s rule that a disclosure on every run
is noise a reader learns to skip.

The structured fields carry the same information without that constraint.
`toolchainFrom` is on every leg — `explicit`, `nvmrc`, `global-json` or
`default` — because a field is not something a reader habituates to, and
`name-the-scope-a-byo-leg-witnessed` states the narrow rule this satisfies: an
every-run value is defensible when it is a structured field a consumer who
chooses to compare envelopes can read. As there, nothing in cicd diffs those
fields; the field buys the *availability* of the signal and exercising it is the
consumer's.

## What is a warning and not an error

A warning, at every threshold, and never an error. Nothing failed to run: the
pinned default band is frequently the right band, a consumer may not care which
node minor runs their tests, and `--fail-on NONE` cannot clear a non-run anyway.
Failing here would be a permanent red on a repository doing nothing wrong, which
is the shape that keeps `NO LANGUAGE DETECTED` a warning too.

## The guard on the copies, and the drift it can see that the old one cannot

Dagger modules are isolated, so `toolchain.go` exists three times: the canonical
`src/internal/detect/toolchain.go` and module copies in `src/quality` and
`src/build`. Nothing checked that the three agreed. Grepping `Makefile`,
`scripts/`, and `scripts/repo-inventory.json` for `toolchain.go` returned
nothing at all, which is the `.slnx` hazard exactly — a marker missing from two
of its three copies for as long as nothing compared them.

The obvious fix is a `synced_files` entry, and it is not sufficient. That check
compares copies **against each other**, and the failure that actually happens is
both copies agreeing with each other and disagreeing with the canonical file,
which is what happens every time somebody edits the canonical file and forgets
the copies. Measured on this tree: appending one line to
`src/internal/detect/toolchain.go` left the two module copies with the identical
md5 `58d938f8…`, so a copy-vs-copy comparison had nothing to report while the
canonical implementation had moved out from under both.

So the copies are **generated** — `scripts/sync-toolchain.py`, `make
sync-toolchain` — and `check_generated_files` in `scripts/repo_surface.py` runs
the generator and diffs its output against what is on disk. Both directions are
measured: editing a copy fails the check, and editing the canonical file fails it
for both copies while a byte comparison between them still passes.

Three properties of that check follow the house rules rather than convenience. A
generator that exits non-zero is a problem and not a pass, because nothing was
compared and reporting agreement would be the founding doctrine's exact failure
in the tooling. An absent generator or source is a problem and not a skip, for
the same reason `check-go-format` has three answers instead of two. And the
generator anchors on the canonical import block's own closing paren rather than
hardcoding an import list, because a hardcoded list would be a fourth copy of the
same information inside the thing built to stop copies drifting.

## What this does not do

**`build.BuildArchive` is still silent, and the reason is structural.** It
resolves its toolchain through the same resolver and now receives the same note —
and it returns a `*dagger.Directory`, not an evidence envelope, because the
commit composite hands that lazy directory reference straight to
`security.ScanArchive`. There is no `warnings[]` on that path to put the note in.
Surfacing it means changing `BuildArchive`'s return type or adding a second entry
point, which is a consumer-visible interface change well outside this change, so
the archive path is documented as silent rather than half-fixed. Anyone reading
this change as "cicd now discloses an unusable version file" should read that
sentence again: `quality.Test` does.

**A usable version file is reported, not vetted.** `toolchainFrom: nvmrc` means
`.nvmrc` chose the image. It does not mean the image is a good idea, and nothing
here checks whether the resolved tag exists before the container is pulled.

**Nothing infers a band from the runner key.** A `global.json` asking for
Microsoft.Testing.Platform and no SDK is now disclosed, not corrected. Guessing
which SDK the consumer wanted is a different decision and belongs to whoever owns
The second issue's remaining half.

**The note quotes the file's content, and the quoting is bounded rather than
sanitised.** `quoteFileValue` maps newlines and tabs to spaces, drops control
characters, and truncates past 60 bytes *with the truncation stated* — a quietly
shortened value is a value the reader believes they are seeing in full. It
deliberately does **not** remove backticks. Markdown safety belongs to notify's
`codeSpan`, which fences with the longest internal backtick run plus one so the
span cannot be closed from inside (`fence-the-span-a-branch-name-can-close`), and
`card.go` renders no warnings at all. Stripping the byte here would re-introduce
the mutation that spec rejected and leave two copies of one rule free to
disagree. A test asserts the backtick survives, so the boundary is recorded
rather than left to be rediscovered.

## Mechanics that are load-bearing

`ResolveToolchain` is kept as a wrapper over `ResolveToolchainDetail` rather than
having its signature changed. Two production call sites and two test files use
it, and the change must be image-preserving; every row of
`TestToolchainDetail_Provenance` asserts that
`ResolveToolchain(...) == ResolveToolchainDetail(...).Image` so a future edit
cannot make the wrapper and the detail disagree.

`toolchainNoteWarnings` lives in `src/quality/testlegs.go`, which is untagged,
and not inline in `byotest.go`, which is `//go:build !unit_test`. The invariant
worth asserting is a biconditional — a warning appears if and only if a
resolution carries a note — and a loop behind that tag cannot be asked about it.
That is the shape that let a `switch` with no `default` arm resolve
`--include golang` to an empty language set and report `passed=true`
(`refuse-a-language-set-that-scans-nothing`).

`toolchainNoteWarnings` returns nothing at all when its two slices differ in
length, rather than iterating the shorter one. Attributing one leg's toolchain to
another is worse than the silence being replaced: it sends the consumer to
correct a file the named leg never read.

The note names the file **and** the image used instead. A disclosure that says
only "a version file was ignored" sends the reader looking, which is most of the
way back to saying nothing; a test asserts both strings are present.

`ToolchainFrom` and `ToolchainNote` both carry `omitempty`, which is safe here
and would not be on a count: an empty string and an absent field make the same
claim about provenance, whereas `CoverageDocumentsMerged` had to be a pointer
because `0` and "never asked" are different facts.
