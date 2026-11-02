# Say what `--artifact none` left unattested

This change closes the artifact-disclosure gap. Artifact *multiplicity*
(`--artifact-legs`) and accepting builder-produced images cicd did not build
remain separate decisions; see "What this does not do" below.

## The two states that were indistinguishable

`commit.Run`'s artifact selector has three values, and the third one recorded
nothing. The whole `none` arm of the switch was this:

```go
case "none":
	// No artifact build. The SBOM comes from stage-2's scan-source Trivy-FS
	// CycloneDX (source lockfiles), already present in srcGate.
```

A comment. No evidence file, no warning, no field. So for a commit-stage run:

| Repository | What the audit contained |
|---|---|
| ships no deployable artifact at all (a library, an infra/config repo) | source-gate evidence, `passed: true`, `sbom.cdx.json`, no artifact record |
| ships multiple deployables, none of which cicd was pointed at | source-gate evidence, `passed: true`, `sbom.cdx.json`, no artifact record |

Byte-identical, modulo the source-gate findings that have nothing to do with the
artifact. Not "similar" — there was no field, no count, no string anywhere in
`combined-evidence.json`, `comment.md` or the Teams card whose presence or
absence separated the two. Measured by reading the branch, and by `grep`:

```
$ grep -n "artifact" src/composites/commit/main.go | grep -i "none\|warn\|not built"
231:	case "none":
234:		return nil, fmt.Errorf("invalid --artifact %q: want container|archive|none", artifact)
```

One `case` label and the invalid-value error. Nothing else.

This is the repository's founding doctrine — *a tool that could not run must
never read as "clean"* — on the artifact side, and it arrives the way the
`--include` hole and the opt-in intent gate arrive: through a configuration
value, not a crashed tool. There is no exit status to classify because nothing
was asked to run. An artifact tail that did not run produces exactly what an
artifact tail that ran and found nothing produces.

Two things make it worse here than the general case.

**`none` is not only chosen by repositories that have nothing.** It is also the
value a consumer lands on when the other two shapes do not fit. For example,
a repository can ship several builder-produced images without Dockerfiles:
`container` cannot build those images, `archive` does not describe that image
set, and `none` is the only applicable selector value.
`none` is therefore the shape most likely to be selected by a repository for
which it is factually wrong, and it was the only shape that said nothing.

**The audit still contains an SBOM.** `sbom.cdx.json` is present in a `none`
audit exactly as it is in a `container` audit, because stage-2's `scan-source`
produces a Trivy-FS CycloneDX from source lockfiles. A reader who opens a
`none`-shape audit directory finds every file they would find in a `container`
one. The only difference is that one CycloneDX document was never merged in, and
"an SBOM that is missing components you cannot enumerate" is not something a
human reads.

## The fix

`build.NoArtifact` — an evidence function that runs no tool and returns a
**warned pass**:

- for machines, `genericReport.artifactAttested: false` (plus `artifactShape` and
  `sbomDescribes`), mirroring intent's `genericReport.required: false`. False
  rather than absent, because an absent key is indistinguishable from an envelope
  produced before the key existed;
- for humans, one warning, which `notify` renders verbatim into the PR comment
  and the Teams card:

```
artifact: NOT ATTESTED — --artifact none was selected, so no artifact was built
and neither an artifact SBOM nor an artifact scan ran (build.Build, build.Sbom,
security.ScanImage, build.BuildArchive and security.ScanArchive were all
skipped). sbom.cdx.json in this audit describes source lockfiles (stage-2
scan-source, Trivy-FS), not a deployable. Select --artifact container or
--artifact archive to attest one, or read this as confirmation that this
repository ships no deployable artifact.
```

(One line in the envelope; wrapped here for reading.)

It quotes facts rather than making a claim the reader has to take on trust —
`quality: NOT SCANNED — node detected (web/package.json) …` is the precedent.
The selector value that produced the run, the five functions that therefore did
not run, and what the `sbom.cdx.json` in the same directory actually describes.
That last clause is the one a reviewer is most likely to get wrong, and it is the
reason the disclosure is worth more than a boolean.

**Warned, not failed.** A repository with nothing deployable is legitimate — it
is the case `none` was added for — and `--fail-on NONE` deliberately does not
suppress a non-run, so the one knob a consumer would reach for could not clear a
failure here either. Gating it would be a permanent red with no remedy, which is
exactly why `quality: NO LANGUAGE DETECTED` is a warning too. This change is
disclosure, not gating; `passed` stays `true` and `failOnSeverity` is left unset,
because an envelope that gates nothing must not claim a threshold was applied.

### Where the logic lives, and why

`src/build/noartifact.go` is **untagged** (no `//go:build !unit_test`), and the
Dagger entry point in `main.go` is a three-line wrapper around it. Assembling an
envelope that records an absence needs no Dagger — no container, no source tree,
no exit status — so the warning text, the machine-readable statement and the fact
that the envelope passes are all driven by `noartifact_test.go` under the
canonical `-tags unit_test` runner. `src/quality/include.go` carries the same
split for the same reason: a `default`-less switch survived in `lint.go` for as
long as it did because nothing in that file could be tested.

`moduleName` and `moduleStage` moved from `main.go` into that untagged file. They
had to: `main.go` is `//go:build !unit_test`, so a test asserting the envelope's
module identity would have had to supply the identity itself, proving nothing
about what ships. `cross-cutting/evidence` rejects an envelope whose `moduleName`
is empty (`"unrecognised format"`), so the identity is load-bearing.

The remedy names `--artifact`, which is the *commit composite's* flag and not the
build module's. That is deliberate and precedented: `intent.Check` names
`--require-intent`, a flag owned by `stage-2` and `precommit`. A message naming
the producing module's own parameters would send the consumer looking in the
wrong place.

### The Dagger mechanics that could have bitten and did not

Both of the measured traps in this repository's Dagger surface are avoided by
construction rather than by care:

- **An optional bool can only ever be transmitted as `true`.** Dagger's generated
  Go client drops any optional argument holding its zero value
  (`if !querybuilder.IsZeroValue(...)`), which is why the intent gate's flag is
  the negatively-named `notRequired`. This change adds **no new parameter** to
  any function — `--artifact` already exists and is a string with three named
  values. There is no bool to get backwards.
- **A `+default=` pragma quoted as prose becomes the real default.** Dagger parses
  those pragmas anywhere in a parameter's doc block, and quoting one in prose
  once silently defaulted `notRequired` to on, disabling the gate for every
  direct caller. `NoArtifact`'s three parameters are required strings whose doc
  comments are one line each and contain no pragma text of any kind, and none of
  the prose in this change lives in a Dagger parameter doc block.

### Both channels are asserted, in both directions

`scripts/smoke/commit-shapes.sh` gained `assert_artifact_not_attested` for the
`none` shape — the record in `combined-evidence.json`, and the record in
`comment.md`, which is `notify.GithubBuildComment`'s real output. Two channels,
because a change that keeps the warning in the envelope while notify stops
rendering warnings would return the reviewer to silence with the envelope still
green.

And `assert_artifact_attested` for `container` and `archive`: neither may carry
the record. A disclosure that appears on every run is noise a reader learns to
skip, so the negative control is part of the guard, not an extra.

## What was proven

Measured on this branch, Dagger v0.20.8, darwin/arm64:

1. `dagger -m ./src/build call no-artifact --commit-sha localsha --branch main
   --repo-url https://example.com/repo` returns the envelope above:
   `passed: true`, `findingsCount: 0`, no `failOnSeverity`,
   `genericFormat: artifact-attestation`,
   `genericReport.artifactAttested: false`, one warning.
2. That envelope through `evidence.Wrap` → `combined-evidence.json` carries the
   warning (the aggregator concatenates `Warnings` from every envelope), and
   `notify.GithubBuildComment` renders it into `comment.md` verbatim, under
   `**Warnings:**`, with the run still reported as `## commit — ✅ Passed`. The
   warned pass and the disclosure survive together, end to end.
3. `bash scripts/smoke/commit-shapes.sh none` — the full commit composite against
   `testdata/python-app` — passes with the two new assertions, including the
   `comment.md` grep.
4. The unit suite: `cd src/build && go test -tags unit_test ./...`, four new
   tests, run by `scripts/test-module-units.sh`.

The negative control for the warning text itself is a unit test rather than a
run: `TestNoArtifactWarningQuotesFactsAndRemedies` fails if the string loses any
of the eight facts it quotes, and fails if a backtick or newline enters it —
`notify/render.go` writes each warning as ``- `%s` ``, so a backtick closes the
code span and a newline breaks the list item. That is a formatting defect a human
reviewing markdown output would very likely wave through.

## What this does not do

Read this section before filing the follow-ups. A disclosure invites being
mistaken for more than it is.

**It does not give a multi-artifact repository a shape that fits.** `--artifact`
still describes at most one artifact. A repository shipping several still has to
pick one or pick `none`; all this change does is make that choice legible in the
evidence instead of invisible. Multiplicity (`--artifact-legs`, mirroring the
`test-legs` precedent from CAPS-008 including the "an artifact nobody attested is
named, not silently dropped" rule) is additive, does not touch doctrine, and is a
separate change with contract and ADR-005 consequences of its own.

**It does not let cicd attest a builder-produced image.** Aspire,
`dotnet publish /t:PublishContainer`, ko, jib and buildpacks all produce OCI
images with no Dockerfile, and `src.DockerBuild(...)` is still cicd's only image
entry. Those repositories get no image SBOM and no image scan, and now they get a
line in the PR comment saying so, which beats silence and falls short of an
answer. Accepting a tarball or a registry reference cicd
did not build weakens ADR-001's ownership split from "cicd owns execution and the
evidence plane" to "cicd owns the evidence plane" — an ADR-shaped decision, not a
feature.

**It does not disclose anything about `precommit`.** The pre-commit composite has
no artifact tail at all and exposes no artifact selector, so there is no
configuration a consumer can get wrong there and nothing that could have been
attested. The commit stage is the one that promises code *and* artifact (ADR-005)
and may deliver only code.

**It does not check whether the claim is true.** Nothing here probes the source
tree for a `Dockerfile`, a `Directory.Build.props` or an `AppHost.cs` to catch a
consumer who selected `none` over a repository that plainly ships something. That
was considered and rejected: it costs a container run in the one shape that
currently starts none, it fixes one marker at a time forever, and — decisively —
it cannot detect builder-produced images that have no Dockerfile at all.
The disclosure is unconditional instead, which needs no heuristic to be right.

**And it does not fix the `build-cmd` configuration gap.** An `archive` build runs
a bare consumer command with no build-time configuration, so a bundle whose
`VITE_*` values are baked in at build time is *scanned in a different form than
the one that ships* — ADR-001's own stated failure mode ("evidence about an
artifact that never ships") arriving through the archive path. Untouched here,
worth its own issue.
