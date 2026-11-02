# Intent: the Go lint leg had never run, on any repository, ever

## Why

`src/quality/lint.go` ran this:

```
golangci-lint run --out-format sarif --issues-exit-code 0 ./... > /tmp/report.sarif 2>/dev/null \
  || echo '{"version":"2.1.0","runs":[]}' > /tmp/report.sarif
```

`--out-format` does not exist in golangci-lint v2, and `sarif` does not exist as a
format in v1 — the two halves of that command come from different major versions.
The pinned image was v1.57.2, so every invocation died on flag validation:

```
Error: unsupported output format "sarif"
Failed executing command with error: unsupported output format "sarif"
```

exit 3, a zero-byte report. The trailing `|| echo` then wrote a clean SARIF document
and left the *shell* exiting 0, so Go saw `err == nil`, no entries in `errs`,
`ran = len(errs) == 0 = true`, an empty severity map, and `passed = true`. The Go
gate reported "clean" on every repository it was ever pointed at. Both halves
measured against the pinned digest before this change.

v1.57.2 was dead a second way. It is built with go1.22.1, so on a tree built by a
current toolchain it fails during type-checking regardless of output format:

```
[runner] Can't run linter goanalysis_metalinter: buildir: failed to load package
goarch: could not load export data: internal error in importing "internal/goarch"
(unsupported version: 2)
```

The drift is visible in the repository's own history: `.github/workflows/ci.yml`
moved to `golangci-lint@v2.12.2` and `src/internal/.golangci.yml` moved to
`version: "2"`, while `src/quality/images.go` stayed on v1.57.2. CI lints Go
correctly; the module that ships Go linting to consumers never did. the earlier spec
named this inconsistency as residue — this change closes it.

**And a valid report is not proof of a run.** This is the load-bearing discovery,
because it is why fixing the flag alone would not have been enough. Measured on
v2.12.2, pointed at a directory outside its workspace, golangci-lint prints
`0 issues.`, writes a schema-correct SARIF document with an empty `results` array,
and exits 7. Those bytes are byte-for-byte what a genuinely clean tree produces
(`cleanSARIF` in `golangcireport_test.go` is that document). Nothing in the report
distinguishes "analysed everything, found nothing" from "never analysed a single
package". Only the exit status does.

## What changed

**The binary is v2.12.2**, pinned by multi-arch index digest in
`src/quality/images.go` and declared in `scripts/runtime-images.json`. v2 is required,
not preferred: it is the only major version with a `sarif` output format at all, and it
matches both the version `ci.yml` already runs and the `version: "2"` config schema
`src/internal/.golangci.yml` already uses. `testdata/go-app/.golangci.yml` is migrated
to the v2 schema, since v1 config on a v2 binary is itself a non-run
(`unsupported version of the configuration`).

**The exit status is captured and classified, never discarded.** The command writes the
report to a fixed path and the status, stdout and stderr to files; `golangciRunError`
(`src/quality/golangcireport.go`) reads them. `--issues-exit-code 0` means findings do
not move the status, so exit 0 is the only value that means the analysis completed —
a stricter rule than ESLint's, where 1 is a legitimate "problems reported", and
stricter on purpose because golangci-lint has no code meaning "partially analysed".
Exit 0 must also produce a document that is actually SARIF: an empty file, non-JSON,
bare `{}`, or a document with zero runs are all non-runs rather than zero findings.
Every classified message carries a remedy for the four failure modes measured here —
v1 config schema, out-of-workspace scope, unsupported output format, export data from
an older toolchain.

**Scope is resolved, then stated.** `resolveGoModules` prefers a root `go.work`'s `use`
directives and falls back to discovering every `go.mod`; `golangci-lint` then runs once
per resolved directory with errors labelled by module. The directories that were linted
and where that answer came from always land in `warnings[]`:

```
lint go: golangci-lint: linted 1 Go module(s) from go.work: src/internal
lint go: golangci-lint: linted 1 Go module(s) from go.mod discovery: .
```

A gate that lints 1 of 16 modules must say which, or `passed` cannot be read.

**The version in evidence is the version that ran.** `golangciVersionLabel` parses
`golangci-lint --version` and returns `unknown` when it cannot — never the compile-time
pin, which is how the .NET leg came to describe an SDK that never started.
`stampSARIFDriverVersion` writes it onto each SARIF run's tool driver, because that is
the only per-leg structure that survives aggregation into `Check`'s combined envelope.

**`ran` is `len(errs) == 0`**, the same rule as the ESLint leg and for the same reason:
findings go to `bySeverity`, so `errs` holds only run failures. Combined with
`gatedPassed`, a Go leg that could not run now fails at every threshold,
including `--fail-on NONE`.

## Proof

Unit tests pin the classifier to measured strings, including the exit-7 valid-empty-SARIF
case as the headline regression. But unit tests cannot prove a container command works,
so three real `dagger call check` runs did:

| Run | Result |
| --- | --- |
| `testdata/go-app`, `--fail-on NONE` | `passed=true`, 0 findings, warning names the module linted |
| `testdata/go-app` + one planted `errcheck`/`unused` violation, `--fail-on HIGH` | `passed=false`, **2 HIGH**, both findings located in `bait.go` |
| this repository's root, `--include go --lint-only --fail-on HIGH` | `passed=true`, 0 findings, `from go.work: src/internal`, SARIF driver version `2.12.2` |

The middle row is the one that matters. The broken leg also reported zero findings, so
only a planted violation separates a working gate from the old one.

## Decisions

**`go.work` outranks discovery.** It is Go's native declaration of which modules form a
tree, and under a workspace `go build ./...` compiles exactly those modules — so a gate
honouring it lints what the build builds. The trade-off is real and belongs in the
record: a `go.work` that omits a module leaves that module unlinted. That is the
consumer's declaration to make, and the scope warning above makes it auditable rather
than implied. It is also what makes *this* repository lint correctly instead of
catastrophically, since its `go.work` lists only `src/internal` — but the rule is
justified on Go's semantics, not on making our own tree pass. See the residue below for
what that costs here.

**Every `go.mod` is its own project** — the opposite of `nodeProjectDirs`'
shallowest-wins rule, and not a style choice. A `go.mod` is a module boundary and
`./...` stops dead at one: from a parent module, `go list ./...` does not descend into a
nested module. Where a root `package.json` legitimately governs everything beneath it, a
root `go.mod` governs nothing beneath a nested one, so keeping only the shallowest would
leave nested modules unlinted while reporting success — the same false pass in a new
costume.

**More than eight modules is an error, not a truncated run.** Each module costs its own
dependency download and full type-check. Linting 8 of 40 and reporting no findings is
precisely what this module exists to prevent, so the leg declines with `ran=false` and a
message naming the modules and the remedy (`go.work` first, since it fixes the scope
permanently rather than per-invocation).

**The threshold stays `HIGH`.** golangci-lint's SARIF marks findings `error`, which maps
to HIGH, so turning this leg on can turn a previously green Go consumer red. Lowering the
default, or remapping Go findings to MEDIUM, would be fudging severity to hide the
consequence of a gate starting to work. `--fail-on NONE` is the documented migration
path for a consumer who wants to see the volume before gating on it.

## Known residue

**The Dagger modules are linted by nothing at all, and this change does not fix it.**
The root `go.work` lists only `src/internal` — 823 lines — because the fifteen Dagger
modules cannot type-check until `dagger develop` has generated their SDK, and the
generated SDK is gitignored. So CI's golangci-lint and this leg both cover 823 lines
while **19,697 lines of Dagger module code are covered by no linter in this repository**.
Measured in a throwaway worktree after `make develop-all`, that code holds **33
findings**: 25 `unused`, 6 `errcheck`, 2 `staticcheck` — three unchecked
`resp.Body.Close`, three unchecked `os.WriteFile` in a test, one `SA9003` empty branch,
one `ST1023` style nit. All trivially fixable. Closing it needs `make develop-all` wired
into the lint job plus those 33 fixes, which is its own change with its own blast radius
on CI duration. Recorded here rather than quietly inherited, because a `go.work` that
excludes most of the repository is exactly the residue the go.work decision above buys.

**`tool.version` in the aggregate envelope is still blank**, for every language.
`Check` folds all legs into one envelope with a bare `toolInfo{Name: "quality"}`
(`main.go`), discarding each sub-envelope's tool name and version. That is why the
observed golangci version is stamped onto the SARIF driver instead — the fix here works,
but the aggregate envelope remains unable to say what tools produced it, which is a
cross-language schema question and not this change.

**A stamped SARIF is no longer byte-identical to what the binary wrote.** Key order
changes; content does not. `mergeSARIFReports` already rebuilds the wrapper for a
multi-module tree, so this is not a new property. Any parse or marshal failure returns
the original bytes untouched: a metadata field must never cost a finding.

**Nothing in CI asserts the quality gate's verdict**, inherited unchanged from the earlier change.
`Check` returns an envelope with `passed:false` and no Go error, so `dagger call check`
exits 0 either way and the `module-test` cell makes no assertion. The three real runs
above are the proof this leg gates; the pipeline does not yet re-prove it per commit.

**`pylintVersion` remains a hand-pinned constant with no Renovate coverage**, because
`make check-image-pins` walks `From(...)` references and a pip package inside an image
is not one.
