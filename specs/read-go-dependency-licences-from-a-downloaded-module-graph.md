# Read Go dependency licences from a downloaded module graph

## Problem

`specs/say-how-many-dependency-licences-were-read.md` made a Go tree's licence
row say what it was: `SKIPPED`, `Dependency licences: NOT READ`, 0 of N. That
was the honest answer, and it left the residue that spec named: cicd read no Go
dependency licence on any checkout.

Trivy reads a Go module's licence from the module's own files in the module
cache (`$GOPATH/pkg/mod/<module>@<version>`), never from `go.mod` or `go.sum`,
which name versions and not licences. Measured with the pinned Trivy on one Go
module of this repository with 36 dependencies:

| Module cache Trivy sees | Dependencies with a licence |
|---|---|
| none | 0 of 36 |
| the full cache after `go mod download` (309 MB) | 36 of 36 |
| a snapshot of each module directory's top-level regular files (about 20 MB) | 36 of 36, the identical licences |

The .NET leg closed the same gap by restoring the NuGet graph
(`specs/read-nuget-licences-and-skip-a-licence-scan-that-read-nothing.md`). Go
needs the equivalent: put the modules a `go.mod` requires where Trivy looks.

## Decision

- **What is downloaded.** For every `go.mod` in the tree that the
  `--license-exclude` filter does not cover, `go mod edit -json` reads its
  `require` and `replace` blocks. Replaces are applied the way the go command
  applies them (a replace naming the required version wins over one naming
  none). The result is a deduplicated, sorted list of `path@version`, each
  remembering which `go.mod` files required it.
- **How.** `go mod download -json` runs in the digest-pinned `golang` image,
  outside any module (an empty working directory, `GOWORK=off`,
  `GOTOOLCHAIN=local`, `GOFLAGS` empty), with the list passed as a data file
  through `xargs`, never as script text. No `go.mod`, `go.work`, `toolchain`
  line or build constraint of the consumer's is evaluated by the go command;
  only the versions it names are fetched. A module reference that is not a
  well-formed module path and canonical version is never passed to the go
  command and is named instead.
- **Where from.** `GOPROXY=https://proxy.golang.org`, with no `direct`
  fallback. We chose the proxy alone because a module path is a URL: with
  `direct`, a consumer's `go.mod` could point this container at any host. The
  proxy is the only party contacted. The
  checksum database stays on, so a module lands in the cache only if it matches
  the published checksum.
- **What Trivy reads.** Inside the same exec, the top-level regular files of
  each downloaded module directory are copied into a snapshot laid out as
  `GOPATH/pkg/mod`. The snapshot is the exec's output, mounted for Trivy with
  `GOPATH` pointing at it. Trivy reads the snapshot rather than the volume
  because a cache volume is not part of an exec's cached result, so reading
  the volume itself would let a pruned volume empty the input behind a cached
  exec — the NuGet snapshot's reason, unchanged.
- **The module cache** is a `CacheSharingModePrivate` volume, so two concurrent
  scans never write the same cache.

### Partial reads are named

Every module the plan listed ends in exactly one bucket, and the warning names
each non-empty bucket with its modules and the `go.mod` files that required
them:

| Bucket | Meaning | Envelope |
|---|---|---|
| downloaded | the proxy served it and its files were copied | counted in `cicd downloaded X of Y` |
| not served by the Go module proxy | the proxy answered 404 or 410: what a private module looks like | warning |
| failed to download | any other per-module error, with the go command's own line | warning |
| replaced by a local directory | a `replace` to a path; its files are in the tree, not in a module cache | warning |
| not passed to the go command | not a well-formed module path or canonical version | warning |

A module that was not downloaded is a warning and not an error, because the
scan ran and what it read is real; the `Dependency licences` coverage line already says
how many listed modules carry a licence. The consumer also cannot clear it:
cicd has **no Go credential input**, so a private module cannot be fetched
here, and the warning says so. A gate the consumer cannot clear gets switched
off, so it must not fail.

The warning also says how many of the `go.mod` files Trivy listed modules for.
Trivy lists nothing for a `go.mod` with no requirement, and nothing for one a
`skip-dirs` or `skip-files` in the tree's `trivy.yaml` removed. Those are
indistinguishable from outside, so both are stated, and the modules required
by such a file are said to be not judged. A scan that did not complete makes
no claim about what it read.

### What cannot be known is an error

These make the download's own result unknown, so each goes to `errors[]` and
the licence row does not run (`ran=false`, never `CLEAN`, never suppressed by
`--fail-on NONE`):

- `go mod edit` could not read a `go.mod` (it names the file, quotes the first
  line of the go command's error, and gives the remedy: fix the `go.mod`, or
  `--license-exclude` its directory if the tree's `trivy.yaml` skips it), wrote
  output cicd could not parse, or left no result for it.
- `xargs` exited with anything but `0` or `123` (123 is "some batch failed",
  which is the per-module failures above), or recorded no exit status.
- `go mod download` wrote output cicd could not parse, returned no result for a
  module it was given, or reported a module directory outside the cache cicd
  copies from.
- A downloaded module's files could not be copied into the snapshot.

A section marker printed in one `go.mod`'s error output cannot forge another
file's result: error lines carry their own prefix.

## Blast radius

- A Go tree whose dependencies are all public reads its dependency licences.
  Its licence row moves from `SKIPPED` with `NOT READ` to a judged result:
  `CLEAN`, or `FINDINGS` when the licence policy denies a dependency's
  licence, graded at `--fail-on` like any other finding. A tree that newly
  fails this way has a gate that started measuring, not a regression, and the
  consumer can clear it.
- A Go tree with private modules reads the public ones and names the private
  ones as not served, with `PARTLY READ` on the coverage line. It keeps its
  verdict over what was read.
- The licence scan now contacts `proxy.golang.org` for a Go tree. The module
  paths it sends are the ones the quality module's Go legs already send to the
  same proxy (they run with the go command's default
  `GOPROXY=https://proxy.golang.org,direct`), so no new party learns a private
  module's name.
- A tree without a `go.mod` runs no download and is unchanged.

## Proof

`src/security/licencegomod_test.go`:

- planning: two `go.mod` files, deduplication, which files required what,
  sorted order, a wildcard replace to another module, a directory replace, and
  the versioned-over-wildcard precedence in both orders;
- every `go mod edit` failure named (non-zero exit with its error line and
  remedy, unparseable output, a missing section) and a forged section marker
  refused;
- reference validation, with pseudo-versions, `+incompatible` and mixed-case
  paths as accepted controls, and the cache path escaping
  (`github.com/BurntSushi/toml` → `github.com/!burnt!sushi/toml`) measured
  against the go command;
- classification of a measured private-module 404, a 410, a checksum failure
  and two successes into their buckets, and each unknown outcome (exit status,
  output, missing result, misplaced directory, failed or missing copy) as an
  error;
- the warning for a complete download, every gap named at once, an incomplete
  scan, and the silent case of a `go.mod` with no requirement;
- that the scripts take paths only as arguments and data files, and a guard
  reading `goexec.go` that the proxy is the only source (no `direct`,
  `GOPRIVATE`, `GONOSUMDB`, `GOINSECURE`), that `GOTOOLCHAIN` is `local`, and
  that every module cache mount is private.

Each branch above was mutated and the suite went red.

End to end with the pinned images, `security.scan-licenses --fail-on NONE`:

| Tree | Before | After |
|---|---|---|
| one module with 36 dependencies (`go.mod` and `go.sum` only) | `SKIPPED`, 0 of 36, `NOT READ` | `CLEAN`, 36 of 36, 50 declarations judged |
| `testdata/go-app` (one dependency) | `SKIPPED`, `NOT READ` | `CLEAN`, 1 of 1 dependency licence read and judged |
| a public module, a replaced one and a private one at `git.example.invalid` | — | `CLEAN` over what was read; the private module named as not served by the proxy |
| a `go.mod` with no requirement | — | no download, no warning |

## Residue

- **No Go credential input.** A private module is named and not read. Adding
  one means a `GOPRIVATE` list, a `direct` fetch for exactly those paths, and a
  credential handed to git — a larger change with its own spec, the way the
  NuGet feed credential was.
- **Modules Trivy lists from `go.sum` and not from `go.mod`.** The download
  follows `go.mod`'s `require` block. A `go.mod` older than Go 1.17 lists only
  direct requirements, and an untidy one omits indirect ones; Trivy then also
  lists modules it finds in `go.sum`, and those are not downloaded. Measured on
  an untidy `go.mod` with three requirements: 2 of 10 listed modules carried a
  licence, and the row read `PARTLY READ`. It says so, and it does not read
  clean. `go mod tidy` in the consumer's tree clears it.
- **A vendored tree** (`vendor/`) is not read from `vendor/`; its modules are
  downloaded from the proxy like any other.
