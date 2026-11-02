# Open the archives the output ships

## Why

`security.ScanArchive` secrets-scans the archive shape's built output with
gitleaks `dir .`. The command passed no `--max-archive-depth`, and on the pinned
gitleaks v8.30.1 that flag defaults to **0**, which opens no archive at all.
Measured on `zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0…`, with a `.env`
holding two live-shaped credentials:

| target | gitleaks said |
|---|---|
| a folder holding `.env` | `scanned ~122 bytes` · `leaks found: 2` |
| a folder holding only `app.zip`, containing that `.env` | `scanned ~0 bytes` · **`no leaks found`** |
| the same, `--max-archive-depth 2` | `scanned ~122 bytes` · `leaks found: 2` |

Exit 0, a well-formed SARIF with one run and zero results, `passed=true`. The
bundled-`.env` leak is the case the archive scan exists for, and a zipped output
read as clean. One consumer zips its app inside `build-cmd` because the
archive shape only produces `tar.gz`; its artifact secrets scan has been empty
since it started.

Raising the depth is half the fix. The other half is that gitleaks decides what
an archive is **by file extension**, measured at every depth:

| file | opened? | trace in the log |
|---|---|---|
| `.zip`, `.tar`, `.tar.gz` | yes | — |
| `.jar`, `.war`, `.nupkg`, `.whl`, `.vsix`, `.apk`, an extensionless zip | **no** | `DBG skipping binary file mime_type=application/zip path=…` |
| `.tgz` | **no** | `… mime_type=application/gzip …` |
| an xz / bzip2 tarball with an unknown extension | **no** | `application/x-xz`, `application/x-tar` |
| an archive deeper than the depth limit | **no** | `WRN skipping archive: exceeds max archive depth max_archive_depth=N path=a.zip!b.zip` |

A Spring Boot jar with `application.properties` inside and a `dotnet publish`
folder full of nupkgs are exactly the outputs this shape exists for, and a
depth flag does nothing for them. So "depth 3" without a disclosure would have
been the next silent floor.

## What changed

- **The tree leg opens three layers** (`gitleaksMaxArchiveDepth`,
  `src/security/gitleaksscript.go`), on both `dir` legs — `ScanArchive`'s
  build output and `ScanSource`'s working tree. The history leg is unchanged.
- **It runs at `--log-level debug`**, because the line naming an unopened jar
  exists at DBG and at no other level.
- **The script filters the debug log before it touches the disk.** DBG also logs
  every decoded segment with its text (`segment found: … "%44" -> "D"
  decoder=percent`, measured), so a base64-encoded credential would be written
  out decoded, past `--redact`, which governs only the report. The awk filter
  keeps the one `skipping binary file` shape, matched on whole fields, in
  `gitleaks.skipped`; drops every other DBG line; and sends the rest to
  `gitleaks.err` as before. A filter that did not reach `END` is exit 125 and an
  `errors[]` entry — an unknowable skipped list must not read as an empty one.
- **`gitleaksarchives.go` reads the kept log** into two `warnings[]` lines —
  archive-typed files read as opaque binaries, and archives nested too deep —
  naming the files, sorted, quoted, capped at 20 with an exact count; and into
  `Examined{Unit: "bytes read from the tree"}` from `INF scanned ~N bytes`.
- **The gitleaks row carries both**, on both envelopes, so the row says how much
  it read and that it is a floor.

## Proof

- `gitleaksarchives_test.go` drives the parser from
  `testdata/gitleaks-8.30.1-dir-archives.stderr`, the verbatim stderr of the
  pinned image over a tree holding a zip with secrets, a four-layer zip, a jar,
  a nupkg under a path with spaces, a `.tgz`, an xz and a bzip2 tarball under
  unknown extensions, and a png.
- `gitleaksscript_test.go` runs the real script under `sh` with a fake gitleaks
  replaying that capture plus two DBG segment lines carrying a decoded
  credential — one shaped to look like the kept line. The credential reaches no
  file; the split matches; gitleaks' own exit is recorded, not awk's; a broken
  awk is exit 125.
- Seven mutations (no DBG drop, substring match for the kept shape, filter fails
  open, no depth flag, no MIME filter, no unquote, unanchored regex) each fail a
  test.
- End to end on engine v0.20.8: an output holding `app.zip` (secret inside),
  `lib/service.jar`, `my app/My Package.1.0.0.nupkg` and a five-layer zip
  reports `app.zip!.env` (HIGH, redacted — the raw token occurs zero times in
  the envelope), names the jar and nupkg, names
  `deep.zip!l3.zip!l2.zip!l1.zip`, and states 68 bytes read.
- `ci.yml`'s security cell zips node-app's planted `leaked.env` into `app.zip`
  and `service.jar` and asserts the `app.zip!leaked.env` finding and the jar
  warning. Checked against a copy of the envelope with both removed: the
  assertion fails.

## Decisions

**Depth 3, not unbounded and not 1.** The flag is the only bound on a recursive
archive — 42.zip opens 16 archives per layer. A zip holding a tar.gz is already
two. The cost of a layer is the bytes in it, not the layer: a single-layer 2 MB
zip of zeros expanding to 2.15 GB took 4m29s at bounded memory (gitleaks
streams), which is what a 2.15 GB file on disk costs too. Anything deeper is
named, not dropped.

**Applied to `ScanSource`'s tree leg too.** The same blind spot holds for
archives committed to a repository. The blast radius is real: precommit can now
report a secret inside a committed zip that it reported nothing about before,
which turns a gate red that was green. That is the gate starting to work, and a
committed zip holding a live credential is exposed to everyone who can clone.
Leaving the source leg at depth 0 would mean the two scopes give different
answers about the same file.

**Warnings, not errors.** On the `semgrepnotifications.go` precedent: the scan
ran over everything else, the remedy for a jar is upstream's, and a permanent
red is how secrets scanning gets switched off with its findings.

**The content-type list is a list of archive types, not of binaries.** A dist
folder is mostly images and fonts; naming every binary would bury the jar.
Six types are measured; ten more are the same library's names for archive
formats not yet seen, listed so the first is disclosed rather than dropped.

**cicd does not unpack the jars itself.** It would make cicd an archive
extractor with its own bomb, symlink and path-escape surface, for a gap that
belongs upstream. The disclosure names what to look at.

## Known residue

- **An archive under an allowlisted extension is not disclosed.** gitleaks'
  global allowlist skips `.bin`, `.png` and others before sniffing, logging
  `DBG skipping file: global allowlist path=data.bin` with no content type, so
  a tarball named `data.bin` is invisible to this disclosure.
- **A corrupt archive is skipped silently** at every log level, measured.
- **A zip bomb costs time, not memory.** Bounded by the job timeout, not by cicd.
- **The disclosure is wording-coupled.** A gitleaks bump that rewords the DBG or
  WRN line silences the warnings without failing anything. Recapture the
  fixture from the new image before bumping; the `ci.yml` jar assertion is the
  integration tripwire.
- **TruffleHog on images** is untouched; `ScanImage` reads layers, not archives
  inside them.
