# Supply the archive gitleaks config

## Why

`security.ScanArchive` secrets-scans the built output with gitleaks `dir .`,
and gitleaks reads a config from one place only: a `.gitleaks.toml` at the
root of the tree it scans. The source tree's config never reaches that scan,
because the scanned tree is the build output, not the source. A consumer whose
bundle carried one false positive had two ways to accept it, and both were
wrong: ship a scanner config inside the deployable, or write a fingerprint into
`.gitleaksignore` that goes stale on the next build because the bundle's path
and line are not stable. The secrets gate for the archive shape was therefore a
gate a consumer could not clear, which is the kind that gets switched off
(`--fail-on NONE`), and a switched-off gate on built output reads as a clean
one.

## The mechanism

`ScanArchive` takes an optional `gitleaksConfig`: a path relative to `src`,
for example `.gitleaks.archive.toml`. `src/security/archive.go` asks a
listing of the source tree (`Directory.Glob`) for the file before any
container is built, so a path the source tree does not hold — or that names a
directory — is cicd's own error (`not found in the source tree`) and never a
scanner that ran with no config and said "no leaks found". `runGitleaksDir`
in `src/security/secrets_source.go` then copies the file to the root of the
scan's copy of the output as `.gitleaks.toml`. We chose injection at the
scanned root instead of a gitleaks `--config` flag because every existing
mechanism keys on that root file: the shadow scan strips it to put back what
it removed, the `SUPPRESSED` line attributes to it, `NARROWED RULES` names the
default rules it left out, and zero loaded rules is still a non-run. The
artifact itself is never touched; the copy lives in the scan container only.

The disclosure wording names the supplied file, because a reader of
`warnings[]` must be able to find the acceptance: `gitleaksConfigOrigin` in
`src/security/gitleaksconfig.go` carries the source path, and
`gitleakssuppress.go` phrases the config as "the gitleaks config supplied from
`.gitleaks.archive.toml` in the source tree" wherever it used to say "the
scanned tree's `.gitleaks.toml`". Without a supplied config, every line is
byte-identical to before.

Two inputs for one scan is refused: an output that already carries a root
`.gitleaks.toml` beside a supplied config is an error, since gitleaks would
read one and cicd could not say which. The commit composite plumbs the knob
as `--archive-gitleaks-config` through `src/composites/commit/main.go` and the
per-app path in `app.go`, where the file is added onto the scoped source view
so an app-mode scan can resolve it, and through the reusable GitHub Actions
workflow and the Azure DevOps templates as an env value, never spliced source.

## Rejected

- **A `.gitleaksignore` input.** Fingerprints are `file:rule:line`, and a
  bundler moves lines on every build, so the acceptance would silently stop
  applying. That is the mechanism the request itself rejected.
- **Honouring `[extend] path` to the source config.** gitleaks resolves it
  against the scanned root, which is the output; measured on the pinned
  v8.30.1, `useDefault` and `path` are also mutually exclusive. Documented as
  unsupported instead of emulated, in order to keep one resolver.
- **Warning when the supplied config uses a path allowlist.** That means
  parsing gitleaks' TOML, a second resolver for a question gitleaks already
  answers; the shadow scan discloses every finding the config swallowed, which
  is the measurement a reviewer needs.
- **Dropping support for an output-root `.gitleaks.toml`.** A consumer who
  already ships one keeps working; the refusal only fires when both are given.

## Traps

- Reading the config in a container instead of checking the listing first
  turns a missing file into a scan that ran without it.
- Probing existence with `File().Contents()` instead of a listing: the read
  fails inside the engine, and the dagger CLI (measured on v0.20) prints that
  failed span (`stat /x.toml: no such file`) and drops the error the function
  returned, so cicd's wording never reached the consumer. `Directory.Glob`
  answers "no match" with an empty list and no failed span.
- Copying the file under any name but `.gitleaks.toml` means gitleaks reads
  nothing and the shadow strips nothing, so the acceptance applies silently.
- Passing an empty `--gitleaks-config` must stay a no-op, and the composite
  must omit the flag when unset rather than pass `""`.
- The history leg is not shadowed and does not run here; a future archive
  history leg must disclose the same way or an acceptance there goes unseen.
