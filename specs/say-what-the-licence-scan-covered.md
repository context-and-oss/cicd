# Say what the licence scan covered

## Why

The licence scan currently has one scope: everything. A consumer whose repository
contains a subtree it did not author and does not ship — a vendored sample, a
fixture tree, an internal documentation site that pulls its own npm tree — has no
way to say so, and every run reports declarations nobody will ever act on.

One consumer run, from `parts/03-security-security-license.json` (figures
rounded):

```json
"genericReport": {
  "scanned": 360,
  "flagged": 0,
  "byCategory": {"notice": 355, "unencumbered": 5}
}
```

Two things in that payload matter for this change.

The first is that the only knob today is the allowlist, which narrows what counts
as a finding. That is exactly the power `licenseflags.go` pins
`--ignored-licenses ""` to keep out of a consumer's `trivy.yaml`: a licence report
a consumer can take to zero from a file cicd honours is a licence report nobody
can rely on. A path exclusion is the same power reached by a different road —
`--license-exclude "**"` is a green licence scan over nothing — so it has to be
built as the narrow thing it claims to be, or not at all.

The second is that the payload records `scanned` and `byCategory` and no path at
all. `findings` is empty here, and findings are the only place a path appears. So
an exclusion bolted on without new fields would be *completely invisible*: 360
would become some smaller number, nothing would say why, and the run would still
read as a clean scan of the whole tree. "The filter removed 240 declarations" and
"there were only 120 declarations" would produce byte-identical evidence.

Three rules follow, and they are what the change is:

1. **It narrows scope, never findings.** Patterns match a file path. There is no
   way to exclude a licence by name or by category.
2. **Nothing is excluded silently.** The count is reported next to the scanned
   count, and the patterns themselves are written into the evidence payload.
3. **A pattern that matched nothing says so.** A typo and a tree with nothing to
   exclude are otherwise the same observation.

Rule 1 is also why the filter runs on the **report** rather than on the tree.
Handing Trivy `--skip-dirs` would mean the excluded tree is never read at all,
and it was rejected twice over. The count in rule 2 is not knowable that way: a
scan that never saw a file cannot say how many licences it skipped, so an
over-broad pattern would produce a clean, empty report with nothing anywhere
saying why. And `--skip-dirs` is itself settable from a consumer `trivy.yaml`,
which would put rule 1 straight back in the consumer's hands.

## What changed

**`src/security/licenseexclude.go`** (new, untagged) — the matcher and the three
rules, as a package doc block that says why each exists.

`compileLicenseGlob` translates one glob into an anchored regexp: `*` is any run
within one path segment, `**` crosses separators, `**/` also matches zero
segments (so `**/node_modules/**` catches `node_modules/x` as well as
`Client/node_modules/x`), `?` is one character within a segment. Every other
character is `QuoteMeta`'d, so `[a-z]` is a literal bracket expression and a
pattern can never smuggle in a regexp that matches more than its author read it
to. Bracket classes are a deliberate omission — they buy little and the failure
mode of a half-implemented one is silent over-matching.

`newLicenseExcluder` rejects an empty pattern, an absolute one, and one
containing `..`, and fails the whole list on one bad entry. Same reasoning as
`validateLicenseGate`: a typo must not quietly become the permissive value, and
the silent form of a rejected pattern is an exclusion its author believes
happened. Duplicates are deduped rather than rejected, so composing two lists of
patterns does not fail for no reason.

`inertWarnings` names every pattern that matched nothing, and attaches a hint
only to a pattern with no wildcard at all — `--license-exclude docs` reads like a
directory and matches only a file called exactly `docs`.

**`src/security/licensereport.go`** — `evaluateLicenses` takes the excluder and
tests each declaration *before* `Scanned++`, so an excluded declaration is never
counted as one the policy judged. The new `Excluded` count is kept apart from
`Scanned` rather than subtracted from it: `Scanned + Excluded` is everything
Trivy reported, and both numbers are in the payload alongside `excludePatterns`,
because a count is worth little without the rule that produced it.

`licenseEntryPath` falls back to the result's `Target` when a declaration carries
no `FilePath`. A licence read from package metadata has no path of its own — the
manifest it came from is the only path it has — and without the fallback
"exclude the doc site" would exclude only part of the doc site.

**`src/security/main.go`** — `ScanLicenses` gains `licenseExclude []string`. The
excluder is built next to `resolveLicenseAllowlist`, before any container exists,
so a malformed pattern fails as a configuration error rather than after a full
scan. `licenseExcludeSummary` is appended to `warnings` whenever any pattern was
configured, *including when it removed nothing*: "no filter" and "a filter that
found nothing" are different runs and must read differently.

**Plumbing** — `src/stage-2/main.go`, `src/composites/commit/main.go`, and
`license-exclude` in `.github/workflows/precommit.yml` (comma-separated, one
`--license-exclude` flag per pattern, a non-empty input yielding no pattern is a
hard error — the same shape as `license-allow`).

**`src/security/licenseexclude_test.go`** (new) — the pattern shapes a consumer
will actually type against the paths Trivy actually reports; the regexp-smuggling
guard; every rejected shape; the nil excluder that every existing caller passes;
and the end-to-end case where a restricted licence under `docs/` is a finding
before the filter, is `Excluded` after it, and where `Scanned + Excluded` still
equals what Trivy reported.

## What this does not do

It does not exclude by licence name or category — see rule 1. It does not reduce
the work Trivy does; the excluded tree is still read, and that is what buys the
count.
It does not change the default: with no patterns configured, the excluder is
empty, the payload gains `"excluded": 0` and nothing else, and no warning is
emitted.
