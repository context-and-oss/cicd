# Say what Trivy examined

## Why

"0 vulnerabilities" is the same two words whether Trivy read three thousand
packages or reached none of them. A finding count with no denominator beside it
is the failure class this repository keeps chasing: an absent signal read as a
verdict. It is also the one number a customer-facing security report cannot ship
without, because "we found nothing" is worth exactly as much as the size of the
thing that was looked at.

The security module already fails the gate when an ecosystem the tree declares
resolves to nothing — `ecosystems.go` does that today. But that check is per
ecosystem and says nothing about scale. A tree that declares no ecosystem at all
passes it, reports zero findings, and reads as clean.

`Examined` is the field that closes this, and three producers already fill it:
`src/quality/sources.go` in coverable lines, `ScanLicenses` in licence
declarations, `src/risk/opa.go` in infrastructure files. The vulnerability scan —
the one a customer asks about first — did not, so `src/notify/outcomereport.go`
rendered its row as `not stated` while the columns either side of it carried
numbers.

## What changed

**`src/security/trivyreport.go`** — `trivyExamined` reads the packages Trivy
already parsed and returns `{Unit: "resolved packages", Count: n}`.

The count **sums** `Packages` across results rather than deduplicating by
`name@version`, because the denominator has to match the numerator. Trivy counts
vulnerabilities per result entry. Measured on a tree with the same
`package-lock.json` committed under `a/` and `b/`: two results, one package each,
ten vulnerabilities each — twenty findings over what deduplication would call one
package. Summing keeps "N findings across M resolved packages" coherent.
Deduplicating would print "20 findings over 1 package".

So on a monorepo this number exceeds the SBOM's component list, and that is not
drift. Measured on `debian:11.6`, where nothing repeats, the two agree exactly:
96 resolved packages against a CycloneDX document of 96 `library` components plus
the one `operating-system` component the image itself contributes.

`Total` is left unset, so `examinedCell` prints "96 resolved packages" and not
"96 of 96". Trivy cannot see the packages it failed to resolve, and a tool that
does not know its own denominator must not imply one — an unresolvable ecosystem
reaches the envelope as an error instead.

The count is trustworthy at zero because `--list-all-pkgs` is pinned in
`trivyflags.go` as a CLI flag, appended after the pinned set. CLI beats
`trivy.yaml`, so a consumer cannot switch package listing off and turn a real
`Count: 0` into a configured one. Same reasoning as `--ignored-licenses ""`.

The return is never nil for a report that parsed. Zero resolved packages is a
real claim and the loud one: Trivy ran and read nothing. Absent is reserved for a
scanner that states no figure at all, which is why the callers that fail before
parsing pass no `Examined` rather than a confident zero.

**`src/security/vuln_source.go`** — `trivyResult` gains `Examined *Examined`,
populated once in `readTrivyResult`. That function is the single choke point all
three scan paths reach — source, image, and frozen-SBOM rescan — so the field
cannot be filled on one path and forgotten on another.

**`src/security/main.go`** and **`src/security/archive.go`** — the three Trivy
`toolResult` sites pass it into `perToolSources`, which already carried
`Examined` through to the envelope.

**`src/security/sbomscan.go`** — one tool under that envelope, so the denominator
sits on the envelope itself rather than in a `Sources` row, the shape
`ScanLicenses` already uses. Nil on every error path above it, because a rescan
that never read its SBOM did not examine zero packages; it did not say.

**`src/security/trivyreport_test.go`** — the duplicate across results that pins
summing over deduplication; the two fixtures that separate "read nothing" from
"said nothing", including a result with a `Target` and no packages; the count
that moves with packages and not with vulnerabilities; and the boundary test
proving `parseTrivyNative` rejects `"Results": null` before `trivyExamined` is
ever reached, so a resultless report cannot arrive here as a zero.

## What this does not do

It does not change any gate. `Examined` is reported, never thresholded — a
consumer who wants to fail on a low package count writes that policy themselves.

It does not touch the other scanners. Semgrep needs an output-format change
before it can state a figure, because its SARIF genuinely carries no scanned-file
count, and Gitleaks stays `not stated`.
