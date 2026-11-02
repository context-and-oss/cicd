# Upgrade x/net past the HTML advisories

## Why

The repository's dependency scan reports two LOW advisories against
`golang.org/x/net v0.61.0`: `CVE-2026-78661` and `CVE-2026-97045`. They affect
HTML parsing/rendering, and the scanner names v0.62.0 as fixed. Each occurs in
all fifteen Dagger module manifests, so two defects produce thirty rows.
A MEDIUM threshold lets those rows pass; a passing gate is not a fixed dependency.

## Change

Upgrade x/net to v0.62.0 in every module's `go.mod`, including
`src/build/go.mod`, `src/security/go.mod` and
`src/cross-cutting/intent/go.mod`, with the `go.sum` entries the Go command
verifies. The modules are isolated, so upgrading one does not upgrade the
others. No fixture dependency is changed.

The upstream module still requires Go 1.26.0, below our existing directives,
and its dependency requirements do not require changing the other pins here.
Keep the OTel replacements and grpc pin unchanged because they enforce
separate compatibility constraints. Do not suppress either advisory, change
the gate threshold or narrow the scan.

## Verification

Check each module's selected x/net version and module checksums, then run
`dagger develop` and check the version survives regeneration. Run the canonical
module-unit and repository script suites. Finally inspect the actual dependency
scan: both identifiers must disappear from the findings, while the report must
still list x/net v0.62.0 as an examined dependency. A green gate alone does not
prove this, because LOW findings already passed before the upgrade.
