# Return security evidence by reference

## Why

A consumer GitHub Actions run exercised the DAST path against the
application's live OpenAPI document. The target was ready, ZAP imported and
scanned the API, and Dagger finished reading ZAP's exit marker after a few minutes.
The next trace operation was:

```text
Container.WithNewFile evidence.json
```

It never completed. GitHub eventually cancelled the job at its configured timeout, so a scan
that had finished produced no `combined-evidence.json`, artifact, or verdict.

The security module built every returned envelope as:

```go
dag.Directory().WithNewFile("evidence.json", string(data)).File("evidence.json")
```

`WithNewFile` embeds the complete JSON document in the Dagger graph value. A
DAST envelope also embeds ZAP's native report byte-for-byte, so graph
construction grows with everything the scanner recorded. The scan was not
slow; serialising its completed result into the graph was.

This repository had already measured and fixed the same failure one seam later
in `cross-cutting/evidence`: a 128 MiB combined bundle could not be returned
when its contents were inside a `Directory` ID, while a 228 MiB bundle exported
successfully when written to the module workdir and returned by reference.

## What changed

`src/security/evidencefile.go` is now the single return path for security
envelopes. It:

1. clears and recreates `security-evidence/` in the module runtime's workdir;
2. writes the marshalled bytes to `security-evidence/evidence.json`; and
3. returns `dag.CurrentModule().Workdir("security-evidence").File("evidence.json")`.

The file contents now travel through Dagger's filesystem rather than inside the
returned graph ID. Clearing the fixed directory first prevents an interrupted
earlier invocation from being mistaken for this run.

Source, licence, image, archive, and SBOM rescan use the helper. DAST initially
did too, but later consumer trials proved that a workdir-backed File retained the
completed scan's module/service graph: the scan and terminal File operation
both reported DONE while the CLI still waited.

DAST therefore uses a bounded exception. It first compacts the native ZAP
document, refuses a final envelope above 16 MiB, and then returns a value-backed
File through `writeInlineDASTEvidenceFile`. This keeps the DAST result detached
without reopening the original unbounded `WithNewFile` failure; all scanners
whose output is not explicitly bounded remain reference-backed.

After every readiness/specification/ZAP output has materialised, `ScanWeb`
explicitly stops the bound application service with `Kill: true`. The service
is a disposable scan fixture at that boundary, and deterministic shutdown keeps
it from extending the Dagger session after evidence is complete.

## Proof

- `go test -tags=unit_test ./...` continues to cover the pure security logic.
- `dagger develop` and the security module/composite smoke compile the Dagger
  return path in CI.
- The consumer proof is the consumer OpenAPI DAST trial: it must get past evidence
  creation, produce the audit bundle, and report the API reach and findings
  from the already-completed scan.

## Provenance

Consumer names and private references in this spec were replaced with neutral
stand-ins because `AGENTS.md` keeps them out of the public tree. The mechanism
and the measured behaviour are unchanged.
