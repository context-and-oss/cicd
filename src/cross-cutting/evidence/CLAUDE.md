# cross-cutting/evidence

Aggregates one or more evidence envelope files into a combined audit directory. Called by composites after all domain-module evidence files are collected.

## Entry function

```go
func (m *Evidence) Wrap(
    ctx context.Context,
    envelopes []*dagger.File,  // evidence files from domain modules
    commitSha, branch, repoUrl string,
) (*dagger.Directory, error)
// Returns directory with: combined-evidence.json, findings.sarif, sbom.cdx.json,
//                         parts/NN-<module>.json, parts/index.json
```

## Run locally

```sh
cd src/cross-cutting/evidence && dagger develop   # once

# Usually called via a composite, but can be called directly:
dagger -m ./src/cross-cutting/evidence call wrap \
  --envelopes /tmp/quality-evidence.json \
  --envelopes /tmp/security-evidence.json \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path ./audit-out
```

## Key logic

- Accepts single `envelope` inputs only (the multi-lang envelope format was removed — no module ever produced it).
- `combined-evidence.json` — overall pass/fail, total findings, per-severity counts, languages, and per-language coverage across all inputs.
- **`combined.passed` is false when any part produced no result** — outcome
  `ERROR` with a non-empty `errors[]` — whatever that part's own `passed` says
  (`producedNoResult`). Neither half alone: a failing suite under NONE carries
  its exit in `errors[]` and stays a pass; notify's lost card is `ERROR` with
  `warnings[]` only and stays a pass. See
  [specs/a-part-that-produced-no-result-fails-the-run.md](../../../specs/a-part-that-produced-no-result-fails-the-run.md).
- `findings.sarif` — SARIF 2.1.0 with all runs concatenated. `uniqueRunIdentities`
  then guarantees no two runs share GitHub Code Scanning's (tool driver name,
  `automationDetails.id`) identity — a collision fails the *entire* upload since
  2025-07-22, and the upload step's Advanced-Security tolerance would read that
  refusal as a repo with nothing to report. Producers stamp meaningful ids at the
  source (quality's `stampSARIFAutomationID`); this is the backstop at the one
  seam every run passes through. First run of an identity keeps its bytes; later
  collisions get a deterministic ordinal suffix; unparseable runs pass through
  untouched. See
  [specs/one-sarif-run-per-category.md](../../../specs/one-sarif-run-per-category.md).
  Before that, `withoutAcceptedResults` drops every result an accepted
  suppression covers: Code Scanning ignores `suppressions`, so each one was an
  open alert failing the PR check on a decision already recorded. The
  disclosure stays in `warnings[]` and in `parts/`. See
  [specs/honor-accepted-sarif-suppressions.md](../../../specs/honor-accepted-sarif-suppressions.md).
- `sbom.cdx.json` — CycloneDX 1.5 with all components and vulnerabilities merged.
- `parts/NN-<module>[-<tool>].json` — each input envelope, byte-for-byte as the
  module produced it, numbered in the order the composite collected them. The
  merged documents answer "what did the pipeline find"; these answer "what did
  each part of it do", which no merge can reconstruct once the rows are pooled.
  Names are sanitised to `[A-Za-z0-9-_]` (a module or tool name reaches this
  from tool output, so it must become a filename, never a path).
- `parts/index.json` — the manifest for the above: file, module, stage, tool,
  verdict, counts and byte size per part. It exists so a *missing* part is
  detectable: a bundle assembled from four envelopes when five modules ran looks
  exactly like a bundle from a four-module pipeline.
- `<tool>-output.txt` — for any **failed** step that captured raw stdout+stderr in its envelope's `rawOutputRef` (e.g. `byo-test-output.txt`), the verbatim command output, so a failing test is debuggable from the uploaded artifact alone. Absent on green runs; name collisions get a numeric suffix.

## Size, and the 128 MiB wall

Dagger serialises a module function's return value into an output file capped at
128 MiB, and applies the same cap to `File.Contents` on the way in. That wall is
close: a formatter reporting one fixable issue per line, over a solution with
inconsistent line endings, produced just over 128 MiB of bundle in a consumer's run and
`Wrap` returned `read function output file: file size 134250496 exceeds limit
134217728` instead of a verdict, an artifact, or any statement of what had been
found. (134250496 is the limit plus one 32 KiB read chunk — it is what the
engine always reports on overflow, not a measurement of the payload.)

Three rules follow, and none of them are stylistic:

- **The bundle is written to disk and returned by reference** —
  `dag.CurrentModule().Workdir(auditDirName)` over the `audit/` tree it just
  wrote, never `dag.Directory().WithNewFile()`.
  `WithNewFile` encodes the content inside the returned Directory's ID, so the
  bundle's size becomes the limit on whether the function can return at all.
  Written to the workdir, content moves through the engine filesystem and the ID
  stays a small reference. Verified end-to-end: a 228 MiB bundle (149 MiB
  `findings.sarif`) exports, and `.File("combined-evidence.json").Contents()`
  still reads back.
- **`combined.Findings` is capped** at `maxCombinedFindings`, with the
  truncation written into `combined.Warnings` naming the row count, the rule the
  kept rows were chosen by, and where the omitted rows still live. The counts
  stay authoritative. The cap is as much for the file's *consumers*: notify
  reads `combined-evidence.json` back through the same ceiling to render the PR
  comment, so an unbounded list only moves the failure one module downstream.
- **The list is written in one total order, and the cap takes its head.**
  `compareFindings` (`findingorder.go`): severity first, then the *class of the
  producing module* — security, risk, intent, an unknown module, then quality —
  then tool, rule, path, line, message. The class is tagged in `mergeFindings`
  from `envelope.moduleName`, never from a tool-name table, and
  `TestFindingClassCoversEveryModule` holds `findingClassOf` to the modules the
  tree declares. Severity alone was measured to keep almost a thousand whitespace rows and
  drop every MEDIUM SAST finding on a run that hit the cap; the parts order
  decided which. notify's 25-row table is the head of this same list and does
  not re-sort.
- **An input envelope still cannot exceed the cap.** A producer inlines its
  `evidence.json` into a File ID, so it hits its own output limit at roughly
  96 MiB of content and `Wrap` cannot read more than 128 MiB of one. The read
  error is wrapped to say so, because the engine's bare byte count is identical
  to the too-large-return case.

`parts/` holds envelopes verbatim, so a bundle can approach twice the size of
its largest envelope. That is deliberate: an audit bundle's product is fidelity,
and the alternative — stripping payloads that "are merged anyway" — silently
drops `genericReport`, which nothing else carries.

## Constraints

- `schema.go` is a verbatim copy of `src/internal/evidence/schema.go` — sync with `make sync-schema`.
- No dependencies on other Dagger modules (no `dagger.json` module deps).
