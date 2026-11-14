# roslyn-sast

Positive control for the Roslyn security-analyzer leg of `security.ScanSource`
(`src/security/roslyn.go`), driven by `scripts/smoke/roslyn-analyzers.sh`.

Every source and project file carries a `.fixture` suffix, so nothing that
walks the repository builds or scans these deliberately vulnerable files; the
smoke script restores the real names in a temporary copy.

| Project | What it proves |
|---|---|
| `web/` | a compiler-traced path injection from a controller parameter (CA3003, graded HIGH), a weak hash (CA5350, MEDIUM), a pragma-suppressed MD5 (CA5351, disclosed, not counted), and a rule switched off by `.editorconfig` (CA5394, disclosed as narrowed) |
| `broken/` | a compile error: analysed over an incomplete program, so counted as partial |
| `legacy/` | a non-SDK project cicd cannot build: named, and in the denominator |
| `fn/` | an F# project, which the analyzers do not cover: named, not in the denominator |
