# roslyn-sast-fallback

Positive control for the Roslyn leg's per-project fallback
(`src/security/roslyn.go`, `roslynFallback`), driven by the second scenario in
`scripts/smoke/roslyn-analyzers.sh`.

The leg first builds every project in one parallel MSBuild call over a
generated solution. A restore failure in one project stops that whole build,
so nothing is analysed by it. Every project it left without an analyzer log is
then built on its own, so the projects that can build are still analysed, and
the evidence says the slow path ran.

Every source and project file carries a `.fixture` suffix, so nothing that
walks the repository builds or scans these files; the smoke script restores
the real names in a temporary copy.

| Project | What it proves |
|---|---|
| `web/` | analysed despite the failed combined build: a weak hash (CA5350, MEDIUM) is still found |
| `norestore/` | references a package no feed serves, so its restore fails: named as not analysed, and the reason the combined build produced nothing |
