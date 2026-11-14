# zizmor 1.32.0 capture

Both runs of `zizmorScript()` (`src/security/zizmor.go`), verbatim from the
pinned `ghcr.io/zizmorcore/zizmor:1.32.0` image, over
`testdata/zizmor-workflows/` materialised. `primary.*` honours the tree's
`zizmor.yml` and ignore comments and is verbose; `shadow.*` honours neither.
Each run is its SARIF on stdout, its stderr, and its exit status.

Re-record on a zizmor bump: materialise the fixture with
`scripts/smoke/materialise-fixtures.py`, run the script in the new image, and
replace these files under a directory named for the new version.

The SARIF files are zizmor's output over cicd's own fixture. The only upstream
text in them is each audit's one-line description and documentation link,
which zizmor (MIT) emits into every report it writes; no zizmor source is
copied here. Like the gitleaks capture beside it, this is recorded as tool
output rather than in `THIRD_PARTY_NOTICES.md`.
