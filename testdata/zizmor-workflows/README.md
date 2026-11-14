# zizmor-workflows

Positive control for the zizmor leg of `security.ScanSource`
(`src/security/zizmor.go`), driven by `scripts/smoke/zizmor.sh`. The unit
suite's capture, `src/security/testdata/zizmor-1.32.0/`, is the pinned image's
verbatim output over this tree.

Every file carries a `.fixture` suffix, so neither this repository's own zizmor
audit nor GitHub reads these deliberately unsafe workflows, and the
`.gitignore` does not apply to the repository; the smoke restores the real
names in a temporary copy (`scripts/smoke/materialise-fixtures.py`).

| File | What it proves |
|---|---|
| `.github/workflows/inject.yml` | a template injection (HIGH), a `pull_request_target` trigger the `zizmor.yml` switches off and a checkout it ignores (both disclosed as removed, not counted), and a tag-pinned action (`unpinned-uses`, graded MEDIUM by cicd) |
| `.github/workflows/ignored.yml` | a template injection removed by an ignore comment: disclosed, not counted |
| `.github/actions/act1/action.yml` | a composite action is audited, not only workflows |
| `.github/dependabot.yml` | a Dependabot file is audited |
| `.github/workflows/broken.yml` | invalid YAML: named as not audited, and in the denominator |
| `.github/workflows/schemabad.yml` | valid YAML that is not a workflow: the same |
| `.github/workflows/nested/n.yml` | a file GitHub never runs: not collected, not counted |
| `ignoredir/` | matched by `.gitignore`, audited anyway: a committed workflow is a workflow |
| `sub/.github/workflows/` | a nested repository's workflows are found |
| `zizmor.yml` | the repository's configuration is honoured, and what it removed is named |
