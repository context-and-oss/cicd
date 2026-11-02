# A policy that evaluated no rule is not clean

## Intent

risk.Validate runs conftest once per infra group with `--namespace` taken from
`infraFileType`, and once over the findings review with `--all-namespaces`.
Measured against the pinned conftest v0.58.0, a namespace with no package does
not fail: conftest names the file and writes

```json
[{"filename": "/in/wf.yml", "namespace": "risk.nope", "successes": 0}]
```

No failures, no warnings, so the group folded as zero violations and the
envelope read CLEAN at every threshold. Renaming one `package` line under
`policy/infra/` would have switched off every pipeline-YAML check in every
consumer while the evidence kept saying the files were scanned and clean.

## Chosen approach

- `conftestRulesEvaluated` (`src/risk/validatereport.go`) sums, per filename,
  `successes + len(failures) + len(warnings) + len(exceptions)` across every row
  for that file. `--all-namespaces` writes one row per namespace, the `*_test`
  packages included at 0 (measured), so a per-row rule would flag every
  findings review; the sum is what says no rule read the file.
- A file conftest named with a sum of 0 is a non-run in the infra group
  ("conftest evaluated no rule in namespace N for <paths>") and in the findings
  pass ("conftest evaluated no rule for /input.json"). A file conftest never
  named stays `unevaluatedMounts`' to report, now read from the same map.
- `policynamespace_test.go` asserts that every namespace `infraFileType` returns
  has a non-test package under `policy/infra/`, and that `policy/findings/`
  declares one. The fold catches the rename at run time on a repository that
  holds such a file; the test catches it at the commit.

## Rejected

- **Read `successes` alone.** Rejected because a file whose every rule failed
  has `successes: 0` and is the most evaluated file in the run.
- **Rely on conftest's exit.** `--no-fail` is deliberate (the gate is
  cicd's), so the exit says nothing about what was evaluated.

## Not claimed

Terraform still reads CLEAN. `.tf`/`.hcl` go to `risk.azure` under the `hcl2`
parser, every rule there iterates `input.resources` (the ARM array), and HCL2
parses to `input.resource`. Each rule evaluates and passes vacuously: a
one-resource `main.tf` measured `successes: 24`. A count of evaluated rules
cannot tell a vacuous pass from a real one. Since closed by routing: Terraform
is reported as not assessed, see
[report-terraform-as-not-assessed.md](report-terraform-as-not-assessed.md).

## Expected result

`nonrun_matrix_test.go`: an infra group whose files sum to 0 (both files, one
file, a row with no `successes` field) fails at every threshold naming the file;
a findings pass with only `*_test` rows at 0 does too; a group whose files
carry only failures is a run (control); the clean group and the measured
three-namespace findings output are runs (controls). Disabling the rule turns
the matrix red; renaming `package risk.pipeline` turns the namespace test red.
