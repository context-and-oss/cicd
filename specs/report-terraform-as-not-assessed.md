# Report Terraform as not assessed

## Intent

risk.Validate routed `.tf` and `.hcl` files to `risk.azure` under conftest's
`hcl2` parser. Every rule in that namespace iterates `input.resources`, the ARM
template array; HCL2 parses to `input.resource`. Each rule therefore evaluated,
found nothing to iterate, and passed. Measured with the pinned conftest v0.58.0,
a one-resource `main.tf` came back `successes: 24` and the envelope read CLEAN
at every threshold.

The rule-count check from
[a-policy-that-evaluated-no-rule-is-not-clean.md](a-policy-that-evaluated-no-rule-is-not-clean.md)
cannot see this: 24 rules did evaluate. A count of rules says a policy ran, not
that it read anything. A Terraform repository was being told its
infrastructure had been checked against policies that had not looked at it.

## Chosen approach

- `isTerraform` (`src/risk/validate.go`) matches `.tf`, `.tf.json` and `.hcl`.
  `infraFileType` no longer maps them, so no conftest group is built for them.
- `planInfraScan` records them in `infraScan.NotAssessed`, sorted: every one in
  the tree for a tree-scoped scan, only the ones the change touched for a
  change-scoped one. They are not candidates, for the reason Bicep is not: the
  denominator is what this tool could have examined, and no policy here reads
  HCL2.
- `terraformNotAssessedWarning` writes `risk: TERRAFORM NOT ASSESSED`, with the
  count, up to three paths, and why: the policies are written for ARM and no
  rule reads HCL2. `infraPlanWarnings` joins it to the scope warnings and is
  the one call `Validate` makes, so the unit tests drive the wiring itself.
  The warning carries the count because `buildCombined` drops the generic
  payload; the payload also lists the paths as `infraFilesNotAssessed`.
- The `NOTHING IN SCOPE` line now says the change touched no infrastructure
  file *a policy reads*. A change that edits only `main.tf` did touch
  infrastructure, and the old sentence would have said it did not.

Outcomes follow from the existing rules, with no new branch:

- **Terraform only.** Nothing is examined, so `skippedIfNothingExamined` makes
  the row SKIPPED, `examined: 0 of 0`, passed at every threshold. The consumer
  cannot clear it by changing code, so it must not fail; the warning is what
  tells this 0 of 0 from a repository with no infrastructure.
- **Terraform beside a Dockerfile, an ARM template or pipeline YAML.** The
  verdict stays graded over the files conftest read, and the warning names the
  Terraform beside it. A finding in the Dockerfile still fails the gate.

## Rejected

- **Keep routing `.tf` to `risk.azure` and flag the vacuous pass.** Nothing in
  conftest's output separates a rule that iterated an empty array from one that
  checked a resource and found it compliant. Detecting it would mean parsing
  every rule's intent, which is writing the HCL2 rules by another name.
- **A non-run in `errors[]`.** conftest did not fail; it was not asked. A
  non-run fails at `--fail-on NONE`, and a gate the consumer cannot clear gets
  switched off (doctrine). The partial-input precedent applies: say what was
  not read, keep the verdict on what was.
- **Count Terraform as candidates.** A `Total` no change can move is the Bicep
  case. `examined: 0 of 3` would read as a scope that excluded three files.
- **Warn on every change-scoped run in a Terraform repository.** That scan was
  not asked about the files the change left alone, and a line on every pull
  request is noise; the tree-scoped commit stage names them on every run.

## Blast radius

- A Terraform-only repository read CLEAN and now reads SKIPPED with the
  warning. It passes at every threshold, as before.
- A mixed repository keeps its verdict and gains one warning; its
  `examined.total` drops by its Terraform file count.
- An ARM, Dockerfile or pipeline-YAML repository is unchanged.

## Proof

`src/risk/terraform_test.go`: a Terraform-only tree builds no group, counts no
candidate, lists the files sorted, reads SKIPPED and passes at all five
thresholds with no `errors[]` and the warning naming both files and
`input.resources`; a mixed tree with a HIGH pipeline finding still fails at
HIGH with `examined: 1 of 1` and the warning naming `main.tf`; a change that
touched only `main.tf` gets both the reworded `NOTHING IN SCOPE` line and the
Terraform line, and a change that touched only the Dockerfile gets no
Terraform line. Putting the `hcl2` case back into `infraFileType` turns five
tests red. `validate_test.go` and `policynamespace_test.go` now assert the
files are not mapped.

## Residue

cicd still assesses no Terraform. Closing it means HCL2 rules: a
`risk.terraform` package reading `input.resource`, a namespace for
`infraFileType` to route `.tf` to, and a fixture that fails a rule, so a
vacuous pass cannot come back unseen. `.hcl` also covers Terragrunt, Packer
and Nomad files, which a Terraform policy would not read either; the routing
will need to tell them apart then.
