# State third-party terms, and make the first check gate

## Intent

A review of the tree before its open-source import found four things a reader
of the public repository would be misled by, or that its licences require.

1. **A consumer fingerprint survived the rounding rule.** A comment carried an
   exact six-digit finding count from a consumer run, and test inputs and a
   spec repeated it and a sibling figure. AGENTS.md asks for a rounded figure,
   since the argument survives rounding and the fingerprint does not.
2. **Copied Trivy data had no attribution.** A test fixture holds Trivy
   v0.70.0's licence-category tables captured verbatim. Trivy is Apache-2.0,
   whose §4(d) requires its NOTICE to travel with a derivative; the root
   `NOTICE` carried only cicd's own.
3. **The default SAST rules are not Apache-2.0, and nothing said so.**
   `security.ScanSource` fetches `semgrep/semgrep-rules` at a pinned commit at
   run time. Those rules are under the Semgrep Rules License v1.0: internal
   business use, no redistribution, not offered to others as a service. That
   differs from both cicd's licence and the Semgrep engine's.
4. **The README's first check could not fail.** It exported evidence at
   `--fail-on HIGH` and stopped, because `dagger call` exits 0 whatever the scan
   concluded. A newcomer who copied it got a gate that blocked nothing.

## Chosen approach

- **Rounded or neutral figures.** The comment in `src/quality/sources.go` now
  says "over 200,000"; the tests in `src/notify/outcomereport_test.go` and
  `src/quality/sources_test.go` and the spec that echoed the figures use
  synthetic values with the same digit shapes, because the formatter's argument
  needs only the shape. A sweep of comments, docs, specs, capsules, fixtures
  and script tests then found more of the same classes, each now rounded or
  replaced with a synthetic value while the test keeps its mechanism: exact
  coverage percentages and coverable-line counts, project, package and URL
  counts and document sizes from consumer runs, the specific findings a
  consumer's scan had dropped, identifiers copied from a consumer's SBOM and
  DAST log, and pull request numbers and CI run ids from this repository's
  private history used as test inputs. Upstream tool limits, image digests,
  measurements of this repository's own CI, public open-source projects and
  synthetic test data were left as they are; so were small structural counts
  that identify nothing on their own.
- **Attribution where it is required.** `NOTICE` reproduces Trivy's upstream
  NOTICE; `THIRD_PARTY_NOTICES.md` records source, tag, files and what was
  copied, and is linked from the README and declared in
  `scripts/repo-inventory.json`.
- **Runtime terms stated where consumers start.** The README, the security
  module README, the complete-pipeline guide and `THIRD_PARTY_NOTICES.md` say
  which rules are fetched, under which licence, what that means for hosted or
  redistributed use, and that a checked-in config passed as `--sast-rulesets`
  replaces the pinned packs while SAST keeps running. The default is unchanged,
  because swapping it for a smaller rule set nobody reviewed would trade a
  licence question for a silent loss of coverage, and no code change grants a
  licence.
- **The first check gates, and a check holds it.** The README and tutorial
  chain the export to `jq -e '.passed == true'` with `&&`, removing a stale file
  first, and explain that a successful call is not a clean scan and that a
  scanner that could not run fails at `NONE` too. `check_first_check_gates` in
  `scripts/repo_surface.py` refuses a first-use export that is not gated on the
  file it wrote, or is gated in a separate statement. It proves the commands'
  shape, not that any scan passes.
- **What only a maintainer can confirm was listed, not asserted.** The
  public-launch checklist in `CONTRIBUTING.md` names the GitHub settings no
  check in this tree can see. At the time of this review, inclusion clearance
  for two raster images embedded in `.drawio.png` diagrams was outstanding
  (see the subsequent resolution below). The explanation in
  the former embedded workflow fallback was newly written for cicd and its
  CWE metadata reduced to an identifier, instead of retaining an uncertain
  description. At that stage its detection pattern and rule identity did not
  change; that was not a provenance claim for the complete rule body.

## Rejected

- *A deny-list of the old figures.* It would publish them.
- *Replace the two images.* At this review's decision point, their origin was
  unconfirmed, not known to be bad; replacing them before a maintainer's answer
  could have discarded original work.

## Subsequent resolution

The maintainer has since supplied inclusion clearance for the embedded raster
images, recorded in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md). This
resolves the outstanding inclusion decision; it is not an independent copyright
certification or a claim that original authorship was established by this review.
The owner also confirmed own-code-only use of the Semgrep rules. That operating
scope does not change the runtime licence terms documented above. Destination
release settings, protections and credentials remain unproven.

The embedded workflow-rule body has subsequently been removed. The first-party
adapter `src/security/semgrep_gha.py` obtains and adapts the pinned rule at
runtime, retaining the complete original source/licensor notices and identifying
its modifications. The generated rule remains under upstream terms, not
Apache-2.0. See [the runtime-adaptation record](adapt-the-workflow-rule-at-runtime.md).

## Residue

The licence texts were taken from the upstream files as cited for this review;
the summary in `THIRD_PARTY_NOTICES.md` is not legal advice, and whether a
given use of the default rules fits the Semgrep Rules License is a decision for
the people operating it.
