# Artifact shapes

The pipeline models exactly two *artifact* shapes: **image** — an OCI container
built from a Dockerfile — and **archive** — a directory or zip produced by a
build command, such as a Dataverse webresource solution or a .NET publish
folder bound for an Azure Web App. Every commit-stage capability (attested
build, SBOM, artifact scanning, evidence aggregation) exists for both shapes. Both are reached through the *same*
composite entry point — `commit run --artifact container|archive` — plus a
third selector value, `none`, for repos that produce no deployable at all
(libraries, infra/config). This page explains why the model looks the way it
does. The normative decisions live in
[ADR-001](../decisions/ADR-001-artifact-shapes.md),
[ADR-002](../decisions/ADR-002-witnessed-test-execution.md),
[ADR-003](../decisions/ADR-003-fileless-coverage-ratchet.md), and
[ADR-005](../decisions/ADR-005-commit-stage-code-and-artifact.md) — which
superseded the original per-shape entry points with the single explicit
selector; this page is the discussion around them.

## Why exactly two shapes

The repositories consuming these modules are heterogeneous: containerized services
sit next to repos whose deployable is a zip. For a long time the commit stage
had only one build primitive — Docker — which left non-container repos with
two bad options: skip the commit stage entirely (no SBOM, no artifact
attestation), or write a Dockerfile for an image they never ship. The second
option is worse than it looks: it produces evidence about a fictional
artifact. An auditor reading that evidence learns nothing about the zip that
actually went to production.

Rather than generalize to N artifact kinds, the model commits to two. Image
and archive genuinely differ in how they are built, what their SBOM source
is, and what scanning them means. A third shape would earn its place the same
way the archive did — by demonstrating that its evidence chain differs
structurally, not just by file extension.

## Who owns what

The dividing question for every pipeline capability: does the organization
need it uniform and auditable, or does the repo need it fast and custom?

Consumers own **definitions**: the Dockerfile, the build command, the test
command, and their entire lint/format/typecheck configuration. These encode
repo-specific truth, and developers need the same gates locally that CI
enforces. The pipeline owns **execution and evidence**: it runs the
consumer's definition in a controlled container and attests what happened —
the SBOM, the scans, the coverage measurement, the aggregated envelope. This
is the split the Dockerfile already proved before the archive shape existed:
nobody expected the pipeline to write Dockerfiles, only to build them
reproducibly and hang evidence off the result.

Test execution follows the same logic with one twist explained in ADR-002:
the pipeline executes the consumer's own test command rather than ingesting a
test report the consumer produced. Executed-and-observed ("witnessed")
evidence is materially stronger attestation than a self-reported file — "we
ran your suite at this commit and measured this" versus "a JSON file said
so."

## Why the SBOM comes from lockfiles but secrets scanning targets the build output

The two scans of an archive deliberately look at different things.

Dependency identity lives in lockfiles. A bundler erases it: a vite bundle is
one minified file, a published .NET app is compiled IL — scanning those for
dependencies yields noise or nothing. So the SBOM and the dependency
vulnerability scan read the source tree's lockfiles, which is both complete
and precise for an archive (unlike a container, an archive has no base-image
OS packages that a source scan would miss).

Secrets risk is the mirror image. The dangerous failure is not a secret in
your source — your source scan already covers that — it is a secret that the
build *baked into the artifact*: a `.env` swept into `dist/`, a connection
string embedded at publish time. Only the built output can reveal that, so
the secrets scan runs there.

## Why the coverage ratchet is file-less and fails open

The ratchet ("coverage may not drop more than a tolerance below the previous
baseline") needs a baseline from somewhere. A baseline file committed to
every consumer repo was rejected: it is hand-editable evidence, it is one
more CI-specific file to maintain, and its bump-commits add noise. Instead,
the baseline is the previous successful default-branch run's own evidence
artifact — the pipeline's output feeding back as its next input. The full
reasoning, including the retention trade-off, is ADR-003.

Failing open is the deliberate half of that design. A missing baseline — the
first run ever, or an artifact expired after long dormancy — skips the
ratchet with a warning instead of blocking the PR. A coverage gate's job is
to stop regressions, not to punish repos for adopting the pipeline or waking
from a pause. The cost is one unguarded PR after a long dormancy; the warning
makes it visible, and the next merge re-seeds the baseline.

The ratchet is also deliberately *not* "coverage must always go up."
Monotonic gates block legitimate work — deleting tested dead code drops
coverage — and teach teams to game the number with assertion-free tests. A
tolerance absorbs refactor noise; the warn-mode escape hatch handles
deliberate drops while leaving a visible trace in the workflow diff.

## What this buys the fleet

A Dataverse team and a container team now produce the same evidence envelope,
the same SBOM format — one compliance
plane over different artifact physics. And because the shape is a single
explicit selector on one entry point rather than a per-shape entry point with
its own workflow templates, the container path stays the default: a consumer
who ships an image reads the same caller stub and the same reference, and the
shape-specific inputs (`build-cmd`, `output-path`) simply stay unset.
