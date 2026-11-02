# Build once and retain the assessed output

The commit composite builds and assesses an image or archive but previously
returned only evidence. A consumer deploying afterward had to rebuild, changing
the object being deployed and paying the compile cost again. Quality also made
separate restore/install environments for automatic lint and witnessed tests.
We chose shared execution state and retained deployables because a second build
adds pipeline time and can produce bytes different from those assessed.
Retaining the assessed output preserves the identity between the bytes scanned
and the bytes later selected for deployment; download caches alone cannot do that.

## Contract

- Consumers own preparation, test and packaging commands. One opt-in prepared
  Node/.NET container retains compatible dependencies and compilation state.
  Its toolchain and selected test language must agree. Immutable branches keep
  lint/test mutations out of packaged output. Existing commands remain valid
  without opting in; no inference rewrites arbitrary shell or MSBuild flags.
- Source assessments keep the original source scope. Archive and image scans
  consume the same built output that is bundled. Application mode retains its
  explicitly deferred dependency assessment; retention adds no SBOM claim.
- The existing evidence directory adds an artifacts subtree and a manifest.
  The manifest binds exact transport bytes and evidence by SHA-256 and carries
  source/run/app identity and verdict. It retains false verdicts for diagnosis;
  workflow uploads and the deployment verifier require true. Consumers download
  by immutable artifact ID/run, verify against independently selected expected
  provenance, then publish/deploy without rebuilding. CI artifacts are subject
  to retention and the consumer owns longer-term promotion.
- Package caches hold downloads, scoped by repository in the Dagger engine.
  They are optional accelerators, not evidence or durable deployables. Fresh
  hosted engines need an explicit persistent backend for cross-job cache hits.
- The Node discovery cap protects against unbounded install/check cost. Keep
  default 4, expose a positive node-project-limit on repository commit and
  precommit surfaces, and fail visibly beyond it. A repository with more
  independent apps can raise the budget without becoming a workspace.
- Independent source check groups in commit and precommit have consumer
  parallelism 1–4, default 1.
  Project budget, group concurrency, inner tool workers and workflow matrix
  fan-out are separate. Deterministic evidence slots and failed envelopes keep
  a failed concurrent check from discarding completed independent results.
- Declared tests do not silently replace lint. Existing explicit app lint
  commands remain the mechanism for consumer-owned lint execution.

## Proof

The scheduler race tests measure its peak active callbacks for limits 1/2/4 and
prove errors do not skip independent work. Module unit tests reject incompatible
preparation selections and mismatched manifest provenance. Python verifier tests
reject altered payload/evidence, wrong source/run/app, failed verdicts and unsafe
transport paths. Workflow tests enforce the separate passing-candidate upload.

`scripts/smoke/commit-apps.sh` now runs both preparation paths. The Node case
compares a runtime-generated preparation token in witnessed test output with the
packaged token and asserts branch-local mutations never leak. The .NET case
builds once, then installs an MSBuild target that fails on another real compile;
lint, no-build tests and no-build publish must still succeed. A stale prepared
coverage report cannot satisfy a later test invocation. Both passing bundles
must verify, and a failed test bundle must not. Existing shape smokes continue
to exercise repository container/archive/none paths.

The consumer setup and remaining compatibility limits are documented in
[the build-once guide](../docs/how-to-guides/build-once.md).
