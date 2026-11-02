# Continuous Delivery

The 12-stage continuous-delivery model that cicd implements: how software moves from
authoring to production with quality, traceability and compliance checked at each stage.

The model is the whole journey; the code is not. cicd ships stage 2 (the pre-commit source
gate) and stage 4 (the commit stage with its artifact tail), plus a running-app DAST pipeline
on its own cadence, and [ROADMAP](../../../ROADMAP.md) says what comes next. Read this section
for the shape a consumer is working toward, and the [reference](../../reference/index.md) for
what the modules do today.

## In This Section

| Topic                                       | Description                                                                  |
| ------------------------------------------- | ---------------------------------------------------------------------------- |
| [Core Concepts](./core-concepts/index.md)           | Unit of Flow and Deployable Modules fundamentals                             |
| [CD Model](./cd-model/index.md)                     | Complete 12-stage framework with visual notation and implementation patterns |
| [Workflow](./workflow/index.md)                     | Trunk-based development and branching strategies                             |
| [Testing](./testing/index.md)                       | Testing strategy integrated throughout all CD Model stages                   |
| [Quality Gates](./quality-gates/index.md)           | Quality gate philosophy and Stage 2, 3, 9 gate explanations                  |
| [Deployment](./deployment/index.md)                 | Deployment strategies and ring-based rollout patterns                        |
| [Release Management](./release-management/index.md) | Release documentation and approval patterns (RA vs CDe)                      |
| [Environments](./environments/index.md)             | Environment types and network security zones                                 |
| [Security](./security/index.md)                     | Security integration using open-source tools                                 |
