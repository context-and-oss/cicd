# Explanation

Understanding-oriented documentation that clarifies the concepts, philosophy, and design decisions behind the CD pipeline.

Explanation answers the question **"Why?"** — it provides context, background, and rationale. It does not tell you how to do things (see [How-to Guides](../how-to-guides/index.md)) or list technical facts (see [Reference](../reference/index.md)).

> **Diataxis note:** Explanation is for reflection. It illuminates a topic from multiple angles. A reader should come away with a deeper understanding of the system — not a list of steps to follow.

## In This Section

| Topic                                                       | Description                                                                                  |
|-------------------------------------------------------------|----------------------------------------------------------------------------------------------|
| [Continuous Delivery](./continuous-delivery/index.md)       | CD model, workflow, quality gates, environments, testing, security, and release management   |
| [Artifact shapes](./artifact-shapes.md)                     | Why the pipeline models image and archive artifacts, the ownership split, and the file-less coverage ratchet |
| [Migrating to cicd](./migrating-to-cicd.md)                 | The mental-model shift and before→after map from a hand-rolled GitHub Actions / Azure DevOps pipeline |
| [The engineering doctrine](./doctrine.md)                   | A tool that could not run must never read as clean: every rule, the false pass it closed, and the trap that would reopen it |
| [The security doctrine](./doctrine-security.md)             | The same rules as the `security` module learned them — Trivy, Semgrep, gitleaks, TruffleHog and ZAP |
| [The quality doctrine](./doctrine-quality.md)               | The same rules as the `quality` module learned them — ESLint, golangci-lint, `dotnet` and the coverage harvest |
| [Glossary](./glossary.md)                                   | Leg, band, witnessed, shape, envelope, non-run and the other words with a fixed meaning here |
