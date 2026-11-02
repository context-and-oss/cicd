# How-to Guides

Task-oriented recipes for common operations. Most run from *your* repository against the
published modules and need no checkout of this one; a guide that needs this repository
checked out says so. Each focuses on getting a specific thing done.

## Getting started and adoption

| Guide | What it covers |
|-------|---------------|
| [Use the complete pipeline](use-complete-pipeline.md) | Adopt the full pre-commit and commit composites in GitHub Actions or Azure DevOps |
| [Use individual modules](use-individual-modules.md) | Run quality, security, risk, build, and notify modules independently |
| [Build your own pipeline](build-your-own-pipeline.md) | Compose imported Dagger modules into a custom pipeline |
| [Mix and match modules](mix-and-match-modules.md) | Choose module combinations for different stages, teams, and rollout phases |
| [Use the pipeline without a Dockerfile](use-without-dockerfile.md) | Adopt the archive shape: zip/folder artifacts, witnessed test coverage with the ratchet gate, lockfile SBOMs |
| [Build once, assess it, deploy the retained output](build-once.md) | Share one prepared Node or .NET context across the commit composite's source checks and build, and get the deployable back beside its evidence |
| [Adopt cicd incrementally](adopt-incrementally.md) | Hand an existing pipeline to cicd one stage at a time (agent-drivable); coexist with the legacy pipeline during the transition |
| [Set up Azure DevOps authentication](set-up-azure-devops-auth.md) | Configure the PAT, OAuth token, and optional secrets an ADO consumer needs to fetch the module and post PR comments |

## Pipeline execution

| Guide | What it covers |
|-------|---------------|
| [Run the pipeline locally](run-pipeline-locally.md) | Run the local pre-push entrypoint, reproduce CI locally, and inspect evidence output |
| [Scan a running app (DAST)](scan-a-running-app.md) | Attack a live web app or API with OWASP ZAP: pick who starts the app, pick a cadence, read the evidence |

## Related sections

- **[Tutorials](../tutorials/index.md)** — step-by-step learning guides for newcomers
- **[Reference](../reference/index.md)** — complete technical reference for modules and APIs
- **[Explanation](../explanation/index.md)** — conceptual background on the CD Model
