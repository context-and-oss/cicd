# Let the consumer bring the model, and trust callers by claims

## Why

The feedback loops in `ROADMAP.md` call a model, but the roadmap did not say
whose model or whose credential. A spike had hard-coded one endpoint and kept
its settings in the repository that ran it. That is fine for a test, and wrong
for a shared workflow: the consumer's code and issue text would travel under
someone else's credential and data terms.

## The mechanism

The roadmap now states that cicd holds no model credential. The consumer brings
the endpoint, the deployment and an Entra identity. Those four non-secret values
are workflow inputs, which an organisation can set once as org-level Actions
variables. The workflow exchanges GitHub's OIDC token for a short-lived Entra
token, so there is no API key to store.

We chose Entra's claims-matching federated credential, though it is in preview,
because a standard federated credential names one repository and an identity
holds only a small number of them. One expression per consumer organisation
covers every repository. It pins three claims:

- the organisation's numeric owner ID;
- the trunk branch;
- cicd's workflow at a release tag.

## Rejected

- An org-level API key secret. Every repository in scope could spend it, usage
  cannot be attributed to a repository, and one leak or rotation hits all of
  them.
- One federated credential per repository, since it runs into the
  per-identity cap as consumers are added.
- Hard-coding the endpoint in cicd's workflows.

## Traps

- Matching `job_workflow_ref` without the owner ID. cicd is public, so any
  repository on GitHub that calls the workflow would match.
- Matching the organisation by a name pattern instead of its numeric ID, because
  a name prefix also matches other organisations.
- Accepting the workflow at `@*` instead of a release tag, which lets a branch
  with a modified copy obtain a token.
