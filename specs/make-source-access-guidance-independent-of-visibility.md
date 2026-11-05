# Intent: make source-access guidance independent of visibility

## Why

Availability text that says a repository is currently private becomes incorrect
when its hosting visibility changes. Repeating a publication approval workflow
in consumer setup instructions also obscures the requirements that actually
matter: a reachable release, appropriate platform access and separate source,
package-feed and notification credentials.

## Change

Update `README.md`, `docs/index.md`, onboarding guides, reference access notes,
module installation notes and starter-template comments to explain access by
repository visibility. Public modules support anonymous fetching; private
forks or mirrors require authorized read-only source access. Keep local checkout
alternatives and verify referenced releases and reusable-workflow/action policy.

Preserve the distinction between source access and feed, notification or model
credentials. A local checkout grants no remote workflow access, and a writer
credential must not become a source-fetch fallback. Keep runtime licence notices,
evidence-verdict requirements and private-reporting fallback guidance intact.

## Verification and limits

Check the defended surface, version pins, template validation, links and whitespace.
Compare fenced commands and template executable bodies with the base because this
change is explanatory text, not pipeline execution. No module code, workflow logic,
release pin, permission, image or diagram reference changes. Updating prose does
not change repository visibility or prove anonymous fetching, fork execution or
security-report delivery. Those checks remain separate from this documentation
change and must be reported from actual execution rather than inferred.
