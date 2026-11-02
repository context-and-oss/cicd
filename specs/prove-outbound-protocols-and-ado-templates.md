# Prove outbound protocols and Azure DevOps templates

## Intent

This change replaces function-list and rendered-template checks because those checks did not execute the production request paths or show how failures behave. The repository needs deterministic evidence that outbound integrations authenticate correctly, stop within a bounded time, reject invalid responses, and keep credentials out of errors.

## Chosen approach

The implementation moves shared notification transport behavior into `src/notify/delivery.go`, drives it with loopback HTTP fixtures, and tests the Dependency Track upload path through `src/cross-cutting/dependency-track/upload.go`. It also validates the shipped Azure DevOps templates with repository-owned parsing and negative fixtures rather than trusting rendered text.

## Expected result

CI now exercises success, authorization failure, malformed responses, timeout behavior, pagination bounds, secret redaction, and template credential handling. Regressions in these paths are detected by the corresponding local commands and CI jobs.
