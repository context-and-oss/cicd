# cross-cutting/contract

Verifies that Dagger module implementations match their declared step contracts (`contract.json`) and that pipeline manifests satisfy stage contracts (`stage-contract.json`).

## Entry functions

```go
// Verify a module's Go source exposes the function and required params from contract.json.
func (m *Contract) VerifySignature(
    ctx context.Context,
    module *dagger.Directory,  // source dir of the module under test
    repo *dagger.Directory,    // repo root containing <step>/contract.json
    step string,               // e.g. "security", "quality", "build"
) (string, error)

// Verify a pipeline manifest satisfies all stage-contract.json files in the repo.
func (m *Contract) VerifyPipeline(
    ctx context.Context,
    manifest *dagger.File,     // pipeline.json
    repo *dagger.Directory,    // repo root
) (string, error)
```

## Run locally

```sh
cd src/cross-cutting/contract && dagger develop   # once

# verify a module's signature
dagger -m ./src/cross-cutting/contract call verify-signature \
  --module ./src/security \
  --repo . \
  --step src/security

# verify a pipeline manifest
make verify-pipeline MANIFEST=pipeline.json
```

## Automation via Makefile

```sh
make verify-contracts   # verifies all modules listed in CONTRACT_STEPS
make verify-pipeline MANIFEST=<file>
```

## Key files

- `main.go` — `VerifySignature()` and `VerifyPipeline()`: the Dagger reads only
- `verify.go` — the contract types, the accepted output schemas, the
  contract-type → Go-type table, and `verifySignatures()`/`verifyPipeline()`,
  which render the whole report (untagged, unit-tested; the module that grades
  every other module's signature had no test of its own until these moved out
  of the tagged file)
- `internal/source/` — hand-written, stdlib-only file selection and Go AST
  parsing; not generated, so untagged code may import it

## Constraints

- Only supports Go-based Dagger modules. All `*.go` files in the module's root are parsed via the Go AST; `dagger.gen.go` and `*_test.go` are excluded.
- Looks for `<step>/contract.json` relative to the repo root for `VerifySignature`.
- Looks for `<stage>/stage-contract.json` relative to the repo root for `VerifyPipeline`.
