package main

// Who every row in this module's evidence came from.
//
// Untagged on purpose: main.go carries the Dagger build tag, and sources.go —
// which stamps these onto every SourceStatus — is untagged so a test can reach
// it.
//
// In its own file, not in schema.go, because schema.go is GENERATED. `make
// sync-schema` rewrites every module copy wholesale from
// internal/evidence/schema.go, so anything hand-added there is deleted the next
// time someone runs it. That is not hypothetical: this block lived in schema.go
// and a routine sync removed it, and the only thing that caught it was the
// compiler. A declaration that survives the generator belongs outside its
// output.
const (
	moduleName  = "quality"
	moduleStage = "domain"
)
