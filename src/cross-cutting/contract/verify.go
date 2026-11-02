// The verifier's decisions: what a step contract may declare, how a Go
// parameter type satisfies a contract type, and the pass/fail report each
// entry function renders.
//
// Untagged (no //go:build !unit_test): main.go carries the Dagger build tag
// because the generated SDK panics outside a session, and for as long as the
// rules lived beside the entry functions no test could reach them — the module
// that verifies every other module's signature had no proof of its own. The
// entry functions keep the Dagger reads and hand the strings here.
// internal/source is hand-written, not generated, so importing it keeps the
// tagged build compiling.
package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"dagger/contract/internal/source"
)

type contractParam struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
	Default  string `json:"default,omitempty"`
}

type moduleContract struct {
	Stage        string          `json:"stage"`
	Step         string          `json:"step"`
	Function     string          `json:"function"`
	Params       []contractParam `json:"params"`
	OutputSchema string          `json:"outputSchema"`
}

// validOutputSchemas is the closed set of output shapes a step contract may
// declare: an evidence envelope (single or list), a container image
// (build.Build), a plain directory (build.BuildArchive — the archive artifact
// shape), or none (side-effect-only steps like notify).
//
// The evidence entries name the MAJOR family, not an exact version. They used
// to read evidence-1.0.0, which made a contract file claim a minor version it
// could not keep: the minor moves when the envelope gains a field and the
// contract stands still, so every additive change made every contract stale.
// The precise version travels in the envelope's own schemaVersion field.
// scripts/repo_surface.py holds these keys to internal/evidence.SchemaVersion's
// major, since this module carries no copy of that constant to compare against.
var validOutputSchemas = map[string]bool{
	"evidence-1":   true,
	"evidence-1[]": true,
	"container":    true,
	"directory":    true,
	"none":         true,
}

// parseModuleContracts reads a contract.json that holds either a single step
// contract object (the original format) or an array of them (modules exposing
// more than one entry function, e.g. build's Build + BuildArchive).
func parseModuleContracts(data string) ([]moduleContract, error) {
	trimmed := strings.TrimSpace(data)
	if strings.HasPrefix(trimmed, "[") {
		var cs []moduleContract
		if err := json.Unmarshal([]byte(trimmed), &cs); err != nil {
			return nil, fmt.Errorf("parse contract array: %w", err)
		}
		if len(cs) == 0 {
			return nil, fmt.Errorf("contract array is empty")
		}
		return cs, nil
	}
	var c moduleContract
	if err := json.Unmarshal([]byte(trimmed), &c); err != nil {
		return nil, fmt.Errorf("parse contract: %w", err)
	}
	return []moduleContract{c}, nil
}

type pipelineStep struct {
	Step   string `json:"step"`
	Module string `json:"module"`
}

type pipelineStage struct {
	Stage string         `json:"stage"`
	Steps []pipelineStep `json:"steps"`
}

type pipelineManifest struct {
	Pipeline string          `json:"pipeline"`
	Stages   []pipelineStage `json:"stages"`
}

type stageContractStep struct {
	Step     string `json:"step"`
	Required bool   `json:"required"`
}

type stageContract struct {
	Stage string              `json:"stage"`
	Steps []stageContractStep `json:"steps"`
}

// stageCheck pairs a manifest stage with the stage contract read for it, so
// verifyPipeline never has to say what it would do about a contract the entry
// function failed to read: that is a hard error before anything is graded.
type stageCheck struct {
	Manifest pipelineStage
	Contract stageContract
}

// verifyPipeline renders the per-stage [pass]/[fail]/[skip] report and the
// closing result line, and says whether every required step was declared.
// The text is the complete report; VerifyPipeline returns it as the value on
// a pass and inside the error on a fail.
func verifyPipeline(stages []stageCheck) (string, bool) {
	var sb strings.Builder
	pass := true

	for _, sc := range stages {
		present := make(map[string]bool, len(sc.Manifest.Steps))
		for _, s := range sc.Manifest.Steps {
			present[s.Step] = true
		}

		fmt.Fprintf(&sb, "stage: %s\n", sc.Manifest.Stage)
		for _, step := range sc.Contract.Steps {
			switch {
			case present[step.Step]:
				fmt.Fprintf(&sb, "  [pass] %s\n", step.Step)
			case step.Required:
				fmt.Fprintf(&sb, "  [fail] %s — required step missing\n", step.Step)
				pass = false
			default:
				fmt.Fprintf(&sb, "  [skip] %s — optional, not declared\n", step.Step)
			}
		}
		sb.WriteString("\n")
	}

	if pass {
		sb.WriteString("result: PASS\n")
	} else {
		sb.WriteString("result: FAIL\n")
	}
	return sb.String(), pass
}

// verifySignatures grades every contract in a module's contract.json against
// the module's Go sources (file name → contents, already narrowed by
// source.Select) and renders the report. A function the sources do not define
// fails that contract and the grading moves on to the next, so one report
// names every gap rather than the first.
func verifySignatures(contracts []moduleContract, sources map[string]string) (string, bool) {
	var sb strings.Builder
	pass := true

	for _, c := range contracts {
		fmt.Fprintf(&sb, "step:     %s/%s\n", c.Stage, c.Step)
		fmt.Fprintf(&sb, "function: %s\n\n", c.Function)

		if validOutputSchemas[c.OutputSchema] {
			fmt.Fprintf(&sb, "  [pass] outputSchema (%s)\n", c.OutputSchema)
		} else {
			fmt.Fprintf(&sb, "  [fail] outputSchema — unknown value %q (expected one of: evidence-1, evidence-1[], container, directory, none)\n", c.OutputSchema)
			pass = false
		}

		goParams, err := source.FuncParams(c.Function, sources)
		if err != nil {
			fmt.Fprintf(&sb, "  [fail] %v\n\n", err)
			pass = false
			continue
		}

		for _, p := range c.Params {
			if !p.Required {
				continue
			}
			goType, found := goParams[strings.ToLower(p.Name)]
			if !found {
				fmt.Fprintf(&sb, "  [fail] %s (%s) — required param missing\n", p.Name, p.Type)
				pass = false
				continue
			}
			if !typeCompatible(p.Type, goType) {
				fmt.Fprintf(&sb, "  [fail] %s — type mismatch: contract=%s go=%s\n", p.Name, p.Type, goType)
				pass = false
				continue
			}
			fmt.Fprintf(&sb, "  [pass] %s (%s)\n", p.Name, p.Type)
		}
		sb.WriteString("\n")
	}

	if pass {
		sb.WriteString("result: PASS\n")
	} else {
		sb.WriteString("result: FAIL\n")
	}
	return sb.String(), pass
}

// typeCompatible returns true when a contract type maps to the given Go type string.
func typeCompatible(contractType, goType string) bool {
	mapping := map[string]string{
		"String":    "string",
		"String[]":  "[]string",
		"Directory": "*dagger.Directory",
		"File":      "*dagger.File",
		"Secret":    "*dagger.Secret",
		"Boolean":   "bool",
		"Integer":   "int",
		// quality.Test and stage-2.Run declare `tolerance` as Float. The
		// parameter is optional, so the verifier never graded it and the gap
		// stayed open until TestRepositoryContractsParse walked every contract.
		"Float": "float64",
		// Container is security.ScanImage's subject and one of security.ScanWeb's
		// three target sources; Service is another. Both are ordinary Dagger
		// Function argument types, and their absence here is why ScanImage had no
		// contract entry at all: a contract naming a type this map does not hold
		// fails verification, so the function was left out instead of the map
		// being widened. A step with no contract entry is not verified against
		// anything, which is a weaker state than a contract that disagrees.
		"Container": "*dagger.Container",
		"Service":   "*dagger.Service",
	}
	expected, ok := mapping[contractType]
	if !ok {
		return false
	}
	return goType == expected
}
