package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const scannerSource = `package main

import (
	"context"

	"dagger/scanner/internal/dagger"
)

type Scanner struct{}

func (m *Scanner) ScanSource(
	ctx context.Context,
	src *dagger.Directory,
	commitSha string,
	failOn string,
	exclude []string,
	token *dagger.Secret,
	limit int,
	verbose bool,
	image *dagger.Container,
	app *dagger.Service,
	spec *dagger.File,
) (*dagger.File, error) {
	return nil, nil
}
`

func scannerContract(params ...contractParam) moduleContract {
	return moduleContract{Stage: "stage-2", Step: "security", Function: "ScanSource", Params: params, OutputSchema: "evidence-1"}
}

func TestParseModuleContracts_singleObjectAndArray(t *testing.T) {
	single, err := parseModuleContracts(` {"stage":"stage-2","step":"quality","function":"Check","outputSchema":"evidence-1"} `)
	if err != nil {
		t.Fatal(err)
	}
	if len(single) != 1 || single[0].Function != "Check" {
		t.Errorf("single = %+v", single)
	}
	many, err := parseModuleContracts(`[{"function":"Build","outputSchema":"container"},{"function":"BuildArchive","outputSchema":"directory"}]`)
	if err != nil {
		t.Fatal(err)
	}
	if len(many) != 2 || many[1].Function != "BuildArchive" {
		t.Errorf("array = %+v", many)
	}
}

func TestParseModuleContracts_refusesEmptyAndMalformed(t *testing.T) {
	for name, data := range map[string]string{
		"empty array":      `[]`,
		"malformed object": `{"function":`,
		"malformed array":  `[{"function":"Build"}`,
		"empty":            ``,
	} {
		t.Run(name, func(t *testing.T) {
			if cs, err := parseModuleContracts(data); err == nil {
				t.Errorf("parsed %+v, want an error", cs)
			}
		})
	}
}

func TestTypeCompatible_everyContractTypeMapsToOneGoType(t *testing.T) {
	mapping := map[string]string{
		"String":    "string",
		"String[]":  "[]string",
		"Directory": "*dagger.Directory",
		"File":      "*dagger.File",
		"Secret":    "*dagger.Secret",
		"Boolean":   "bool",
		"Integer":   "int",
		"Float":     "float64",
		"Container": "*dagger.Container",
		"Service":   "*dagger.Service",
	}
	for contractType, goType := range mapping {
		if !typeCompatible(contractType, goType) {
			t.Errorf("%s should accept %s", contractType, goType)
		}
		for other, otherGo := range mapping {
			if other != contractType && typeCompatible(contractType, otherGo) {
				t.Errorf("%s accepted %s's Go type %s", contractType, other, otherGo)
			}
		}
	}
	if typeCompatible("Decimal", "float64") {
		t.Error("an unknown contract type must never be compatible with anything")
	}
	if typeCompatible("String", "String") {
		t.Error("the Go type is compared exactly, not case-folded")
	}
}

func TestVerifySignatures_passReportNamesEveryRequiredParam(t *testing.T) {
	c := scannerContract(
		contractParam{Name: "src", Type: "Directory", Required: true},
		contractParam{Name: "commitSha", Type: "String", Required: true},
		contractParam{Name: "exclude", Type: "String[]", Required: false},
		contractParam{Name: "token", Type: "Secret", Required: true},
		contractParam{Name: "limit", Type: "Integer", Required: true},
		contractParam{Name: "verbose", Type: "Boolean", Required: true},
		contractParam{Name: "image", Type: "Container", Required: true},
		contractParam{Name: "app", Type: "Service", Required: true},
		contractParam{Name: "spec", Type: "File", Required: true},
	)
	report, pass := verifySignatures([]moduleContract{c}, map[string]string{"main.go": scannerSource})
	if !pass {
		t.Fatalf("expected a pass:\n%s", report)
	}
	want := "step:     stage-2/security\n" +
		"function: ScanSource\n\n" +
		"  [pass] outputSchema (evidence-1)\n" +
		"  [pass] src (Directory)\n" +
		"  [pass] commitSha (String)\n" +
		"  [pass] token (Secret)\n" +
		"  [pass] limit (Integer)\n" +
		"  [pass] verbose (Boolean)\n" +
		"  [pass] image (Container)\n" +
		"  [pass] app (Service)\n" +
		"  [pass] spec (File)\n" +
		"\n" +
		"result: PASS\n"
	if report != want {
		t.Errorf("report:\n%s\nwant:\n%s", report, want)
	}
}

func TestVerifySignatures_paramNamesAreCaseInsensitive(t *testing.T) {
	c := scannerContract(contractParam{Name: "CommitSHA", Type: "String", Required: true})
	report, pass := verifySignatures([]moduleContract{c}, map[string]string{"main.go": scannerSource})
	if !pass || !strings.Contains(report, "  [pass] CommitSHA (String)\n") {
		t.Errorf("report:\n%s", report)
	}
}

func TestVerifySignatures_failsNameTheGap(t *testing.T) {
	cases := []struct {
		name     string
		contract moduleContract
		wantLine string
	}{
		{
			"required param missing",
			scannerContract(contractParam{Name: "repoUrl", Type: "String", Required: true}),
			"  [fail] repoUrl (String) — required param missing\n",
		},
		{
			"type mismatch",
			scannerContract(contractParam{Name: "src", Type: "File", Required: true}),
			"  [fail] src — type mismatch: contract=File go=*dagger.Directory\n",
		},
		{
			"unknown output schema",
			moduleContract{Stage: "stage-2", Step: "security", Function: "ScanSource", OutputSchema: "evidence-1.0.0"},
			"  [fail] outputSchema — unknown value \"evidence-1.0.0\" (expected one of: evidence-1, evidence-1[], container, directory, none)\n",
		},
		{
			"function not defined",
			moduleContract{Stage: "stage-2", Step: "security", Function: "ScanImage", OutputSchema: "evidence-1"},
			"  [fail] function \"ScanImage\" not found in module sources\n\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report, pass := verifySignatures([]moduleContract{tc.contract}, map[string]string{"main.go": scannerSource})
			if pass {
				t.Fatalf("expected a fail:\n%s", report)
			}
			if !strings.Contains(report, tc.wantLine) {
				t.Errorf("report lacks %q:\n%s", tc.wantLine, report)
			}
			if !strings.HasSuffix(report, "\nresult: FAIL\n") {
				t.Errorf("report does not end in the FAIL line:\n%s", report)
			}
		})
	}
}

func TestVerifySignatures_oneFailingContractFailsTheModuleAndTheRestAreStillGraded(t *testing.T) {
	ok := scannerContract(contractParam{Name: "src", Type: "Directory", Required: true})
	missing := moduleContract{Stage: "stage-2", Step: "security", Function: "ScanImage", OutputSchema: "evidence-1"}
	report, pass := verifySignatures([]moduleContract{missing, ok}, map[string]string{"main.go": scannerSource})
	if pass {
		t.Fatalf("expected a fail:\n%s", report)
	}
	if !strings.Contains(report, "  [pass] src (Directory)\n") {
		t.Errorf("the contract after the failing one was not graded:\n%s", report)
	}
}

func TestVerifySignatures_anOptionalParamIsNeverGraded(t *testing.T) {
	c := scannerContract(contractParam{Name: "doesNotExist", Type: "String", Required: false})
	report, pass := verifySignatures([]moduleContract{c}, map[string]string{"main.go": scannerSource})
	if !pass || strings.Contains(report, "doesNotExist") {
		t.Errorf("report:\n%s", report)
	}
}

func TestVerifySignatures_aParseFailureInAnySourceFileFailsTheContract(t *testing.T) {
	c := scannerContract(contractParam{Name: "src", Type: "Directory", Required: true})
	sources := map[string]string{"main.go": scannerSource, "broken.go": "package main\n\nfunc ("}
	report, pass := verifySignatures([]moduleContract{c}, sources)
	if pass {
		t.Fatalf("a module whose sources do not parse must not verify:\n%s", report)
	}
	if !strings.Contains(report, "[fail] parse broken.go:") {
		t.Errorf("report does not name the file that failed to parse:\n%s", report)
	}
}

func stage2Contract() stageContract {
	return stageContract{Stage: "stage-2", Steps: []stageContractStep{
		{Step: "quality", Required: true},
		{Step: "security", Required: true},
		{Step: "risk", Required: false},
	}}
}

func TestVerifyPipeline_passSkipAndFailLines(t *testing.T) {
	full := stageCheck{
		Manifest: pipelineStage{Stage: "src/stage-2", Steps: []pipelineStep{{Step: "quality"}, {Step: "security"}, {Step: "risk"}}},
		Contract: stage2Contract(),
	}
	report, pass := verifyPipeline([]stageCheck{full})
	want := "stage: src/stage-2\n  [pass] quality\n  [pass] security\n  [pass] risk\n\nresult: PASS\n"
	if !pass || report != want {
		t.Errorf("pass=%v report:\n%s\nwant:\n%s", pass, report, want)
	}

	optionalOmitted := full
	optionalOmitted.Manifest.Steps = []pipelineStep{{Step: "quality"}, {Step: "security"}}
	report, pass = verifyPipeline([]stageCheck{optionalOmitted})
	want = "stage: src/stage-2\n  [pass] quality\n  [pass] security\n  [skip] risk — optional, not declared\n\nresult: PASS\n"
	if !pass || report != want {
		t.Errorf("pass=%v report:\n%s\nwant:\n%s", pass, report, want)
	}

	requiredOmitted := full
	requiredOmitted.Manifest.Steps = []pipelineStep{{Step: "quality"}}
	report, pass = verifyPipeline([]stageCheck{requiredOmitted})
	want = "stage: src/stage-2\n  [pass] quality\n  [fail] security — required step missing\n  [skip] risk — optional, not declared\n\nresult: FAIL\n"
	if pass || report != want {
		t.Errorf("pass=%v report:\n%s\nwant:\n%s", pass, report, want)
	}
}

func TestVerifyPipeline_oneFailingStageFailsTheManifest(t *testing.T) {
	good := stageCheck{
		Manifest: pipelineStage{Stage: "src/stage-2", Steps: []pipelineStep{{Step: "quality"}, {Step: "security"}}},
		Contract: stage2Contract(),
	}
	bad := stageCheck{
		Manifest: pipelineStage{Stage: "src/stage-4", Steps: nil},
		Contract: stageContract{Stage: "stage-4", Steps: []stageContractStep{{Step: "build", Required: true}}},
	}
	report, pass := verifyPipeline([]stageCheck{good, bad})
	if pass {
		t.Fatalf("expected a fail:\n%s", report)
	}
	if !strings.Contains(report, "stage: src/stage-2\n  [pass] quality\n") || !strings.Contains(report, "stage: src/stage-4\n  [fail] build — required step missing\n") {
		t.Errorf("report:\n%s", report)
	}
}

func TestVerifyPipeline_noStagesIsAVacuousPassThatSaysSo(t *testing.T) {
	report, pass := verifyPipeline(nil)
	if !pass || report != "result: PASS\n" {
		t.Errorf("pass=%v report=%q", pass, report)
	}
}

// Every contract this repository ships must parse under the rules above and
// declare an output schema the verifier accepts. make verify-contracts proves
// the signatures through Dagger; this proves the documents, and refuses an
// empty walk so a moved tree cannot pass by finding nothing.
func TestRepositoryContractsParse(t *testing.T) {
	var contracts, stageContracts []string
	err := filepath.WalkDir("../..", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "internal" || d.Name() == "node_modules" || d.Name() == ".git") {
			return filepath.SkipDir
		}
		switch d.Name() {
		case "contract.json":
			contracts = append(contracts, path)
		case "stage-contract.json":
			stageContracts = append(stageContracts, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(contracts)
	sort.Strings(stageContracts)
	if len(contracts) == 0 || len(stageContracts) == 0 {
		t.Fatalf("walk found %d contract.json and %d stage-contract.json files; the tree moved", len(contracts), len(stageContracts))
	}
	for _, path := range contracts {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		cs, err := parseModuleContracts(string(data))
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		for _, c := range cs {
			if !validOutputSchemas[c.OutputSchema] {
				t.Errorf("%s: %s declares outputSchema %q, which the verifier does not accept", path, c.Function, c.OutputSchema)
			}
			if c.Function == "" {
				t.Errorf("%s: a contract names no function", path)
			}
			for _, p := range c.Params {
				known := false
				for _, goType := range []string{"string", "[]string", "*dagger.Directory", "*dagger.File", "*dagger.Secret", "bool", "int", "float64", "*dagger.Container", "*dagger.Service"} {
					if typeCompatible(p.Type, goType) {
						known = true
					}
				}
				if !known {
					t.Errorf("%s: %s.%s declares type %q, which maps to no Go type", path, c.Function, p.Name, p.Type)
				}
			}
		}
	}
	for _, path := range stageContracts {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var sc stageContract
		if err := json.Unmarshal(data, &sc); err != nil {
			t.Errorf("%s: %v", path, err)
		}
		if sc.Stage == "" || len(sc.Steps) == 0 {
			t.Errorf("%s: stage %q with %d steps", path, sc.Stage, len(sc.Steps))
		}
	}
}
