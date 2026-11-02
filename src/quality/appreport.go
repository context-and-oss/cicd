package main

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"
)

func appTestStatuses(label string, ran, passed, coverageDeclared, coverageMeasured bool) []SourceStatus {
	testRow := SourceStatus{ModuleName: moduleName, Stage: moduleStage, Tool: label, Scope: "application-tests", Concern: ConcernTests, Passed: ran && passed, Outcome: runOutcome(ran, passed)}
	if !testRow.Passed {
		testRow.ErrorsCount = 1
	}
	coverageRow := SourceStatus{ModuleName: moduleName, Stage: moduleStage, Tool: label, Scope: "application-tests", Concern: ConcernCoverage, Passed: true, Outcome: OutcomeSkipped}
	if coverageDeclared {
		coverageRow.Passed = coverageMeasured
		coverageRow.Outcome = OutcomeClean
		if !coverageMeasured {
			coverageRow.Outcome = OutcomeError
			coverageRow.ErrorsCount = 1
		}
	}
	return []SourceStatus{testRow, coverageRow}
}

func evidenceOutputPath(p string) bool {
	return p != "" && p != "." && p != ".." && !path.IsAbs(p) && path.Clean(p) == p &&
		!strings.HasPrefix(p, "../") && !strings.ContainsAny(p, "\\\x00\r\n*?[]") && p != ".git" && !strings.HasPrefix(p, ".git/")
}

func appReportPath(file string, scope []string) (string, error) {
	file = strings.TrimPrefix(file, "/src/")
	if !evidenceOutputPath(file) {
		return "", fmt.Errorf("report has an invalid source location %q", file)
	}
	for _, p := range scope {
		if file == p || strings.HasPrefix(file, p+"/") {
			return file, nil
		}
	}
	return "", fmt.Errorf("report includes %q outside declared application source paths", file)
}

// Validate before the existing native parsers: JSON null and [{}] must not
// turn into an empty lint verdict merely because Go can decode them.
func parseAppLint(raw []byte, format string, scope []string) (json.RawMessage, map[Severity]int, []string, error) {
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rows); err != nil || rows == nil {
		return nil, nil, nil, fmt.Errorf("lint output must be a JSON array")
	}
	switch format {
	case "eslint":
		if len(rows) == 0 {
			return nil, nil, nil, fmt.Errorf("ESLint examined no files")
		}
		var results []eslintResult
		if err := json.Unmarshal(raw, &results); err != nil {
			return nil, nil, nil, err
		}
		for i := range results {
			if rows[i]["messages"] == nil || string(rows[i]["messages"]) == "null" {
				return nil, nil, nil, fmt.Errorf("ESLint entry lacks messages")
			}
			p, err := appReportPath(results[i].FilePath, scope)
			if err != nil {
				return nil, nil, nil, err
			}
			results[i].FilePath = p
		}
		data, err := json.Marshal(results)
		if err != nil {
			return nil, nil, nil, err
		}
		sarif, counts := parseEslintJSON(data, "unknown")
		return sarif, counts, nil, nil
	case "dotnet-format":
		var changes []dotnetFormatChange
		if err := json.Unmarshal(raw, &changes); err != nil {
			return nil, nil, nil, err
		}
		for i, c := range changes {
			if rows[i]["FileChanges"] == nil || string(rows[i]["FileChanges"]) == "null" {
				return nil, nil, nil, fmt.Errorf("dotnet format entry lacks FileChanges")
			}
			p, err := appReportPath(c.FilePath, scope)
			if err != nil {
				return nil, nil, nil, err
			}
			changes[i].FilePath = "/src/" + p
		}
		data, err := json.Marshal(changes)
		if err != nil {
			return nil, nil, nil, err
		}
		sarif, counts, warnings := parseDotnetFormatReport(data, "unknown", "/src")
		return sarif, counts, warnings, nil
	default:
		return nil, nil, nil, fmt.Errorf("unsupported native lint format %q", format)
	}
}

func validateAppInventory(raw []byte, lang string) (int, error) {
	var doc struct {
		BomFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Metadata    struct {
			Component struct {
				Name string `json:"name"`
			} `json:"component"`
		} `json:"metadata"`
		Components []struct {
			Name string `json:"name"`
			PURL string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return 0, err
	}
	if doc.BomFormat != "CycloneDX" || doc.SpecVersion == "" || doc.Metadata.Component.Name == "" || doc.Components == nil {
		return 0, fmt.Errorf("inventory requires CycloneDX JSON with specVersion, metadata.component.name and an explicit components array")
	}
	prefix := "pkg:npm/"
	if lang == "dotnet" {
		prefix = "pkg:nuget/"
	}
	for _, c := range doc.Components {
		if c.Name == "" || !strings.HasPrefix(c.PURL, prefix) {
			return 0, fmt.Errorf("inventory component %q needs a %s package URL", c.Name, prefix)
		}
	}
	return len(doc.Components), nil
}
