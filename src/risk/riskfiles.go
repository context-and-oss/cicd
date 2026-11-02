package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// errNoRiskFiles is returned by classifyRiskFilePaths (and surfaced by findRiskFiles)
// when neither findings.json nor decisions.json can be found.
// Validate treats this as a pass-with-warning rather than an error.
var errNoRiskFiles = errors.New("no risk files found")

// classifyRiskFilePaths takes a list of repository-relative file paths (as
// returned by `find … | sed 's|^/src/||'`) and locates the unique findings.json
// and decisions.json pair.
//
// Rules:
//   - Both files must exist (exactly one each).
//   - Both files must be in the same directory (so they unambiguously belong
//     together and cannot be mixed from different scan runs).
//
// Returns errNoRiskFiles when either file is absent.
func classifyRiskFilePaths(paths []string) (findingsPath, decisionsPath string, err error) {
	var allFindings, allDecisions []string
	for _, line := range paths {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch filepath.Base(line) {
		case "findings.json":
			allFindings = append(allFindings, line)
		case "decisions.json":
			allDecisions = append(allDecisions, line)
		}
	}

	if len(allFindings) == 0 || len(allDecisions) == 0 {
		return "", "", errNoRiskFiles
	}
	if len(allFindings) > 1 {
		return "", "", fmt.Errorf("multiple findings.json found: %v — move risk files to one directory or point --source at that directory", allFindings)
	}
	if len(allDecisions) > 1 {
		return "", "", fmt.Errorf("multiple decisions.json found: %v — move risk files to one directory or point --source at that directory", allDecisions)
	}

	fDir := filepath.Dir(allFindings[0])
	dDir := filepath.Dir(allDecisions[0])
	if fDir != dDir {
		return "", "", fmt.Errorf(
			"findings.json (%s) and decisions.json (%s) are in different directories — they must be co-located",
			allFindings[0], allDecisions[0],
		)
	}

	return allFindings[0], allDecisions[0], nil
}
