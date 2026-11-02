package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Explicit selection prevents sharing a .NET compilation with an unrelated
// Node leg or silently accepting a different toolchain for tests and packaging.
func validatePreparation(cmd, lang, image, label, testCmd, testLegs string) error {
	if cmd == "" {
		if lang != "" || label != "" {
			return fmt.Errorf("prepare-language and prepare-test-label require prepare-cmd")
		}
		return nil
	}
	if strings.TrimSpace(cmd) == "" || strings.TrimSpace(image) == "" || (lang != "node" && lang != "dotnet") {
		return fmt.Errorf("prepare-cmd requires an explicit toolchain-image and prepare-language node or dotnet")
	}
	if testCmd != "" && testLegs == "" {
		if label != "" && label != "test-cmd" {
			return fmt.Errorf("prepare-test-label must be test-cmd with test-cmd")
		}
		return nil
	}
	if testCmd != "" || testLegs == "" || label == "" {
		return fmt.Errorf("preparation requires test-cmd or test-legs with an explicit prepare-test-label")
	}
	var legs []struct{ Label, Language, ToolchainImage string }
	if err := json.Unmarshal([]byte(testLegs), &legs); err != nil {
		return fmt.Errorf("test-legs: %w", err)
	}
	matches := 0
	for _, leg := range legs {
		if leg.Label != label {
			continue
		}
		matches++
		if leg.Language != lang || (leg.ToolchainImage != "" && leg.ToolchainImage != image) {
			return fmt.Errorf("prepared test leg must use prepare-language and the preparation toolchain-image")
		}
	}
	if matches != 1 {
		return fmt.Errorf("prepare-test-label must name exactly one declared test leg")
	}
	return nil
}
