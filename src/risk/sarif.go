package main

import (
	"encoding/json"
	"sort"
	"strings"
)

const (
	riskToolName    = "risk-validate"
	riskToolVersion = "conftest:" + conftestVersion
	riskReviewRule  = "RISK-REVIEW"
)

type riskSARIFDocument struct {
	Version string         `json:"version"`
	Schema  string         `json:"$schema"`
	Runs    []riskSARIFRun `json:"runs"`
}

type riskSARIFRun struct {
	Tool        riskSARIFTool         `json:"tool"`
	Invocations []riskSARIFInvocation `json:"invocations"`
	Results     []riskSARIFResult     `json:"results"`
}

type riskSARIFTool struct {
	Driver riskSARIFDriver `json:"driver"`
}

type riskSARIFDriver struct {
	Name    string          `json:"name"`
	Version string          `json:"version"`
	Rules   []riskSARIFRule `json:"rules"`
}

type riskSARIFRule struct {
	ID                   string                        `json:"id"`
	Name                 string                        `json:"name"`
	DefaultConfiguration riskSARIFDefaultConfiguration `json:"defaultConfiguration"`
	Properties           riskSARIFProperties           `json:"properties"`
}

type riskSARIFDefaultConfiguration struct {
	Level string `json:"level"`
}

type riskSARIFProperties struct {
	// SARIF has only error/warning/note, so its standard level cannot preserve
	// the distinction between CRITICAL and HIGH. The bundle aggregator reads
	// this property back to keep its canonical severity detail aligned with the
	// envelope's FindingsBySeverity counts; generic SARIF consumers ignore it.
	CICDSeverity string `json:"cicdSeverity"`
}

type riskSARIFInvocation struct {
	ExecutionSuccessful        bool                    `json:"executionSuccessful"`
	ToolExecutionNotifications []riskSARIFNotification `json:"toolExecutionNotifications,omitempty"`
}

type riskSARIFNotification struct {
	Level   string           `json:"level"`
	Message riskSARIFMessage `json:"message"`
}

type riskSARIFResult struct {
	RuleID     string              `json:"ruleId"`
	Level      string              `json:"level"`
	Message    riskSARIFMessage    `json:"message"`
	Locations  []riskSARIFLocation `json:"locations,omitempty"`
	Properties riskSARIFProperties `json:"properties"`
}

type riskSARIFMessage struct {
	Text string `json:"text"`
}

type riskSARIFLocation struct {
	PhysicalLocation riskSARIFPhysicalLocation `json:"physicalLocation"`
}

type riskSARIFPhysicalLocation struct {
	ArtifactLocation riskSARIFArtifactLocation `json:"artifactLocation"`
}

type riskSARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// buildRiskSARIF turns the same post-override violations that drive the gate
// into the standard report channel consumed by findings.sarif and GitHub Code
// Scanning. A run is emitted even when it is clean: [] means the policy engine
// ran and found nothing, while invocations.executionSuccessful=false records a
// non-run without inventing a policy finding.
func buildRiskSARIF(violations []reportViol, ran bool, runErrors []string) (json.RawMessage, error) {
	results := make([]riskSARIFResult, 0, len(violations))
	rulesByID := make(map[string]riskSARIFRule)

	for _, violation := range violations {
		severity := string(normalizeSeverity(violation.Severity))
		ruleID := strings.TrimSpace(violation.PolicyID)
		if ruleID == "" {
			ruleID = riskReviewRule
		}
		level := riskSeverityToSARIFLevel(severity)
		properties := riskSARIFProperties{CICDSeverity: severity}

		result := riskSARIFResult{
			RuleID:     ruleID,
			Level:      level,
			Message:    riskSARIFMessage{Text: riskViolationMessage(violation.Msg)},
			Properties: properties,
		}
		if file := strings.TrimSpace(violation.File); file != "" {
			result.Locations = []riskSARIFLocation{{
				PhysicalLocation: riskSARIFPhysicalLocation{
					ArtifactLocation: riskSARIFArtifactLocation{URI: file},
				},
			}}
		}
		results = append(results, result)

		if _, exists := rulesByID[ruleID]; !exists {
			rulesByID[ruleID] = riskSARIFRule{
				ID:                   ruleID,
				Name:                 ruleID,
				DefaultConfiguration: riskSARIFDefaultConfiguration{Level: level},
				Properties:           properties,
			}
		}
	}

	ruleIDs := make([]string, 0, len(rulesByID))
	for id := range rulesByID {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	rules := make([]riskSARIFRule, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		rules = append(rules, rulesByID[id])
	}

	invocation := riskSARIFInvocation{ExecutionSuccessful: ran}
	if !ran {
		invocation.ToolExecutionNotifications = make([]riskSARIFNotification, 0, len(runErrors))
		for _, runError := range runErrors {
			if message := strings.TrimSpace(runError); message != "" {
				invocation.ToolExecutionNotifications = append(invocation.ToolExecutionNotifications, riskSARIFNotification{
					Level:   "error",
					Message: riskSARIFMessage{Text: message},
				})
			}
		}
	}

	doc := riskSARIFDocument{
		Version: "2.1.0",
		Schema:  "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
		Runs: []riskSARIFRun{{
			Tool: riskSARIFTool{Driver: riskSARIFDriver{
				Name: riskToolName, Version: riskToolVersion, Rules: rules,
			}},
			Invocations: []riskSARIFInvocation{invocation},
			Results:     results,
		}},
	}
	return json.Marshal(doc)
}

func riskSeverityToSARIFLevel(severity string) string {
	switch normalizeSeverity(severity) {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	case SeverityLow:
		return "note"
	default:
		return "error"
	}
}

func riskViolationMessage(message string) string {
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(message), "-"))
}
