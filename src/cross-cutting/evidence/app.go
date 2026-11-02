package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"time"
)

const appDependencyDeferralWarning = "Dependencies: NOT ASSESSED — SBOM generation, dependency vulnerability scanning and dependency licence assessment are intentionally disabled in the monorepo workflow pending reliable per-application dependency scoping. A passing run covers only the enabled checks."

// Deferred work is a deliberate, non-gating skip, never a clean measurement.
// Refuse incoming inventory data rather than silently discarding it.
func deferredAppDependencies(envs []*envelope, repo repoContext, now time.Time) (*envelope, error) {
	if repo.AppID == "" {
		return nil, fmt.Errorf("omitting SBOM requires application identity")
	}
	for _, e := range envs {
		if len(e.CycloneDXReport) > 0 {
			return nil, fmt.Errorf("cannot omit SBOM when a producer supplied inventory evidence")
		}
	}
	e := &envelope{SchemaVersion: evidenceSchemaVersion, ModuleName: moduleName, Stage: "commit",
		Tool: toolInfo{Name: "deferred-dependencies"}, Repo: repo, TimestampUTC: now.UTC(),
		Passed: true, Outcome: OutcomeSkipped, FailOnSeverity: SeverityNone,
		Warnings:      []string{appDependencyDeferralWarning},
		GenericFormat: "assessment-status", GenericReport: json.RawMessage(`{"sbomGenerated":false,"dependencyAssessment":"not-assessed","reason":"monorepo-support-deferred"}`)}
	for _, concern := range []Concern{ConcernSBOM, ConcernSCA, ConcernLicenses} {
		e.Sources = append(e.Sources, SourceStatus{ModuleName: moduleName, Stage: "commit", Tool: "deferred-dependencies",
			Scope: "application-dependencies", Concern: concern, Passed: true, Outcome: OutcomeSkipped, WarningsCount: 1})
	}
	return e, nil
}

// Enrich only provenance. Preserve unknown producer fields and native payloads.
// Repository-mode parts continue to be stored byte-for-byte without this step.
func stampApp(raw string, repo repoContext) (string, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		return "", err
	}
	var existing repoContext
	if err := json.Unmarshal(fields["repo"], &existing); err != nil {
		return "", err
	}
	if existing.RepoURL != repo.RepoURL || existing.CommitSHA != repo.CommitSHA || existing.Branch != repo.Branch {
		return "", fmt.Errorf("app evidence provenance differs from the requested checkout")
	}
	if existing.AppID != "" && (existing.AppID != repo.AppID || !reflect.DeepEqual(existing.SourcePaths, repo.SourcePaths)) {
		return "", fmt.Errorf("cannot combine evidence from different applications or scopes")
	}
	existing.AppID, existing.SourcePaths = repo.AppID, repo.SourcePaths
	data, err := json.Marshal(existing)
	if err != nil {
		return "", err
	}
	fields["repo"] = data
	data, err = json.Marshal(fields)
	return string(data), err
}

func appSARIF(doc sarifDocument, id string) (sarifDocument, error) {
	for i, raw := range doc.Runs {
		var run map[string]json.RawMessage
		if err := json.Unmarshal(raw, &run); err != nil {
			return doc, err
		}
		if run == nil {
			return doc, fmt.Errorf("SARIF run is null")
		}
		automation := map[string]any{}
		if len(run["automationDetails"]) > 0 {
			if err := json.Unmarshal(run["automationDetails"], &automation); err != nil {
				return doc, err
			}
		}
		if automation == nil {
			automation = map[string]any{}
		}
		previous, _ := automation["id"].(string)
		automation["id"] = "app/" + id + "/" + previous
		b, err := json.Marshal(automation)
		if err != nil {
			return doc, err
		}
		run["automationDetails"] = b
		b, err = json.Marshal(run)
		if err != nil {
			return doc, err
		}
		doc.Runs[i] = b
	}
	return doc, nil
}
