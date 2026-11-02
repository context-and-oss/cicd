package main

import (
	"encoding/json"
	"strings"
	"time"
)

const (
	moduleName  = "intent"
	moduleStage = "cross-cutting"
	toolVersion = "1.0.0"
)

// defaultGlobs are the artifact patterns searched when the caller supplies none.
var defaultGlobs = []string{
	".capsules/*.yaml",
	".capsules/*.yml",
	// Top-level only: nested specs/<feature>/ trees are plan-feature decomposition
	// docs (briefs, design notes), not per-change intent artifacts — scanning them
	// with prose rules would resurrect the pre-existing-debt problem this scoping
	// fixes. A nested doc that IS an intent artifact can use the *.intent.md glob.
	"specs/*.md",
	"docs/specs/*.md",
	"*.intent.md",
	".changes/*.md",
	"changes/*.md",
}

// filterToChanged returns the artifacts whose path is in the changed set.
// Both sides are repo-root-relative, so paths compare directly.
func filterToChanged(artifacts []string, changed map[string]bool) []string {
	var out []string
	for _, a := range artifacts {
		if changed[a] {
			out = append(out, a)
		}
	}
	return out
}

// buildEnvelope constructs the standard evidence envelope from a set of findings.
func buildEnvelope(commitSha, branch, repoUrl string, findings []IntentFinding, failOn string, duration time.Duration) *envelope {
	threshold := parseFailOn(failOn)

	bySeverity := make(map[Severity]int)
	for _, f := range findings {
		bySeverity[mapRuleSeverity(f.Severity)]++
	}

	genericPayload, _ := json.Marshal(map[string]any{
		"tool":     "intent-gate",
		"version":  toolVersion,
		"required": true,
		"findings": findings,
	})

	return &envelope{
		SchemaVersion: evidenceSchemaVersion,
		ModuleName:    moduleName,
		Stage:         moduleStage,
		Tool: toolInfo{
			Name:    "intent-gate",
			Version: toolVersion,
			Args:    []string{"check"},
		},
		Repo: repoContext{
			RepoURL:   repoUrl,
			CommitSHA: commitSha,
			Branch:    branch,
		},
		TimestampUTC: time.Now().UTC(),
		DurationMS:   duration.Milliseconds(),
		Passed:       !shouldFail(bySeverity, threshold),
		// CLEAN or FINDINGS here; markNonRun turns it into ERROR when the
		// artifact search could not complete, which is the one failure that
		// still has an envelope to report into.
		Outcome:            scanOutcome(true, len(findings)),
		FailOnSeverity:     threshold,
		FindingsCount:      len(findings),
		FindingsBySeverity: bySeverity,
		GenericReport:      json.RawMessage(genericPayload),
		GenericFormat:      "intent-gate",
	}
}

// markNonRun records that the check did not see everything it was asked to
// judge. A glob that errored may have hidden the very artifact the change
// carries, so the findings the envelope holds are a verdict on part of the
// tree, and passed is false at every --fail-on, never included.
func markNonRun(env *envelope, errs []string) {
	if len(errs) == 0 {
		return
	}
	env.Errors = append(env.Errors, errs...)
	env.Passed = false
	env.Outcome = OutcomeError
}

// notRequiredWarning is the record a gate that was never consulted leaves
// behind. The gate is opt-in, and an opt-in gate that is off produces exactly
// what a gate that passed produces: no findings. So "off" is stated, in the one
// place a reviewer reads (the PR comment renders warnings verbatim), rather
// than inferred from an absence. Upgrading to the release that made the gate
// opt-in turns it off for every consumer who had it on; this line is how they
// find out.
const notRequiredWarning = "intent-gate: NOT REQUIRED — change intent was not checked for this change (opt in with --require-intent)"

// buildNotRequiredEnvelope records that the gate was not consulted at all: no
// artifact discovery, no diff read, no rules. It still emits an envelope so the
// module stays in the audit trail with an explicit `required: false` for
// machines and notRequiredWarning for humans — an absent envelope would leave
// the audit unable to distinguish "no intent artifact was required here" from
// "intent was checked and clean".
func buildNotRequiredEnvelope(commitSha, branch, repoUrl, failOn string, duration time.Duration) *envelope {
	env := buildEnvelope(commitSha, branch, repoUrl, nil, failOn, duration)
	genericPayload, _ := json.Marshal(map[string]any{
		"tool":     "intent-gate",
		"version":  toolVersion,
		"required": false,
		"findings": []IntentFinding{},
	})
	env.GenericReport = json.RawMessage(genericPayload)
	env.Warnings = append(env.Warnings, notRequiredWarning)
	// SKIPPED, overriding the CLEAN buildEnvelope just computed from zero
	// findings. This function's own doc comment names the distinction it
	// exists to preserve — "no intent artifact was required here" versus
	// "intent was checked and clean" — and the outcome field is where a
	// machine reads it. `required: false` in the payload says the same thing
	// to anything that knows this module's format; this says it to everything
	// that does not.
	env.Outcome = OutcomeSkipped
	return env
}

func mapRuleSeverity(s string) Severity {
	switch s {
	case RuleSeverityError:
		return SeverityHigh
	case RuleSeverityWarn:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

func parseFailOn(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	// Intent gate's native vocabulary.
	case "error":
		return SeverityHigh
	case "warn":
		return SeverityMedium
	case "never":
		return SeverityNone
	// Standard workflow severity vocabulary (NONE|LOW|MEDIUM|HIGH|CRITICAL),
	// shared with quality/security/risk so `fail-on` threads through uniformly.
	case "none":
		return SeverityNone
	case "low":
		return SeverityLow
	case "medium":
		return SeverityMedium
	case "high", "critical":
		return SeverityHigh
	}
	// Unrecognized or empty: gate at HIGH so a typo never silently passes.
	return SeverityHigh
}
