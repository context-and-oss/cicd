package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

type reportViol struct {
	Msg      string `json:"msg"`
	Severity string `json:"severity"`
	PolicyID string `json:"policyId,omitempty"`
	File     string `json:"file,omitempty"`
	Resource string `json:"resource,omitempty"`
}

type overriddenPolicyViolation struct {
	Msg           string `json:"msg"`
	Severity      string `json:"severity"`
	PolicyID      string `json:"policyId"`
	File          string `json:"file"`
	Resource      string `json:"resource"`
	DecisionKey   string `json:"decisionKey"`
	Justification string `json:"justification"`
	ReviewedBy    string `json:"reviewedBy"`
	ReviewedAt    string `json:"reviewedAt"`
	ExpiresAt     string `json:"expiresAt,omitempty"`
}

type policyOverrideReport = overriddenPolicyViolation

func applyPolicyDecisions(violations []ParsedViolation, decisions map[string]Decision, now time.Time) ([]ParsedViolation, []policyOverrideReport) {
	remaining := make([]ParsedViolation, 0, len(violations))
	var overridden []policyOverrideReport
	for _, violation := range violations {
		if report, ok := acceptedPolicyOverride(violation, violation.Filename, decisions, now); ok {
			overridden = append(overridden, report)
			continue
		}
		remaining = append(remaining, violation)
	}
	return remaining, overridden
}

func policyDecisionKey(policyID, filePath, resource string) string {
	return fmt.Sprintf("policy:%s:%s:%s",
		strings.TrimSpace(policyID),
		normalizePolicyPath(filePath),
		strings.TrimSpace(resource),
	)
}

func normalizePolicyPath(path string) string {
	path = filepath.ToSlash(strings.TrimSpace(path))
	path = strings.TrimPrefix(path, "./")
	return path
}

func repoPathForConftestFilename(filename string, mountedInputs map[string]string) string {
	if rel, ok := mountedInputs[filename]; ok {
		return normalizePolicyPath(rel)
	}
	clean := filepath.ToSlash(filepath.Clean(filename))
	if rel, ok := mountedInputs[clean]; ok {
		return normalizePolicyPath(rel)
	}
	if strings.HasPrefix(clean, "/src/") {
		return normalizePolicyPath(strings.TrimPrefix(clean, "/src/"))
	}
	return normalizePolicyPath(filename)
}

func resolveConftestFilename(filename string, mountedInputs map[string]string) string {
	return repoPathForConftestFilename(filename, mountedInputs)
}

func acceptedPolicyOverride(v ParsedViolation, filePath string, decisions map[string]Decision, now time.Time) (overriddenPolicyViolation, bool) {
	policyID := strings.TrimSpace(v.PolicyID)
	resource := strings.TrimSpace(v.Resource)
	filePath = normalizePolicyPath(filePath)
	if policyID == "" || filePath == "" || resource == "" {
		return overriddenPolicyViolation{}, false
	}
	key := policyDecisionKey(policyID, filePath, resource)
	decision, ok := decisions[key]
	if !ok || !acceptedPolicyDecision(decision, now) {
		return overriddenPolicyViolation{}, false
	}
	return overriddenPolicyViolation{
		Msg:           v.Msg,
		Severity:      string(normalizeSeverity(v.Severity)),
		PolicyID:      policyID,
		File:          filePath,
		Resource:      resource,
		DecisionKey:   key,
		Justification: strings.TrimSpace(decision.Justification),
		ReviewedBy:    strings.TrimSpace(decision.ReviewedBy),
		ReviewedAt:    strings.TrimSpace(decision.ReviewedAt),
		ExpiresAt:     strings.TrimSpace(decision.ExpiresAt),
	}, true
}

func acceptedPolicyDecision(decision Decision, now time.Time) bool {
	if strings.TrimSpace(decision.Status) != "accepted_risk" {
		return false
	}
	if strings.TrimSpace(decision.Justification) == "" ||
		strings.TrimSpace(decision.ReviewedBy) == "" ||
		strings.TrimSpace(decision.ReviewedAt) == "" {
		return false
	}
	if _, _, ok := parsePolicyDecisionTime(decision.ReviewedAt); !ok {
		return false
	}
	expiresAt := strings.TrimSpace(decision.ExpiresAt)
	if expiresAt == "" {
		return true
	}
	expires, dateOnly, ok := parsePolicyDecisionTime(expiresAt)
	if !ok {
		return false
	}
	if dateOnly {
		expires = expires.AddDate(0, 0, 1)
	}
	return now.UTC().Before(expires.UTC())
}

func parsePolicyDecisionTime(value string) (time.Time, bool, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false, false
	}
	if t, err := time.Parse("2006-01-02", value); err == nil {
		return t, true, true
	}
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t, false, true
	}
	return time.Time{}, false, false
}
