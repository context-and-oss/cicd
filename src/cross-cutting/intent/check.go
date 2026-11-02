//go:build !unit_test

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"dagger/intent/internal/dagger"
)

// Intent is a format-agnostic gate that verifies a change was intentional and
// understood — not vibed in a second. It accepts any artifact (capsule YAML,
// spec markdown, bug.md, etc.) and applies three tiers of checks:
//  1. Presence  — the change is covered by an intent artifact.
//  2. Semantic  — deterministic rules: no placeholder text, no weasel words,
//     causal language required, minimum length, coupling to diff.
//  3. (future)  — LLM-based quality scoring (opt-in, not yet implemented).
//
// Scope: when a diff is supplied, the gate judges only the artifacts the change
// actually touches — a PR owns the intent of what it changes, not the repo's
// pre-existing artifact debt. With no diff (or an empty one) it falls back to
// auditing every discovered artifact.
type Intent struct{}

// Check validates that src contains at least one intent artifact proving the
// change was intentional and understood. Returns a JSON evidence envelope.
func (m *Intent) Check(
	ctx context.Context,
	// Repository source directory.
	src *dagger.Directory,
	// Output of `git diff <base>...HEAD` as a file. When provided, scopes the
	// gate to artifacts changed by this diff and enables refs-infer-coupling:
	// whole text for new/copied/renamed artifacts, newly introduced references
	// for artifacts edited in place. Other prose rules always read the whole
	// artifact. An empty diff falls back to a full-repo audit; a diff that is not a
	// git diff, or carries no b/ prefixes, is refused.
	// +optional
	diff *dagger.File,
	// Git commit SHA for evidence provenance.
	commitSha string,
	// Git branch name.
	branch string,
	// Repository URL.
	repoUrl string,
	// Minimum finding severity that fails the gate: error|warn|never.
	// +default="error"
	failOn string,
	// Glob patterns used to discover intent artifacts. Repeatable, optional.
	// Defaults: .capsules/*.yaml|yml, specs/*.md, docs/specs/*.md, *.intent.md,
	// .changes/*.md, changes/*.md.
	// +optional
	globs []string,
	// Asserts the diff originates from a pull request whose actor is exactly
	// dependabot[bot] and is limited to the approved GitHub Actions pin-bump
	// shape (specs/harden-workflow-supply-chain.md). The caller (the
	// reusable/dogfood precommit workflow) sets this only after checking the
	// PR actor itself — it is never inferred here and never trusted blindly:
	// the module independently re-validates every diff hunk before accepting
	// it as a substitute for a human intent artifact. Commit/push execution
	// (post-merge) must never set this — dependabot origin cannot be inferred
	// after merge.
	// +optional
	dependabotActionsPin bool,
	// Declares that this change is not required to carry a change-intent
	// artifact: the gate discovers nothing, reads no diff, applies no rule, and
	// returns an envelope that says so (`required: false` plus a warning). The
	// orchestrators set this whenever their opt-in `--require-intent` is absent;
	// a direct call gates normally, because a gate you asked for by name must
	// never be the one that quietly does nothing.
	//
	// The flag is negative on purpose, and inverting it would break the gate.
	// Dagger's generated Go client omits any optional argument holding its zero
	// value (`if !querybuilder.IsZeroValue(opts[i].NotRequired)`), so an optional
	// bool can only ever be transmitted as true. A positively-named "required"
	// parameter defaulting to on could therefore never be turned off by a
	// caller: the orchestrator would pass false, the client would drop it, and
	// the gate would run anyway. Keep the state that must reach the server —
	// "do not check" — as the non-zero one.
	//
	// Do not write a default pragma into this comment even as prose. Dagger's
	// parser reads pragmas anywhere in a parameter's doc block, so quoting one
	// as an example silently becomes that parameter's real default — measured:
	// it made notRequired default to on, which turns the gate off for every
	// direct caller.
	// +optional
	notRequired bool,
) (*dagger.File, error) {
	start := time.Now()

	if failOn == "" {
		failOn = "error"
	}

	if notRequired {
		env := buildNotRequiredEnvelope(commitSha, branch, repoUrl, failOn, time.Since(start))
		data, err := json.Marshal(env)
		if err != nil {
			return nil, fmt.Errorf("marshal evidence: %w", err)
		}
		return dag.Directory().WithNewFile("intent-evidence.json", string(data)).File("intent-evidence.json"), nil
	}
	if len(globs) == 0 {
		globs = defaultGlobs
	}

	var diffContent string
	if diff != nil {
		d, err := diff.Contents(ctx)
		if err != nil {
			return nil, fmt.Errorf("read diff: %w", err)
		}
		diffContent = d
	}

	artifacts, globErrs := findArtifacts(ctx, src, globs)

	// Scope to the artifacts this change touches. A non-empty diff means we know
	// the change set, so the gate judges only changed artifacts — and a change
	// that touches none of them fails presence ("no intent artifact for this
	// change"). An empty or absent diff carries no change set, so we audit every
	// discovered artifact instead (standalone calls, default-branch runs).
	changed, scopedToDiff, err := changeScope(diffContent)
	if err != nil {
		return nil, fmt.Errorf("read diff: %w", err)
	}
	scoped := artifacts
	if scopedToDiff {
		scoped = filterToChanged(artifacts, changed)
	}

	var findings []IntentFinding
	var machineOrigin *MachineOriginDecision

	if len(scoped) == 0 {
		if scopedToDiff && dependabotActionsPin {
			decision := validateMachineOriginDiff(diffContent)
			machineOrigin = &decision
		}
		if machineOrigin == nil || !machineOrigin.Accepted {
			var msg string
			if scopedToDiff {
				msg = "this change touches no intent artifact; every change must carry one (capsule, spec, *.intent.md, …) proving it was deliberate"
			} else {
				msg = fmt.Sprintf("no intent artifact found; searched: %s", strings.Join(globs, ", "))
				if len(globErrs) > 0 {
					msg += fmt.Sprintf(" (glob errors: %s)", strings.Join(globErrs, "; "))
				}
			}
			findings = append(findings, IntentFinding{
				Rule:     "presence",
				Severity: RuleSeverityError,
				Message:  msg,
			})
		}
	}

	modifiedCoupling := 0
	for _, a := range scoped {
		content, err := src.File(a).Contents(ctx)
		if err != nil {
			return nil, fmt.Errorf("read artifact %s: %w", a, err)
		}
		artifactFindings, narrowed, err := runArtifactRules(a, content, diffContent)
		if err != nil {
			return nil, fmt.Errorf("check artifact: %w", err)
		}
		findings = append(findings, artifactFindings...)
		if narrowed {
			modifiedCoupling++
		}
	}

	env := buildEnvelope(commitSha, branch, repoUrl, findings, failOn, time.Since(start))
	var searchErrs []string
	for _, e := range globErrs {
		searchErrs = append(searchErrs, "intent-gate: artifact search failed for "+e+", so an artifact it would have found was never judged")
	}
	markNonRun(env, searchErrs)
	if modifiedCoupling > 0 {
		env.Warnings = append(env.Warnings, couplingScopeWarning(modifiedCoupling))
	}

	// A clean pass produces no finding, so emit a note proving the gate actually
	// ran and was wired in — mirrors risk's "no risk files" warning and gives
	// downstream rendering (and the composite smoke) a positive signal for a
	// module that otherwise leaves no trace in the merged envelope when it passes.
	if len(findings) == 0 && len(searchErrs) == 0 && (machineOrigin == nil || !machineOrigin.Accepted) {
		env.Warnings = append(env.Warnings,
			fmt.Sprintf("intent-gate: %d artifact(s) checked, no violations", len(scoped)))
	}

	// Explicit positive evidence for the machine-origin path: it is NOT
	// represented as a human-authored artifact, so it gets its own distinct
	// warning rather than reusing the "artifact(s) checked" message above.
	if machineOrigin != nil && machineOrigin.Accepted {
		env.Warnings = append(env.Warnings,
			fmt.Sprintf("intent-gate: machine-origin accepted (dependabot[bot] github actions pin bump) — %s", machineOrigin.Reason))
	}

	data, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal evidence: %w", err)
	}

	return dag.Directory().WithNewFile("intent-evidence.json", string(data)).File("intent-evidence.json"), nil
}

// findArtifacts searches src for files matching any of the provided glob patterns.
// Returns matched paths and a slice of non-fatal error strings for diagnostic use.
func findArtifacts(ctx context.Context, src *dagger.Directory, globs []string) ([]string, []string) {
	seen := make(map[string]bool)
	var found []string
	var errs []string
	for _, pattern := range globs {
		matches, err := src.Glob(ctx, pattern)
		if err != nil {
			// Most common cause: subdirectory does not exist. Surface in presence
			// message rather than silently dropping so callers can distinguish
			// "no artifacts" from "glob failed unexpectedly".
			errs = append(errs, fmt.Sprintf("%s: %v", pattern, err))
			continue
		}
		for _, m := range matches {
			if !seen[m] {
				seen[m] = true
				found = append(found, m)
			}
		}
	}
	return found, errs
}
