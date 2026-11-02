//go:build !unit_test

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"dagger/risk/internal/dagger"
)

// execStderr recovers the container's stderr from a failed WithExec.
//
// Without it the envelope reads "exit code: 1" and nothing else — measured, and
// useless: the actual cause (`exec: "conftest": executable file not found`, a rego
// compile error, an unreadable policy mount) is only in stderr. Dagger wraps it in
// *dagger.ExecError; anything else returns "" and conftestFailureMessage simply
// omits the clause.
func execStderr(err error) string {
	var execErr *dagger.ExecError
	if errors.As(err, &execErr) {
		return execErr.Stderr
	}
	return ""
}

// loadPolicyDir reads a module-relative policy directory, excluding *_test.rego
// files so conftest does not try to evaluate them as policy.
func loadPolicyDir(modulePath string) *dagger.Directory {
	src := dag.CurrentModule().Source().Directory(modulePath)
	return dag.Directory().WithDirectory(".", src, dagger.DirectoryWithDirectoryOpts{
		Exclude: []string{"*_test.rego"},
	})
}

// Validate runs OPA policy checks: findings+decisions review enforcement and
// infra file scanning (Dockerfile, ARM JSON, pipeline YAML).
// Returns an evidence envelope. Missing risk files: passes with a warning.
//
// Scope: infraScope decides. "changed" judges only the files the supplied diff
// touches — a pull request owns the infra it changes, not the repository's
// pre-existing artifact debt (mirrors the intent gate) — and falls back to the
// whole tree when there is no change set to narrow by (standalone calls,
// default-branch runs). "tree" judges every parseable file in the checkout and
// ignores the diff, which is what the commit stage asks for: on a push that has
// already merged there is no author left to hold responsible for one file, and a
// scan scoped to that push reads a file on the commit that edits it and never
// again.
//
// Either way the envelope states both numbers — how many files were examined and
// how many the scanner could have read — because a zero is unreadable without
// its denominator.
func (m *Risk) Validate(
	ctx context.Context,
	// Source directory to validate.
	source *dagger.Directory,
	// Minimum severity that fails the pipeline: CRITICAL|HIGH|MEDIUM|LOW|NONE
	// +default="HIGH"
	failOn string,
	// Git commit SHA for evidence provenance.
	commitSha string,
	// Git branch name for evidence provenance.
	branch string,
	// Repository URL for evidence provenance.
	repoUrl string,
	// Output of `git diff <base>...HEAD` as a file. Supplies the change set that
	// infraScope "changed" narrows by. Ignored when infraScope is "tree".
	// +optional
	diff *dagger.File,
	// Which infrastructure files to evaluate: "changed" (only those in --diff)
	// or "tree" (every parseable file in the checkout).
	// +default="changed"
	// +optional
	infraScope string,
) (*dagger.File, error) {
	start := time.Now()
	threshold := Severity(failOn)
	if !ValidSeverity(threshold) {
		return nil, fmt.Errorf("invalid failOn severity %q: must be CRITICAL, HIGH, MEDIUM, LOW, or NONE", failOn)
	}
	repo := RepoContext{RepoURL: repoUrl, CommitSHA: commitSha, Branch: branch}

	// The caller names the scope; the diff only supplies the change set it
	// narrows by. An unrecognised scope is refused before anything runs, so no
	// envelope is written that could be misread as a result — the same reason
	// quality.resolveIncludeNames is a hard error.
	wantChangeScope, err := resolveInfraScope(infraScope)
	if err != nil {
		return nil, err
	}
	// An empty/absent diff under "changed" means we don't know the change set
	// (standalone call, default-branch run), so we scan the whole repo. Parsed
	// up front so a read failure surfaces before the scan.
	//
	// A diff that cannot be read is refused (diffChangeScope).
	var changedPaths map[string]bool
	scopedToDiff := false
	if wantChangeScope && diff != nil {
		diffContent, err := diff.Contents(ctx)
		if err != nil {
			return nil, fmt.Errorf("read diff: %w", err)
		}
		if changedPaths, scopedToDiff, err = diffChangeScope(diffContent); err != nil {
			return nil, fmt.Errorf("read diff: %w", err)
		}
	}

	fold := newValidateFold()
	decisions := map[string]Decision{}

	findingsPath, decisionsPath, err := findRiskFiles(ctx, source)
	if errors.Is(err, errNoRiskFiles) {
		fold.warnings = append(fold.warnings, "no risk files found — run 'dagger -m github.com/context-and-oss/cicd/src/risk call scan' to initialise")
	} else if err != nil {
		return nil, err
	} else {
		// Pass 1: findings+decisions OPA gate (only when risk files exist).
		findingsJSON, err := source.File(findingsPath).Contents(ctx)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", findingsPath, err)
		}
		decisionsJSON, err := source.File(decisionsPath).Contents(ctx)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", decisionsPath, err)
		}
		in, err := parseRiskInputs(findingsJSON, decisionsJSON)
		if err != nil {
			return nil, err
		}
		decisions = in.decisions
		fold.findingsReviewed = len(in.findings.Findings)

		policyDir := loadPolicyDir("policy/findings")
		inputFile := dag.Directory().WithNewFile("input.json", string(in.merged)).File("input.json")
		findingsOut, err := dag.Container().
			From(conftestImage).
			WithMountedDirectory("/policy", policyDir).
			WithMountedFile("/input.json", inputFile).
			WithExec([]string{"conftest", "test", "--policy", "/policy",
				"--all-namespaces", "--no-fail", "--output", "json", "/input.json"}).
			Stdout(ctx)
		if err != nil {
			return nil, fmt.Errorf("conftest findings: %w", err)
		}
		fold.addFindingsPass(findingsOut)
	}

	// Pass 2: infra file scanning — always runs regardless of whether risk files exist.
	infraPolicyDir := loadPolicyDir("policy/infra")
	fileListRaw, err := dag.Container().
		From(alpineImage).
		WithMountedDirectory("/src", source).
		WithExec([]string{"sh", "-c",
			`find /src -type f ! -path '*/.git/*' ! -path '*/node_modules/*' ! -path '*/vendor/*' ! -path '*/out/*' | sed 's|^/src/||'`,
		}).Stdout(ctx)
	if err != nil {
		return nil, fmt.Errorf("list infra files: %w", err)
	}

	// Classification happens before scoping, so the count of files this scanner
	// could have read survives even when the scope excludes all of them. See
	// planInfraScan — it is untagged, like the fold in validatereport.go.
	infraScan := planInfraScan(
		strings.Split(strings.TrimSpace(fileListRaw), "\n"), changedPaths, scopedToDiff)
	fold.warnings = append(fold.warnings, infraPlanWarnings(infraScan)...)

	for _, group := range infraScan.Groups {
		execArgs, mounts := conftestGroupPlan(group)
		ctr := dag.Container().
			From(conftestImage).
			WithMountedDirectory("/policy", infraPolicyDir)
		for _, m := range mounts {
			ctr = ctr.WithMountedFile(m.Mount, source.File(m.Rel))
		}
		out, err := ctr.WithExec(execArgs).Stdout(ctx)
		if err != nil {
			// This was the false pass. A conftest that could not start became a
			// synthetic HIGH *violation*: the evidence reported a policy failure no
			// policy had produced, findingsCount was inflated by an event that is not
			// a finding, and — because the verdict was `!shouldFail(...)` alone —
			// `--fail-on NONE` suppressed it and the gate reported clean on a policy
			// engine that never ran. Pass 1 above, the same tool in the same function,
			// returns a hard Go error for the identical failure; it stays that way
			// because it fails before there is anything to put in an envelope, while
			// here the group loop can still emit evidence saying exactly what broke.
			fold.nonRun(conftestFailureMessage(group.Parser, group.Namespace, err.Error(), execStderr(err)))
			continue
		}
		fold.addInfraGroup(out, group, mounts, decisions, start.UTC())
	}

	env, err := buildValidateEnvelope(fold, infraScan, repo, threshold, start)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal evidence: %w", err)
	}
	return dag.Directory().WithNewFile("evidence.json", string(data)).File("evidence.json"), nil
}

// findRiskFiles searches the source tree for findings.json and decisions.json,
// then delegates classification/validation to classifyRiskFilePaths.
func findRiskFiles(ctx context.Context, source *dagger.Directory) (findingsPath, decisionsPath string, err error) {
	out, err := dag.Container().
		From(alpineImage).
		WithMountedDirectory("/src", source).
		WithExec([]string{"sh", "-c",
			`find /src -type f \( -name "findings.json" -o -name "decisions.json" \) ` +
				`! -path '*/.git/*' ! -path '*/node_modules/*' ! -path '*/vendor/*' ` +
				`| sed 's|^/src/||' | sort`,
		}).Stdout(ctx)
	if err != nil {
		return "", "", fmt.Errorf("search for risk files: %w", err)
	}
	return classifyRiskFilePaths(strings.Split(strings.TrimSpace(out), "\n"))
}
