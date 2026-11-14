//go:build !unit_test

package main

import (
	"context"
	"dagger/security/internal/dagger"
	"encoding/json"
	"errors"
	"strings"
)

// runSemgrep executes semgrep with SARIF output and returns raw SARIF, severity
// counts, how many files semgrep looked at, which rules it applied, and any
// non-fatal disclosure. A non-nil error means semgrep did not scan what was
// asked — never that it found nothing. Callers surface that in the envelope's
// errors[], which fails the gate; the previous implementation swallowed it into
// an empty report that read as zero findings.
//
// A scan below its rule floor, or one whose inline pass failed after the
// ordinary pass completed, returns its usable result alongside the error.
// Its findings are kept; the error prevents a partial scan from passing.
func runSemgrep(ctx context.Context, src *dagger.Directory, rulesets string) (semgrepScan, error) {
	packs, err := loadSemgrepPacks()
	if err != nil {
		return semgrepScan{}, err
	}
	plan, err := semgrepPlanFor(rulesets, packs)
	if err != nil {
		return semgrepScan{}, err
	}

	var pinned *dagger.Directory
	if len(plan.Pinned) > 0 {
		// Fetched by commit, not by branch or tag, so the bytes cannot move.
		// Synced here so a fetch failure is named as one rather than surfacing
		// as an opaque error from the scan container's first read.
		pinned, err = fetchSemgrepRules(ctx)
		if err != nil {
			return semgrepScan{}, err
		}
	}

	var warnings []string
	if w := semgrepLiveWarning(plan.Live); w != "" {
		warnings = append(warnings, w)
	}

	scan, err := runSemgrepOnce(ctx, src, plan.Args, pinned, plan)
	if err != nil {
		return scan, err
	}
	if semgrepNeedsGHACurlPipeFallback(scan.SARIF) {
		// The upstream rule asks Semgrep to parse each whole run scalar as
		// Bash. Ordinary GitHub expressions, command substitutions and
		// multiline prose make both OSS 1.161.0 and 1.162.0 reject that
		// metavariable. Exclude only that rule and rerun with the runtime-adapted
		// YAML+regex equivalent, which keeps the security check without
		// pretending the affected files were fully evaluated on the first
		// pass. No pinned pack carries the upstream rule, so only a live
		// pack can bring it here. See semgreprules.go.
		plan.Args = semgrepGHAFallbackArgs(plan.Args)
		scan, err = runSemgrepOnce(ctx, src, plan.Args, pinned, plan)
		if err != nil {
			return scan, errors.New("opengrep: gha-curl-pipe-shell compatibility rerun failed: " + err.Error())
		}
		warnings = append([]string{semgrepGHAFallbackWarning}, warnings...)
	}
	scan.Warnings = append(scan.Warnings, warnings...)

	scan.Rules, err = semgrepRuleSet(scan.SARIF, plan)
	return scan, err
}

func fetchSemgrepRules(ctx context.Context) (*dagger.Directory, error) {
	tree, err := dag.Git(semgrepRulesRepo).
		Commit(semgrepRulesCommit).
		Tree(dagger.GitRefTreeOpts{DiscardGitDir: true}).
		Sync(ctx)
	if err != nil {
		return nil, errors.New("opengrep: could not fetch pinned rule source semgrep-rules@" +
			semgrepRulesCommit[:12] + " from " + semgrepRulesRepo + ": " + err.Error())
	}
	return tree, nil
}

// runSemgrepOnce is one materialised invocation. Keeping the whole read and
// classification path here means the fallback is held to exactly the same
// non-run rules as the ordinary scan; a failed second pass can never inherit
// the first pass's exit-zero report and read as complete.
//
// pinned is nil unless the plan includes a pinned pack. When it is set, the
// tree and the plan's staging lists are mounted for the script to copy from;
// see semgrepScript.
func runSemgrepOnce(ctx context.Context, src *dagger.Directory, args []string, pinned *dagger.Directory, plan semgrepPlan) (semgrepScan, error) {
	if pinned == nil && semgrepUsesGHAFallback(args) {
		// Live/custom scans fetch no pinned source unless the measured rule
		// actually needs a compatibility rerun. Never stage a fallback from
		// unversioned registry content or silently omit it after fetch failure.
		var err error
		pinned, err = fetchSemgrepRules(ctx)
		if err != nil {
			return semgrepScan{}, err
		}
	}
	base := dag.Container().From(pythonImage)
	platform, err := base.Platform(ctx)
	if err != nil {
		return semgrepScan{}, errors.New("opengrep: could not read the engine platform to pick the pinned binary: " + err.Error())
	}
	assets, err := opengrepAssetsFor(string(platform))
	if err != nil {
		return semgrepScan{}, err
	}
	ctr := base.
		WithoutEntrypoint().
		// Both fetched by URL and checked against their pinned sha256 by
		// opengrepVerifyScript before either is used; see opengrep.go.
		WithFile(opengrepBinPath, dag.HTTP(assets.BinURL, dagger.HTTPOpts{Name: "opengrep"}), dagger.ContainerWithFileOpts{Permissions: 0o755}).
		WithFile(assets.WheelPath(), dag.HTTP(assets.WheelURL, dagger.HTTPOpts{Name: assets.WheelName}), dagger.ContainerWithFileOpts{Permissions: 0o644}).
		WithEnvVariable(opengrepSHA256Env, assets.BinSHA256).
		WithEnvVariable(pyyamlSHA256Env, assets.WheelSHA256).
		WithEnvVariable(pyyamlWheelEnv, assets.WheelPath()).
		WithNewFile(semgrepGHAAdapterPath, semgrepGHAAdapter).
		WithNewFile(semgrepMetadataPath, semgrepMetadataScript).
		WithNewFile(semgrepDOMRulePath, semgrepDOMRule).
		WithNewFile(semgrepInlineWarnings, "[]")
	if plan.Inline {
		ctr = ctr.
			WithNewFile(semgrepInlinePath, semgrepInlineScript).
			WithNewFile(semgrepInlinePlanPath, semgrepInlinePlan(plan))
	}
	if pinned != nil {
		ctr = ctr.
			WithMountedDirectory(semgrepPackSrc, pinned).
			WithNewFile(semgrepPackFiles, semgrepPackStaging(plan.Files)).
			WithNewFile(semgrepPackTops, strings.Join(plan.Tops, "\n")+"\n")
	}
	ran := ctr.
		WithMountedDirectory("/src", withoutGitMetadata(src)).
		WithWorkdir("/src").
		WithExec(append([]string{"sh", "-c", semgrepScript, "sh"}, args...))

	code, err := ran.File("/tmp/semgrep.exit").Contents(ctx)
	if err != nil {
		return semgrepScan{}, err
	}
	// Before anything else is read: an engine that did not match its pin is
	// the most important thing this scan has to say.
	verify, err := ran.File(opengrepVerifyPath).Contents(ctx)
	if err != nil {
		return semgrepScan{}, errors.New(readbackError("opengrep", opengrepVerifyPath, err))
	}
	if msg := opengrepVerifyError(verify, assets); msg != "" {
		return semgrepScan{}, errors.New(msg)
	}
	// Read before the exit is classified: a staging failure writes exit 2 and
	// no report, and the generic "did not run (exit 2)" would hide that the
	// rule set, not the tool, is what failed.
	packErr, err := ran.File(semgrepPackErrPath).Contents(ctx)
	if err != nil {
		return semgrepScan{}, errors.New(readbackError("opengrep", semgrepPackErrPath, err))
	}
	if line := lastNonEmptyLine(packErr); line != "" {
		return semgrepScan{}, errors.New("opengrep: could not stage rules from semgrep-rules@" +
			semgrepRulesCommit[:12] + ", so it did not scan: " + line)
	}
	// The script creates the file before semgrep runs, so a read that fails
	// is cicd's; semgrepRunError must not classify the exit against an empty
	// stderr it would read as "the tool said nothing".
	stderr, err := ran.File("/tmp/semgrep.err").Contents(ctx)
	if err != nil {
		return semgrepScan{}, errors.New(readbackError("opengrep", "/tmp/semgrep.err", err))
	}
	report, err := ran.File("/tmp/report.sarif").Contents(ctx)
	if err != nil {
		return semgrepScan{}, err
	}

	runFailure := semgrepRunError(code, stderr, report)

	// The count is read, not the list. semgrep's JSON names every file it
	// scanned. Its length is taken in the container, where the optional
	// metadata adapter also reads the native JSON. Only the count and the
	// allowlisted SARIF projection cross the boundary, never the selected-file
	// list or the native report's matched-source payload.
	//
	// Its absence is not an error. A scan whose SARIF is good and whose
	// accounting could not be read is still a scan; the honest report of that
	// is an unstated denominator, and failing the gate over it would turn a
	// reporting gap into an outage.
	scanned, _ := ran.File("/tmp/semgrep.scanned").Contents(ctx)

	// Before anything reads the report, so that no copy of the matched
	// source — the counts, the rule set, the envelope — ever exists past this
	// line. See semgrepredact.go.
	sarifRaw, err := redactSemgrepSARIF(json.RawMessage(report))
	if err != nil {
		if runFailure != "" {
			return semgrepScan{}, errors.New(runFailure)
		}
		return semgrepScan{}, err
	}
	scan := semgrepScan{
		SARIF:      sarifRaw,
		BySeverity: parseSarifSeverities(sarifRaw),
		Examined:   semgrepExamined(scanned),
	}
	if runFailure != "" {
		// An inline non-run fails the gate, but never discards findings from
		// the ordinary scan that completed before it.
		return scan, errors.New(runFailure)
	}
	notes, err := ran.File(semgrepInlineWarnings).Contents(ctx)
	if err != nil {
		return scan, errors.New(readbackError("opengrep", semgrepInlineWarnings, err))
	}
	if err := json.Unmarshal([]byte(notes), &scan.Warnings); err != nil {
		return scan, errors.New("opengrep: could not read inline scan disclosures")
	}
	return scan, nil
}

// withoutGitMetadata drops the tree's .git, whichever shape it has (a
// directory in a clone, a "gitdir:" pointer file in a worktree or submodule).
// Opengrep lists a git project's files with `git ls-files`, and its base image
// carries no git, so any checkout with a .git was a scan that did not run.
// Without it Opengrep walks the tree itself. See specs/swap-semgrep-for-opengrep.md.
func withoutGitMetadata(src *dagger.Directory) *dagger.Directory {
	return src.WithoutDirectory(".git").WithoutFile(".git")
}
