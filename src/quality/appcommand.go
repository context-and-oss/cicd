//go:build !unit_test

package main

import (
	"context"
	"dagger/quality/internal/dagger"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Collect runs a caller-owned lint or SBOM command in the full checkout and
// returns evidence. Setup belongs in cmd. The named output is removed inside
// the execution container first, so committed or stale output cannot pass.
func (m *Quality) Collect(
	ctx context.Context,
	src *dagger.Directory,
	kind, label, language, cmd, reportPath, format string,
	sourcePaths []string,
	commitSha, branch, repoUrl string,
	// +optional
	toolchainImage string,
	// +default="HIGH"
	failOn string,
	// +optional
	npmFeedUrl string,
	// "registry" (default) or "npmrc"; see quality.Check.
	// +optional
	npmFeedRouting string,
	// +optional
	npmToken *dagger.Secret,
	// +optional
	nugetFeedUrl string,
	// +optional
	nugetToken *dagger.Secret,
	// +optional
	prepared *dagger.Container,
) (*dagger.File, error) {
	start := time.Now()
	if kind != "lint" && kind != "sbom" {
		return nil, fmt.Errorf("kind must be lint or sbom")
	}
	if language != "node" && language != "dotnet" {
		return nil, fmt.Errorf("language must be node or dotnet")
	}
	if !evidenceOutputPath(reportPath) || strings.TrimSpace(cmd) == "" || len(sourcePaths) == 0 {
		return nil, fmt.Errorf("cmd, literal reportPath and sourcePaths are required")
	}
	if err := validateNpmFeedRouting(npmFeedRouting, npmFeedUrl); err != nil {
		return nil, err
	}
	if err := validateFeedCredentials(npmFeedUrl, npmToken != nil, nugetFeedUrl, nugetToken != nil); err != nil {
		return nil, err
	}
	res, err := resolveTestToolchain(ctx, src, []languageType{languageType(language)}, toolchainImage)
	if err != nil {
		return nil, err
	}
	ctr := prepared
	if ctr == nil {
		ctr = commandBase(src, res.Image, repoUrl)
	}
	ctr = withNodeFeed(ctr, npmFeedUrl, npmFeedRouting, npmToken)
	if nugetFeedUrl != "" && nugetToken != nil {
		ctr = ctr.WithNewFile("/root/.nuget/NuGet/NuGet.Config", nugetCredentialedConfig(nugetSourceNameForFeed(ctx, src, nugetFeedUrl), nugetFeedUrl)).WithSecretVariable("NUGET_AUTH_TOKEN", nugetToken)
	}
	// Preserve nonzero command output in the execution log without changing the
	// captured verdict or publishing raw command output in the evidence bundle.
	ctr = ctr.WithExec([]string{"sh", "-c", `rm -f -- "$2" && { sh -c "$1" > /tmp/app-command.out 2>&1; code=$?; printf '%s' "$code" > /tmp/app-command.exit; if [ "$code" -ne 0 ]; then cat /tmp/app-command.out >&2; fi; }`, "app-command", cmd, "/src/" + reportPath})
	e := envelope{SchemaVersion: evidenceSchemaVersion, ModuleName: moduleName, Stage: moduleStage,
		Tool: toolInfo{Name: kind + "/" + label}, Repo: repoContext{RepoURL: repoUrl, CommitSHA: commitSha, Branch: branch},
		TimestampUTC: start.UTC(), FailOnSeverity: Severity(failOn), Concern: ConcernLint, Languages: []string{language}}
	if kind == "sbom" {
		e.Concern = ConcernSBOM
	}
	var raw string
	codeRaw, runErr := ctr.File("/tmp/app-command.exit").Contents(ctx)
	code, codeErr := strconv.Atoi(strings.TrimSpace(codeRaw))
	if runErr != nil || codeErr != nil {
		e.Errors = append(e.Errors, "command did not produce a valid execution result")
	} else {
		raw, err = ctr.File("/src/" + reportPath).Contents(ctx)
		if err != nil {
			e.Errors = append(e.Errors, "command did not produce its required output: "+reportPath)
		} else if kind == "lint" {
			var parseErr error
			e.SARIFReport, e.FindingsBySeverity, e.Warnings, parseErr = parseAppLint([]byte(raw), format, sourcePaths)
			if parseErr != nil {
				e.Errors = append(e.Errors, parseErr.Error())
			}
			for _, n := range e.FindingsBySeverity {
				e.FindingsCount += n
			}
			// ESLint and dotnet format use 1/2 respectively for findings. Other
			// exits, including setup failures without findings, are execution errors.
			findingsExit := 1
			if format == "dotnet-format" {
				findingsExit = 2
			}
			if code != 0 && (code != findingsExit || e.FindingsCount == 0) {
				e.Errors = append(e.Errors, fmt.Sprintf("lint command exited %d", code))
			}
		} else {
			n, validationErr := validateAppInventory([]byte(raw), language)
			if validationErr != nil {
				e.Errors = append(e.Errors, validationErr.Error())
			} else {
				e.CycloneDXReport = json.RawMessage(raw)
				e.Examined = &Examined{Unit: "inventory components", Count: n}
			}
			if code != 0 {
				e.Errors = append(e.Errors, fmt.Sprintf("inventory command exited %d", code))
			}
		}
	}
	e.DurationMS = time.Since(start).Milliseconds()
	e.Passed = gatedPassed(len(e.Errors) == 0, !shouldFail(e.FindingsBySeverity, Severity(failOn)), Severity(failOn))
	e.Outcome = OutcomeClean
	if e.FindingsCount > 0 {
		e.Outcome = OutcomeFindings
	}
	if len(e.Errors) > 0 {
		e.Outcome = OutcomeError
	}
	meta := map[string]any{"label": label, "toolchainImage": res.Image, "reportPath": reportPath, "sourcePaths": sourcePaths, "executionContext": "repository", "scopeAuthority": "caller-command"}
	if runErr == nil && codeErr == nil {
		meta["exitCode"] = code
	}
	e.GenericReport, err = json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	e.GenericFormat = "app-command"
	if res.Note != "" {
		e.Warnings = append(e.Warnings, res.Note)
	}
	e.Warnings = append(e.Warnings, "Command selection is caller-owned; tool version and complete command scope are not inferred.")
	data, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return dag.Directory().WithNewFile("evidence.json", string(data)).File("evidence.json"), nil
}

// Alias permits a CLI argument named language without shadowing the type.
type languageType = language
