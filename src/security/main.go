//go:build !unit_test

package main

import (
	"context"
	"dagger/security/internal/dagger"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Security is the Dagger module for the scanners: SAST and secrets over the
// source tree (ScanSource), vulnerabilities in a built image (ScanImage) or a
// built archive (ScanArchive), licence policy over the dependency graph
// (ScanLicenses), a frozen SBOM against today's database (ScanSbom), and DAST
// against a running application (ScanWeb). Every
// entry returns an evidence envelope in which a scanner that did not run is an
// errors[] entry, never a clean result.
type Security struct{}

// ScanSource runs SAST (Semgrep), secrets detection (Gitleaks), and filesystem
// vulnerability scan (Trivy) on source code. Returns an aggregated evidence envelope.
func (m *Security) ScanSource(
	ctx context.Context,
	// Source directory to scan.
	src *dagger.Directory,
	// Subdirectory within src to scan. Empty string scans the entire src.
	// +optional
	path string,
	// Directory names to exclude (e.g. "vendor", "node_modules").
	// Relative to path if set, otherwise relative to src root.
	// +optional
	exclude []string,
	// Comma-separated SAST rulesets in Semgrep rule syntax, run by Opengrep:
	// registry packs (e.g. "p/security-audit,p/owasp-top-ten") or a config path
	// in the scanned tree (e.g. "./semgrep.yml"). "auto" is rejected — the
	// registry's answer is not a rule set the engine can load, nor one the
	// evidence could name. Never pass empty. p/security-audit is read
	// from a pinned semgrep-rules commit and must load every rule it declares;
	// any other registry pack is fetched live and reported as unpinned.
	// +default="p/security-audit"
	sastRulesets string,
	// Minimum severity that fails the pipeline: CRITICAL|HIGH|MEDIUM|LOW|NONE
	// +default="HIGH"
	failOn string,
	// Git commit SHA for evidence provenance.
	commitSha string,
	// Git branch name for evidence provenance.
	branch string,
	// Repository URL for evidence provenance.
	repoUrl string,
	// Private NuGet feed index URL, used only by the lockfile-free dependency
	// graph fallback: a .NET tree that commits no packages.lock.json is restored
	// in a pinned SDK so there is a graph to scan, and a restore that cannot
	// reach the consumer's feed cannot produce one.
	// +optional
	nugetFeedUrl string,
	// Token for nugetFeedUrl. Handed to NuGet as a secret and never written to
	// the evidence envelope.
	// +optional
	nugetToken *dagger.Secret,
	// Scan source code only. Dependency checks must be supplied separately from
	// app-specific inventories by the orchestrator; no filesystem SCA runs.
	// +optional
	codeOnly bool,
	// Vulnerability findings to accept, ONE PER LINE, each as "<id>=<reason>"
	// — e.g. "CVE-2026-81871=the exporter only reaches the Dagger engine's own
	// telemetry endpoint on the runner". An accepted identifier is removed from
	// the severity counts, from findings[] and from the gate, and is disclosed
	// in warnings[] with the reason given; the row stays in the CycloneDX
	// report, so the vulnerability is still in the evidence. A reason is
	// mandatory, patterns are refused, and an acceptance matching nothing warns
	// so a stale one is visible rather than a standing permission. The
	// separator is a newline and never a comma, because a reason is prose that
	// contains commas — see splitVulnAcceptances in vulnallow.go for what the
	// CLI does to a []string here.
	// +optional
	vulnAccept string,
) (*dagger.File, error) {
	start := time.Now()
	threshold := Severity(failOn)
	repo := repoContext{RepoURL: repoUrl, CommitSHA: commitSha, Branch: branch}

	// Before any container is built. A token handed to a cleartext endpoint is
	// a readable secret on the wire, and NuGet does not refuse on the consumer's
	// behalf — it answers the 401 challenge with Basic auth over whatever
	// transport it was given. Failing here rather than dropping the credential is
	// deliberate: a dropped credential is a silent 401, which reaches the
	// consumer as "restore failed" and names neither the feed nor the token.
	if nugetToken != nil {
		if err := feedTransportOK("nuget-feed-url", nugetFeedUrl, schemeRequired); err != nil {
			return nil, err
		}
	}

	// Parsed before any container is built. A malformed acceptance is a
	// narrowing the caller asked for and did not get, and this one fails toward
	// red — which sounds safe until the remedy a consumer reaches for is
	// --fail-on NONE. Same rule as resolveIncludeNames: no envelope, so nothing
	// can be misread as a result.
	accepted, err := newVulnAccepter(vulnAccept)
	if err != nil {
		return nil, err
	}

	filtered, err := applyPathFilter(src, path, exclude)
	if err != nil {
		return nil, err
	}

	sast, err1 := runSemgrep(ctx, filtered, sastRulesets)
	// The second SAST engine, for C# and Visual Basic: the SDK's security
	// analyzers, run inside a build. Present only when the tree has a .NET
	// project. Runs on a code-only scan too — it is SAST, not dependency
	// assessment. See roslyn.go.
	roslyn := runRoslyn(ctx, filtered, nugetFeedUrl, nugetToken)
	// The third, for GitHub Actions: zizmor over every workflow, composite
	// action and Dependabot file. Present only when the tree has one. See
	// zizmor.go.
	zizmor := runZizmor(ctx, filtered)
	sarifSecrets, findingsSecrets, secretsScan, err2 := runGitleaks(ctx, filtered)
	var vuln trivyResult
	var err3, err4 error
	var inventory toolResult
	if !codeOnly {
		vuln, err3 = runTrivyFS(ctx, filtered, nugetFeedUrl, nugetToken, accepted)
		// The same scan's second answer: the inventory it resolved, which the
		// bundle publishes as sbom.cdx.json. See inventory.go.
		inventory, err4 = inventoryResult(err3, vuln)
	}

	// Semgrep names the files its parser rejected and the rules that timed out
	// in the SARIF it already handed over (invocations[].toolExecutionNotifications),
	// and exits 0 either way. Read from the same document the envelope carries,
	// so the warning and the report cannot describe two different scans. See
	// semgrepnotifications.go.
	sastWarnings := append(sast.Warnings, semgrepNotificationWarnings(sast.SARIF)...)
	// The same notifications, as a number on the row: how many of the files
	// semgrep examined it named as read only in part. The warning says what
	// happened; this is what lets a report mark the row without parsing prose.
	// Only when semgrep stated its denominator — a partial count with no Count
	// beside it would be a share of nothing.
	if sast.Examined != nil {
		sast.Examined.Partial = parseSemgrepNotifications(sast.SARIF).partialFiles()
	}
	if warning := sarifSuppressionWarning("opengrep", sast.SARIF); warning != "" {
		sastWarnings = append(sastWarnings, warning)
	}

	var errs []string
	for _, e := range []error{err1, roslyn.Err, zizmor.Err, err2, err3, err4} {
		if e != nil {
			errs = append(errs, e.Error())
		}
	}

	combined := mergeSeverity(sast.BySeverity, roslyn.BySeverity, zizmor.BySeverity, bySeverityFromFindings(findingsSecrets), vuln.BySeverity)
	total := 0
	for _, c := range combined {
		total += c
	}
	ran := len(errs) == 0
	severityOK := !shouldFail(combined, threshold)

	// The three verdicts behind the single Passed below, plus the inventory
	// row. Declared by the module rather than synthesised by the aggregator,
	// because only the module can still see the split — by the time the
	// envelope is written the counts have been merged. See perToolSources.
	//
	// The dependency rows are left out, not sliced off, when the scan did not
	// run: a code-only scan has nothing to say about dependencies, and a row
	// saying ERROR about a scan nobody asked for would be the wrong sentence.
	tools := []toolResult{
		// Opengrep's warnings are its partial-scan disclosure: files it
		// could not parse, rules that timed out. Counted on this row so a
		// reader of the row alone sees that FINDINGS here is a floor —
		// Examined beside it says what that floor was measured over, and
		// Rules which rules it was measured with.
		{
			Name:       "opengrep",
			BySeverity: sast.BySeverity,
			Examined:   sast.Examined,
			Rules:      sast.Rules,
			Err:        err1,
			Warnings:   len(sastWarnings),
			Concern:    ConcernSAST,
		},
	}
	if roslyn.Present {
		// Its warnings are its own partial-scan disclosure: projects it could
		// not build or reach, compiles with errors, rules the repository
		// switched off. Examined counts C#/VB projects, buildable or not.
		tools = append(tools, toolResult{
			Name:       roslynToolName,
			BySeverity: roslyn.BySeverity,
			Examined:   roslyn.Examined,
			Rules:      roslyn.Rules,
			Err:        roslyn.Err,
			Warnings:   len(roslyn.Warnings),
			Skipped:    roslyn.Skipped,
			Concern:    ConcernSAST,
		})
	}
	if zizmor.Present {
		// Its warnings name the files it could not parse, the online audits
		// an offline run cannot perform, and the findings an ignore comment
		// or the repository's configuration removed.
		tools = append(tools, toolResult{
			Name:       zizmorToolName,
			BySeverity: zizmor.BySeverity,
			Examined:   zizmor.Examined,
			Rules:      zizmor.Rules,
			Err:        zizmor.Err,
			Warnings:   len(zizmor.Warnings),
			Concern:    ConcernSAST,
		})
	}
	tools = append(tools,
		// Gitleaks' warnings name the archives it did not open; Examined is
		// the bytes its tree leg read. See gitleaksarchives.go.
		toolResult{
			Name:       "gitleaks",
			BySeverity: bySeverityFromFindings(findingsSecrets),
			Examined:   secretsScan.Examined,
			Err:        err2,
			Warnings:   len(secretsScan.Warnings),
			Concern:    ConcernSecrets,
		},
	)
	if !codeOnly {
		tools = append(tools,
			// Each tool's warnings are counted on its own row and
			// concatenated below, in row order.
			toolResult{
				Name:       "trivy",
				BySeverity: vuln.BySeverity,
				Examined:   vuln.Examined,
				Err:        err3,
				Warnings:   len(vuln.Warnings),
				Skipped:    vuln.Skipped,
				Concern:    ConcernSCA,
			},
			inventory,
		)
	}

	env := &envelope{
		SchemaVersion:      evidenceSchemaVersion,
		ModuleName:         moduleName,
		Stage:              moduleStage,
		Tool:               toolInfo{Name: scopeSource},
		Repo:               repo,
		TimestampUTC:       start.UTC(),
		DurationMS:         time.Since(start).Milliseconds(),
		Passed:             gatedPassed(ran, severityOK, threshold),
		FailOnSeverity:     threshold,
		FindingsCount:      total,
		FindingsBySeverity: combined,
		// The three verdicts behind the single Passed above. Declared by the
		// module rather than synthesised by the aggregator, because only the
		// module can still see the split — by the time the envelope is written
		// the counts have been merged. See perToolSources.
		Sources: perToolSources(scopeSource, threshold, tools...),
		// Secrets are counted HIGH by bySeverityFromFindings; stamp the same
		// level into gitleaks' own SARIF so the detail rows agree with the counts.
		// Roslyn's and zizmor's runs are already graded by cicd's own table
		// (roslyn.go, zizmor.go).
		SARIFReport:     mergeSARIF(sast.SARIF, roslyn.SARIF, zizmor.SARIF, stampSARIFLevel(sarifSecrets, "error")),
		CycloneDXReport: vuln.CycloneDX,
		// Only the vulnerability detail is carried explicitly. Lint, SAST and
		// secrets detail is expressible in SARIF and the aggregator reads it from
		// there; CycloneDX cannot express the severity Trivy resolved, so deriving
		// vulnerability rows downstream would put a HIGH row under a CRITICAL
		// count. See trivyreport.go.
		Findings: vuln.Findings,
		Warnings: concatWarnings(sastWarnings, roslyn.Warnings, zizmor.Warnings, secretsScan.Warnings, vuln.Warnings, vuln.InventoryWarnings),
		Errors:   errs,
	}
	// The envelope reports what its tools found, folded from the rows above.
	// Derived from the rows that actually ship rather than recomputed from the
	// same inputs, so the two cannot disagree.
	if codeOnly {
		env.Warnings = append(env.Warnings, "Source-code scan of the declared checkout files only, without Git history. Dependency assessment is not part of this scan; consult the separate dependency assessment status.")
	}
	env.Outcome = sourcesOutcome(env.Sources)

	data, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal evidence: %w", err)
	}
	return writeEvidenceFile(data)
}

// ScanLicenses runs a Trivy license scan over the source tree and judges every
// license it finds against an allowlist of Trivy license categories. Returns an
// evidence envelope.
//
// A separate step from ScanSource rather than a fourth leg inside it, and the
// separation is semantic before it is structural. A license finding is a
// compliance judgement, not a vulnerability: it has no CVE, no fix version and
// no vendor severity, and folding it into ScanSource's merged counts would let a
// copyleft dependency consume the budget of a `--fail-on HIGH` gate that exists
// to stop exploitable code shipping. The two verdicts answer different questions
// and belong on different envelopes. licenseflags.go carries the parallel
// argument for keeping the Trivy invocations apart.
//
// Warn mode lowers the EFFECTIVE threshold to NONE rather than post-processing
// the verdict, which is what keeps the envelope internally consistent: the row
// verdict, FailOnSeverity and Passed all describe one threshold, and no reader
// has to reconcile a HIGH finding with a passing gate. It reuses the NONE
// semantics gatedPassed already defines, which means warn mode inherits the
// property that matters most — a scan that could not RUN still fails. Per that
// function's reasoning, "do not fail me over findings" never meant "do not tell
// me the scanner was skipped", and an advisory license policy is no more
// entitled to hide a broken scanner than `--fail-on NONE` is.
func (m *Security) ScanLicenses(
	ctx context.Context,
	// Source directory to scan.
	src *dagger.Directory,
	// Subdirectory within src to scan. Empty string scans the entire src.
	// +optional
	path string,
	// Directory names to exclude (e.g. "vendor", "node_modules").
	// Relative to path if set, otherwise relative to src root.
	// +optional
	exclude []string,
	// Glob patterns whose license declarations are reported but not judged
	// against the policy, e.g. "docs/**" or "**/node_modules/**". Matched
	// against each declaration's file path, relative to the scanned root.
	// Every exclusion is counted and every pattern is recorded in the
	// evidence — see licenseexclude.go.
	// +optional
	licenseExclude []string,
	// Whether license findings fail the gate: "gate" or "warn". There is
	// deliberately no "off" — see licensereport.go.
	// +default="warn"
	licenseGate string,
	// Trivy license categories that are permitted. Empty uses cicd's default
	// policy (permissive, notice, unencumbered); anything outside the allowlist
	// is a finding, including a category nothing recognises.
	// +optional
	licenseAllow []string,
	// Read licenses from source headers and LICENSE files as well as from
	// package metadata. On by default because metadata-only mode never reads
	// the tree's own LICENSE, which in an ecosystem whose manifests carry no
	// license field — Go among them — can be all there is to read. It does not
	// read dependency licences: those come from installed package metadata, and
	// a graph with none read is SKIPPED (licencecoverage.go).
	// +default=true
	licenseFull bool,
	// Minimum severity that fails the pipeline: CRITICAL|HIGH|MEDIUM|LOW|NONE.
	// Ignored when licenseGate is "warn".
	// +default="HIGH"
	failOn string,
	// Git commit SHA for evidence provenance.
	commitSha string,
	// Git branch name for evidence provenance.
	branch string,
	// Repository URL for evidence provenance.
	repoUrl string,
	// Optional generated application inventory. Scanned instead of filesystem
	// dependencies, using the same Trivy scanner and licence policy.
	// +optional
	sbom *dagger.File,
	// Only source-file declarations; dependency licence assessment is outside
	// this scan. Always enables source-file collection. Incompatible with sbom.
	// +optional
	sourceOnly bool,
	// Private NuGet feed index URL. A NuGet package's licence is read from its
	// .nuspec, which only a restore puts on disk, so every .NET tree is
	// restored for this scan — lockfile or not — and a restore that cannot
	// reach the consumer's feed reads no licence for what it could not fetch.
	// +optional
	nugetFeedUrl string,
	// Token for nugetFeedUrl. Handed to NuGet as a secret and never written to
	// the evidence envelope.
	// +optional
	nugetToken *dagger.Secret,
) (*dagger.File, error) {
	start := time.Now()
	repo := repoContext{RepoURL: repoUrl, CommitSHA: commitSha, Branch: branch}

	// Same rule, and the same reason, as ScanSource: a token handed to a
	// cleartext endpoint is a readable secret on the wire.
	if nugetToken != nil {
		if err := feedTransportOK("nuget-feed-url", nugetFeedUrl, schemeRequired); err != nil {
			return nil, err
		}
	}

	// Both config errors are raised before any container is built. A
	// misspelled gate mode or license category is a mistake in the pipeline
	// definition, and reporting it as a failed scan would send the author
	// looking at their dependencies instead of at their arguments.
	if err := validateLicenseGate(licenseGate); err != nil {
		return nil, err
	}
	pol, allower, err := resolveLicenseAllowlist(licenseAllow)
	if err != nil {
		return nil, err
	}
	// Same reason as the two above: a malformed exclude pattern is a mistake in
	// the pipeline definition, and its silent form — a pattern that matches
	// nothing — is indistinguishable from a tree with nothing to exclude.
	excluder, err := newLicenseExcluder(licenseExclude)
	if err != nil {
		return nil, err
	}
	pol.Mode = licenseGate
	pol.Full = licenseFull || sourceOnly
	if sbom != nil {
		pol.Full = false
	}
	pol.FailOn = failOn

	threshold := Severity(failOn)
	if licenseGate == licenseGateWarn {
		threshold = SeverityNone
	}

	filtered, err := applyPathFilter(src, path, exclude)
	if err != nil {
		return nil, err
	}

	var errs []string
	var res licenseResult
	if sbom != nil && sourceOnly {
		return nil, fmt.Errorf("sbom and source-only are mutually exclusive")
	}
	var raw json.RawMessage
	var scanErr error
	// prep is what had to happen before Trivy could read every licence: the
	// dependency probe and, for a .NET tree, the restore. A failure there is
	// the row's error even when Trivy itself ran, because the licences it read
	// are then a subset nobody can see the edge of.
	var prep []string
	// restoredOut is the .NET restore that completed, kept until Trivy has run so
	// its warning can say how much of the restored graph was read.
	var restoredOut *dotnetRestoreOutcome
	// goOut is the Go module download that completed, kept for the same reason.
	var goOut *goDownloadOutcome
	var dependencyInputs []string
	// dotnetSolutions are the solution files of a tree with no project, which
	// neither restore nor error and are named in a warning instead.
	var dotnetSolutions []string
	mode := licenceScanTree
	switch {
	case sbom != nil:
		mode = licenceScanSBOM
		raw, scanErr = runTrivyLicenseSbom(ctx, sbom)
	case sourceOnly:
		mode = licenceScanSourceOnly
		raw, scanErr = runTrivyLicense(ctx, filtered, pol.Full, nil, nil)
		if scanErr == nil {
			raw, scanErr = sourceLicenseReport(raw)
		}
	default:
		scanSrc := filtered
		var nuspecs, gopath *dagger.Directory
		files, probeErr := probeDependencyInputs(ctx, filtered)
		if probeErr != nil {
			prep = append(prep, "security license scan: could not tell whether this tree holds "+
				".NET projects whose NuGet licences need a restore, or Go modules whose licences "+
				"need a download, so whether every dependency licence was read is unknown: "+
				probeErr.Error())
		} else {
			dependencyInputs = dependencyDeclarations(trivyConfigDir, files)
			dotnetSolutions = dotnetSolutionsWithoutProjects(trivyConfigDir, files)
			if len(dotnetLicenceRestoreNeeded(trivyConfigDir, files)) > 0 {
				restored, snapshot, out, err := restoreDotnetGraph(ctx, filtered, nugetFeedUrl, nugetToken)
				switch {
				case err != nil:
					prep = append(prep, "security license scan: the .NET restore the NuGet "+
						"licences are read from did not complete, so no NuGet licence was read: "+
						err.Error())
				default:
					// Scanned even when some project failed, as the dependency
					// scan does: the licences of the projects that restored are
					// real. The error is what stops that reading as complete.
					scanSrc, nuspecs = restored, snapshot
					if msg := dotnetLicenceRestoreError(out); msg != "" {
						prep = append(prep, msg)
					} else {
						restoredOut = &out
					}
				}
			}
			// A go.mod --license-exclude covers is one whose modules the
			// coverage line already leaves out, so it is not downloaded.
			var gomods []string
			for _, gm := range goLicenceDownloadNeeded(trivyConfigDir, files) {
				if !excluder.covers(gm) {
					gomods = append(gomods, gm)
				}
			}
			if len(gomods) > 0 {
				snapshot, out, err := downloadGoModules(ctx, filtered, gomods)
				if err != nil {
					prep = append(prep, err.Error())
				} else {
					// Scanned even when some module did not download, for the
					// .NET reason: the licences of the modules that did are
					// real, and the warning names the rest.
					gopath = snapshot
					prep = append(prep, out.Plan.Errors...)
					prep = append(prep, out.Errors...)
					goOut = &out
				}
			}
		}
		raw, scanErr = runTrivyLicense(ctx, scanSrc, pol.Full, nuspecs, gopath)
	}
	errs = append(errs, prep...)
	var evalErr error
	if scanErr != nil {
		errs = append(errs, scanErr.Error())
	} else {
		res, evalErr = evaluateLicenses(raw, pol, excluder, allower)
		if evalErr != nil {
			// An unparseable report is a run failure, not an empty policy. Left
			// in errs so ran=false, which fails at every threshold including the
			// NONE that warn mode selects.
			errs = append(errs, evalErr.Error())
		}
	}
	licenseErr := licenseScanErr(scanErr, evalErr)
	if licenseErr == nil && len(prep) > 0 {
		licenseErr = errors.New(strings.Join(prep, "; "))
	}

	total := 0
	for _, c := range res.BySeverity {
		total += c
	}
	ran := len(errs) == 0
	severityOK := !shouldFail(res.BySeverity, threshold)

	var warnings []string
	if len(dotnetSolutions) > 0 {
		warnings = append(warnings, dotnetSolutionsWithoutProjectsWarning("Dependency licences", dotnetSolutions))
	}
	if restoredOut != nil {
		var cov *licenceCoverage
		if scanErr == nil && evalErr == nil {
			cov = &res.Coverage
		}
		warnings = append(warnings, dotnetLicenceRestoreWarning(*restoredOut, cov, excluder))
	}
	if goOut != nil {
		var cov *licenceCoverage
		if scanErr == nil && evalErr == nil {
			cov = &res.Coverage
		}
		if w := goLicenceDownloadWarning(*goOut, cov); w != "" {
			warnings = append(warnings, w)
		}
	}
	if sourceOnly {
		warnings = append(warnings, "Source-file licence declarations only; this scan does not assess dependency licences.")
	}
	if sbom != nil {
		warnings = append(warnings, "Dependency licences are limited to declarations present in the supplied SBOM; absent licence metadata is not proof of licence compliance.")
	}
	if ran {
		// The policy is stated on every run, pass or fail, and as a warning
		// rather than only inside genericReport — buildCombined in
		// cross-cutting/evidence drops the generic payload, so the audit bundle
		// a consumer uploads would carry the verdict with no record of which
		// allowlist produced it. "Passed" under a strict policy and "passed"
		// under a permissive one are the same word otherwise. The precedent is
		// the intent gate's NOT REQUIRED line, which is also an informational
		// warning recording what was and was not checked.
		warnings = append(warnings, licensePolicyWarning(pol, res.Scanned, total))
		if s := licenseExcludeSummary(excluder, res.Excluded); s != "" {
			warnings = append(warnings, s)
		}
		// A pattern that removed nothing is reported even though the run is
		// otherwise clean: the alternative is that a typo and a tree with
		// nothing to exclude produce identical evidence.
		warnings = append(warnings, excluder.inertWarnings()...)
		if s := licenseAllowSummary(allower, res.AllowedByName); s != "" {
			warnings = append(warnings, s)
		}
		// Same rule as the inert exclude pattern, and the reason it matters
		// more here: an allowance that covers nothing is usually a declaration
		// that has since changed, and its silent form is a policy still
		// carrying an exception for a package that no longer declares it.
		warnings = append(warnings, allower.inertWarnings()...)
	}
	zeroRead := licenceZeroRead(ran, res.Scanned, res.Excluded)
	if zeroRead {
		warnings = append(warnings, licenceZeroReadWarning(mode, dependencyInputs))
	} else if ran {
		if s := licenceCoverageWarning(mode, res.Coverage, res.Scanned); s != "" {
			warnings = append(warnings, s)
		}
	}
	skipped := zeroRead || licenceDependenciesUnread(ran, res.Coverage)
	if ran && licenseGate == licenseGateWarn && total > 0 {
		// Without this an envelope carrying HIGH license findings and
		// passed=true looks like a gate that failed to fire.
		warnings = append(warnings, fmt.Sprintf(
			"%d license finding(s) outside the policy (%s). license-gate is %q, so they are reported and not enforced.",
			total, strings.Join(pol.AllowedCategories, ", "), licenseGateWarn))
	}

	env := &envelope{
		SchemaVersion: evidenceSchemaVersion,
		ModuleName:    moduleName,
		Stage:         moduleStage,
		Tool:          toolInfo{Name: scopeLicense},
		Repo:          repo,
		TimestampUTC:  start.UTC(),
		DurationMS:    time.Since(start).Milliseconds(),
		Passed:        gatedPassed(ran, severityOK, threshold),
		// How many licence declarations the scan actually read. "0 outside
		// policy" is the same phrase whether it read three thousand or none,
		// and on a consumer's shadow run it read a few hundred beside an SBOM
		// listing thousands of components — a gap that lived only in the English
		// warning above and a separate file. Total is left unset because this
		// scan cannot see that denominator; claiming one it did not measure
		// would be worse than admitting it does not know.
		//
		// Scanned, not Scanned+Excluded: Examined is the denominator that makes
		// the finding count mean something, and that is what the policy JUDGED.
		// A run that excluded all 365 must read as examined 0 — the number that
		// says this scan judged nothing — and not as 365, which would say the
		// opposite. The declarations a pattern removed are in the payload's
		// "excluded" and in the warning beside it.
		Concern:            ConcernLicenses,
		Examined:           &Examined{Unit: "licence declarations", Count: res.Scanned},
		FailOnSeverity:     threshold,
		FindingsCount:      total,
		FindingsBySeverity: res.BySeverity,
		Sources: perToolSources(scopeLicense, threshold,
			toolResult{
				Name:       "trivy-license",
				BySeverity: res.BySeverity,
				Err:        licenseErr,
				Warnings:   len(warnings),
				Skipped:    skipped,
				Examined:   &Examined{Unit: "licence declarations", Count: res.Scanned},
				Concern:    ConcernLicenses,
			},
		),
		// genericReport, not cyclonedxReport. The schema reserves this slot for
		// tools that produce neither SARIF nor CycloneDX and names licence
		// scanners as the example; filing it as CycloneDX would assert it is an
		// SBOM, which conflates an inventory with a verdict.
		GenericReport: res.Report,
		GenericFormat: "trivy-license",
		Findings:      res.Findings,
		Warnings:      warnings,
		Errors:        errs,
	}
	// The envelope reports what its tools found, folded from the rows above.
	// Derived from the rows that actually ship rather than recomputed from the
	// same inputs, so the two cannot disagree.
	env.Outcome = sourcesOutcome(env.Sources)

	data, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal evidence: %w", err)
	}
	return writeEvidenceFile(data)
}

// ScanTaint follows untrusted input across functions and files with
// Opengrep's interfile analysis, over the pinned audit and OWASP rules whose
// authors marked them interfile, and reports only what ScanSource's
// single-function pass of the same rules does not. Returns an evidence
// envelope.
//
// Advisory by default, and a separate step rather than a ScanSource flag,
// because the analysis costs a multiple of the single-function scan and that
// cost is the analysis's, not the rule count's: see taint.go. Warn mode works
// as ScanLicenses' does, by lowering the effective threshold to NONE, so a
// run that did not complete still fails.
func (m *Security) ScanTaint(
	ctx context.Context,
	// Source directory to scan.
	src *dagger.Directory,
	// Subdirectory within src to scan. Empty string scans the entire src.
	// +optional
	path string,
	// Directory names to exclude (e.g. "vendor", "node_modules").
	// Relative to path if set, otherwise relative to src root.
	// +optional
	exclude []string,
	// Whether cross-function findings fail the gate: "gate" or "warn".
	// There is deliberately no "off": not calling the step is off.
	// +default="warn"
	taintGate string,
	// How many calls deep the interfile search follows a source toward a
	// sink. -1 removes the limit. The evidence names every rule the limit
	// stopped; raising it costs time and memory.
	// +default=3
	interfileDepth int,
	// Minimum severity that fails the pipeline: CRITICAL|HIGH|MEDIUM|LOW|NONE.
	// Ignored when taintGate is "warn".
	// +default="HIGH"
	failOn string,
	// Git commit SHA for evidence provenance.
	commitSha string,
	// Git branch name for evidence provenance.
	branch string,
	// Repository URL for evidence provenance.
	repoUrl string,
) (*dagger.File, error) {
	start := time.Now()
	repo := repoContext{RepoURL: repoUrl, CommitSHA: commitSha, Branch: branch}

	// Configuration errors before any container, for ScanLicenses' reason: a
	// misspelled mode is a mistake in the pipeline, not a failed scan.
	if err := validateTaintGate(taintGate); err != nil {
		return nil, err
	}
	if err := validateInterfileDepth(interfileDepth); err != nil {
		return nil, err
	}
	threshold := Severity(failOn)
	if taintGate == taintGateWarn {
		threshold = SeverityNone
	}
	plan, err := loadTaintPlan()
	if err != nil {
		return nil, err
	}
	filtered, err := applyPathFilter(src, path, exclude)
	if err != nil {
		return nil, err
	}

	// One fetch for both runs, so they cannot stage different rules.
	var res taintResult
	pinned, fetchErr := fetchSemgrepRules(ctx)
	if fetchErr != nil {
		res = taintResult{Errs: []string{taintToolName + ": " + fetchErr.Error()},
			Warnings: []string{taintScopeWarning(interfileDepth)}}
	} else {
		baseline, baseErr := runSemgrepOnce(ctx, filtered, plan.Args, pinned, plan)
		interfile, interErr := runSemgrepOnce(ctx, filtered, taintInterfileArgs(plan, interfileDepth), pinned, plan)
		res = analyseTaint(baseline, interfile, baseErr, interErr, plan, interfileDepth)
	}

	total := 0
	for _, c := range res.BySeverity {
		total += c
	}
	ran := len(res.Errs) == 0
	severityOK := !shouldFail(res.BySeverity, threshold)
	if ran && taintGate == taintGateWarn && total > 0 {
		res.Warnings = append(res.Warnings, taintAdvisoryWarning(total))
	}
	var rowErr error
	if !ran {
		rowErr = errors.New(strings.Join(res.Errs, "; "))
	}

	env := &envelope{
		SchemaVersion:      evidenceSchemaVersion,
		ModuleName:         moduleName,
		Stage:              moduleStage,
		Tool:               toolInfo{Name: scopeTaint},
		Repo:               repo,
		TimestampUTC:       start.UTC(),
		DurationMS:         time.Since(start).Milliseconds(),
		Passed:             gatedPassed(ran, severityOK, threshold),
		Concern:            ConcernSAST,
		Examined:           res.Examined,
		FailOnSeverity:     threshold,
		FindingsCount:      total,
		FindingsBySeverity: res.BySeverity,
		Sources: perToolSources(scopeTaint, threshold, toolResult{
			Name:       taintToolName,
			BySeverity: res.BySeverity,
			Examined:   res.Examined,
			Rules:      res.Rules,
			Err:        rowErr,
			Warnings:   len(res.Warnings),
			Concern:    ConcernSAST,
		}),
		SARIFReport: res.SARIF,
		Warnings:    res.Warnings,
		Errors:      res.Errs,
	}
	env.Outcome = sourcesOutcome(env.Sources)

	data, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal evidence: %w", err)
	}
	return writeEvidenceFile(data)
}

// ScanImage runs secrets entropy scan (TruffleHog) and image vulnerability scan (Trivy)
// on a built container image. Returns an aggregated evidence envelope.
func (m *Security) ScanImage(
	ctx context.Context,
	// Built container image to scan.
	image *dagger.Container,
	// Minimum severity that fails the pipeline: CRITICAL|HIGH|MEDIUM|LOW|NONE
	// +default="HIGH"
	failOn string,
	// Restrict secrets findings to live-verified credentials (adds TruffleHog's
	// --only-verified). Opt-in "heavier secrets" gate; probes secret providers.
	// +default=false
	verifySecrets bool,
	// Git commit SHA for evidence provenance.
	commitSha string,
	// Git branch name for evidence provenance.
	branch string,
	// Repository URL for evidence provenance.
	repoUrl string,
	// Vulnerability findings to accept, ONE PER LINE, each as "<id>=<reason>"
	// — e.g. "CVE-2026-81871=the exporter only reaches the Dagger engine's own
	// telemetry endpoint on the runner". An accepted identifier is removed from
	// the severity counts, from findings[] and from the gate, and is disclosed
	// in warnings[] with the reason given; the row stays in the CycloneDX
	// report, so the vulnerability is still in the evidence. A reason is
	// mandatory, patterns are refused, and an acceptance matching nothing warns
	// so a stale one is visible rather than a standing permission. The
	// separator is a newline and never a comma, because a reason is prose that
	// contains commas — see splitVulnAcceptances in vulnallow.go for what the
	// CLI does to a []string here.
	// +optional
	vulnAccept string,
) (*dagger.File, error) {
	start := time.Now()
	threshold := Severity(failOn)
	repo := repoContext{RepoURL: repoUrl, CommitSHA: commitSha, Branch: branch}

	// Parsed before any container is built. A malformed acceptance is a
	// narrowing the caller asked for and did not get, and this one fails toward
	// red — which sounds safe until the remedy a consumer reaches for is
	// --fail-on NONE. Same rule as resolveIncludeNames: no envelope, so nothing
	// can be misread as a result.
	accepted, err := newVulnAccepter(vulnAccept)
	if err != nil {
		return nil, err
	}

	sarifSecrets, findingsSecrets, err1 := runTrufflehog(ctx, image, verifySecrets)
	vuln, err2 := runTrivyImage(ctx, image, accepted)

	var errs []string
	for _, e := range []error{err1, err2} {
		if e != nil {
			errs = append(errs, e.Error())
		}
	}

	combined := mergeSeverity(bySeverityFromFindings(findingsSecrets), vuln.BySeverity)
	total := 0
	for _, c := range combined {
		total += c
	}
	ran := len(errs) == 0
	severityOK := !shouldFail(combined, threshold)

	env := &envelope{
		SchemaVersion:      evidenceSchemaVersion,
		ModuleName:         moduleName,
		Stage:              moduleStage,
		Tool:               toolInfo{Name: scopeImage},
		Repo:               repo,
		TimestampUTC:       start.UTC(),
		DurationMS:         time.Since(start).Milliseconds(),
		Passed:             gatedPassed(ran, severityOK, threshold),
		FailOnSeverity:     threshold,
		FindingsCount:      total,
		FindingsBySeverity: combined,
		// The two verdicts behind the single Passed above — see the note in
		// ScanSource and perToolSources.
		Sources: perToolSources(scopeImage, threshold,
			toolResult{
				Name:       "trufflehog",
				BySeverity: bySeverityFromFindings(findingsSecrets),
				Err:        err1,
				Concern:    ConcernSecrets,
			},
			toolResult{
				Name:       "trivy",
				BySeverity: vuln.BySeverity,
				Examined:   vuln.Examined,
				Err:        err2,
				Warnings:   len(vuln.Warnings),
				Concern:    ConcernSCA,
			},
		),
		SARIFReport:     sarifSecrets,
		CycloneDXReport: vuln.CycloneDX,
		// Vulnerability detail only — see the note in ScanSource.
		Findings: vuln.Findings,
		Warnings: vuln.Warnings,
		Errors:   errs,
	}
	// The envelope reports what its tools found, folded from the rows above.
	// Derived from the rows that actually ship rather than recomputed from the
	// same inputs, so the two cannot disagree.
	env.Outcome = sourcesOutcome(env.Sources)

	data, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal evidence: %w", err)
	}
	return writeEvidenceFile(data)
}

// ScanWeb runs OWASP ZAP dynamic analysis against a running application.
//
// The application reaches the scanner one of three ways, and exactly one of
// them may be supplied:
//
//	--target     a URL the Dagger engine can route to. The consumer started the
//	             app; cicd cannot know what is behind the address.
//	--service    tcp://host:port — an app running on the CI runner, tunnelled in
//	             by the Dagger CLI. Same provenance position as --target, and
//	             the only route that reaches a composed stack (docker compose
//	             up) on the runner's loopback, which no URL from inside the
//	             engine can.
//	--container  an image cicd starts itself, normally build.Build's output.
//	             The only source whose evidence can say the running code was
//	             built from this commit.
//
// Three scan modes: baseline (passive), api (driven from an OpenAPI/SOAP/
// GraphQL document) and full (active — sends attack payloads; only against an
// environment you own).
//
// The evidence states what the scan could not test. A scan against an
// application in a non-production profile is an application-layer regression
// detector, not a security attestation of the deployed system, and the
// warnings[] lines say so rather than leaving a green envelope to imply
// otherwise.
func (m *Security) ScanWeb(
	ctx context.Context,

	// Full HTTP/S URL of a live target the engine can reach. One of --target,
	// --service or --container.
	// +optional
	target string,
	// A service to bind and scan, e.g. --service=tcp://localhost:5000 for an
	// application running on the CI runner. One of --target, --service or
	// --container.
	// +optional
	service *dagger.Service,
	// A container cicd starts as a service and scans. One of --target,
	// --service or --container.
	// +optional
	container *dagger.Container,

	// Port the application answers on. Ignored for --target, which carries its
	// own.
	// +default=8080
	port int,
	// http or https. Ignored for --target.
	// +default="http"
	scheme string,
	// Path the application is served under. Ignored for --target.
	// +default="/"
	basePath string,
	// Path the readiness probe requests. Defaults to the base path.
	// +optional
	healthPath string,
	// How long to wait for the target to answer before recording a non-run.
	// +default=120
	readyTimeoutSeconds int,

	// Scan mode: baseline (passive) | api (from a document) | full (active).
	// +default="baseline"
	mode string,
	// API document to drive mode=api from. Mutually exclusive with
	// --api-spec-path.
	// +optional
	apiSpec *dagger.File,
	// Path the target serves its API document on, e.g. /swagger/v1/swagger.json.
	// Mutually exclusive with --api-spec.
	// +optional
	apiSpecPath string,
	// Format of the API document: openapi | soap | graphql.
	// +default="openapi"
	apiFormat string,
	// ZAP rule configuration (-c). Every rule it names is reported in the
	// evidence, including any that raised no alert.
	// +optional
	ruleConfig *dagger.File,
	// Cap the whole scan at this many minutes (ZAP -T). 0 means no cap; an
	// uncapped active scan against a slow target can run for hours.
	// +default=0
	maxDurationMinutes int,

	// The configuration the application ran under, e.g. "Staging". Recorded
	// in the evidence and never interpreted — cicd cannot check the claim.
	// +optional
	profile string,
	// Set when the scan exercised a real login. Absent means the findings
	// describe the anonymous surface only, and the evidence says so.
	// +optional
	authenticated bool,

	// Minimum severity that fails the pipeline: CRITICAL|HIGH|MEDIUM|LOW|NONE.
	// ZAP's maximum risk is High, so CRITICAL can never fail over findings and
	// the evidence warns when it is used.
	// +default="HIGH"
	failOn string,
	// Git commit SHA for evidence provenance.
	commitSha string,
	// Git branch name for evidence provenance.
	branch string,
	// Repository URL for evidence provenance.
	repoUrl string,
) (*dagger.File, error) {
	start := time.Now()
	threshold := Severity(failOn)
	repo := repoContext{RepoURL: repoUrl, CommitSHA: commitSha, Branch: branch}

	// Everything that can be decided without starting a container is decided
	// first, and a failure here returns an error rather than an envelope. An
	// envelope is a thing a consumer reads as a verdict; a scan with no
	// resolvable target must not produce one.
	if err := validateWebInputs(mode, apiSpec != nil, strings.TrimSpace(apiSpecPath) != ""); err != nil {
		return nil, err
	}
	tgt, err := resolveWebTarget(target, service != nil, container != nil,
		scheme, port, basePath, healthPath)
	if err != nil {
		return nil, err
	}

	// A rule config that cannot be parsed is a hard error too: the parse
	// produces the suppression disclosure, and handing ZAP a file cicd could
	// not read would mean scanning with suppressions nobody is told about.
	ruleSettings, err := readRuleConfig(ctx, ruleConfig)
	if err != nil {
		return nil, err
	}

	run := dastRun{
		Target:      tgt,
		Mode:        mode,
		APISpec:     apiSpec,
		APISpecPath: apiSpecPath,
		APIFormat:   apiFormat,
		RuleConfig:  ruleConfig,
		MaxDuration: maxDurationMinutes,
		ReadyBudget: readyTimeoutSeconds,
	}
	if container != nil {
		run.Service = container.WithExposedPort(port).AsService()
	} else if service != nil {
		run.Service = service
	}

	var errs, warnings []string

	// Readiness first, and its verdict is recorded whether or not it passed.
	// An application that never came up produces a ZAP report with no alerts,
	// which is byte-for-byte the shape of a clean scan; this is the only thing
	// that separates them.
	readiness := probeReadiness(ctx, run)
	if !readiness.OK {
		errs = append(errs, readiness.Error)
	}

	payload := dastPayload{
		Mode:          mode,
		Source:        tgt.Source,
		TargetURL:     tgt.BaseURL,
		Profile:       strings.TrimSpace(profile),
		Authenticated: authenticated,
		Readiness:     readiness,
		RuleSettings:  ruleSettings,
	}

	// The operation count is the one scope number in this leg that is not a
	// floor, so it is read from the document itself — from the file when the
	// caller handed one in, and otherwise from the target, which is the shape
	// a consumer reaches for first because the application already serves it.
	//
	// A document cicd cannot fetch or cannot parse warns and does not fail:
	// ZAP may have read what cicd could not, and that is a gap in cicd's
	// accounting rather than in the scan. The served fetch is skipped when the
	// readiness probe failed, because a target that never answered already has
	// exactly one verdict recorded against it and a second failure about the
	// same silence tells the reader nothing new.
	specBytes, specErr := readAPISpecContents(ctx, apiSpec)
	if specErr == nil && len(specBytes) == 0 && strings.TrimSpace(apiSpecPath) != "" && readiness.OK {
		specBytes, specErr = fetchAPISpecContents(ctx, run)
	}
	var specWarnings []string
	payload.EndpointsFromSpec, payload.APIPaths, specWarnings = specScope(specBytes, specErr)
	warnings = append(warnings, specWarnings...)

	var fold zapFold

	// A target that never answered is not scanned. Running ZAP anyway would
	// produce a report of zero alerts against a host that was never there, and
	// that report is the false pass this whole leg exists to refuse.
	if readiness.OK {
		res, runErr := runZAP(ctx, run)
		fold = foldZAPRun(res, runErr, payload, specBytes, zapPassiveAlertCapPerRule)
		errs = append(errs, fold.Errs...)
		warnings = append(warnings, fold.Warnings...)
	} else {
		fold = zapFold{Payload: payload}
		warnings = append(warnings, notScannedWarning())
	}

	warnings = append(warnings, webDisclosureWarnings(fold.Payload, threshold, fold.Parsed.UnknownRiskCodes)...)

	// Every consumer of the bound application has finished: readiness, API
	// document fetch, and ZAP all materialised their outputs above. Stop the
	// service explicitly before returning evidence so a long-lived application
	// cannot keep the Dagger session open after ScanWeb and File.Export report
	// DONE. Kill is intentional at this boundary; the scanned application is a
	// disposable test process and has no shutdown work the evidence depends on.
	if run.Service != nil {
		if _, err := run.Service.Stop(ctx, dagger.ServiceStopOpts{Kill: true}); err != nil {
			warnings = append(warnings, "dast: application service cleanup failed: "+err.Error())
		}
	}

	env, err := buildWebEnvelope(fold, repo, threshold, start, warnings, errs)
	if err != nil {
		return nil, err
	}

	data, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal evidence: %w", err)
	}
	return writeInlineDASTEvidenceFile(data)
}

// applyPathFilter scopes src to path (if non-empty) then removes each exclude directory.
// Returns an error if path is absolute or contains ".." to prevent directory traversal.
func applyPathFilter(src *dagger.Directory, path string, exclude []string) (*dagger.Directory, error) {
	if err := checkScopePath(path); err != nil {
		return nil, err
	}
	if path != "" {
		src = src.Directory(path)
	}
	for _, e := range exclude {
		src = src.WithoutDirectory(e)
	}
	return src, nil
}
