//go:build !unit_test

package main

import (
	"context"
	"dagger/security/internal/dagger"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// runTrivyFS runs a Trivy filesystem scan over src.
//
// The flag policy — including why --scanners vuln is load-bearing rather than
// decorative, which knobs a consumer's trivy.yaml is *not* allowed to touch, and
// why the scan asks for native JSON rather than CycloneDX — lives in
// trivyflags.go.
//
// The container works in /src rather than the image default so Trivy auto-loads
// a `trivy.yaml` committed at the root of the scanned tree. The scan target
// stays absolute, which keeps that file's skip-dirs patterns relative to the
// source root and the report byte-identical for a repo that ships no config.
//
// A successful scan is reconciled against the tree before it is returned: an
// ecosystem the tree declares and Trivy resolved no dependency graph from is a
// non-run *for that ecosystem*, and comes back as a populated result plus a
// non-nil error. See ecosystems.go for why the resolvable input, and not the empty
// report, is the signal.
//
// Before the scan, one ecosystem gets a second chance. A .NET tree that commits
// no dependency graph is the widest instance of that non-run — NuGet writes a
// lockfile only when a project opts in — and it is one cicd can close itself, by
// restoring the graph in a pinned SDK and scanning the result. That happens here,
// not in the reconciliation, because the restored lockfiles have to exist before
// Trivy walks the tree. See dotnetrestore.go for the three properties that keep
// the fallback from becoming the false pass it exists to remove.
//
// The reconciliation deliberately still runs against the **original** probe — the
// tree as the consumer committed it — so a restore that wrote lockfiles Trivy
// then resolved nothing from is still reported. Re-probing the restored tree
// would let the fallback's own output clear the check that judges it.
func runTrivyFS(
	ctx context.Context,
	src *dagger.Directory,
	nugetFeedUrl string,
	nugetToken *dagger.Secret,
	accepted *vulnAccepter,
) (trivyResult, error) {
	// The probe runs first now, because whether a restore is needed is a question
	// about the tree Trivy has not looked at yet. A probe failure does not skip
	// the scan: "which ecosystems are here" being unknown is a reason to fail the
	// gate, never a reason to also throw away the vulnerabilities Trivy can find.
	files, probeErr := probeDependencyInputs(ctx, src)

	scanSrc := src
	var pre []string
	var warnings []string
	restoreBand := ""

	// Whether the report Trivy is about to write was narrowed before cicd could
	// read it. The listing is of the tree as mounted — after ScanSource's
	// --exclude, which is what lands at /src — because a .trivyignore excluded
	// from the mount is not loaded and must not be reported as though it were.
	// A listing cicd could not take is a warning, not an error: the scan is
	// unaffected, and only cicd's ability to say whether it was narrowed is.
	if entries, err := src.Entries(ctx); err != nil {
		warnings = append(warnings, fmt.Sprintf("security: SCAN NARROWING UNKNOWN — cicd could "+
			"not list the root of the scanned tree, so it cannot say whether a %s narrowed "+
			"this report before Trivy wrote it: %v", trivyIgnoreFile, err))
	} else if msg := trivyIgnoreWarning(entries); msg != "" {
		warnings = append(warnings, msg)
	}

	if probeErr == nil {
		if sln := dotnetSolutionsWithoutProjects(trivyConfigDir, files); len(sln) > 0 {
			warnings = append(warnings, dotnetSolutionsWithoutProjectsWarning("Dependency vulnerabilities", sln))
		}
	}

	if probeErr == nil && len(dotnetRestoreNeeded(trivyConfigDir, files)) > 0 {
		restored, _, out, err := restoreDotnetGraph(ctx, src, nugetFeedUrl, nugetToken)
		restoreBand = out.Band
		switch {
		case err != nil:
			// The restore container itself did not complete. Nothing was written
			// to the tree, so the scan proceeds on the source as committed and
			// lands on the unresolved-ecosystem verdict it would have had anyway.
			pre = append(pre, err.Error())
		default:
			// The restored tree is scanned even when some project failed, because
			// the projects that did restore hold real, actionable findings. The
			// classification is what stops that from reading as complete: a
			// partial restore is an error, and it names the projects it missed.
			scanSrc = restored
			if msg := dotnetRestoreRunError(out); msg != "" {
				pre = append(pre, msg)
			} else {
				warnings = append(warnings, dotnetRestoreWarning(out))
			}
		}
	}

	base := dag.Container().
		From(trivyImage).
		WithMountedCache(trivyCachePath, dag.CacheVolume(trivyCacheVolume)).
		WithMountedDirectory("/src", scanSrc).
		WithWorkdir(trivyConfigDir)
	ctr := base.
		WithExec(trivyFSArgs("/src")).
		WithExec(trivyConvertArgs())

	res, err := readTrivyResult(ctx, ctr, accepted)
	switch {
	case err == nil:
		res.Warnings = append(res.Warnings, warnings...)
	case probeErr != nil || !errors.Is(err, errTrivyNoTargets):
		return trivyResult{}, err
	default:
		if skipped, ok := dependencyNotApplicableResult(files, err, warnings); ok {
			return skipped, nil
		}
		// The probe found a dependency input and the gated scan read nothing
		// from it. Either every package in it is a development dependency, or
		// Trivy could not parse it; only a rescan with development
		// dependencies included can tell the two apart. See devonly.go.
		res, err = rescanDevOnly(ctx, base, ctr, files, err, warnings)
		if err != nil {
			return trivyResult{}, err
		}
		res.Warnings = append(res.Warnings, accepted.disclosures()...)
	}

	// The result is returned alongside any reconciliation error rather than
	// nulled — the same shape runGitleaks uses for a failed history leg. The
	// vulnerabilities Trivy *did* find in the ecosystems it *could* read are real
	// and actionable, and discarding them to report that a different ecosystem was
	// unreadable trades a located finding for a message. main.go and archive.go
	// already fold this error into errors[], which sets ran=false, so the gate
	// fails at every threshold including --fail-on NONE.
	if probeErr != nil {
		return res, probeErr
	}

	msgs := pre
	for _, v := range unresolvedEcosystems(trivyConfigDir, files, res.ResolvedTypes) {
		msg := v.Message
		if v.Name == "dotnet" && restoreBand != "" {
			// Without this the verdict reads as though cicd never tried, and the
			// first thing a consumer does about it is what cicd already did.
			msg += " " + dotnetRestoreAttemptedNote(restoreBand)
		}
		msgs = append(msgs, msg)
	}
	if len(msgs) > 0 {
		return res, errors.New(joinEcosystemErrors(msgs))
	}
	return res, nil
}

// rescanDevOnly runs the development-inclusive rescan over the same mounted
// tree and returns a dependency result only when it proves a
// development-only input. The CycloneDX attached is the gated scan's, read
// from ctr, so no development package reaches the SBOM. Every failure,
// including one to read the rescan at all, keeps the gated scan's error.
//
// The probe behind files is the original one, so a restored tree cannot clear
// the check that judges it — the same rule the reconciliation below follows.
func rescanDevOnly(
	ctx context.Context,
	base, ctr *dagger.Container,
	files []string,
	scanErr error,
	warnings []string,
) (trivyResult, error) {
	raw, err := base.WithExec(trivyDevRescanArgs("/src")).File(trivyDevNativePath).Contents(ctx)
	if err != nil {
		return trivyResult{}, noTargetsWithInputsError(files, scanErr,
			fmt.Errorf("the rescan with development dependencies included did not complete: %w", err))
	}
	scan, err := classifyDevOnlyRescan([]byte(raw))
	if err != nil {
		return trivyResult{}, noTargetsWithInputsError(files, scanErr, err)
	}
	cdx, err := ctr.File(trivyReportPath).Contents(ctx)
	if err != nil {
		return trivyResult{}, err
	}
	return devOnlyResult(scan, json.RawMessage(cdx), warnings), nil
}

// probeDependencyInputs lists every dependency declaration and lockfile in the
// scanned tree.
//
// It runs in alpine rather than the Trivy image deliberately: the probe's whole
// job is to check Trivy's silence against an independent reading of the tree, and
// a probe sharing the suspect's container shares its failure modes.
//
// Nothing is swallowed. `find`'s exit status, stdout and stderr each go to a file
// and are classified in Go, because a probe that could not walk the tree leaves
// "which ecosystems are here" *unknown* — and unknown must fail the gate, not
// quietly agree that nothing is here. That agreement is precisely the false pass
// this leg exists to close, so importing it through the checker's own error
// handling would be the joke writing itself.
func probeDependencyInputs(ctx context.Context, src *dagger.Directory) ([]string, error) {
	ctr := dag.Container().
		From(alpineImage).
		WithMountedDirectory(trivyConfigDir, src).
		WithExec([]string{"sh", "-c", dependencyProbeScript(trivyConfigDir)})

	code, err := ctr.File(depProbeExitPath).Contents(ctx)
	if err != nil {
		return nil, fmt.Errorf("security dependency scan: the dependency-input probe left no "+
			"exit status, so which ecosystems the source tree declares is unknown: %w", err)
	}
	stderr, err := ctr.File(depProbeErrPath).Contents(ctx)
	if err != nil {
		return nil, fmt.Errorf("security dependency scan: could not read the dependency-input "+
			"probe's stderr: %w", err)
	}
	if msg := dependencyProbeRunError(code, stderr); msg != "" {
		return nil, errors.New(msg)
	}

	out, err := ctr.File(depProbeOutPath).Contents(ctx)
	if err != nil {
		return nil, fmt.Errorf("security dependency scan: could not read the dependency-input "+
			"probe's output: %w", err)
	}
	return strings.Split(out, "\n"), nil
}

// readTrivyResult pulls both reports out of a container that has scanned and
// converted, and derives everything the envelope needs from them.
//
// The native report is read first and parsed before the CycloneDX document is
// even fetched: it is the document the gate counts, so if it is missing or
// unparseable the caller must get an error, not a CycloneDX payload with no
// findings beside it.
func readTrivyResult(ctx context.Context, ctr *dagger.Container, accepted *vulnAccepter) (trivyResult, error) {
	native, err := ctr.File(trivyNativePath).Contents(ctx)
	if err != nil {
		return trivyResult{}, err
	}
	doc, err := parseTrivyNative(json.RawMessage(native))
	if err != nil {
		return trivyResult{}, err
	}

	cdx, err := ctr.File(trivyReportPath).Contents(ctx)
	if err != nil {
		return trivyResult{}, err
	}

	// --vuln-accept is applied here, once, so every scan shape gets it and no
	// two derived values can disagree about which rows are in force. Note which
	// call reads which document:
	//
	//   - the counts, the findings and trivyWarnings read the GATED document, so
	//     an accepted row cannot fail the gate, cannot occupy a slot in the
	//     truncated findings table, and is not counted among the unrated;
	//   - trivyResolvedTypes and trivyExamined read the ORIGINAL, because they
	//     describe what Trivy read rather than what it found. Resolving types
	//     from the gated document would let an acceptance empty a Result and so
	//     manufacture an unresolved-ecosystem error — an acceptance turning a
	//     scan into a non-run. TestFilteringCanHideAnEcosystem holds that.
	//   - the CycloneDX document is Trivy's own and is attached untouched, so the
	//     accepted vulnerability is still in the evidence a reader can look up.
	gated, removed := accepted.partition(doc)

	return trivyResult{
		CycloneDX:     json.RawMessage(cdx),
		BySeverity:    trivySeverities(gated),
		Findings:      trivyFindings(gated),
		Warnings:      append(trivyWarnings(gated), accepted.disclosures()...),
		ResolvedTypes: trivyResolvedTypes(doc),
		Examined:      trivyExamined(doc),
		Accepted:      removed,
	}, nil
}
