// The development-only lockfile: a dependency input Trivy read in full and
// whose every package it classified as a development dependency.
//
// Deliberately untagged (no //go:build !unit_test): this classifies a report
// and builds a result, neither of which needs Dagger, so devonly_test.go can
// drive it under `go test -tags unit_test ./...`.
//
// Why this file exists. The gated filesystem scan excludes development
// dependencies (--include-dev-deps=false, pinned in trivyFSArgs). A tree whose
// lockfile lists only development packages — observed on a Poetry project whose
// packages were all in dependency groups — makes Trivy write `Results: null`,
// byte-for-byte what it writes for a lockfile it could not parse. Both used to
// end on errTrivyNoTargets, a permanent ERROR the consumer could not clear
// without inventing a runtime dependency. A gate the consumer cannot clear gets
// switched off, so cicd clears it: it rescans with development dependencies
// included and keeps the original error unless that rescan proves the input
// parsed and held nothing but development packages.
//
// The proof is the rescan, never the empty report. The classification is
// Trivy's — read from the lockfile and, for Poetry, the pyproject.toml beside
// it — and the warning says so, because a package that ships at runtime but is
// declared as development is the one way this verdict can be wrong.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// trivyDevNativePath is where the development-inclusive rescan writes its
// report. It is never converted to CycloneDX: the inventory the bundle ships
// is the gated scan's, so development packages cannot enter the SBOM through
// this path.
const trivyDevNativePath = "/tmp/report.dev.json"

// maxNamedDevVulns caps how many development-only vulnerabilities the warning
// names. A count cannot say which, so the first ones are named, ordered by
// severity, and the rest are counted.
const maxNamedDevVulns = 10

// devOnlyScan is what the development-inclusive rescan proved.
type devOnlyScan struct {
	// Inputs are the report targets that resolved packages: the lockfiles.
	Inputs []string
	// Packages is how many packages Trivy read, all flagged Dev.
	Packages int
	// ResolvedTypes are the ecosystems those packages came from, for the
	// reconciliation against the tree's markers.
	ResolvedTypes []string
	// BySeverity and Vulns describe what Trivy reported for those packages.
	// They are raw counts, never gated.
	BySeverity map[Severity]int
	Vulns      []trivyVuln
}

// classifyDevOnlyRescan reads the rescan's native report and returns an error
// unless it proves a development-only input: at least one package, every one
// flagged Dev. Anything else — no results again, results with no packages, or
// a single package Trivy did not flag as development — leaves the gated
// scan's emptiness unexplained, and the caller keeps it as an error.
func classifyDevOnlyRescan(raw []byte) (devOnlyScan, error) {
	doc, err := parseTrivyNative(json.RawMessage(raw))
	if err != nil {
		if errors.Is(err, errTrivyNoTargets) {
			return devOnlyScan{}, errors.New("the rescan with development dependencies included also produced no results")
		}
		return devOnlyScan{}, fmt.Errorf("the rescan with development dependencies included could not be read: %w", err)
	}
	var scan devOnlyScan
	var runtime []string
	types := map[string]bool{}
	for _, res := range doc.Results {
		if len(res.Packages) > 0 {
			scan.Inputs = append(scan.Inputs, res.Target)
			if t := strings.ToLower(strings.TrimSpace(res.Type)); t != "" {
				types[t] = true
			}
		}
		for _, p := range res.Packages {
			var pkg struct {
				Name    string `json:"Name"`
				Version string `json:"Version"`
				Dev     bool   `json:"Dev"`
			}
			if err := json.Unmarshal(p, &pkg); err != nil {
				return devOnlyScan{}, fmt.Errorf("the rescan with development dependencies included lists a package that is not an object: %w", err)
			}
			scan.Packages++
			if !pkg.Dev {
				runtime = append(runtime, pkg.Name+"@"+pkg.Version)
			}
		}
		scan.Vulns = append(scan.Vulns, res.Vulnerabilities...)
	}
	if scan.Packages == 0 {
		return devOnlyScan{}, errors.New("the rescan with development dependencies included resolved no package")
	}
	if len(runtime) > 0 {
		sort.Strings(runtime)
		return devOnlyScan{}, fmt.Errorf("the rescan with development dependencies included read %d "+
			"package(s) Trivy did not flag as development (e.g. %s), which the gated scan should have "+
			"reported, so the two scans disagree about the same input",
			len(runtime), strings.Join(firstN(runtime, 3), ", "))
	}
	for t := range types {
		scan.ResolvedTypes = append(scan.ResolvedTypes, t)
	}
	sort.Strings(scan.ResolvedTypes)
	scan.BySeverity = trivySeverities(doc)
	return scan, nil
}

// noTargetsWithInputsError is the gated scan's no-results error, kept as an
// error because the rescan did not prove a development-only input. It wraps
// errTrivyNoTargets, so its text and its identity survive, and adds what is
// known: which input was found, why the rescan did not clear it, and the way
// out.
func noTargetsWithInputsError(files []string, scanErr, rescanErr error) error {
	var inputs []string
	for _, f := range files {
		if f = strings.TrimSpace(f); f != "" {
			inputs = append(inputs, strings.TrimPrefix(strings.TrimPrefix(f, trivyConfigDir), "/"))
		}
	}
	return fmt.Errorf("security dependency scan: a dependency input was found (%d file(s), e.g. %s) "+
		"but Trivy produced no results for it, and %v. A lockfile Trivy cannot parse and a tree "+
		"Trivy has no analyser for both end here. Fix: check that the lockfile is the one your "+
		"package manager writes now (regenerate and commit it) and that it is not excluded by "+
		"trivy.yaml or --exclude: %w",
		len(inputs), strings.Join(firstN(inputs, 3), ", "), rescanErr, scanErr)
}

// devOnlyResult is the dependency result for a tree whose runtime dependency
// set is proven empty: the vulnerability row examined zero runtime packages
// and found nothing gated, and the SBOM row carries the gated scan's own,
// empty inventory. cdx is that gated scan's CycloneDX, never the rescan's.
func devOnlyResult(scan devOnlyScan, cdx json.RawMessage, scanWarnings []string) trivyResult {
	return trivyResult{
		CycloneDX:     cdx,
		BySeverity:    map[Severity]int{},
		Warnings:      append(append([]string{}, scanWarnings...), devOnlyWarning(scan)),
		ResolvedTypes: scan.ResolvedTypes,
		// Zero is a measurement here: the gated scan read the input and it held
		// no runtime package. Total stays unset — the development packages are
		// out of scope, not unread, so N of M would read as partial coverage.
		Examined: &Examined{Unit: "resolved packages", Count: 0},
		InventoryWarnings: []string{fmt.Sprintf("Source SBOM: RUNTIME SET EMPTY — %s resolved %d "+
			"package(s), all development-only, so the source inventory names no runtime component.",
			strings.Join(scan.Inputs, ", "), scan.Packages)},
	}
}

// devOnlyWarning says what the gate measured, what it did not, and which
// development-only vulnerabilities a reader would want to know about anyway.
func devOnlyWarning(scan devOnlyScan) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Dependency vulnerabilities: RUNTIME SET EMPTY — Trivy classified all %d "+
		"package(s) in %s as development dependencies, so the gated scan, which excludes them, "+
		"examined no runtime package. cicd rescanned with development dependencies included to "+
		"prove the input parsed; those packages are not gated",
		scan.Packages, strings.Join(scan.Inputs, ", "))
	if len(scan.Vulns) == 0 {
		sb.WriteString(" and carry no known vulnerability.")
	} else {
		fmt.Fprintf(&sb, " and carry %d known vulnerability finding(s) (%s): %s.",
			len(scan.Vulns), severitySummary(scan.BySeverity), namedDevVulns(scan.Vulns))
	}
	sb.WriteString(" The development classification is Trivy's, read from the lockfile and its " +
		"manifest; a package that ships at runtime belongs in the runtime dependencies, where " +
		"this gate reads it.")
	return sb.String()
}

func severitySummary(counts map[Severity]int) string {
	var parts []string
	for _, s := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
		if n := counts[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	return strings.Join(parts, ", ")
}

// namedDevVulns names the most severe first, by identifier then package, so
// the list is stable across runs, and counts what it did not name.
func namedDevVulns(vulns []trivyVuln) string {
	rank := map[Severity]int{SeverityCritical: 0, SeverityHigh: 1, SeverityMedium: 2, SeverityLow: 3}
	sorted := append([]trivyVuln{}, vulns...)
	sort.SliceStable(sorted, func(i, j int) bool {
		ri, rj := rank[trivySeverity(sorted[i].Severity)], rank[trivySeverity(sorted[j].Severity)]
		if ri != rj {
			return ri < rj
		}
		if sorted[i].VulnerabilityID != sorted[j].VulnerabilityID {
			return sorted[i].VulnerabilityID < sorted[j].VulnerabilityID
		}
		return sorted[i].PkgName < sorted[j].PkgName
	})
	var named []string
	for i, v := range sorted {
		if i == maxNamedDevVulns {
			named = append(named, fmt.Sprintf("and %d more", len(sorted)-i))
			break
		}
		named = append(named, fmt.Sprintf("%s %s in %s@%s", trivySeverity(v.Severity), v.VulnerabilityID, v.PkgName, v.InstalledVersion))
	}
	return strings.Join(named, "; ")
}
