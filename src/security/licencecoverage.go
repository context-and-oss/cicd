// How much of the dependency graph the licence scan could read a licence for.
//
// Deliberately untagged: JSON decoding and message construction only, so
// licencecoverage_test.go reaches it under `go test -tags unit_test`.
//
// Why this exists. "Scanned" counts licence declarations, and a declaration is
// not a dependency. Measured with the pinned Trivy and --license-full on a Go
// tree with no module cache: 540 dependency packages, none carrying a licence,
// beside one Apache-2.0 declaration read from the tree's own LICENSE. Scanned
// was 1, so the zero-read rule did not fire and the row read CLEAN — a policy
// that had judged the root LICENSE and none of the dependencies. With a
// populated module cache, one module of the same tree gave 36 of its 36
// dependencies a licence. Only Trivy's own package list tells those runs apart,
// so it is read here rather than inferred from the declarations.
package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// trivyLicensePackages is the slice of a Trivy licence report this file reads.
// Its own type rather than fields on trivyLicenseDoc: sourceLicenseReport
// re-marshals that type, and a source-only scan must keep carrying no package
// list, because it does not assess dependency licences at all.
type trivyLicensePackages struct {
	Results []struct {
		Target   string `json:"Target"`
		Class    string `json:"Class"`
		Type     string `json:"Type"`
		Packages []struct {
			Name         string   `json:"Name"`
			Relationship string   `json:"Relationship"`
			Licenses     []string `json:"Licenses"`
		} `json:"Packages"`
	} `json:"Results"`
}

// licenceEcosystemCoverage is one package ecosystem's share of the graph.
type licenceEcosystemCoverage struct {
	Type        string   `json:"type"`
	Targets     []string `json:"targets"`
	Packages    int      `json:"packages"`
	WithLicence int      `json:"withLicence"`
}

// licenceCoverage is the dependency packages Trivy listed and how many carry a
// licence it read. Packages is the denominator Examined cannot carry: Examined
// counts declarations, and a declaration count has no total.
type licenceCoverage struct {
	Packages    int                        `json:"packages"`
	WithLicence int                        `json:"withLicence"`
	Ecosystems  []licenceEcosystemCoverage `json:"ecosystems,omitempty"`
}

// firstPartyRelationship is a package Trivy lists that is the consumer's own:
// the module or project itself, or a member of its workspace. Its licence is
// the consumer's, read (if at all) from the tree's own files, so it is neither
// a dependency that was read nor one that was missed.
func firstPartyRelationship(rel string) bool {
	switch strings.ToLower(strings.TrimSpace(rel)) {
	case "root", "workspace":
		return true
	}
	return false
}

// readLicenceCoverage counts the dependency packages in a Trivy licence report.
//
// A manifest the excluder covers is left out of both counts, by the same path
// evaluateLicenses matches a metadata declaration on (its Target), so an
// excluded subtree is neither read nor missed. covers, not match: this pass must
// not record a hit, or a pattern that removed no declaration would stop being
// reported as inert. An unknown or empty Relationship counts as a dependency —
// a package nobody classified is not one cicd may assume is first-party.
func readLicenceCoverage(raw json.RawMessage, ex *licenseExcluder) (licenceCoverage, error) {
	var doc trivyLicensePackages
	if err := json.Unmarshal(raw, &doc); err != nil {
		return licenceCoverage{}, fmt.Errorf("parse trivy license report packages: %w", err)
	}
	byType := map[string]*licenceEcosystemCoverage{}
	var cov licenceCoverage
	for _, r := range doc.Results {
		if len(r.Packages) == 0 || ex.covers(r.Target) {
			continue
		}
		typ := strings.TrimSpace(r.Type)
		if typ == "" {
			typ = "unknown"
		}
		e := byType[typ]
		if e == nil {
			e = &licenceEcosystemCoverage{Type: typ}
			byType[typ] = e
		}
		counted := false
		for _, p := range r.Packages {
			if firstPartyRelationship(p.Relationship) {
				continue
			}
			counted = true
			e.Packages++
			cov.Packages++
			if len(p.Licenses) > 0 {
				e.WithLicence++
				cov.WithLicence++
			}
		}
		if counted {
			e.Targets = append(e.Targets, strings.TrimSpace(r.Target))
		}
	}
	for _, e := range byType {
		if e.Packages == 0 {
			continue
		}
		sort.Strings(e.Targets)
		cov.Ecosystems = append(cov.Ecosystems, *e)
	}
	sort.Slice(cov.Ecosystems, func(i, j int) bool { return cov.Ecosystems[i].Type < cov.Ecosystems[j].Type })
	return cov, nil
}

// licenceDependenciesUnread reports whether a completed scan listed dependency
// packages and read a licence for none of them, which makes the row SKIPPED
// even when declarations from the tree's own files were judged.
//
// Those declarations are real and stay judged — a finding among them still
// makes the row FINDINGS, because perToolSources lets a finding outrank
// SKIPPED. What they cannot do is make a clean row read as a judged dependency
// graph: one root LICENSE beside thirty-six unread modules is the case the
// declaration count hides. Never on a run that errored, for licenceZeroRead's
// reason.
func licenceDependenciesUnread(ran bool, cov licenceCoverage) bool {
	return ran && cov.Packages > 0 && cov.WithLicence == 0
}

// licenceCoverageWarning names the dependency packages whose licences were not
// read, or "" when every listed dependency carries one. scanned is the
// declaration count, said beside the package count so a reader can see which
// of the two a finding count is over. mode picks where the missing licences
// would have come from: an SBOM rescan reads only what the SBOM declares.
func licenceCoverageWarning(mode licenceScanMode, cov licenceCoverage, scanned int) string {
	if cov.Packages == 0 || cov.WithLicence == cov.Packages {
		return ""
	}
	var parts []string
	for _, e := range cov.Ecosystems {
		if e.WithLicence == e.Packages {
			continue
		}
		parts = append(parts, e.Type+" "+strconv.Itoa(e.WithLicence)+" of "+strconv.Itoa(e.Packages)+
			" in "+strings.Join(firstN(e.Targets, 3), ", ")+moreSuffix(len(e.Targets), 3))
	}
	why := " A dependency with no licence metadata is not a dependency with an acceptable licence: " +
		"Trivy reads a dependency's licence from installed package metadata (the Go module cache, " +
		"node_modules, site-packages, the NuGet packages folder), and a lockfile names versions, not " +
		"licences. cicd supplies that metadata only for .NET, by restoring the NuGet graph, and " +
		"for Go, by downloading the module graph from the Go module proxy."
	from := "the tree's own files"
	if mode == licenceScanSBOM {
		why = " A component the SBOM gives no licence is not a component with an acceptable licence: " +
			"this scan reads only the licences the supplied SBOM declares."
		from = "components outside the dependency graph"
	}
	if cov.WithLicence == 0 {
		return "Dependency licences: NOT READ — Trivy listed " + strconv.Itoa(cov.Packages) +
			" dependency package(s) and read a licence for none of them (" + strings.Join(parts, "; ") +
			"). The " + strconv.Itoa(scanned) + " licence declaration(s) judged came from " + from +
			", not its dependencies, so this row is SKIPPED rather than CLEAN." + why
	}
	return "Dependency licences: PARTLY READ — " + strconv.Itoa(cov.WithLicence) + " of " +
		strconv.Itoa(cov.Packages) + " dependency package(s) carry a licence Trivy read; the rest " +
		"were not judged (" + strings.Join(parts, "; ") + ")." + why
}
