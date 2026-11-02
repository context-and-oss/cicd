// Trivy native-report parsing: severity counts and finding detail.
//
// Deliberately untagged (no //go:build !unit_test): none of this needs Dagger,
// so trivyreport_test.go can drive it with `go test -tags unit_test ./...`.
//
// This file exists because CycloneDX has no field for the severity Trivy
// resolved. A CycloneDX `vulnerability` carries `ratings[]` — one entry per
// vendor that published an opinion — and no verdict, so reading a severity out
// of it is guesswork. Measured against trivy 0.70.0 on debian:11.6, whose 205
// vulnerabilities average five vendor ratings each:
//
//   - Taking ratings[0], which is what this module used to do, under-reported 34
//     vulnerabilities and found 3 of the 9 CRITICALs. The other 6 could not fail
//     a --fail-on CRITICAL gate.
//   - ratings[0]'s vendor is not even the vendor for the image being scanned: on
//     that debian image it was `alma` for 117 of the 205, `debian` for 29. It is
//     the order Trivy's advisory database happened to serialise, nothing more.
//   - Trivy's own choice cannot be recovered from the document. For
//     CVE-2023-45853 the vulnerability's `source.name` is "debian", and the
//     ratings array holds amazon, azure, cbl-mariner, ghsa, julia, nvd, photon,
//     redhat and ubuntu — every vendor except debian. Trivy reports it CRITICAL
//     by falling back to NVD. `properties` is null, so there is no side channel.
//
// SARIF is no better as a carrier: `trivy convert --format sarif` maps both
// critical and high onto level "error" (measured: 9 critical + 41 high, all
// "error"), so the two collapse and every CRITICAL renders as HIGH.
//
// The native report states Severity per finding, so nothing here reconstructs
// anything.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// errTrivyNoTargets is deliberately distinguishable from every other report
// error. The caller has an independent probe of dependency inputs and can turn
// this one state into NOT APPLICABLE when that probe proves there was nothing
// for a filesystem dependency scan to examine. An empty, malformed or
// otherwise unreadable report remains an error regardless of repository shape.
var errTrivyNoTargets = errors.New("trivy: report contains no scan results, so no target was examined")

// trivyNativeDoc models the parts of Trivy's JSON report this module reads.
type trivyNativeDoc struct {
	Results []struct {
		// Target is the scanned artefact: an OS name for the distro results, or
		// a lockfile path for language results.
		Target string `json:"Target"`
		Class  string `json:"Class"`
		// Type is the ecosystem Trivy resolved this result from — "nuget",
		// "npm", "gomod", … — and is what ecosystems.go reconciles the tree's
		// marker files against.
		Type string `json:"Type"`
		// Packages is the resolved dependency list. It is read only to count:
		// a result carrying zero packages *and* zero vulnerabilities means
		// Trivy produced a heading for the ecosystem without resolving
		// anything from it, which must not count as having scanned it. The scan
		// pins --list-all-pkgs, so this is populated whenever a graph was read.
		Packages        []json.RawMessage `json:"Packages"`
		Vulnerabilities []trivyVuln       `json:"Vulnerabilities"`
	} `json:"Results"`
}

type trivyVuln struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	PkgPath          string `json:"PkgPath"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	// Severity is Trivy's resolved verdict, already reconciled across vendors.
	Severity string `json:"Severity"`
	// SeveritySource names the vendor that verdict came from, which is worth
	// showing: "nvd" on a debian image means no debian rating existed.
	SeveritySource string `json:"SeveritySource"`
	Title          string `json:"Title"`
}

// trivySeverity maps Trivy's severity vocabulary onto the canonical one.
//
// UNKNOWN maps to LOW rather than being dropped. Dropping is what happened
// before — a severity outside the four known strings matched no case and the
// vulnerability was counted in nothing, so it reached neither
// findingsBySeverity nor findingsCount nor the findings list. Seven of
// debian:11.6's 205 were invisible that way. LOW keeps them visible and
// countable without letting an unrated CVE trip a --fail-on MEDIUM gate on its
// own; scanTrivyWarnings says how many there were so "unrated" is not read as
// "harmless".
func trivySeverity(s string) Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MEDIUM":
		return SeverityMedium
	}
	return SeverityLow
}

// parseTrivyNative decodes a native Trivy report. A report that does not parse
// is an error rather than an empty result: this is the document the gate counts,
// and "no vulnerabilities" and "unreadable" must not look the same.
func parseTrivyNative(raw json.RawMessage) (*trivyNativeDoc, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, fmt.Errorf("trivy: wrote an empty report, so nothing was scanned")
	}
	var doc trivyNativeDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("trivy: report is not valid JSON: %w", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(raw)), "{") {
		// `null` decodes into the struct without error. It is not a report
		// that named no target; it is not a report, so it must not reach the
		// no-targets path that a dependency-free tree may turn into N/A.
		return nil, fmt.Errorf("trivy: report is %s, not a Trivy report", trivyDocShape(raw))
	}
	if len(doc.Results) == 0 {
		// A scan that found no targets at all omits "Results" (Trivy marks it
		// omitempty), and `null` and `[]` say the same thing. That is not a
		// scan that found targets with no vulnerabilities, and it must not read
		// as clean — an empty source tree, a bad --input path or a language
		// Trivy has no analyser for all land here. `[]` used to pass as a scan
		// of zero targets with zero findings.
		return nil, errTrivyNoTargets
	}
	return &doc, nil
}

// trivySeverities counts vulnerabilities per canonical severity.
//
// A vulnerability affecting three packages is counted three times, because each
// pair needs its own upgrade. That is also how Trivy itself reports: the
// debian:11.6 report holds 364 vulnerability entries across 205 distinct CVEs.
// The gate compares severities present against a threshold rather than totals,
// so this changes the reported number, not the verdict.
func trivySeverities(doc *trivyNativeDoc) map[Severity]int {
	counts := map[Severity]int{}
	for _, res := range doc.Results {
		for _, v := range res.Vulnerabilities {
			counts[trivySeverity(v.Severity)]++
		}
	}
	return counts
}

// trivyFindings renders each vulnerability as envelope detail.
//
// These go into the envelope's Findings list rather than being left for the
// aggregator to derive, because the aggregator only sees the CycloneDX and SARIF
// payloads and neither can carry the resolved severity (see this file's package
// comment). Deriving there would put a HIGH row under a CRITICAL count.
func trivyFindings(doc *trivyNativeDoc) []Finding {
	var out []Finding
	for _, res := range doc.Results {
		for _, v := range res.Vulnerabilities {
			out = append(out, Finding{
				Severity:     trivySeverity(v.Severity),
				Tool:         "trivy",
				Rule:         v.VulnerabilityID,
				Message:      trivyFindingMessage(v),
				ArtifactPath: trivyFindingPath(res.Target, v),
			})
		}
	}
	return out
}

// trivyFindingMessage states the package, the version in use and the way out.
// The fixed version is the actionable half; "no fix available" is said out loud
// because a blank there otherwise reads as an omission.
func trivyFindingMessage(v trivyVuln) string {
	var sb strings.Builder
	sb.WriteString(v.PkgName)
	if v.InstalledVersion != "" {
		sb.WriteString("@" + v.InstalledVersion)
	}
	if v.FixedVersion != "" {
		sb.WriteString(" — fixed in " + v.FixedVersion)
	} else {
		sb.WriteString(" — no fix available")
	}
	if v.Title != "" {
		sb.WriteString(": " + v.Title)
	}
	// Naming the vendor the severity came from is what makes an unexpected
	// rating auditable rather than mysterious.
	if v.SeveritySource != "" {
		sb.WriteString(" (severity: " + v.SeveritySource + ")")
	}
	return sb.String()
}

// trivyFindingPath prefers the lockfile a dependency was declared in, since that
// is the file someone edits to fix it. OS packages have no such file, so those
// fall back to the scan target (the distro name).
func trivyFindingPath(target string, v trivyVuln) string {
	if v.PkgPath != "" {
		return v.PkgPath
	}
	return target
}

// trivyResolvedTypes lists the ecosystems Trivy actually resolved something from,
// lowercased and deduplicated.
//
// "Resolved something" is deliberately stricter than "a Result exists with this
// Type": the result must carry at least one package or one vulnerability. An empty
// result is Trivy naming an ecosystem it could not read a graph from, which is the
// state ecosystems.go exists to report — treating it as proof of scanning would
// re-open the hole from inside the exculpating check.
func trivyResolvedTypes(doc *trivyNativeDoc) []string {
	var out []string
	seen := map[string]bool{}
	for _, res := range doc.Results {
		if len(res.Packages) == 0 && len(res.Vulnerabilities) == 0 {
			continue
		}
		t := strings.ToLower(strings.TrimSpace(res.Type))
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

// trivyWarnings reports counts worth stating that are not failures: how many
// vulnerabilities Trivy could not rate. Unrated is not harmless, and a bare LOW
// row does not convey that on its own.
func trivyWarnings(doc *trivyNativeDoc) []string {
	unrated := 0
	for _, res := range doc.Results {
		for _, v := range res.Vulnerabilities {
			if s := strings.ToUpper(strings.TrimSpace(v.Severity)); s != "CRITICAL" &&
				s != "HIGH" && s != "MEDIUM" && s != "LOW" {
				unrated++
			}
		}
	}
	if unrated == 0 {
		return nil
	}
	return []string{fmt.Sprintf(
		"trivy: %d vulnerability(ies) carry no vendor severity rating and are counted LOW; "+
			"an unrated CVE is not a low-risk one, so review them in the CycloneDX report", unrated)}
}

// trivyExamined states how many packages Trivy resolved, so a zero finding
// count has a denominator.
//
// "0 vulnerabilities" is the same two words whether Trivy read three thousand
// packages or reached none of them, and findingsCount alone cannot separate
// those. The security module already fails the gate when an ecosystem the tree
// declares resolved nothing (see ecosystems.go), but that check is per
// ecosystem and says nothing about scale — a report saying "0 findings" is
// unreportable to a customer without the number of things looked at beside it.
//
// The count SUMS Packages across results rather than deduplicating by
// name@version, because the denominator has to match the numerator. Trivy
// counts vulnerabilities per result entry: measured on a tree with the same
// package-lock.json committed in two directories, Trivy emits two results of
// one package and ten vulnerabilities each — twenty findings over what
// deduplication would call one package. Summing keeps "N findings across M
// resolved packages" coherent; deduplicating would not.
//
// So this number can exceed the SBOM's component list on a monorepo, and that
// is not drift. Measured on debian:11.6, where nothing repeats, the two agree
// exactly: 96 resolved packages against a CycloneDX document of 96 `library`
// components plus the one `operating-system` component the image itself
// contributes.
//
// Total is deliberately left unset. Trivy cannot see the packages it failed to
// resolve, and a tool that does not know its own denominator must not imply one
// — an unresolvable ecosystem reaches the envelope as an error instead.
//
// Never nil for a report that parsed. Zero resolved packages is a real claim,
// and the loud one: Trivy ran and read nothing. Absent is reserved for the
// scanners that do not state a figure at all, which is why the callers that
// fail before parsing pass no Examined rather than a confident zero.
func trivyExamined(doc *trivyNativeDoc) *Examined {
	n := 0
	for _, res := range doc.Results {
		n += len(res.Packages)
	}
	return &Examined{Unit: "resolved packages", Count: n}
}

// trivyDocShape names what a document that is not a Trivy report turned out to
// be, for an error message, without echoing its content.
func trivyDocShape(raw json.RawMessage) string {
	t := strings.TrimSpace(string(raw))
	switch {
	case t == "null":
		return "JSON null"
	case strings.HasPrefix(t, "["):
		return "a JSON array"
	case strings.HasPrefix(t, "{"):
		return "a JSON object"
	default:
		return "a JSON scalar"
	}
}
