// License policy: turning Trivy's license report into findings, a verdict and a
// payload that records the policy it was judged against.
//
// Deliberately untagged (no //go:build !unit_test): no Dagger dependency, so
// licensereport_test.go can exercise the classification and the gate arithmetic
// under `go test -tags unit_test ./...`.
package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// License gate modes. The vocabulary is "gate" or "warn" and deliberately has no
// "off", copying coverageGate in src/quality/byotest.go: a check can be
// downgraded to advisory, never silenced. A consumer who could switch the scan
// off would get an envelope that says nothing rather than one that says
// "reported, not enforced".
const (
	licenseGateEnforce = "gate"
	licenseGateWarn    = "warn"
)

// Trivy's license categories, as they appear in the report's Category field.
//
// Listed as constants rather than matched as free strings so an allowlist entry
// can be validated against the closed set, and so a category Trivy adds in a
// future release fails validation loudly instead of being silently unmatched.
const (
	licenseForbidden    = "forbidden"
	licenseRestricted   = "restricted"
	licenseReciprocal   = "reciprocal"
	licenseNotice       = "notice"
	licensePermissive   = "permissive"
	licenseUnencumbered = "unencumbered"
	licenseUnknown      = "unknown"
)

// knownLicenseCategories is the closed set a Trivy report may carry, pinned
// against the real taxonomy by licensecategories_test.go.
var knownLicenseCategories = []string{
	licenseForbidden, licenseRestricted, licenseReciprocal,
	licenseNotice, licensePermissive, licenseUnencumbered, licenseUnknown,
}

// allowableLicenseCategories is the subset --license-allow accepts: every
// category except `unknown`.
//
// `unknown` is not a licence tier. It is Trivy answering "I could not classify
// this", so allowing it allows every future unclassifiable declaration too,
// including the one nobody has looked at yet — the off switch this module
// refuses to have, reached through the allowlist instead of through
// --ignored-licenses. It used to be allowable, and removing it is a deliberate
// breaking change: a consumer who had allowed it gets a hard error naming the
// route that replaces it, which is the by-name allowance in licenseallow.go.
// Failing loudly is the point — silently reinterpreting it would leave a
// pipeline reporting a policy nobody wrote.
var allowableLicenseCategories = []string{
	licenseForbidden, licenseRestricted, licenseReciprocal,
	licenseNotice, licensePermissive, licenseUnencumbered,
}

// defaultLicenseAllowlist is the policy applied when a consumer names none.
//
// A default is required, not a convenience. The policy is fail-closed — a
// category outside the allowlist is a finding — so an empty allowlist would flag
// every dependency including MIT. That is not strictness, it is an unusable
// check, and the first thing a consumer does with an unusable check is stop
// running it.
//
// The default screening policy allows permissive, notice and unencumbered
// categories without a finding. This is a screening choice, not a rights grant
// or a guarantee of suitability for a deliverable. Actual licence conditions,
// including applicable notice and attribution requirements, still require
// review and compliance.
//
// reciprocal is deliberately NOT here. In Trivy's taxonomy that category is
// MPL, EPL, CDDL, CPL, APSL, IPL and Ruby — file-level or module-level
// source-sharing obligations whose reach depends on how the artifact links and
// is distributed, which is a per-product legal judgement cicd cannot make on a
// consumer's behalf. Surfacing it is the point.
//
// This comment used to name LGPL as reciprocal, which is wrong against the
// table it claims to describe: Trivy files LGPL-2.0/2.1/3.0 under `restricted`
// alongside GPL-1.0/2.0/3.0, and AGPL-1.0/3.0 under `forbidden`. The error
// mattered because it made `--license-allow reciprocal` read as "accept the
// weak-copyleft tier" when it accepts neither LGPL nor GPL, and it hid the real
// cliff: the one category between reciprocal and forbidden is `restricted`, and
// allowing it accepts GPL. licensecategories_test.go pins the taxonomy against
// a fixture captured from the pinned Trivy's own category.go, so the next
// person to write a sentence about it is contradicted by a test rather than
// believed.
//
// This default is strict on purpose, and the reason it is safe is that
// licenseGateWarn is the default mode: a strict default in warn mode costs a
// report section and shows a consumer their true exposure immediately. The
// inverse — a permissive default — would read as clean until someone switched to
// gate, which is the worst moment to discover the real picture.
var defaultLicenseAllowlist = []string{licensePermissive, licenseNotice, licenseUnencumbered}

// licenseSeverity projects a category onto the severity scale the gate reads.
//
// Derived here rather than taken from Trivy's own Severity field, for the reason
// trivyflags.go gives for reading native JSON instead of CycloneDX ratings[]:
// the verdict's input belongs to cicd. Trivy's license severity is itself a
// projection of the category, so adopting it would make the gate's meaning move
// whenever upstream retuned that projection, silently and in either direction.
//
// An unrecognised category maps to HIGH rather than to LOW or to nothing. That
// is the fail-closed half of the policy: a license Trivy could not classify, or
// a category this module has never heard of, is exactly the case a compliance
// check exists to surface, so it must not be able to pass by being unfamiliar.
func licenseSeverity(category string) Severity {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case licenseForbidden:
		return SeverityCritical
	case licenseRestricted:
		return SeverityHigh
	case licenseReciprocal:
		return SeverityMedium
	case licenseNotice:
		return SeverityLow
	case licensePermissive, licenseUnencumbered:
		return SeverityLow
	default:
		return SeverityHigh
	}
}

// licenseEntry is one license Trivy attributed to a package or a file.
type licenseEntry struct {
	Name       string  `json:"Name"`
	Category   string  `json:"Category"`
	PkgName    string  `json:"PkgName"`
	FilePath   string  `json:"FilePath"`
	Confidence float64 `json:"Confidence"`
	Link       string  `json:"Link"`
}

// trivyLicenseDoc is the shape of Trivy's native license report.
//
// Licenses[] is read from every Results[] entry regardless of its Class. The
// pinned 0.70.0 puts license findings under Class "license" and leaves the
// parallel "lang-pkgs" entries empty, but filtering on that string would make
// this parser silently blind if a future release or a different artifact type
// files them elsewhere — and silently blind is the failure mode this whole
// module is built to refuse.
//
// SchemaVersion is read only to recognise the document. Trivy writes it on
// every report, a clean one included, while `{}` and `null` decode without
// error to a document with no results, which used to evaluate to zero licences
// scanned and a pass. sourceLicenseReport re-marshals this type, so the field
// also keeps the filtered source report recognisable.
type trivyLicenseDoc struct {
	SchemaVersion int `json:"SchemaVersion"`
	Results       []struct {
		Target   string         `json:"Target"`
		Class    string         `json:"Class"`
		Licenses []licenseEntry `json:"Licenses"`
	} `json:"Results"`
}

// licenseResult is what the license scan contributes: the findings that fell
// outside the policy, the counts the gate reads, and the payload written to the
// envelope's genericReport.
type licenseResult struct {
	Findings   []Finding
	BySeverity map[Severity]int
	// Scanned is every license judged against the policy, in policy or not.
	// Reported so a zero finding count can be told apart from a scan that saw
	// nothing at all.
	Scanned int
	// Excluded is every license a path pattern removed before judging. Kept
	// apart from Scanned rather than subtracted from it: a reader has to be
	// able to see that a filter ran, and how much it took, without comparing
	// this run against one that had no filter. Scanned+Excluded is everything
	// Trivy reported.
	Excluded int
	// AllowedByName is every declaration a named allowance covered. Kept apart
	// from Scanned for licenseexclude.go's reason, one door over: a reader has
	// to be able to see that an allowance fired, and how much it covered,
	// without diffing this run against one that had none.
	AllowedByName int
	// Coverage is the dependency packages Trivy listed and how many carry a
	// licence it read. Scanned cannot say it: a root LICENSE and a graph of
	// thirty-six modules with no licence metadata is one declaration either way.
	Coverage licenceCoverage
	Report   json.RawMessage
}

// licensePolicyWarning states the policy that produced a verdict.
//
// It lives here rather than inline in ScanLicenses so it is reachable under
// `-tags unit_test`: main.go is a Dagger entrypoint and excluded from that
// build, so a string assembled there is a string no test can read.
func licensePolicyWarning(pol licensePolicy, scanned, flagged int) string {
	origin := "caller"
	if pol.Defaulted {
		origin = "cicd default"
	}
	named := ""
	if len(pol.AllowedNames) > 0 {
		named = fmt.Sprintf(", allowed by name %s", strings.Join(pol.AllowedNames, ", "))
	}
	return fmt.Sprintf(
		"license policy: mode %s, allowed categories %s (%s)%s; %d license(s) scanned, %d outside policy",
		pol.Mode, strings.Join(pol.AllowedCategories, ", "), origin, named, scanned, flagged)
}

// licensePolicy is the effective policy, recorded in the evidence payload.
//
// It travels in the report rather than living only in the caller's arguments
// because a license verdict is otherwise unfalsifiable: "passed" with a
// permissive allowlist and "passed" with a strict one are the same word, and a
// reader with no record of which was applied cannot tell a clean tree from a
// policy that permitted everything. That is the conflation gating.go exists to
// prevent, one layer up.
type licensePolicy struct {
	AllowedCategories []string `json:"allowedCategories"`
	// AllowedNames is every named allowance, as the consumer wrote it. In the
	// payload beside the categories because the two together are the policy: a
	// reader who sees only the categories cannot tell a clean scan from one
	// where a declaration was named and accepted.
	AllowedNames []string `json:"allowedNames,omitempty"`
	Mode         string   `json:"mode"`
	Full         bool     `json:"licenseFull"`
	// FailOn is the severity the caller asked to fail on, recorded even in warn
	// mode — where the effective threshold is NONE — so the report says what was
	// requested as well as what was enforced.
	FailOn string `json:"failOn,omitempty"`
	// Defaulted records that the consumer named no allowlist, so a reader can
	// tell cicd's policy from the consumer's.
	Defaulted bool `json:"defaulted"`
}

// validateLicenseGate mirrors the coverage gate's validation in
// src/quality/byotest.go: an unrecognised mode is an error, not a fallback to
// the safer value. A typo silently becoming "warn" would downgrade an enforced
// gate, which is the direction that loses.
func validateLicenseGate(mode string) error {
	if mode != licenseGateEnforce && mode != licenseGateWarn {
		return fmt.Errorf("license-gate must be %q or %q, got %q",
			licenseGateEnforce, licenseGateWarn, mode)
	}
	return nil
}

// resolveLicenseAllowlist normalises a consumer's allowlist into the categories
// it names and the individual declarations it names, and rejects everything
// else.
//
// An entry that is neither errors rather than being dropped. Dropping it would
// fail in the safe direction — the real category stays unallowed, so findings
// increase — but it would do so while reporting a policy the consumer did not
// write, and a misspelled category is a config bug whose only symptom would be
// noise nobody could trace back to the typo.
//
// The two kinds share one flag because they answer one question: "what may this
// report contain without being a finding?". A second flag would let a consumer
// pass names and no categories and get cicd's default categories silently
// bolted on beside them — a policy nobody wrote, which is exactly what
// licensePolicy exists to make impossible.
//
// An allowlist naming ONLY declarations keeps the default categories, and says
// so through Defaulted. That is the shape the licence-policy report asked for: "the default policy,
// plus these three declarations I have read". A consumer who wants to replace
// the categories names them.
func resolveLicenseAllowlist(allowed []string) (licensePolicy, *licenseAllower, error) {
	pol := licensePolicy{}
	if len(allowed) == 0 {
		pol.AllowedCategories = append([]string(nil), defaultLicenseAllowlist...)
		pol.Defaulted = true
		return pol, newLicenseAllower(nil), nil
	}

	seen := map[string]bool{}
	var out []string
	var names []licenseAllowance
	for _, a := range allowed {
		raw := strings.TrimSpace(a)
		if raw == "" {
			continue
		}
		c := strings.ToLower(raw)
		if c == licenseUnknown {
			return licensePolicy{}, nil, fmt.Errorf(
				"license-allow names %q, which is not an allowable category: `unknown` is "+
					"Trivy reporting that it could not classify a declaration, so allowing it "+
					"would allow every future unclassifiable declaration too. Allow the "+
					"declarations you have read, by name — for example "+
					"--license-allow BlueOak-1.0.0 or "+
					"--license-allow 'example-sdk=SEE LICENSE IN LICENSE'. Allowable "+
					"categories are %s",
				raw, strings.Join(allowableLicenseCategories, ", "))
		}
		if licenseCategoryAllowable(c) {
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
			continue
		}
		allowance, err := parseLicenseAllowance(raw)
		if err != nil {
			return licensePolicy{}, nil, err
		}
		names = append(names, allowance)
	}
	if len(out) == 0 && len(names) == 0 {
		return licensePolicy{}, nil, fmt.Errorf(
			"license-allow was given but names no category or license; pass no value to use the default policy (%s)",
			strings.Join(defaultLicenseAllowlist, ", "))
	}
	if len(out) == 0 {
		// Named declarations only: the category policy is still cicd's, and the
		// payload has to say so or a reader would read the empty category list
		// as "nothing is allowed".
		out = append([]string(nil), defaultLicenseAllowlist...)
		pol.Defaulted = true
	}
	sort.Strings(out)
	pol.AllowedCategories = out
	al := newLicenseAllower(names)
	pol.AllowedNames = al.raws()
	return pol, al, nil
}

// licenseCategoryKnown reports whether a category may appear in a Trivy report.
func licenseCategoryKnown(c string) bool {
	for _, k := range knownLicenseCategories {
		if k == c {
			return true
		}
	}
	return false
}

// licenseCategoryAllowable reports whether --license-allow accepts a category.
// Deliberately a different set from licenseCategoryKnown: `unknown` is one
// Trivy emits and one no allowlist may name.
func licenseCategoryAllowable(c string) bool {
	for _, k := range allowableLicenseCategories {
		if k == c {
			return true
		}
	}
	return false
}

// evaluateLicenses classifies every license in the report against the policy.
//
// A license whose category is in the allowlist is counted as scanned and
// produces no finding. Everything else is a finding at the severity its category
// projects onto, including a category the allowlist could not name because
// nothing recognises it.
//
// A named allowance is checked AFTER the category, not before. The order is not
// an optimisation: a declaration already allowed by its category must not
// consume an allowance's hit, or an allowance that covers nothing new would
// report itself as working and never warn.
func evaluateLicenses(raw json.RawMessage, pol licensePolicy, ex *licenseExcluder, al *licenseAllower) (licenseResult, error) {
	var doc trivyLicenseDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return licenseResult{}, fmt.Errorf("parse trivy license report: %w", err)
	}
	if doc.SchemaVersion == 0 {
		return licenseResult{}, fmt.Errorf("parse trivy license report: %s carries no SchemaVersion, so it is not a Trivy report and no licence was read", trivyDocShape(raw))
	}

	coverage, err := readLicenceCoverage(raw, ex)
	if err != nil {
		return licenseResult{}, err
	}

	allowed := map[string]bool{}
	for _, c := range pol.AllowedCategories {
		allowed[c] = true
	}

	res := licenseResult{BySeverity: map[Severity]int{}, Coverage: coverage}
	byCategory := map[string]int{}
	type row struct {
		Name       string   `json:"name"`
		Category   string   `json:"category"`
		Severity   Severity `json:"severity"`
		Package    string   `json:"package,omitempty"`
		Path       string   `json:"path,omitempty"`
		Confidence float64  `json:"confidence,omitempty"`
		Link       string   `json:"link,omitempty"`
	}
	rows := []row{}

	for _, r := range doc.Results {
		for _, l := range r.Licenses {
			// Before Scanned++, so an excluded declaration is never counted as
			// one the policy judged. r.Target is the fallback because a license
			// read from package metadata carries no FilePath of its own — the
			// manifest it came from is the only path it has, and a pattern
			// naming a vendored subtree has to be able to reach it.
			if ex.match(licenseEntryPath(l, r.Target)) {
				res.Excluded++
				continue
			}
			res.Scanned++
			cat := strings.ToLower(strings.TrimSpace(l.Category))
			if cat == "" {
				cat = licenseUnknown
			}
			byCategory[cat]++
			if allowed[cat] {
				continue
			}
			if al.match(l.PkgName, l.Name) {
				res.AllowedByName++
				continue
			}
			sev := licenseSeverity(cat)
			res.BySeverity[sev]++
			where := l.PkgName
			if where == "" {
				where = l.FilePath
			}
			res.Findings = append(res.Findings, Finding{
				Severity:     sev,
				Tool:         "trivy-license",
				Rule:         "license/" + cat,
				Message:      licenseMessage(l.Name, cat, where),
				ArtifactPath: l.FilePath,
			})
			rows = append(rows, row{
				Name:       l.Name,
				Category:   cat,
				Severity:   sev,
				Package:    l.PkgName,
				Path:       l.FilePath,
				Confidence: l.Confidence,
				Link:       l.Link,
			})
		}
	}

	// The patterns go in the payload, not only their effect. A count of what
	// was removed is worth little without the rule that removed it: a reader
	// auditing this report has to be able to see WHICH paths were dropped, and
	// judge whether that was reasonable, without access to the pipeline
	// definition that set them.
	var excludePatterns []string
	if ex != nil {
		excludePatterns = ex.patterns
	}
	payload := struct {
		Policy          licensePolicy  `json:"policy"`
		Scanned         int            `json:"scanned"`
		Excluded        int            `json:"excluded"`
		ExcludePatterns []string       `json:"excludePatterns,omitempty"`
		AllowedByName   int            `json:"allowedByName"`
		AllowedNameHits map[string]int `json:"allowedNameHits,omitempty"`
		Flagged         int            `json:"flagged"`
		ByCategory      map[string]int `json:"byCategory"`
		// DependencyCoverage is in the payload, and its gaps in warnings[]
		// too, because buildCombined drops this payload from the audit bundle.
		DependencyCoverage licenceCoverage `json:"dependencyCoverage"`
		Findings           []row           `json:"findings"`
	}{
		Policy:             pol,
		Scanned:            res.Scanned,
		Excluded:           res.Excluded,
		ExcludePatterns:    excludePatterns,
		AllowedByName:      res.AllowedByName,
		AllowedNameHits:    al.hitsByAllowance(),
		Flagged:            len(rows),
		ByCategory:         byCategory,
		DependencyCoverage: coverage,
		Findings:           rows,
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return licenseResult{}, fmt.Errorf("marshal license report: %w", err)
	}
	res.Report = out
	return res, nil
}

// licenseMessage names the license, its category and where it was found, in that
// order, because the license is what a reader acts on and the category is why.
func licenseMessage(name, category, where string) string {
	if name == "" {
		name = "an undeclared license"
	}
	msg := fmt.Sprintf("%s is categorised %s, which the license policy does not allow", name, category)
	if where != "" {
		msg += " (" + where + ")"
	}
	return msg
}

// licenseEntryPath is the one path a license declaration has, for matching.
//
// FilePath when Trivy set it — a license read out of a LICENSE file or a source
// header names that file. Otherwise the Result's Target, which for a license
// read from package metadata is the manifest the package was declared in, and
// is the only location the declaration has at all. One location per declaration
// rather than matching against both: a pattern that can match either field
// excludes more than its author can predict, and the whole point of counting
// exclusions is that a reader can predict them.
func licenseEntryPath(l licenseEntry, target string) string {
	if p := strings.TrimSpace(l.FilePath); p != "" {
		return p
	}
	return strings.TrimSpace(target)
}
