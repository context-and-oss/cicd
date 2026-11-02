package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func buildCombined(modName, stage string, repo repoContext, envs []*envelope, start time.Time) *envelope {
	// The combined envelope describes the run, not the aggregation of it. See
	// combinedSpan for why its own clock is the wrong one to read.
	began, durationMS := combinedSpan(envs, start, time.Now())
	combined := &envelope{
		SchemaVersion: evidenceSchemaVersion,
		ModuleName:    modName,
		Stage:         stage,
		Tool:          toolInfo{Name: "cicd-evidence"},
		Repo:          repo,
		TimestampUTC:  began,
		DurationMS:    durationMS,
		Passed:        true,
	}
	seen := map[string]bool{}
	var ratchetFail, ratchetPass bool
	var ratchetSkipped string
	for _, e := range envs {
		for _, lang := range e.Languages {
			if !seen[lang] {
				seen[lang] = true
				combined.Languages = append(combined.Languages, lang)
			}
		}
		combined.FindingsCount += e.FindingsCount
		if !e.Passed || producedNoResult(e) {
			combined.Passed = false
		}
		for sev, cnt := range e.FindingsBySeverity {
			if combined.FindingsBySeverity == nil {
				combined.FindingsBySeverity = map[Severity]int{}
			}
			combined.FindingsBySeverity[sev] += cnt
		}
		// Percentage and coverable-line count are merged together, from the
		// SAME envelope, and that pairing is the whole point rather than a
		// tidiness preference. Both maps are last-writer-wins, so merging them
		// in separate loops would let one envelope supply a language's
		// percentage and a different one supply its line count — and a weighted
		// figure computed from a mismatched pair is not a slightly wrong number,
		// it is a number about no run that ever happened. Taking both from the
		// same envelope makes the pair unmergeable-apart by construction.
		//
		// A language whose envelope reports a percentage but no line count still
		// merges its percentage and contributes no count. That asymmetry is
		// deliberate and is what weightedCoveragePercent below keys off: a
		// per-language percentage is honest on its own, a weighted total is not
		// unless every language brought its weight.
		for lang, pct := range e.CoverageByLanguage {
			if combined.CoverageByLanguage == nil {
				combined.CoverageByLanguage = map[string]float64{}
			}
			combined.CoverageByLanguage[lang] = pct
			if lines, ok := e.CoverageLinesByLanguage[lang]; ok {
				if combined.CoverageLinesByLanguage == nil {
					combined.CoverageLinesByLanguage = map[string]int{}
				}
				combined.CoverageLinesByLanguage[lang] = lines
			} else if combined.CoverageLinesByLanguage != nil {
				// An earlier envelope's count for this language described an
				// earlier envelope's percentage. The percentage has just been
				// overwritten, so keeping the count would reconstitute exactly
				// the mismatched pair this block exists to prevent.
				delete(combined.CoverageLinesByLanguage, lang)
			}
		}
		// One map, holding whole values. There is deliberately no sibling map
		// to keep in step here — see the type comment on TestCounts, and the
		// coverage merge above for what the alternative costs.
		for lang, counts := range e.TestsByLanguage {
			if combined.TestsByLanguage == nil {
				combined.TestsByLanguage = map[string]TestCounts{}
			}
			combined.TestsByLanguage[lang] = counts
		}
		for lang, pct := range e.CoverageBaselineByLanguage {
			if combined.CoverageBaselineByLanguage == nil {
				combined.CoverageBaselineByLanguage = map[string]float64{}
			}
			combined.CoverageBaselineByLanguage[lang] = pct
		}
		// Ratchet verdict merge is fail-dominant: any "fail" wins, then any
		// "pass", then the first "skipped:*" reason; absent everywhere → absent.
		switch {
		case e.CoverageRatchet == "fail":
			ratchetFail = true
		case e.CoverageRatchet == "pass":
			ratchetPass = true
		case e.CoverageRatchet != "" && ratchetSkipped == "":
			ratchetSkipped = e.CoverageRatchet
		}
		combined.Warnings = append(combined.Warnings, e.Warnings...)
		combined.Errors = append(combined.Errors, e.Errors...)
		// The per-source verdict behind the combined AND, in input order —
		// without it a failed combined envelope cannot say which gate tripped.
		//
		// An envelope that already declares its OWN sources is a module fusing
		// several tools under one verdict (security.ScanSource runs Semgrep,
		// Gitleaks and Trivy behind `security-source`). Its rows are propagated
		// INSTEAD OF a row for the envelope, not in addition to one: the two
		// describe the same findings, so emitting both would double every count
		// for a consumer that sums the list. The envelope's own verdict is not
		// lost — it is the AND of the rows that replace it, by construction, and
		// the rows say which of them tripped, which the single row never could.
		combined.Sources = append(combined.Sources, envelopeRows(e)...)
	}
	switch {
	case ratchetFail:
		combined.CoverageRatchet = "fail"
	case ratchetPass:
		combined.CoverageRatchet = "pass"
	default:
		combined.CoverageRatchet = ratchetSkipped
	}
	combined.CoveragePercent, combined.CoverageLines = weightedCoverage(
		combined.CoverageByLanguage, combined.CoverageLinesByLanguage)
	combined.Tests = totalTestCounts(combined.TestsByLanguage, combined.Languages)
	combined.Findings = mergeFindings(envs)
	// The un-gated counterpart to combined.Passed, folded from the rows that
	// ship rather than from the envelopes, so the two cannot disagree about
	// which sources were counted. A module that fused several tools contributes
	// its per-tool rows here and its envelope-wide roll-up nowhere, which is
	// what the branch above already established for every other field.
	//
	// One source that states no outcome collapses this to unset — see
	// worstOutcome. That is the conservative reading and it is deliberate: the
	// alternative is a combined envelope reporting CLEAN over a run where one
	// module never said what it found.
	combined.Outcome = sourcesOutcome(combined.Sources)
	// Sources again, folded by the question each row answers, so a consumer
	// holding only this file can say "SAST clean, SCA failed" without a table
	// mapping scanners to modules. Folded here rather than in notify because
	// the bundle's concerns/ directory and the pull request comment are read
	// by the same person in the same sitting, and two folds of one set of rows
	// eventually disagree with nothing anywhere failing.
	combined.Concerns = concernReport(envs)
	return combined
}

// producedNoResult reports a part that says it ran to no usable result and
// says why, whatever its own passed field claims. Every workflow gate reads
// only the combined .passed, so a part that wrote passed:true beside ERROR — a
// native test leg whose runner exited non-zero with its accounting green, under
// --fail-on NONE — turned the whole run green with the reason sitting in
// errors[] where no gate looked.
//
// Both halves are required, and each one alone is wrong:
//   - errors[] alone: a real failing suite under NONE is FAILED with "go test
//     failed (exit 1)" in errors[] and passed:true, which is the documented
//     meaning of NONE and must stay a pass.
//   - ERROR alone: notify reports a Teams card it could not deliver as ERROR
//     with the reason in warnings[], and a lost notification must not redden
//     a pipeline whose gates all passed.
func producedNoResult(e *envelope) bool {
	return e.Outcome == OutcomeError && len(e.Errors) > 0
}

// weightedCoverage returns the repo-wide coverage percentage weighted by
// coverable lines, together with the line count it is a percentage of. Both are
// nil when the figure cannot be computed honestly.
//
// The two results are one claim — "this fraction, of this many lines" — so they
// are returned together rather than by two functions sharing a predicate. A
// caller cannot obtain the percentage without its denominator, and cannot
// publish a denominator for a percentage that was withheld.
//
// The reason this is not a plain average: an unweighted mean over per-language
// percentages is a fabricated number. A repository with 10 covered lines of 10
// in Go and 500 of 1000 in Node is at 51% overall, not at 75%, and the 75% is
// the figure a customer-facing report would print. So the weights are required,
// and the weights are the coverable-line counts merged above.
//
// It returns nil rather than a partial figure in three cases, all of which are
// "the inputs cannot support the claim". Note that the total is withheld in the
// same three cases and for the same reason: a sum over only the languages that
// reported counts is a denominator for part of the repository, and printed
// beside a percentage presented as the whole it invites a reader to multiply the
// two and recover a covered-line count that is simply wrong.
//
//   - Any language has a percentage but no line count. Weighting the subset
//     that does have counts silently redefines the number as being about part
//     of the repository while still presenting it as the whole, which is the
//     more dangerous failure precisely because it looks plausible.
//   - The total coverable-line count is zero. There is nothing to be a
//     percentage of, and 0% would read as "measured, and nothing is covered".
//   - No language reports coverage at all.
//
// Absent is a state a consumer can render honestly ("not measured"); a wrong
// number is not. This mirrors quality.Check's rule that a coverage gate which
// could not measure must never read as satisfied.
func weightedCoverage(byLang map[string]float64, linesByLang map[string]int) (*float64, *int) {
	if len(byLang) == 0 {
		return nil, nil
	}
	var totalLines int
	var coveredLines float64
	for lang, pct := range byLang {
		lines, ok := linesByLang[lang]
		if !ok {
			return nil, nil
		}
		totalLines += lines
		coveredLines += pct / 100 * float64(lines)
	}
	if totalLines == 0 {
		return nil, nil
	}
	pct := coveredLines / float64(totalLines) * 100
	return &pct, &totalLines
}

// totalTestCounts sums the per-language accounting into a repo-wide total, or
// returns nil when the sum would not describe the whole repository.
//
// Test counts are the mirror image of coverage percentages: they sum honestly,
// where an unweighted mean over percentages does not. So no weighting is needed
// and none is applied. What does carry over from weightedCoverage is the refusal
// to publish a partial figure as a whole one. A repository that tested Go and
// Node and could only count Go does not have "431 tests"; it has 431 plus an
// unknown number, and 431 is the figure a release report would print beside the
// word "total".
//
// languages is the set the run actually covered, and it is the only thing that
// makes the gap visible: a missing map entry is indistinguishable from a
// language that was never tested unless you know which were. When a language
// was tested and produced no accounting, the total is withheld and the
// per-language entries that do exist are left untouched — an accounted suite is
// honest on its own, exactly as a per-language coverage percentage is.
func totalTestCounts(byLang map[string]TestCounts, languages []string) *TestCounts {
	if len(byLang) == 0 {
		return nil
	}
	for _, lang := range languages {
		if _, ok := byLang[lang]; !ok {
			return nil
		}
	}
	var out TestCounts
	for _, c := range byLang {
		out.Total += c.Total
		out.Passed += c.Passed
		out.Failed += c.Failed
		out.Skipped += c.Skipped
		// Suites may run concurrently, so summing wall-clock overstates elapsed
		// time and taking a max understates the work. The sum is the honest
		// answer to "how much test time did this cost", which is the question a
		// duration in an aggregate is asked, and it is what the per-language
		// entries support if a consumer wants to disagree.
		out.DurationMS += c.DurationMS
	}
	return &out
}

// rawOutputFileName derives a filesystem-safe, unique name for the file that
// holds a failed step's captured stdout+stderr in the audit dir. It keys off
// the producing tool (falling back to the module name, then "step"), sanitises
// it with sanitiseNameSegment, and disambiguates collisions with a numeric
// suffix so two failed steps from the same tool don't clobber each other.
// `used` is mutated to record the returned name.
//
// The fallback is applied twice — before and after sanitising — because a name
// made entirely of punctuation sanitises to nothing, and "-output.txt" is a
// filename that names no step.
func rawOutputFileName(e *envelope, used map[string]bool) string {
	base := e.Tool.Name
	if base == "" {
		base = e.ModuleName
	}
	if base == "" {
		base = "step"
	}
	base = sanitiseNameSegment(base)
	if base == "" {
		base = "step"
	}
	name := base + "-output.txt"
	for i := 2; used[name]; i++ {
		name = fmt.Sprintf("%s-output-%d.txt", base, i)
	}
	used[name] = true
	return name
}

// mergeFindings extracts a normalised, human-readable detail list from each
// module's SARIF and genericReport payloads. The combined FindingsBySeverity
// counts remain authoritative for the gate decision; this list is best-effort
// detail so the combined evidence, PR comment, job summary and CI gate step
// can show *what* tripped the gate, not just how many.
//
// It understands the three finding-bearing shapes in this repo: SARIF results
// (quality lint, security scans), the intent-gate genericReport, and the
// ctx-risk-validate genericReport. Payloads it cannot parse are skipped — the
// counts still carry the signal.
//
// A module may also state its findings outright in envelope.Findings, and those
// are taken as given rather than re-derived. That is not a convenience: the
// security module's vulnerability severities cannot be recovered from either
// payload it ships. CycloneDX carries a bag of per-vendor `ratings[]` and no
// verdict, and `trivy convert --format sarif` maps critical and high both onto
// level "error", so deriving here would render every CRITICAL vulnerability as a
// HIGH row underneath a CRITICAL count. Until this read them, Trivy findings
// reached no detail list at all — a vulnerability-only failure showed a count
// with an empty table.
//
// Every row leaves here tagged with the class of the module whose envelope it
// came out of — the one moment the producer is known — and the list is then
// deduplicated and written in the total order compareFindings defines:
// severity first, then class, then every remaining field. The order is what
// capFindings and notify's 25-row table both truncate, so it decides which
// rows a reader sees when a run has more than fit; see findingorder.go for
// why "most severe first" alone was not enough.
func mergeFindings(envs []*envelope) []Finding {
	var out []classedFinding
	for _, e := range envs {
		class := findingClassOf(e.ModuleName)
		add := func(rows []Finding) {
			for _, f := range rows {
				out = append(out, classedFinding{Finding: f, class: class})
			}
		}
		add(e.Findings)
		add(sarifFindings(e.SARIFReport))
		switch e.GenericFormat {
		case "intent-gate":
			add(intentFindings(e.GenericReport))
		case "ctx-risk-validate/1.0":
			// Risk envelopes predating their SARIF producer carry findings only
			// in genericReport, so retain that reader for old evidence. New
			// envelopes describe the same rows in both channels; prefer SARIF,
			// which carries policy identity and location into findings.sarif,
			// rather than rendering every policy violation twice here.
			if len(e.SARIFReport) == 0 {
				add(riskFindings(e.GenericReport))
			}
		}
	}
	// A module that both states a finding and ships a payload describing the same
	// one would otherwise show it twice. Deduplicating is cheaper than requiring
	// every producer to pick exactly one channel, and a duplicated row is a
	// reporting bug a reader cannot tell from two genuine findings at one site.
	return orderFindings(out)
}

func sarifFindings(raw json.RawMessage) []Finding {
	if len(raw) == 0 {
		return nil
	}
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID                   string `json:"id"`
						DefaultConfiguration struct {
							Level string `json:"level"`
						} `json:"defaultConfiguration"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID       string `json:"ruleId"`
				RuleIndex    *int   `json:"ruleIndex"`
				Level        string `json:"level"`
				Kind         string `json:"kind"`
				Suppressions []struct {
					Status string `json:"status"`
				} `json:"suppressions"`
				Properties struct {
					CICDSeverity string `json:"cicdSeverity"`
				} `json:"properties"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						// SARIF 2.1.0 §3.30.5. Every producer upstream of here
						// already emits it — eslint, pylint, the dotnet reports
						// and gitleaks' own SARIF all set region.startLine — and
						// dropping it on the way in is what made two findings in
						// one file indistinguishable.
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	var out []Finding
	for _, run := range doc.Runs {
		rules := run.Tool.Driver.Rules
		ruleLevel := make(map[string]string, len(rules))
		for _, rule := range rules {
			ruleLevel[rule.ID] = rule.DefaultConfiguration.Level
		}
		for _, r := range run.Results {
			// SARIF 2.1.0 §3.35.3: an absent suppression status means
			// accepted, as does the explicit "accepted" value. Semgrep uses
			// this for nosemgrep. Pending and rejected decisions remain visible.
			suppressed := false
			for _, suppression := range r.Suppressions {
				if acceptedSuppression(suppression.Status) {
					suppressed = true
					break
				}
			}
			if suppressed {
				continue
			}
			// SARIF 2.1.0 §3.27.10: an absent result.level inherits the
			// producing rule's defaultConfiguration.level. Semgrep OSS relies on
			// that entirely — it sets no level on results — so without this
			// every SAST row rendered as the bare default.
			level := r.Level
			if level == "" {
				switch {
				case r.Kind != "" && r.Kind != "fail":
					// §3.27.9: a non-"fail" result is not a failure.
					level = "none"
				case ruleLevel[r.RuleID] != "":
					level = ruleLevel[r.RuleID]
				case r.RuleIndex != nil && *r.RuleIndex >= 0 && *r.RuleIndex < len(rules):
					level = rules[*r.RuleIndex].DefaultConfiguration.Level
				}
			}
			severity := sarifLevelToSeverity(level)
			if stated := Severity(strings.ToUpper(strings.TrimSpace(r.Properties.CICDSeverity))); severityOrder(stated) != 0 {
				severity = stated
			}
			f := Finding{
				Severity: severity,
				Tool:     run.Tool.Driver.Name,
				Rule:     r.RuleID,
				Message:  r.Message.Text,
			}
			if len(r.Locations) > 0 {
				phys := r.Locations[0].PhysicalLocation
				f.ArtifactPath = phys.ArtifactLocation.URI
				// A negative or zero startLine is "the tool did not say", and
				// 0 is the zero value already — never invent line 1.
				if phys.Region.StartLine > 0 {
					f.Line = phys.Region.StartLine
				}
			}
			out = append(out, f)
		}
	}
	return out
}

func intentFindings(raw json.RawMessage) []Finding {
	if len(raw) == 0 {
		return nil
	}
	var rpt struct {
		Findings []struct {
			Rule         string `json:"rule"`
			Severity     string `json:"severity"`
			ArtifactPath string `json:"artifactPath"`
			Message      string `json:"message"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &rpt); err != nil {
		return nil
	}
	out := make([]Finding, 0, len(rpt.Findings))
	for _, f := range rpt.Findings {
		out = append(out, Finding{
			Severity:     intentSeverityToSeverity(f.Severity),
			Tool:         "intent-gate",
			Rule:         f.Rule,
			Message:      f.Message,
			ArtifactPath: f.ArtifactPath,
		})
	}
	return out
}

func riskFindings(raw json.RawMessage) []Finding {
	if len(raw) == 0 {
		return nil
	}
	var rpt struct {
		Violations []struct {
			Msg      string `json:"msg"`
			Severity string `json:"severity"`
			PolicyID string `json:"policyId"`
			File     string `json:"file"`
		} `json:"violations"`
	}
	if err := json.Unmarshal(raw, &rpt); err != nil {
		return nil
	}
	out := make([]Finding, 0, len(rpt.Violations))
	for _, v := range rpt.Violations {
		sev := Severity(strings.ToUpper(strings.TrimSpace(v.Severity)))
		if severityOrder(sev) == 0 {
			sev = SeverityHigh
		}
		out = append(out, Finding{
			Severity:     sev,
			Tool:         "risk-validate",
			Rule:         v.PolicyID,
			Message:      strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v.Msg), "-")),
			ArtifactPath: v.File,
		})
	}
	return out
}

// sarifLevelToSeverity maps an *already resolved* SARIF level to a canonical
// severity. Callers must resolve rule-inherited levels first (see sarifFindings)
// — passing a raw result.level through here treats "absent" as "unspecified" and
// buckets real findings at the default. The empty/unknown case returns MEDIUM to
// match the spec's "warning" default, keeping these detail severities in step
// with each module's FindingsBySeverity counts.
func sarifLevelToSeverity(level string) Severity {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error":
		return SeverityHigh
	case "warning":
		return SeverityMedium
	case "note", "info", "none":
		return SeverityLow
	}
	return SeverityMedium
}

// intentSeverityToSeverity mirrors the intent module's mapRuleSeverity
// (error→HIGH, warn→MEDIUM, info→LOW) so detail severities match the counts.
func intentSeverityToSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "error":
		return SeverityHigh
	case "warn":
		return SeverityMedium
	default:
		return SeverityLow
	}
}

type sarifDocument struct {
	Version string            `json:"version"`
	Schema  string            `json:"$schema"`
	Runs    []json.RawMessage `json:"runs"`
}

func mergeSARIF(envs []*envelope) sarifDocument {
	doc := sarifDocument{
		Version: "2.1.0",
		Schema:  "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
		// SARIF requires runs to be an array. DAST currently contributes its
		// findings through the generic report, so a DAST-only bundle has no SARIF
		// runs to merge. Keep that valid and iterable instead of encoding a nil
		// slice as JSON null, which github/codeql-action/upload-sarif rejects.
		Runs: []json.RawMessage{},
	}
	for _, e := range envs {
		if e.SARIFReport == nil {
			continue
		}
		var src struct {
			Runs []json.RawMessage `json:"runs"`
		}
		if err := json.Unmarshal(e.SARIFReport, &src); err == nil {
			for _, r := range src.Runs {
				doc.Runs = append(doc.Runs, withoutAcceptedResults(r))
			}
		}
	}
	doc.Runs = uniqueRunIdentities(doc.Runs)
	return doc
}

// acceptedSuppression is SARIF 2.1.0 §3.35.3: an absent status means accepted,
// as does the explicit "accepted". underReview and rejected stay active.
func acceptedSuppression(status string) bool {
	return status == "" || status == "accepted"
}

// withoutAcceptedResults drops every result an accepted suppression covers
// from a run bound for findings.sarif. GitHub Code Scanning ignores
// result.suppressions on a third-party upload, so an accepted result there is
// an open alert, and a pull request touching the file fails the code scanning
// check on a decision the repository already recorded — a gate the consumer
// cannot clear except by dismissing alerts by hand. The acceptance stays
// readable where it was disclosed: the producing module's warnings[] and its
// native SARIF under parts/. A run that keeps all its results keeps its bytes;
// a run that cannot be parsed passes through, because filtering must never
// cost a finding. A run left with no results still uploads, with results: [],
// so the alerts an earlier upload opened are closed.
func withoutAcceptedResults(run json.RawMessage) json.RawMessage {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(run, &fields); err != nil {
		return run
	}
	rawResults, ok := fields["results"]
	if !ok {
		return run
	}
	var results []json.RawMessage
	if err := json.Unmarshal(rawResults, &results); err != nil {
		return run
	}
	kept := make([]json.RawMessage, 0, len(results))
	for _, r := range results {
		var probe struct {
			Suppressions []struct {
				Status string `json:"status"`
			} `json:"suppressions"`
		}
		if err := json.Unmarshal(r, &probe); err != nil {
			kept = append(kept, r)
			continue
		}
		accepted := false
		for _, s := range probe.Suppressions {
			if acceptedSuppression(s.Status) {
				accepted = true
				break
			}
		}
		if !accepted {
			kept = append(kept, r)
		}
	}
	if len(kept) == len(results) {
		return run
	}
	encoded, err := json.Marshal(kept)
	if err != nil {
		return run
	}
	fields["results"] = encoded
	out, err := json.Marshal(fields)
	if err != nil {
		return run
	}
	return out
}

// runIdentity is what GitHub Code Scanning keys a SARIF run on since
// 2025-07-22: the tool driver name plus the analysis category. The category of
// a run is its own automationDetails.id when present; the upload step's
// `category:` input fills it only where absent, so within one file "absent"
// is itself one shared value.
type runIdentity struct {
	tool string
	id   string
}

// uniqueRunIdentities makes findings.sarif structurally unable to trip
// GitHub's same-identity rejection: two runs colliding on (tool, category)
// fail the entire upload, and because the upload step must tolerate repos
// without Advanced Security, a refused file reads exactly like a repository
// with nothing to report.
//
// Producers stamp meaningful ids at the source, where the project directory is
// known (quality's stampSARIFAutomationID) — this is the backstop at the one
// seam every run passes through, so a future producer that forgets cannot
// reintroduce the silent loss. The first run of each identity keeps its bytes
// untouched (its alerts stay keyed as they always were); later collisions get
// a deterministic ordinal suffix. A run that cannot be parsed passes through
// unmodified — rewriting is cosmetic and must never cost a finding.
func uniqueRunIdentities(runs []json.RawMessage) []json.RawMessage {
	if len(runs) < 2 {
		return runs
	}
	used := map[runIdentity]bool{}
	out := make([]json.RawMessage, 0, len(runs))
	for _, raw := range runs {
		var probe struct {
			Tool struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
			AutomationDetails struct {
				ID string `json:"id"`
			} `json:"automationDetails"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			out = append(out, raw)
			continue
		}
		key := runIdentity{probe.Tool.Driver.Name, probe.AutomationDetails.ID}
		if !used[key] {
			used[key] = true
			out = append(out, raw)
			continue
		}
		// Collision. Suffix an ordinal onto the existing id — or synthesise one
		// from the tool name when the run had none — and keep bumping until the
		// result is itself unused, so a rewrite can never collide with an id a
		// producer chose.
		base := key.id
		if base == "" {
			tool := key.tool
			if tool == "" {
				tool = "unnamed-tool"
			}
			base = "cicd/" + tool
		}
		n := 2
		newKey := runIdentity{key.tool, fmt.Sprintf("%s/%d", base, n)}
		for used[newKey] {
			n++
			newKey = runIdentity{key.tool, fmt.Sprintf("%s/%d", base, n)}
		}
		used[newKey] = true
		out = append(out, rewriteRunAutomationID(raw, newKey.id))
	}
	return out
}

// rewriteRunAutomationID sets automationDetails.id on a single raw run,
// preserving every other property. Any failure returns the original bytes:
// the caller then ships a collision GitHub will refuse, but a refused upload
// with the findings intact in the artifact beats a rewritten report that
// dropped one.
func rewriteRunAutomationID(raw json.RawMessage, id string) json.RawMessage {
	var run map[string]any
	if err := json.Unmarshal(raw, &run); err != nil {
		return raw
	}
	details, ok := run["automationDetails"].(map[string]any)
	if !ok {
		details = map[string]any{}
	}
	details["id"] = id
	run["automationDetails"] = details
	out, err := json.Marshal(run)
	if err != nil {
		return raw
	}
	return out
}

// envelopeRows is the per-source verdicts one envelope contributes to the
// combined list: its own rows if it declares any, otherwise a single row
// standing for the envelope.
//
// An envelope that already declares its OWN sources is a module fusing several
// tools under one verdict (security.ScanSource runs Semgrep, Gitleaks and Trivy
// behind `security-source`). Its rows are propagated INSTEAD OF a row for the
// envelope, not in addition to one: the two describe the same findings, so
// emitting both would double every count for a consumer that sums the list. The
// envelope's own verdict is not lost — it is the AND of the rows that replace
// it, by construction, and the rows say which of them tripped, which the single
// row never could.
//
// It is a function rather than an inline branch because the concern index needs
// the same answer, walking the same envelopes. Two copies of this rule would
// eventually disagree, and the disagreement would be invisible: a bundle whose
// concerns/ counts a fused module once and whose combined-evidence.json counts
// it three times is internally inconsistent with nothing anywhere failing.
func envelopeRows(e *envelope) []SourceStatus {
	if len(e.Sources) > 0 {
		return e.Sources
	}
	return []SourceStatus{{
		ModuleName: e.ModuleName,
		Stage:      e.Stage,
		Tool:       e.Tool.Name,
		Passed:     e.Passed,
		// Propagated, never derived. passed, findingsCount and errors[]
		// cannot tell "the tests failed" from "the scanner crashed" from
		// "it found things" — under `fail-on: NONE` passed cannot even
		// tell those from "nothing happened" — so anything computed here
		// would be a guess wearing a verdict's clothes. An envelope from
		// a producer that states no outcome propagates none.
		Outcome: e.Outcome,
		// Propagated for the same reason as Outcome, and the reason is
		// sharpest here: a concern derived from Tool.Name would file
		// build's Trivy (which generates the SBOM) under the same concern
		// as security's Trivy (which scans one). Absent, the row is
		// reported as unclassified, which is a fact a reader can act on;
		// wrong, it silently relocates a whole section of the report.
		Concern: e.Concern,
		// Propagated for the same reason as Outcome: nothing here can
		// reconstruct how much a scanner looked at, and a denominator
		// this layer invented would be worse than none.
		Examined:      e.Examined,
		FindingsCount: e.FindingsCount,
		ErrorsCount:   len(e.Errors),
		WarningsCount: len(e.Warnings),
	}}
}
