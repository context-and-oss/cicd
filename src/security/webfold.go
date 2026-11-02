package main

import (
	"encoding/json"
	"fmt"
	"time"
)

// specScope reads the two scope facts cicd takes from the API document it
// could read: the operation count and the declared paths. Both come back
// empty, with a warning, when the document was unreadable or uncountable.
//
// A warning and not an error, because ZAP may have read what cicd could not;
// that is a gap in cicd's accounting rather than in the scan. What must never
// happen is silence: an envelope with no endpoint count must say why.
func specScope(spec []byte, specErr error) (endpoints *int, paths []string, warnings []string) {
	if specErr != nil {
		return nil, nil, []string{"dast: API document unreadable, so no endpoint count is reported: " + specErr.Error()}
	}
	if len(spec) == 0 {
		return nil, nil, nil
	}
	n, err := countOpenAPIOperations(spec)
	if err != nil {
		return nil, nil, []string{"dast: API document could not be counted, so no endpoint count is reported: " + err.Error()}
	}
	return &n, openAPIPaths(spec), nil
}

// notScannedWarning is the one line that separates a target that never
// answered from a clean one. It is a warning and not an error because the
// readiness verdict already sits in errors[]; this names the consequence.
func notScannedWarning() string {
	return "dast: NOT SCANNED — the readiness probe never got a served response, " +
		"so ZAP was not run at all. A scan of a target that was never reached would report zero alerts."
}

// zapResult is one ZAP invocation: what it wrote, and how it ended.
type zapResult struct {
	Raw      json.RawMessage
	ExitCode int
	Args     []string
	Duration time.Duration
	// Stdout and Stderr are the invocation's two streams, carried out whole so
	// the caller can keep a tail of them in the evidence. zapFailureDetail
	// reads the same bytes for its one-line summary; see zapLogTail for why one
	// line is not enough.
	Stdout string
	Stderr string
	// StartAndPassiveBudgetSeconds is the -T the packaged scan actually ran
	// under, including the value it defaults to when cicd passes none, and
	// StartAndPassiveBudgetDefaulted says which of the two it was.
	StartAndPassiveBudgetSeconds   int
	StartAndPassiveBudgetDefaulted bool
	// URLDump is the raw contents of the file the --hook module wrote: ZAP's
	// own site tree, or the reason it could not be read. Carried out
	// unparsed so the one place that decides what a missing dump means is the
	// caller, which is also the place that knows whether the scan completed.
	URLDump string
	// Import is what ZAP's own log said about the API document it was
	// handed. Carried out as the three raw pieces the script produced, for
	// the same reason URLDump is: the caller decides what they mean.
	Import zapImportProbe
	// AddOnStatus is which of zapaddons.go's three answers applied to the
	// pinned pscanrulesBeta artifact. Empty when the status file could not be
	// read at all, which zapAddOnStatus folds into "missing" — cicd not
	// knowing whether the rules loaded is the same disclosure as knowing they
	// did not, and the opposite of silence.
	AddOnStatus string
}

// zapFold is what one ZAP invocation folds into: the payload with every
// fact the run established, the parsed report (zero-valued when the run left
// none), the argv the envelope records, and the errors[] and warnings[] lines
// the run earned, in the order they were earned.
type zapFold struct {
	Payload  dastPayload
	Parsed   zapParsed
	ScanArgs []string
	Errs     []string
	Warnings []string
}

// foldZAPRun turns a ZAP invocation into the facts the envelope states.
//
// payload is the pre-scan payload: mode, source, target, readiness, the rule
// settings as parsed, and the document scope from specScope. spec is the API
// document cicd read, needed for the reach reconciliation. alertCap is the
// per-rule passive alert cap of the pinned image (zapPassiveAlertCapPerRule).
//
// The order inside is the order the disclosures depend on each other, and
// the comments say which line depends on which. ScanCompleted is set in
// exactly one place and only when both the exit status and the report were
// acceptable; a partial report written before a crash satisfies neither.
func foldZAPRun(res zapResult, runErr error, payload dastPayload, spec []byte, alertCap int) zapFold {
	f := zapFold{Payload: payload, ScanArgs: res.Args}
	p := &f.Payload

	p.ZapExitCode = res.ExitCode
	p.ScanDurationSeconds = int(res.Duration.Seconds())
	p.StartAndPassiveBudgetSeconds = res.StartAndPassiveBudgetSeconds
	p.StartAndPassiveBudgetDefaulted = res.StartAndPassiveBudgetDefaulted
	p.PassiveRuleAddOn = res.AddOnStatus
	// Recorded and judged before anything about the scan's outcome, because
	// it is a fact about what the scanner *was*, not about what it found. A
	// reader comparing two envelopes needs to know the rule sets differed
	// before they compare the finding counts.
	if msg := zapAddOnError(res.AddOnStatus); msg != "" {
		f.Errs = append(f.Errs, msg)
	}
	if msg := zapAddOnWarning(res.AddOnStatus); msg != "" {
		f.Warnings = append(f.Warnings, msg)
	}
	// The mark zapLogFor reads. Everything appended to Errs from here to the
	// end is this invocation's doing, and any one of them makes the run the
	// rare one whose log is worth carrying.
	errsBeforeScan := len(f.Errs)
	if runErr != nil {
		f.Errs = append(f.Errs, runErr.Error())
	} else if parsed, parseErr := parseZAPReport(res.Raw); parseErr != nil {
		f.Errs = append(f.Errs, "zap: "+parseErr.Error())
	} else {
		f.Parsed = parsed
		// Keep ZAP's alert document, but not its unbounded request and
		// response captures. Those bytes duplicate the normalized findings
		// and can make a modest scan produce an envelope too large for
		// Dagger to return or export.
		p.ZapReport = compactZAPReport(res.Raw)
		// The one place ScanCompleted is set. It requires both that ZAP
		// exited a status zapRunError accepts and that the report it left
		// parsed — a partial report written before a crash satisfies
		// neither, and this flag is what the disclosures read instead of
		// the alert count.
		p.ScanCompleted = true
		p.URLsWithAlerts = parsed.URLsWithAlerts
		p.RuleSettings = markFiredRules(payload.RuleSettings, parsed.FiredRuleIDs)
		// The cap is a property of the image, so it is recorded on every
		// completed scan whether or not a rule reached it: the list below
		// is only readable beside the number it is a list of.
		p.PassiveAlertCapPerRule = alertCap
		p.RulesAtAlertCap = rulesAtAlertCap(parsed.AlertsByRule, alertCap)
	}
	// Read from the streams whatever the verdict, because the scope counts
	// are as informative about a scan that died as about one that finished
	// — an exit 3 with "Number of Imported URLs: 1" in the log says which
	// of the two failures happened. They are separate from zapLogFor for
	// the reason that function gives for dropping the log on a good run:
	// these are two integers, not tens of thousands of INFO lines.
	scope := parseZAPScope(res.Stdout, res.Stderr)
	p.URLsRequested = scope.Requested
	p.URLsImported = scope.Imported

	// Whether ZAP refused the document, read before the reconciliation so
	// that a refusal is stated as itself rather than inferred from its
	// consequence. apiReachError below reports the same run as having
	// reached nothing, which is true and is the symptom; this is the cause,
	// and a reader needs the cause to know whose problem it is. Both are
	// kept: neither implies the other, since a document ZAP accepted can
	// still go unreached.
	p.APIImport = zapImportBuildReport(res.Import)
	if msg := zapImportError(p.APIImport); msg != "" {
		f.Errs = append(f.Errs, msg)
	}
	if msg := zapImportProbeWarning(res.Import); msg != "" {
		f.Warnings = append(f.Warnings, msg)
	}

	// The reconciliation: set the paths the document declares against the
	// URLs ZAP actually requested. It needs both lists, so it runs only when
	// cicd could read the document (APIPaths) and the scan finished
	// (ScanCompleted). A scan that did not finish already carries an
	// errors[] entry, and reporting that its endpoints went unreached as
	// well would be the same silence counted twice.
	if p.ScanCompleted && len(p.APIPaths) > 0 {
		dump, dumpErr := parseZAPURLDump(res.URLDump)
		if dumpErr != nil {
			// A warning and not an error, for the reason fetchAPISpecContents
			// gives for its own failures: the scan ran, and cicd's instrument
			// for measuring it did not. What must never happen is silence —
			// without this line an envelope with no apiReach block is
			// indistinguishable from one produced before this check existed.
			f.Warnings = append(f.Warnings, "dast: ENDPOINT RECONCILIATION NOT RUN — cicd could not read "+
				"ZAP's own list of requested URLs, so this envelope does not say which declared endpoints "+
				"were reached: "+dumpErr.Error())
		} else {
			// TargetURL is both halves of the comparison: the origin a
			// requested URL must share to count as reach, and the path
			// prefix ZAP puts in front of every declared path when it is
			// handed to the importer as -O.
			requested, unparsed, offOrigin := requestedAPIPaths(dump.URLs, p.TargetURL)
			prefixes := apiReachPrefixes(spec, p.TargetURL)
			reach := reconcileAPIReach(p.APIPaths, prefixes, requested)
			reach.Unparsed = unparsed
			reach.OffOrigin = offOrigin
			p.APIReach = newAPIReachReport(reach, prefixes, dump.Trigger)
			if msg := apiReachError(reach); msg != "" {
				f.Errs = append(f.Errs, msg)
			}
			f.Warnings = append(f.Warnings, apiReachWarnings(reach)...)
		}
	}
	// Kept last so it sees every verdict this fold reached, the
	// reconciliation's included. Moving it earlier is what made the
	// prompting run unexplainable: the streams were dropped as a completed
	// scan's before apiReachError had said that the scan reached nothing.
	p.ZapLog = zapLogFor(p.ScanCompleted, len(f.Errs) > errsBeforeScan, res.Stdout, res.Stderr)
	return f
}

// buildWebEnvelope states the DAST verdict. ZAP is one tool under its own
// envelope, so there are no rows to fold: the envelope IS the tool and states
// its outcome directly. ran is false the moment errors[] is non-empty — the
// readiness probe, the add-on check, the run itself, the document import and
// the reach reconciliation all land there, and any one of them fails the gate
// at every threshold, NONE included.
func buildWebEnvelope(f zapFold, repo repoContext, threshold Severity, start time.Time, warnings, errs []string) (*envelope, error) {
	bySeverity := f.Parsed.BySeverity
	if bySeverity == nil {
		bySeverity = map[Severity]int{}
	}
	total := 0
	for _, c := range bySeverity {
		total += c
	}

	ran := len(errs) == 0
	severityOK := !shouldFail(bySeverity, threshold)

	reportJSON, err := json.Marshal(f.Payload)
	if err != nil {
		return nil, fmt.Errorf("marshal dast report: %w", err)
	}

	scanArgs := f.ScanArgs
	if len(scanArgs) == 0 {
		scanArgs = []string{f.Payload.Mode, f.Payload.TargetURL}
	}

	env := &envelope{
		SchemaVersion:  evidenceSchemaVersion,
		ModuleName:     moduleName,
		Stage:          moduleStage,
		Tool:           toolInfo{Name: "zap", Version: zapVersion, Args: scanArgs},
		Repo:           repo,
		TimestampUTC:   start.UTC(),
		DurationMS:     time.Since(start).Milliseconds(),
		Passed:         gatedPassed(ran, severityOK, threshold),
		Concern:        ConcernDAST,
		FailOnSeverity: threshold,
		Findings:       f.Parsed.Findings,
		FindingsCount:  total,
		// The one scope field that survives aggregation: cross-cutting/evidence
		// drops genericReport and propagates Examined verbatim, so without this
		// the DAST row in combined-evidence.json and in the PR comment reads
		// "not stated" no matter how much the payload knows.
		Examined:           zapExamined(f.Payload.URLsRequested),
		FindingsBySeverity: bySeverity,
		GenericReport:      json.RawMessage(reportJSON),
		GenericFormat:      dastReportFormat,
		Warnings:           warnings,
		Errors:             errs,
	}
	env.Outcome = scanOutcome(ran, total)
	return env, nil
}
