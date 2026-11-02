package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// zapCleanReport is a report with one alert at risk 1 (Low) on one URL.
const zapLowReport = `{"site":[{"@name":"http://app/","alerts":[{` +
	`"pluginid":"10021","name":"Header missing","riskcode":"1","count":"1",` +
	`"instances":[{"uri":"http://app/a","method":"GET","param":"header"}]}]}]}`

func webPayload() dastPayload {
	return dastPayload{
		Mode:      webModeBaseline,
		Source:    "service",
		TargetURL: "http://app:8080/",
		Readiness: readinessResult{OK: true},
		RuleSettings: []zapRuleSetting{
			{ID: "10021", Action: "WARN"},
		},
	}
}

func TestSpecScope(t *testing.T) {
	t.Run("an unreadable document warns and reports no count", func(t *testing.T) {
		n, paths, w := specScope(nil, errors.New("fetch: 404"))
		if n != nil || paths != nil {
			t.Fatalf("count=%v paths=%v; want neither", n, paths)
		}
		if len(w) != 1 || !strings.Contains(w[0], "API document unreadable") || !strings.Contains(w[0], "fetch: 404") {
			t.Fatalf("warnings = %q", w)
		}
	})
	t.Run("no document is silence, not a warning", func(t *testing.T) {
		n, paths, w := specScope(nil, nil)
		if n != nil || paths != nil || w != nil {
			t.Fatalf("got %v %v %q; want nothing", n, paths, w)
		}
	})
	t.Run("a document that cannot be counted warns", func(t *testing.T) {
		_, _, w := specScope([]byte("not a document"), nil)
		if len(w) != 1 || !strings.Contains(w[0], "could not be counted") {
			t.Fatalf("warnings = %q", w)
		}
	})
	t.Run("a readable document yields its count and paths", func(t *testing.T) {
		spec := []byte(`{"openapi":"3.0.0","paths":{"/a":{"get":{}},"/b":{"get":{},"post":{}}}}`)
		n, paths, w := specScope(spec, nil)
		if w != nil {
			t.Fatalf("warnings = %q", w)
		}
		if n == nil || *n != 3 {
			t.Fatalf("count = %v; want 3", n)
		}
		if len(paths) != 2 {
			t.Fatalf("paths = %v", paths)
		}
	})
}

func TestFoldZAPRunCompletedScan(t *testing.T) {
	res := zapResult{
		Raw:         json.RawMessage(zapLowReport),
		ExitCode:    2,
		Args:        []string{"zap-baseline.py", "-t", "http://app:8080/"},
		Duration:    90 * time.Second,
		Stdout:      "Total of 7 URLs\n",
		Import:      zapImportProbe{Status: 1},
		AddOnStatus: zapAddOnStatusOK,
	}
	f := foldZAPRun(res, nil, webPayload(), nil, 10)

	if len(f.Errs) != 0 {
		t.Fatalf("errs = %q", f.Errs)
	}
	p := f.Payload
	if !p.ScanCompleted {
		t.Fatal("ScanCompleted false on a parsed report")
	}
	if p.ZapExitCode != 2 || p.ScanDurationSeconds != 90 {
		t.Fatalf("exit=%d duration=%d", p.ZapExitCode, p.ScanDurationSeconds)
	}
	if p.URLsRequested == nil || *p.URLsRequested != 7 {
		t.Fatalf("URLsRequested = %v; want 7", p.URLsRequested)
	}
	if p.URLsWithAlerts != 1 || len(f.Parsed.Findings) != 1 || f.Parsed.BySeverity[SeverityLow] != 1 {
		t.Fatalf("parsed = %+v", f.Parsed)
	}
	if p.PassiveAlertCapPerRule != 10 {
		t.Fatalf("cap = %d", p.PassiveAlertCapPerRule)
	}
	if len(p.RuleSettings) != 1 || !p.RuleSettings[0].Fired {
		t.Fatalf("rule 10021 not marked fired: %+v", p.RuleSettings)
	}
	if p.ZapReport == nil {
		t.Fatal("ZapReport dropped")
	}
	if p.ZapLog != nil {
		t.Fatalf("a completed, unerrored scan carries no log tail: %+v", p.ZapLog)
	}
	if len(f.ScanArgs) != 3 {
		t.Fatalf("ScanArgs = %v", f.ScanArgs)
	}
}

func TestFoldZAPRunDeadScanIsAnErrorNeverZeroFindings(t *testing.T) {
	t.Run("the run itself failed", func(t *testing.T) {
		res := zapResult{ExitCode: 3, Stdout: "Total of 2 URLs\n", Stderr: "boom", Import: zapImportProbe{Status: 1}, AddOnStatus: zapAddOnStatusOK}
		f := foldZAPRun(res, errors.New("zap: exit 3"), webPayload(), nil, 10)
		if f.Payload.ScanCompleted {
			t.Fatal("ScanCompleted set on a run that failed")
		}
		if len(f.Errs) != 1 || f.Errs[0] != "zap: exit 3" {
			t.Fatalf("errs = %q", f.Errs)
		}
		if f.Payload.URLsRequested == nil || *f.Payload.URLsRequested != 2 {
			t.Fatal("scope counts are read even from a scan that died")
		}
		if f.Payload.ZapLog == nil || f.Payload.ZapLog.Stderr != "boom" {
			t.Fatalf("an errored run keeps its log tail: %+v", f.Payload.ZapLog)
		}
		if f.Parsed.BySeverity != nil {
			t.Fatal("a dead scan must not carry counts")
		}
	})
	t.Run("the report did not parse", func(t *testing.T) {
		res := zapResult{Raw: json.RawMessage(`{"site":`), Import: zapImportProbe{Status: 1}, AddOnStatus: zapAddOnStatusOK}
		f := foldZAPRun(res, nil, webPayload(), nil, 10)
		if f.Payload.ScanCompleted {
			t.Fatal("ScanCompleted set on an unparseable report")
		}
		if len(f.Errs) != 1 || !strings.HasPrefix(f.Errs[0], "zap: parse ZAP report") {
			t.Fatalf("errs = %q", f.Errs)
		}
	})
}

func TestFoldZAPRunAddOnVerdictComesFirst(t *testing.T) {
	res := zapResult{Raw: json.RawMessage(`{"site":`), Import: zapImportProbe{Status: 1}, AddOnStatus: zapAddOnStatusMismatch}
	f := foldZAPRun(res, nil, webPayload(), nil, 10)
	if len(f.Errs) != 2 || !strings.Contains(f.Errs[0], "PINNED ADD-ON REJECTED") {
		t.Fatalf("errs = %q; want the add-on verdict before the parse failure", f.Errs)
	}
	if f.Payload.PassiveRuleAddOn != zapAddOnStatusMismatch {
		t.Fatalf("PassiveRuleAddOn = %q", f.Payload.PassiveRuleAddOn)
	}
	res.AddOnStatus = zapAddOnStatusMissing
	f = foldZAPRun(res, nil, webPayload(), nil, 10)
	if len(f.Warnings) == 0 || !strings.Contains(f.Warnings[0], "PASSIVE RULES REDUCED") {
		t.Fatalf("warnings = %q", f.Warnings)
	}
}

func TestFoldZAPRunAPIReach(t *testing.T) {
	spec := []byte(`{"openapi":"3.0.0","paths":{"/pets":{"get":{}},"/owners":{"get":{}}}}`)
	payload := webPayload()
	payload.Mode = webModeAPI
	payload.EndpointsFromSpec, payload.APIPaths, _ = specScope(spec, nil)

	t.Run("reached nothing is an error and the document rejection its cause", func(t *testing.T) {
		res := zapResult{
			Raw:         json.RawMessage(`{"site":[]}`),
			Stdout:      "Number of Imported URLs: 0\nTotal of 1 URLs\n",
			URLDump:     `{"trigger":"end","urls":["http://app:8080/"]}`,
			Import:      zapImportProbe{Status: 0, Block: "ERROR The OpenAPI definition was invalid"},
			AddOnStatus: zapAddOnStatusOK,
		}
		f := foldZAPRun(res, nil, payload, spec, 10)
		if !f.Payload.ScanCompleted {
			t.Fatal("ScanCompleted false")
		}
		if f.Payload.APIImport == nil {
			t.Fatal("APIImport dropped")
		}
		if len(f.Errs) != 2 {
			t.Fatalf("errs = %q; want the import rejection then API NOT REACHED", f.Errs)
		}
		if !strings.Contains(f.Errs[0], "API DOCUMENT REFUSED") || !strings.Contains(f.Errs[1], "API NOT REACHED") {
			t.Fatalf("errs = %q", f.Errs)
		}
		if f.Payload.APIReach == nil || f.Payload.APIReach.UnreachedPaths != 2 {
			t.Fatalf("APIReach = %+v", f.Payload.APIReach)
		}
		if f.Payload.ZapLog == nil {
			t.Fatal("a run that reached nothing keeps its log tail")
		}
	})
	t.Run("an unreadable URL dump warns and reconciles nothing", func(t *testing.T) {
		res := zapResult{Raw: json.RawMessage(`{"site":[]}`), URLDump: "", Import: zapImportProbe{Status: 1}, AddOnStatus: zapAddOnStatusOK}
		f := foldZAPRun(res, nil, payload, spec, 10)
		if len(f.Errs) != 0 {
			t.Fatalf("errs = %q", f.Errs)
		}
		if f.Payload.APIReach != nil {
			t.Fatal("APIReach set without a dump")
		}
		found := false
		for _, w := range f.Warnings {
			found = found || strings.Contains(w, "ENDPOINT RECONCILIATION NOT RUN")
		}
		if !found {
			t.Fatalf("warnings = %q", f.Warnings)
		}
	})
	t.Run("every path reached is silent", func(t *testing.T) {
		res := zapResult{
			Raw:         json.RawMessage(`{"site":[]}`),
			URLDump:     `{"trigger":"end","urls":["http://app:8080/pets","http://app:8080/owners"]}`,
			Import:      zapImportProbe{Status: 1},
			AddOnStatus: zapAddOnStatusOK,
		}
		f := foldZAPRun(res, nil, payload, spec, 10)
		if len(f.Errs) != 0 || len(f.Warnings) != 0 {
			t.Fatalf("errs=%q warnings=%q", f.Errs, f.Warnings)
		}
		if f.Payload.APIReach == nil || f.Payload.APIReach.ReachedPaths != 2 {
			t.Fatalf("APIReach = %+v", f.Payload.APIReach)
		}
	})
}

func TestBuildWebEnvelope(t *testing.T) {
	repo := repoContext{RepoURL: "https://example.com", CommitSHA: "abc", Branch: "main"}
	start := time.Now().Add(-time.Second)

	t.Run("a clean completed scan passes at every threshold", func(t *testing.T) {
		f := foldZAPRun(zapResult{Raw: json.RawMessage(`{"site":[]}`), Args: []string{"zap-baseline.py"}, Import: zapImportProbe{Status: 1}, AddOnStatus: zapAddOnStatusOK}, nil, webPayload(), nil, 10)
		for _, th := range []Severity{SeverityCritical, SeverityHigh, SeverityLow, SeverityNone} {
			env, err := buildWebEnvelope(f, repo, th, start, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !env.Passed || env.Outcome != OutcomeClean || env.FindingsCount != 0 {
				t.Fatalf("%s: passed=%v outcome=%s count=%d", th, env.Passed, env.Outcome, env.FindingsCount)
			}
			if env.Tool.Args[0] != "zap-baseline.py" || env.GenericFormat != dastReportFormat || env.Concern != ConcernDAST {
				t.Fatalf("%s: envelope header %+v", th, env.Tool)
			}
		}
	})
	t.Run("a low finding fails at LOW and passes at HIGH and NONE", func(t *testing.T) {
		f := foldZAPRun(zapResult{Raw: json.RawMessage(zapLowReport), Import: zapImportProbe{Status: 1}, AddOnStatus: zapAddOnStatusOK}, nil, webPayload(), nil, 10)
		for th, want := range map[Severity]bool{SeverityLow: false, SeverityHigh: true, SeverityNone: true} {
			env, err := buildWebEnvelope(f, repo, th, start, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if env.Passed != want || env.FindingsCount != 1 || env.FindingsBySeverity[SeverityLow] != 1 {
				t.Fatalf("%s: passed=%v count=%d by=%v", th, env.Passed, env.FindingsCount, env.FindingsBySeverity)
			}
			if env.Outcome != OutcomeFindings {
				t.Fatalf("%s: outcome %s; want FINDINGS when a finding exists", th, env.Outcome)
			}
		}
	})
	t.Run("a non-run fails at NONE too and records the mode and target as its args", func(t *testing.T) {
		f := zapFold{Payload: webPayload()}
		errs := []string{"readiness probe: never answered"}
		env, err := buildWebEnvelope(f, repo, SeverityNone, start, []string{notScannedWarning()}, errs)
		if err != nil {
			t.Fatal(err)
		}
		if env.Passed {
			t.Fatal("passed with an errors[] entry")
		}
		if env.Outcome != OutcomeError {
			t.Fatalf("outcome = %s", env.Outcome)
		}
		if len(env.Tool.Args) != 2 || env.Tool.Args[0] != webModeBaseline || env.Tool.Args[1] != "http://app:8080/" {
			t.Fatalf("args = %v", env.Tool.Args)
		}
		if env.FindingsBySeverity == nil || len(env.Errors) != 1 || len(env.Warnings) != 1 {
			t.Fatalf("by=%v errors=%q warnings=%q", env.FindingsBySeverity, env.Errors, env.Warnings)
		}
		if env.Examined != nil {
			t.Fatalf("examined = %+v; a scan that never ran states no scope", env.Examined)
		}
	})
}
