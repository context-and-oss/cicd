package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// The founding rule as a matrix, for the documents security reads back from
// its scanners: every shape that is not a report of a scan must come out as an
// error, so ran=false, so passed=false at every threshold, `--fail-on NONE`
// included. Each fold has a positive control proving the matrix does not pass
// because the fold refuses everything.

var allThresholds = []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityNone}

func assertNeverPasses(t *testing.T, name string, ran bool) {
	t.Helper()
	for _, th := range allThresholds {
		if gatedPassed(ran, true, th) {
			t.Errorf("%s: passed at --fail-on %s", name, th)
		}
	}
}

// TestNonRunMatrixTrivy splits the refusals in two, because only one of them
// may become N/A. A report that names no target is errTrivyNoTargets, which a
// dependency-free tree (proven by the independent probe) turns into a skip. A
// document that is not a report at all must never take that path: no probe
// result can make `null` a scan.
func TestNonRunMatrixTrivy(t *testing.T) {
	noTargets := []string{`{}`, `{"SchemaVersion":2}`, `{"Results":null}`, `{"Results":[]}`}
	notAReport := []string{``, ` `, `null`, `[]`, `[{"Target":"go.mod"}]`, `"report"`, `42`, `{"Results":`}

	for _, doc := range noTargets {
		_, err := parseTrivyNative(json.RawMessage(doc))
		if !errors.Is(err, errTrivyNoTargets) {
			t.Errorf("%s: err = %v, want errTrivyNoTargets", doc, err)
			continue
		}
		assertNeverPasses(t, doc, err == nil)
		if _, na := dependencyNotApplicableResult([]string{"go.mod"}, err, nil); na {
			t.Errorf("%s: became N/A on a tree that declares go.mod", doc)
		}
	}
	for _, doc := range notAReport {
		_, err := parseTrivyNative(json.RawMessage(doc))
		if err == nil {
			t.Errorf("%q parsed as a Trivy report", doc)
			continue
		}
		if errors.Is(err, errTrivyNoTargets) {
			t.Errorf("%q: refused as a scan of no targets, which a dependency-free tree turns into N/A", doc)
		}
		assertNeverPasses(t, doc, false)
		if _, na := dependencyNotApplicableResult(nil, err, nil); na {
			t.Errorf("%q: became N/A on a dependency-free tree", doc)
		}
	}

	// Controls: a scan with a target, and the one resultless shape that is a
	// proven N/A.
	if _, err := parseTrivyNative(json.RawMessage(`{"SchemaVersion":2,"Results":[{"Target":"go.mod","Class":"lang-pkgs"}]}`)); err != nil {
		t.Fatalf("control: a report with a target was refused: %v", err)
	}
	_, err := parseTrivyNative(json.RawMessage(`{"SchemaVersion":2}`))
	if _, na := dependencyNotApplicableResult(nil, err, nil); !na {
		t.Fatal("control: a resultless report on a dependency-free tree is not N/A")
	}
}

func TestNonRunMatrixLicense(t *testing.T) {
	pol := defaultPolicy(t)
	for _, doc := range []string{``, `null`, `{}`, `{"Results":[]}`, `[]`, `"x"`, `{"Results":`} {
		res, err := evaluateLicenses(json.RawMessage(doc), pol, nil, nil)
		if err == nil {
			t.Errorf("%q: evaluated as a licence report (scanned %d)", doc, res.Scanned)
			continue
		}
		assertNeverPasses(t, doc, false)
	}

	clean, err := evaluateLicenses(json.RawMessage(`{"SchemaVersion":2}`), pol, nil, nil)
	if err != nil || len(clean.Findings) != 0 {
		t.Fatalf("control: an empty Trivy licence report: findings=%d err=%v, want a parse with nothing in it", len(clean.Findings), err)
	}
	// It parses, but it read nothing, and a policy that judged nothing is not
	// CLEAN: ScanLicenses ships this row SKIPPED (licencenuget_test.go pins
	// the row), which passes without claiming a judgement.
	if !licenceZeroRead(true, clean.Scanned, clean.Excluded) {
		t.Fatalf("control: an empty licence report must be a zero read, scanned %d", clean.Scanned)
	}
	flagged, err := evaluateLicenses(json.RawMessage(`{"SchemaVersion":2,"Results":[{"Target":"x","Class":"license","Licenses":[
	  {"Category":"restricted","Name":"GPL-3.0","PkgName":"gpl-thing"}]}]}`), pol, nil, nil)
	if err != nil || len(flagged.Findings) != 1 {
		t.Fatalf("control: a restricted licence: findings=%d err=%v, want one finding", len(flagged.Findings), err)
	}
}

func TestNonRunMatrixZAP(t *testing.T) {
	for _, report := range []string{``, ` `, `null`, `{}`, `{"site":null}`, `{"site":[]}`, `{"site":{}}`, `{"site":"x"}`, `[]`, `not json`} {
		msg := zapRunError("0", "", "", report)
		if msg == "" {
			t.Errorf("%q: accepted as a finished scan", report)
			continue
		}
		assertNeverPasses(t, report, false)
	}
	for _, exit := range []string{"", "x", "3", "-1", "137"} {
		if zapRunError(exit, "", "", `{"site":[{"@name":"http://app","alerts":[]}]}`) == "" {
			t.Errorf("exit %q: accepted", exit)
		}
	}

	const clean = `{"site":[{"@name":"http://app","alerts":[]}]}`
	if msg := zapRunError("0", "", "", clean); msg != "" {
		t.Fatalf("control: a scanned site with no alerts was refused: %s", msg)
	}
	if msg := zapRunError("2", "", "", clean); msg != "" {
		t.Fatalf("control: exit 2 (alerts raised) with a site was refused: %s", msg)
	}
	if strings.Contains(zapRunError("0", "", "", `{"site":[]}`), "describes no site") == false {
		t.Error("an empty site array must be named as a report that describes no site")
	}
}
