package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// fakeSemgrepSecret stands in for a credential in a scanned file. It is not a
// real key and matches no gitleaks rule; what the test needs is a string that
// must appear nowhere in the redacted report.
const fakeSemgrepSecret = "cicd-test-not-a-secret-7f3a91"

// semgrepLeakyReport uses newly written synthetic catalogue text, not a rule
// body's prose. It is a semgrep SARIF document with the matched source in
// every place semgrep is known to write it: the result's interpolated message,
// the location's snippet, a contextRegion snippet, a related location, a
// codeFlows step and a fix. The shape of the first location is what
// semgrep/semgrep:1.162.0 wrote, measured; the others follow SARIF 2.1.0.
var semgrepLeakyReport = `{
 "version": "2.1.0",
 "runs": [{
  "tool": {"driver": {"name": "Semgrep OSS", "rules": [
   {"id": "yaml.kubernetes.security.secrets-in-config-file",
    "fullDescription": {"text": "Synthetic catalogue check: review the fixture value ($VALUE)."},
    "shortDescription": {"text": "Semgrep Finding: yaml.kubernetes.security.secrets-in-config-file"}}
  ]}},
  "invocations": [{"executionSuccessful": true, "toolExecutionNotifications": [
   {"descriptor": {"id": "Timeout"}, "level": "warning",
    "message": {"text": "Timeout when running some.rule on slow.yaml:\n "}}
  ]}],
  "results": [
   {"ruleId": "yaml.kubernetes.security.secrets-in-config-file",
    "message": {"text": "Synthetic catalogue check: review the fixture value (` + fakeSemgrepSecret + `)."},
    "fingerprints": {"matchBasedId/v1": "abc123"},
    "properties": {},
    "suppressions": [{"kind": "inSource"}],
    "locations": [{"physicalLocation": {
      "artifactLocation": {"uri": "k8s/secret.yaml", "uriBaseId": "%SRCROOT%"},
      "region": {"startLine": 7, "startColumn": 9, "endLine": 7, "endColumn": 40,
                 "snippet": {"text": "  password: ` + fakeSemgrepSecret + `"}},
      "contextRegion": {"startLine": 6, "endLine": 8, "snippet": {"text": "data:\n  password: ` + fakeSemgrepSecret + `\n"}}}}],
    "relatedLocations": [{"id": 1, "message": {"text": "bound to ` + fakeSemgrepSecret + `"},
      "physicalLocation": {"artifactLocation": {"uri": "k8s/secret.yaml"},
        "region": {"startLine": 7, "snippet": {"text": "` + fakeSemgrepSecret + `"}}}}],
    "codeFlows": [{"threadFlows": [{"locations": [{"location": {
      "message": {"text": "Source: ` + fakeSemgrepSecret + `"},
      "physicalLocation": {"artifactLocation": {"uri": "k8s/secret.yaml"},
        "region": {"startLine": 7, "snippet": {"text": "` + fakeSemgrepSecret + `"}}}}}]}]}],
    "fixes": [{"description": {"text": "replace ` + fakeSemgrepSecret + `"},
      "artifactChanges": [{"artifactLocation": {"uri": "k8s/secret.yaml"},
        "replacements": [{"deletedRegion": {"startLine": 7}, "insertedContent": {"text": "` + fakeSemgrepSecret + `"}}]}]}]},
   {"ruleId": "rule.not.in.the.catalogue",
    "message": {"text": "matched ` + fakeSemgrepSecret + `"},
    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.go"},
      "region": {"startLine": 2, "snippet": {"text": "` + fakeSemgrepSecret + `"}}}}]}
  ]
 }]
}`

func TestRedactSemgrepSARIFWithholdsEveryCopyOfTheMatchedSource(t *testing.T) {
	out, err := redactSemgrepSARIF(json.RawMessage(semgrepLeakyReport))
	if err != nil {
		t.Fatalf("redactSemgrepSARIF: %v", err)
	}
	if n := strings.Count(string(out), fakeSemgrepSecret); n != 0 {
		t.Fatalf("matched source survives redaction %d time(s):\n%s", n, out)
	}
	if strings.Contains(string(out), `"snippet"`) || strings.Contains(string(out), `"fixes"`) {
		t.Errorf("a snippet or fixes key survives:\n%s", out)
	}
}

func TestRedactSemgrepSARIFKeepsWhatTriageAndThisModuleRead(t *testing.T) {
	out, err := redactSemgrepSARIF(json.RawMessage(semgrepLeakyReport))
	if err != nil {
		t.Fatalf("redactSemgrepSARIF: %v", err)
	}
	var doc sarifDoc
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("redacted report is not SARIF: %v", err)
	}
	results := doc.Runs[0].Results
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2 — redaction must never drop a finding", len(results))
	}
	if !sarifResultIsSuppressed(results[0]) {
		t.Error("the nosemgrep suppression was lost, so an accepted finding would be counted again")
	}

	var raw struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []json.RawMessage `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Invocations []struct {
				Notifications []json.RawMessage `json:"toolExecutionNotifications"`
			} `json:"invocations"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Fingerprints map[string]string `json:"fingerprints"`
				Locations    []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine   int `json:"startLine"`
							StartColumn int `json:"startColumn"`
							EndLine     int `json:"endLine"`
							EndColumn   int `json:"endColumn"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatal(err)
	}
	run := raw.Runs[0]
	if len(run.Tool.Driver.Rules) != 1 || len(run.Invocations[0].Notifications) != 1 {
		t.Error("the rule catalogue or the notifications were touched; semgrepRuleSet and semgrepnotifications.go read them")
	}
	first := run.Results[0]
	if first.RuleID != "yaml.kubernetes.security.secrets-in-config-file" {
		t.Errorf("ruleId = %q", first.RuleID)
	}
	if want := "Synthetic catalogue check: review the fixture value ($VALUE)."; first.Message.Text != want {
		t.Errorf("message = %q, want the rule's declared message %q", first.Message.Text, want)
	}
	region := first.Locations[0].PhysicalLocation.Region
	if first.Locations[0].PhysicalLocation.ArtifactLocation.URI != "k8s/secret.yaml" ||
		region.StartLine != 7 || region.StartColumn != 9 || region.EndLine != 7 || region.EndColumn != 40 {
		t.Errorf("the location was changed: %+v", first.Locations[0])
	}
	if first.Fingerprints["matchBasedId/v1"] != "abc123" {
		t.Error("the fingerprint was lost")
	}
	if want := semgrepWithheldMessage("rule.not.in.the.catalogue"); run.Results[1].Message.Text != want {
		t.Errorf("uncatalogued rule message = %q, want %q", run.Results[1].Message.Text, want)
	}
}

func TestRedactSemgrepSARIFKeepsTheCounts(t *testing.T) {
	out, err := redactSemgrepSARIF(json.RawMessage(semgrepLeakyReport))
	if err != nil {
		t.Fatal(err)
	}
	before := parseSarifSeverities(json.RawMessage(semgrepLeakyReport))
	after := parseSarifSeverities(out)
	if len(before) != len(after) {
		t.Fatalf("severity buckets changed: %v -> %v", before, after)
	}
	for k, v := range before {
		if after[k] != v {
			t.Errorf("severity %s: %d -> %d", k, v, after[k])
		}
	}
}

func TestRedactSemgrepSARIFRefusesWhatItCannotRead(t *testing.T) {
	for name, raw := range map[string]string{
		"not json":          `{"runs": [`,
		"no runs":           `{"version": "2.1.0"}`,
		"runs not an array": `{"runs": {}}`,
		"run not an object": `{"runs": ["x"]}`,
		"result not object": `{"runs": [{"results": ["` + fakeSemgrepSecret + `"]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			out, err := redactSemgrepSARIF(json.RawMessage(raw))
			if err == nil {
				t.Fatalf("an unreadable report was passed on: %s", out)
			}
			if !strings.HasPrefix(err.Error(), "semgrep: ") {
				t.Errorf("error %q does not name semgrep", err)
			}
			if strings.Contains(err.Error(), fakeSemgrepSecret) {
				t.Errorf("the refusal quotes the report: %q", err)
			}
		})
	}
}

func TestRedactSemgrepSARIFLeavesACleanReportClean(t *testing.T) {
	raw := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep OSS","rules":[]}},"results":[]}]}`
	out, err := redactSemgrepSARIF(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got := parseSarifSeverities(out); len(got) != 0 {
		t.Errorf("a clean report gained findings: %v", got)
	}
}

// semgrepQuotingNotifications is what semgrep/semgrep:1.162.0 wrote for a
// JavaScript file whose line it could not parse, measured, with the probe value
// swapped for fakeSemgrepSecret: the quote is the whole line. Beside it, the
// measured gha-curl-pipe-shell failure the fallback keys on, a template
// literal (source holding backticks of its own), a lone backtick, and a
// configuration notification.
var semgrepQuotingNotifications = `[{"executionSuccessful":true,` +
	`"toolExecutionNotifications":[` +
	`{"descriptor":{"id":"Syntax error"},"level":"warning","message":{"text":"Syntax error at line b.js:1:\n ` + "`function f( { const k = \\\"" + fakeSemgrepSecret + "\\\" }`" + ` was unexpected"}},` +
	`{"descriptor":{"id":"Syntax error"},"level":"warning","message":{"text":"Syntax error at line .github/workflows/pages.yml:63:\n When parsing a snippet as Bash for metavariable-pattern in rule '` + semgrepGHACurlPipeRuleID + `', ` + "`{ github.repository`" + ` was unexpected"}},` +
	`{"descriptor":{"id":"Syntax error"},"level":"warning","message":{"text":"Syntax error at line c.ts:4:\n ` + "`const k = `" + fakeSemgrepSecret + "` + x`" + ` was unexpected"}},` +
	`{"descriptor":{"id":"Lexical error"},"level":"error","message":{"text":"Lexical error at line d.py:2: ` + "`" + fakeSemgrepSecret + `"}},` +
	`{"descriptor":{"id":"Timeout"},"level":"warning","message":{"text":"Timeout when running some.rule on slow.yaml:\n "}}],` +
	`"toolConfigurationNotifications":[` +
	`{"level":"warning","message":{"text":"rule parse note ` + "`" + fakeSemgrepSecret + "`" + `"},"locations":[{"physicalLocation":{"region":{"snippet":{"text":"` + fakeSemgrepSecret + `"}}}}]}]}]`

func TestRedactSemgrepSARIFWithholdsTheSourceANotificationQuotes(t *testing.T) {
	raw := sarifWithInvocations(semgrepQuotingNotifications)
	if !strings.Contains(string(raw), fakeSemgrepSecret) {
		t.Fatal("fixture does not carry the secret, so this test proves nothing")
	}
	out, err := redactSemgrepSARIF(raw)
	if err != nil {
		t.Fatalf("redactSemgrepSARIF: %v", err)
	}
	if strings.Contains(string(out), fakeSemgrepSecret) {
		t.Fatalf("a notification still quotes the source:\n%s", out)
	}
	if strings.Contains(string(out), "github.repository") {
		t.Errorf("the fallback notification's quoted source survived:\n%s", out)
	}

	// Everything the notifications are read for survives: the file and line
	// the parser gave up at, the rule id the fallback keys on, the timeout.
	n := parseSemgrepNotifications(out)
	if got := strings.Join(n.UnparsedFiles, ","); got != "b.js,.github/workflows/pages.yml,c.ts" {
		t.Errorf("UnparsedFiles = %q", got)
	}
	if want := "b.js:1 [source withheld] was unexpected"; n.FirstParserMessage != want {
		t.Errorf("FirstParserMessage = %q, want %q", n.FirstParserMessage, want)
	}
	if n.Timeouts != 1 || strings.Join(n.TimedOutFiles, ",") != "slow.yaml" {
		t.Errorf("the timeout did not survive: %+v", n)
	}
	if strings.Join(n.ErrorLevel, ",") != "Lexical error" {
		t.Errorf("ErrorLevel = %v, want the lexical error still counted", n.ErrorLevel)
	}
	if !semgrepNeedsGHACurlPipeFallback(out) {
		t.Error("the fallback no longer recognises its rule once the quote is withheld")
	}
	w := semgrepNotificationWarnings(out)
	if len(w) != 1 || !strings.Contains(w[0], "First parser message: b.js:1 [source withheld] was unexpected.") {
		t.Errorf("warning = %v", w)
	}
}

// TestSemgrepNotificationsWithholdTheQuoteWithoutTheRewrite: the warning is
// built from the notification, so it withholds the quote itself rather than
// rely on every caller having rewritten the report first.
func TestSemgrepNotificationsWithholdTheQuoteWithoutTheRewrite(t *testing.T) {
	raw := sarifWithInvocations(semgrepQuotingNotifications)
	for _, w := range semgrepNotificationWarnings(raw) {
		if strings.Contains(w, fakeSemgrepSecret) {
			t.Fatalf("the warning quotes the source:\n%s", w)
		}
	}
}

func TestWithholdSemgrepQuotedSource(t *testing.T) {
	for in, want := range map[string]string{
		"`(int x)` was unexpected":         "[source withheld] was unexpected",
		"no quote at all":                  "no quote at all",
		"rule 'a.b', `{ x` was unexpected": "rule 'a.b', [source withheld] was unexpected",
		"`a = `inner` + b` was unexpected": "[source withheld] was unexpected",
		"lone ` then the rest of the line": "lone [source withheld]",
		"`one` and `two`":                  "[source withheld]",
		"":                                 "",
	} {
		if got := withholdSemgrepQuotedSource(in); got != want {
			t.Errorf("withholdSemgrepQuotedSource(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedactSemgrepSARIFRefusesNotificationsItCannotWalk(t *testing.T) {
	for name, invocations := range map[string]string{
		"invocations not an array":   `{"toolExecutionNotifications":[]}`,
		"invocation not an object":   `["` + fakeSemgrepSecret + `"]`,
		"notifications not an array": `[{"toolExecutionNotifications":"` + fakeSemgrepSecret + `"}]`,
		"notification not an object": `[{"toolExecutionNotifications":["` + fakeSemgrepSecret + `"]}]`,
	} {
		t.Run(name, func(t *testing.T) {
			out, err := redactSemgrepSARIF(sarifWithInvocations(invocations))
			if err == nil {
				t.Fatalf("accepted a notification list it cannot walk:\n%s", out)
			}
			if strings.Contains(err.Error(), fakeSemgrepSecret) {
				t.Errorf("the refusal quotes the report: %v", err)
			}
		})
	}
}
