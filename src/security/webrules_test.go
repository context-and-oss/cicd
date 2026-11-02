package main

import (
	"strings"
	"testing"
)

// zapRuleConfigFixture is the shape ZAP writes with -c: tab-separated, a
// comment header, and an optional free-text note after the action.
const zapRuleConfigFixture = "# zap-rules.conf\n" +
	"10038\tIGNORE\tCSP is set at the ingress, which dev mode has none of\n" +
	"10021\tWARN\n" +
	"40012\tFAIL\treflected XSS must never merge\n" +
	"\n" +
	"10049\tIGNORE\tcaching headers are the CDN's\n"

func TestParseZAPRuleConfigReadsTabsAndSpacesAlike(t *testing.T) {
	tabs, err := parseZAPRuleConfig(zapRuleConfigFixture)
	if err != nil {
		t.Fatalf("parseZAPRuleConfig: %v", err)
	}
	// Sorted by id, so a reader diffing two runs is not reading an ordering
	// change as a configuration change.
	want := []zapRuleSetting{
		{ID: "10021", Action: zapRuleWarn},
		{ID: "10038", Action: zapRuleIgnore, Note: "CSP is set at the ingress, which dev mode has none of"},
		{ID: "10049", Action: zapRuleIgnore, Note: "caching headers are the CDN's"},
		{ID: "40012", Action: zapRuleFail, Note: "reflected XSS must never merge"},
	}
	if len(tabs) != len(want) {
		t.Fatalf("got %d settings, want %d: %+v", len(tabs), len(want), tabs)
	}
	for i := range want {
		if tabs[i] != want[i] {
			t.Errorf("setting %d = %+v, want %+v", i, tabs[i], want[i])
		}
	}

	// A hand-edited copy uses spaces. Refusing it would make the disclosure the
	// reason a scan cannot run, over a file ZAP itself reads.
	spaces, err := parseZAPRuleConfig(strings.ReplaceAll(zapRuleConfigFixture, "\t", "  "))
	if err != nil {
		t.Fatalf("parseZAPRuleConfig (spaces): %v", err)
	}
	if len(spaces) != len(tabs) {
		t.Fatalf("space-separated parse gave %d settings, tab-separated gave %d", len(spaces), len(tabs))
	}
	for i := range tabs {
		if spaces[i].ID != tabs[i].ID || spaces[i].Action != tabs[i].Action {
			t.Errorf("setting %d differs between separators: %+v vs %+v", i, spaces[i], tabs[i])
		}
	}
}

func TestParseZAPRuleConfigAcceptsAnEmptyOrCommentOnlyFile(t *testing.T) {
	for _, tc := range []struct{ name, content string }{
		{"empty", ""},
		{"blank lines", "\n\n   \n"},
		{"comments only", "# nothing suppressed yet\n# see PR 41\n"},
		{"crlf", "10038\tIGNORE\tone\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseZAPRuleConfig(tc.content); err != nil {
				t.Errorf("parseZAPRuleConfig: %v", err)
			}
		})
	}
}

// TestParseZAPRuleConfigRefusesWhatItCannotUnderstand.
//
// A line dropped here does not shorten a report, it shortens the *disclosure* —
// and a disclosure assembled by dropping the entries it did not understand
// reads as complete. So each of these is an error rather than a skip.
func TestParseZAPRuleConfigRefusesWhatItCannotUnderstand(t *testing.T) {
	for _, tc := range []struct{ name, content, wantErr string }{
		{"no action", "10038\n", "expected"},
		{"unknown action", "10038\tSKIP\n", "unknown action"},
		{"duplicate id", "10038\tIGNORE\n10038\tWARN\n", "configured twice"},
		{"duplicate id, same action", "10038\tIGNORE\n10038\tIGNORE\n", "configured twice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseZAPRuleConfig(tc.content)
			if err == nil {
				t.Fatalf("parseZAPRuleConfig = %+v, want an error", got)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestParseZAPRuleConfigNormalisesActionCase(t *testing.T) {
	got, err := parseZAPRuleConfig("10038\tignore\n10021\tWarn\n")
	if err != nil {
		t.Fatalf("parseZAPRuleConfig: %v", err)
	}
	if got[0].Action != zapRuleWarn || got[1].Action != zapRuleIgnore {
		t.Errorf("actions were not normalised: %+v", got)
	}
}

func TestMarkFiredRulesDoesNotMutateItsInput(t *testing.T) {
	settings, err := parseZAPRuleConfig(zapRuleConfigFixture)
	if err != nil {
		t.Fatalf("parseZAPRuleConfig: %v", err)
	}
	marked := markFiredRules(settings, []string{"10038", "99999"})

	for _, s := range settings {
		if s.Fired {
			t.Errorf("markFiredRules mutated its input: %+v", s)
		}
	}
	fired := map[string]bool{}
	for _, s := range marked {
		fired[s.ID] = s.Fired
	}
	if !fired["10038"] {
		t.Error("10038 raised an alert and is not marked fired")
	}
	for _, id := range []string{"10021", "10049", "40012"} {
		if fired[id] {
			t.Errorf("%s raised no alert and is marked fired", id)
		}
	}
}

// TestRuleConfigWarningsNamesEveryRuleItChanged.
//
// say-what-the-licence-scan-covered's three rules, applied to a scanner: it
// narrows scope and never findings, so the ids are named rather than counted;
// nothing is excluded silently; and a pattern that matched nothing says so.
func TestRuleConfigWarningsNamesEveryRuleItChanged(t *testing.T) {
	settings, err := parseZAPRuleConfig(zapRuleConfigFixture)
	if err != nil {
		t.Fatalf("parseZAPRuleConfig: %v", err)
	}
	got := strings.Join(ruleConfigWarnings(markFiredRules(settings, []string{"10038"})), "\n")

	for _, want := range []string{
		"RULES SUPPRESSED",
		"10038, 10049", // named, not counted
		"RULES DOWNGRADED",
		"10021",
		"RULES ESCALATED",
		"40012",
		"SUPPRESSION MATCHED NOTHING",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("warnings missing %q:\n%s", want, got)
		}
	}

	// 10038 fired, so it is a live suppression and must not appear in the
	// matched-nothing line. Only 10049 is stale.
	for _, line := range ruleConfigWarnings(markFiredRules(settings, []string{"10038"})) {
		if strings.Contains(line, "SUPPRESSION MATCHED NOTHING") {
			if strings.Contains(line, "10038") {
				t.Errorf("a rule that fired is reported as matching nothing: %s", line)
			}
			if !strings.Contains(line, "10049") {
				t.Errorf("a suppressed rule that never fired is not reported: %s", line)
			}
		}
	}
}

func TestRuleConfigWarningsSaySomethingWheneverAConfigExists(t *testing.T) {
	// No config at all is the only silence: there is nothing to disclose.
	if got := ruleConfigWarnings(nil); got != nil {
		t.Errorf("ruleConfigWarnings(nil) = %v, want nothing", got)
	}

	// A config that only escalates suppresses nothing, and still says so —
	// otherwise a run with a rule config is indistinguishable from one without.
	settings, err := parseZAPRuleConfig("40012\tFAIL\n")
	if err != nil {
		t.Fatalf("parseZAPRuleConfig: %v", err)
	}
	got := ruleConfigWarnings(markFiredRules(settings, nil))
	if len(got) != 1 || !strings.Contains(got[0], "RULES ESCALATED") {
		t.Errorf("ruleConfigWarnings = %v, want a single escalation line", got)
	}
}

// TestRuleConfigWarningsReportOnlyIgnoredRulesAsUnmatched. A WARN rule that
// never fired is a rule that found nothing, which is ordinary. An IGNORE rule
// that never fired is the actionable one: either stale, or never needed.
func TestRuleConfigWarningsReportOnlyIgnoredRulesAsUnmatched(t *testing.T) {
	settings, err := parseZAPRuleConfig("10021\tWARN\n40012\tFAIL\n")
	if err != nil {
		t.Fatalf("parseZAPRuleConfig: %v", err)
	}
	for _, line := range ruleConfigWarnings(markFiredRules(settings, nil)) {
		if strings.Contains(line, "SUPPRESSION MATCHED NOTHING") {
			t.Errorf("a config that suppresses nothing produced a stale-suppression line: %s", line)
		}
	}
}
