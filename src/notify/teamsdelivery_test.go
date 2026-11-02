// Proof for the three states a Teams notification can end in, and for the one
// that used to be indistinguishable from success.
//
// Every delivery case drives the production seam over a real loopback socket
// (see delivery_test.go for the fixture); the envelope cases assert on the
// serialised JSON rather than on struct fields, because the field that gets
// missed is the leak.

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestTeamsDelivery(t *testing.T) {
	t.Run("BlankWebhookSendsNothing", testBlankWebhookSendsNothing)
	t.Run("ConfiguredWebhookIsAttempted", testConfiguredWebhookIsAttempted)
	t.Run("PresentButBrokenWebhookIsAttempted", testPresentButBrokenWebhookIsAttempted)
	t.Run("UnexpandedAdoMacroIsNotAWebhook", testUnexpandedAdoMacroIsNotAWebhook)
	t.Run("EvidenceUnconfigured", testEvidenceUnconfigured)
	t.Run("EvidenceDelivered", testEvidenceDelivered)
	t.Run("EvidenceNotDelivered", testEvidenceNotDelivered)
	t.Run("EvidenceCarriesTheRunItReportedOn", testEvidenceCarriesTheRunItReportedOn)
	t.Run("ScrubValuesRefuseToManglePlainText", testScrubValuesRefuseToManglePlainText)
}

// A webhook that is empty — or holds only whitespace, which is what a secret
// file with a trailing newline resolves to — must produce no HTTP request at
// all. This is the defect: `!= nil` was true for every consumer under
// `secrets: inherit`, so cicd POSTed to the empty string on every run.
func testBlankWebhookSendsNothing(t *testing.T) {
	for _, raw := range []string{"", " ", "\n", "\t \r\n"} {
		f := newFixture(t, status(http.StatusOK, "1"))
		card := buildTeamsCard("commit", "", testEnvelope())

		attempted, reason, err := deliverTeamsCard(context.Background(), f.del, raw, card)
		if attempted {
			t.Fatalf("webhook %q was attempted; a blank value is not a configuration", raw)
		}
		if err != nil {
			t.Fatalf("webhook %q: err = %v, want nil — nothing went wrong, there was nothing to do", raw, err)
		}
		if reason == "" {
			t.Fatalf("webhook %q: no reason recorded; the warning would say why nothing happened", raw)
		}
		if got := f.requests.Load(); got != 0 {
			t.Fatalf("webhook %q: request count = %d, want 0", raw, got)
		}
	}
}

func testConfiguredWebhookIsAttempted(t *testing.T) {
	f := newFixture(t, status(http.StatusOK, "1"))
	card := buildTeamsCard("commit", "", testEnvelope())

	attempted, reason, err := deliverTeamsCard(context.Background(), f.del, f.teamsWebhook(), card)
	if !attempted || err != nil {
		t.Fatalf("attempted = %v, err = %v; want true, nil", attempted, err)
	}
	if reason != "" {
		t.Fatalf("reason = %q for a configured webhook; want none", reason)
	}
	if got := f.requests.Load(); got != 1 {
		t.Fatalf("request count = %d, want 1", got)
	}
}

// A value that is present and wrong is a broken configuration, not an absent
// one. Reclassifying it as unconfigured would restore the bug from the other
// side: the team relying on the channel would be told they never set one up.
func testPresentButBrokenWebhookIsAttempted(t *testing.T) {
	f := newFixture(t, status(http.StatusOK, "1"))
	card := buildTeamsCard("commit", "", testEnvelope())

	attempted, _, err := deliverTeamsCard(context.Background(), f.del, "not-a-url", card)
	if !attempted {
		t.Fatal("a non-blank webhook must be attempted, however malformed")
	}
	if err == nil {
		t.Fatal("err = nil for a malformed webhook; a failed POST must be reported")
	}
	if got := f.requests.Load(); got != 0 {
		t.Fatalf("request count = %d, want 0 — the malformed URL reaches no server", got)
	}
}

// Azure DevOps expands `$(TEAMS_WEBHOOK)` before the shell sees the line, and an
// *undefined* variable expands to its own literal text — so a pipeline that
// never declared the variable hands cicd a non-empty string that is not a URL.
// Classified as a broken webhook it would tell a team their channel had died
// when they never had one; a URL that merely contains `$(` is a real webhook
// and must still be attempted.
func testUnexpandedAdoMacroIsNotAWebhook(t *testing.T) {
	unconfigured := []string{"$(TEAMS_WEBHOOK)", "  $(TEAMS_WEBHOOK)\n", "$(Teams.Webhook_1)"}
	for _, raw := range unconfigured {
		f := newFixture(t, status(http.StatusOK, "1"))
		card := buildTeamsCard("commit", "", testEnvelope())

		attempted, reason, err := deliverTeamsCard(context.Background(), f.del, raw, card)
		if attempted || err != nil {
			t.Fatalf("webhook %q: attempted = %v, err = %v; an unexpanded macro is not a configuration", raw, attempted, err)
		}
		if got := f.requests.Load(); got != 0 {
			t.Fatalf("webhook %q: request count = %d, want 0", raw, got)
		}
		if !strings.Contains(reason, "Azure DevOps") {
			t.Errorf("webhook %q: reason %q does not name what produced it", raw, reason)
		}
		if !strings.Contains(teamsUnconfiguredWarning(reason), strings.TrimSpace(raw)) {
			t.Errorf("webhook %q: the warning does not quote the value a reader has to find", raw)
		}
	}

	// Anchored at both ends: these are configurations and must be attempted.
	for _, raw := range []string{
		"https://example.com/webhookb2/tok?x=$(y)",
		"$(TEAMS_WEBHOOK)/extra",
		"prefix$(TEAMS_WEBHOOK)",
		"$()",
	} {
		if got := teamsUnconfiguredReason(raw); got != "" {
			t.Errorf("teamsUnconfiguredReason(%q) = %q, want none — a present value is attempted", raw, got)
		}
	}
}

func marshalEvidence(t *testing.T, env *envelope) (string, map[string]any) {
	t.Helper()
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode evidence: %v", err)
	}
	return string(data), decoded
}

func testEvidenceUnconfigured(t *testing.T) {
	raw, decoded := marshalEvidence(t, teamsEvidence(time.Now(), repoContext{}, "commit", false, teamsUnconfiguredReason(""), nil))

	if decoded["passed"] != true {
		t.Errorf("passed = %v, want true — a notification is not a gate", decoded["passed"])
	}
	if decoded["outcome"] != string(OutcomeSkipped) {
		t.Errorf("outcome = %v, want %s", decoded["outcome"], OutcomeSkipped)
	}
	if _, ok := decoded["errors"]; ok {
		t.Errorf("errors[] is set; an unconfigured channel is a warning, not a fault: %s", raw)
	}
	if !strings.Contains(raw, "NOT CONFIGURED") {
		t.Errorf("evidence does not say the channel was not configured: %s", raw)
	}
	// The remedy has to be in the record, or the reader learns only that
	// something is off.
	if !strings.Contains(raw, "--teams-webhook") || !strings.Contains(raw, "TEAMS_WEBHOOK") {
		t.Errorf("warning names neither the flag nor the secret: %s", raw)
	}
}

func testEvidenceDelivered(t *testing.T) {
	raw, decoded := marshalEvidence(t, teamsEvidence(time.Now(), repoContext{}, "commit", true, "", nil))

	if decoded["outcome"] != string(OutcomeClean) {
		t.Errorf("outcome = %v, want %s", decoded["outcome"], OutcomeClean)
	}
	if strings.Contains(raw, "warnings") {
		t.Errorf("a delivered card warns about nothing; a line on every run is noise: %s", raw)
	}
	if !strings.Contains(raw, "delivered=true") {
		t.Errorf("tool args do not record the delivery: %s", raw)
	}
}

// The case the change exists for: configured, attempted, lost. It must be
// visible, must not fail the run, and must not carry the webhook — the URL is
// the credential.
func testEvidenceNotDelivered(t *testing.T) {
	f := newFixture(t, status(http.StatusInternalServerError, "webhook rejected "+fakeWebhookPath))
	card := buildTeamsCard("commit", "", testEnvelope())

	// Built exactly as teams.go builds it, so the scrubbing under test is the
	// scrubbing production has.
	attempted, _, deliverErr := deliverTeamsCard(
		context.Background(), newTeamsDelivery(f.teamsWebhook()), f.teamsWebhook(), card)
	if !attempted || deliverErr == nil {
		t.Fatalf("attempted = %v, err = %v; want true and a delivery error", attempted, deliverErr)
	}

	raw, decoded := marshalEvidence(t, teamsEvidence(time.Now(), repoContext{}, "commit", true, "", deliverErr))

	if decoded["passed"] != true {
		t.Errorf("passed = %v, want true — a webhook outage must not red a scan", decoded["passed"])
	}
	if decoded["outcome"] != string(OutcomeError) {
		t.Errorf("outcome = %v, want %s", decoded["outcome"], OutcomeError)
	}
	if !strings.Contains(raw, "NOT DELIVERED") {
		t.Errorf("evidence does not say the card was lost: %s", raw)
	}
	if !strings.Contains(raw, "delivered=false") {
		t.Errorf("tool args claim a delivery that did not happen: %s", raw)
	}
	assertNoSecretLeak(t, "teams delivery evidence", raw)
}

func testEvidenceCarriesTheRunItReportedOn(t *testing.T) {
	repo := repoContext{RepoURL: "https://example.com/org/repo", CommitSHA: "deadbeef", Branch: "main"}
	_, decoded := marshalEvidence(t, teamsEvidence(time.Now(), repo, "commit", true, "", nil))

	got, ok := decoded["repo"].(map[string]any)
	if !ok {
		t.Fatalf("repo missing from evidence: %+v", decoded)
	}
	if got["commitSha"] != "deadbeef" || got["branch"] != "main" {
		t.Errorf("repo = %+v, want the context of the run this card reported on", got)
	}
	if decoded["moduleName"] != moduleName || decoded["schemaVersion"] != evidenceSchemaVersion {
		t.Errorf("envelope is not a recognisable evidence document: %+v", decoded)
	}
}

// A short path is not registered, because replacing it would shred the message
// it is supposed to protect. The guard is what keeps teamsScrubValues from
// turning every slash in a warning into "***".
func testScrubValuesRefuseToManglePlainText(t *testing.T) {
	for _, short := range []string{"https://example.com/", "https://example.com/a", "https://example.com"} {
		for _, v := range teamsScrubValues(short) {
			if v != short && len(v) < teamsMinScrubLen {
				t.Errorf("teamsScrubValues(%q) registered the fragment %q", short, v)
			}
		}
	}
	long := "https://example.com/webhookb2/0000000000000000/IncomingWebhook/abc"
	got := teamsScrubValues(long)
	var sawPath bool
	for _, v := range got {
		if v == "/webhookb2/0000000000000000/IncomingWebhook/abc" {
			sawPath = true
		}
	}
	if !sawPath {
		t.Errorf("teamsScrubValues(%q) = %q; the token-bearing path must be registered", long, got)
	}
}
