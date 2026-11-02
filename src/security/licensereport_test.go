package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// licenseDoc builds a Trivy license report with the field names and the nesting
// the pinned 0.70.0 actually emits, captured from a real run against
// testdata/node-app rather than written from the documentation.
func licenseDoc(entries ...string) json.RawMessage {
	body := ""
	for i, e := range entries {
		if i > 0 {
			body += ","
		}
		body += e
	}
	return json.RawMessage(`{"SchemaVersion":2,"Results":[
	  {"Target":"package-lock.json","Class":"lang-pkgs","Type":"npm"},
	  {"Target":"package-lock.json","Class":"license","Licenses":[` + body + `]}]}`)
}

const mitEntry = `{"Severity":"LOW","Category":"notice","PkgName":"lodash","FilePath":"package-lock.json","Name":"MIT","Confidence":1}`

func defaultPolicy(t *testing.T) licensePolicy {
	t.Helper()
	pol, _, err := resolveLicenseAllowlist(nil)
	if err != nil {
		t.Fatalf("resolveLicenseAllowlist(nil) error: %v", err)
	}
	return pol
}

// TestDefaultAllowlistPermitsTheHarmlessCategories pins the shipped default. It
// exists so a change to that list is a deliberate edit to a test that states
// the reasoning, not a quiet widening of what passes.
func TestDefaultAllowlistPermitsTheHarmlessCategories(t *testing.T) {
	pol := defaultPolicy(t)
	if !pol.Defaulted {
		t.Error("policy resolved from no allowlist is not marked Defaulted; a reader could not tell cicd's policy from the consumer's")
	}
	allowed := map[string]bool{}
	for _, c := range pol.AllowedCategories {
		allowed[c] = true
	}
	for _, c := range []string{licensePermissive, licenseNotice, licenseUnencumbered} {
		if !allowed[c] {
			t.Errorf("default allowlist omits %q", c)
		}
	}
	// reciprocal is the deliberate exclusion: MPL/EPL/LGPL obligations depend on
	// linking and distribution, which is a per-product legal judgement.
	for _, c := range []string{licenseReciprocal, licenseRestricted, licenseForbidden, licenseUnknown} {
		if allowed[c] {
			t.Errorf("default allowlist permits %q, which must surface for a human decision", c)
		}
	}
}

// TestUnrecognisedCategoryIsAFinding is the fail-closed guard. A licence Trivy
// could not classify, or a category this module has never heard of, is exactly
// what a compliance check exists to surface — it must not pass by being
// unfamiliar.
func TestUnrecognisedCategoryIsAFinding(t *testing.T) {
	doc := licenseDoc(`{"Category":"something-trivy-invented","Name":"Weird-1.0","PkgName":"pkg","FilePath":"go.mod"}`)
	res, err := evaluateLicenses(doc, defaultPolicy(t), nil, nil)
	if err != nil {
		t.Fatalf("evaluateLicenses error: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1 for an unrecognised category", len(res.Findings))
	}
	if got := res.Findings[0].Severity; got != SeverityHigh {
		t.Errorf("severity = %q, want HIGH so it trips the default --fail-on HIGH gate", got)
	}
}

// TestEmptyCategoryIsTreatedAsUnknown covers the other shape of the same hole: a
// Licenses[] entry with no Category at all must not fall through the allowlist
// as a zero-value match.
func TestEmptyCategoryIsTreatedAsUnknown(t *testing.T) {
	res, err := evaluateLicenses(licenseDoc(`{"Name":"NOASSERTION","PkgName":"pkg"}`), defaultPolicy(t), nil, nil)
	if err != nil {
		t.Fatalf("evaluateLicenses error: %v", err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Severity != SeverityHigh {
		t.Fatalf("findings = %+v, want one HIGH finding for a category-less entry", res.Findings)
	}
	if res.Findings[0].Rule != "license/unknown" {
		t.Errorf("rule = %q, want license/unknown", res.Findings[0].Rule)
	}
}

// TestAllowedCategoryProducesNoFindingButStillCounts is the distinction between
// "clean" and "saw nothing" — the conflation gating.go exists to prevent. An
// allowed licence must leave Scanned non-zero so a zero finding count is
// falsifiable.
func TestAllowedCategoryProducesNoFindingButStillCounts(t *testing.T) {
	res, err := evaluateLicenses(licenseDoc(mitEntry), defaultPolicy(t), nil, nil)
	if err != nil {
		t.Fatalf("evaluateLicenses error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings = %+v, want none for MIT under the default policy", res.Findings)
	}
	if res.Scanned != 1 {
		t.Errorf("Scanned = %d, want 1 — a clean verdict must be distinguishable from a scan that saw nothing", res.Scanned)
	}
}

// TestCategorySeverityLadder pins the projection the gate reads. Derived in cicd
// rather than taken from Trivy's own Severity field so the gate's meaning cannot
// move when upstream retunes that projection.
func TestCategorySeverityLadder(t *testing.T) {
	for cat, want := range map[string]Severity{
		licenseForbidden:    SeverityCritical,
		licenseRestricted:   SeverityHigh,
		licenseReciprocal:   SeverityMedium,
		licenseNotice:       SeverityLow,
		licensePermissive:   SeverityLow,
		licenseUnencumbered: SeverityLow,
		licenseUnknown:      SeverityHigh,
	} {
		if got := licenseSeverity(cat); got != want {
			t.Errorf("licenseSeverity(%q) = %q, want %q", cat, got, want)
		}
	}
	// Case and padding come from a consumer-authored allowlist and from Trivy
	// alike; neither should change a verdict.
	if licenseSeverity(" FORBIDDEN ") != SeverityCritical {
		t.Error("licenseSeverity does not normalise case and padding")
	}
}

// TestPolicyTravelsInTheReport is why licensePolicy is serialised at all: a
// verdict with no record of the policy applied cannot distinguish a clean tree
// from an allowlist that permitted everything.
func TestPolicyTravelsInTheReport(t *testing.T) {
	res, err := evaluateLicenses(licenseDoc(mitEntry), defaultPolicy(t), nil, nil)
	if err != nil {
		t.Fatalf("evaluateLicenses error: %v", err)
	}
	var payload struct {
		Policy struct {
			AllowedCategories []string `json:"allowedCategories"`
			Defaulted         bool     `json:"defaulted"`
		} `json:"policy"`
		Scanned    int            `json:"scanned"`
		Flagged    int            `json:"flagged"`
		ByCategory map[string]int `json:"byCategory"`
	}
	if err := json.Unmarshal(res.Report, &payload); err != nil {
		t.Fatalf("license report is not readable JSON: %v", err)
	}
	if len(payload.Policy.AllowedCategories) == 0 {
		t.Error("report records no allowlist, so the verdict is unfalsifiable")
	}
	if !payload.Policy.Defaulted {
		t.Error("report does not record that the policy was cicd's default")
	}
	if payload.Scanned != 1 || payload.Flagged != 0 {
		t.Errorf("report scanned=%d flagged=%d, want 1/0", payload.Scanned, payload.Flagged)
	}
	if payload.ByCategory[licenseNotice] != 1 {
		t.Errorf("byCategory = %v, want one notice — allowed licences must still be reported", payload.ByCategory)
	}
}

// TestLicensesReadFromEveryResultClass guards the parser against being scoped to
// Class "license". The pinned version files them there, but a parser that
// filtered on that string would go silently blind if a future release moved
// them — and silence reads downstream as a clean policy.
func TestLicensesReadFromEveryResultClass(t *testing.T) {
	doc := json.RawMessage(`{"SchemaVersion":2,"Results":[{"Target":"x","Class":"lang-pkgs","Licenses":[
	  {"Category":"restricted","Name":"GPL-3.0","PkgName":"gpl-thing"}]}]}`)
	res, err := evaluateLicenses(doc, defaultPolicy(t), nil, nil)
	if err != nil {
		t.Fatalf("evaluateLicenses error: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1 — Licenses[] must be read regardless of Result.Class", len(res.Findings))
	}
}

// TestConsumerAllowlistOverridesAndNormalises covers the policy layer that is
// deliberately the consumer's.
func TestConsumerAllowlistOverridesAndNormalises(t *testing.T) {
	pol, _, err := resolveLicenseAllowlist([]string{" Reciprocal ", "notice", "notice"})
	if err != nil {
		t.Fatalf("resolveLicenseAllowlist error: %v", err)
	}
	if pol.Defaulted {
		t.Error("a consumer-supplied allowlist is marked Defaulted")
	}
	if len(pol.AllowedCategories) != 2 {
		t.Fatalf("AllowedCategories = %v, want the duplicate collapsed", pol.AllowedCategories)
	}
	res, err := evaluateLicenses(licenseDoc(`{"Category":"reciprocal","Name":"MPL-2.0","PkgName":"mpl-thing"}`), pol, nil, nil)
	if err != nil {
		t.Fatalf("evaluateLicenses error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings = %+v, want none once the consumer allows reciprocal", res.Findings)
	}
}

// TestAllowlistRejectsUnknownCategory keeps a typo from reporting a policy the
// consumer did not write. It fails in the safe direction either way, but the
// only symptom of silent dropping would be noise nobody could trace to a typo.
func TestAllowlistRejectsUnknownCategory(t *testing.T) {
	if _, _, err := resolveLicenseAllowlist([]string{"permisive"}); err == nil {
		t.Fatal("resolveLicenseAllowlist accepted a misspelled category")
	}
	if _, _, err := resolveLicenseAllowlist([]string{"   "}); err == nil {
		t.Fatal("resolveLicenseAllowlist accepted an allowlist naming no category")
	}
}

// TestValidateLicenseGate mirrors src/quality/byotest.go: an unrecognised mode
// errors rather than falling back, because a typo becoming "warn" would
// downgrade an enforced gate.
func TestValidateLicenseGate(t *testing.T) {
	for _, ok := range []string{licenseGateEnforce, licenseGateWarn} {
		if err := validateLicenseGate(ok); err != nil {
			t.Errorf("validateLicenseGate(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "off", "GATE", "advisory"} {
		if err := validateLicenseGate(bad); err == nil {
			t.Errorf("validateLicenseGate(%q) = nil, want an error", bad)
		}
	}
}

// TestUnparseableReportIsAnError keeps a broken report from reading as a clean
// policy. Trivy leaving unusable output is a run failure, not zero findings.
func TestUnparseableReportIsAnError(t *testing.T) {
	if _, err := evaluateLicenses(json.RawMessage(`{"Results":`), defaultPolicy(t), nil, nil); err == nil {
		t.Fatal("evaluateLicenses accepted a truncated report")
	}
}

// A green run with no findings must still say which allowlist produced the
// green. buildCombined in cross-cutting/evidence drops genericReport, so this
// string is the only record of the policy that reaches an uploaded audit
// bundle — see the comment on licensePolicyWarning.
func TestPolicyWarningNamesTheDefaultAsDefaulted(t *testing.T) {
	pol, _, err := resolveLicenseAllowlist(nil)
	if err != nil {
		t.Fatalf("resolveLicenseAllowlist(nil): %v", err)
	}
	pol.Mode = licenseGateWarn

	got := licensePolicyWarning(pol, 41, 0)
	for _, want := range []string{
		"mode warn",
		"permissive, notice, unencumbered",
		"cicd default",
		"41 license(s) scanned",
		"0 outside policy",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("policy warning is missing %q:\n%s", want, got)
		}
	}
}

func TestPolicyWarningDistinguishesACallerPolicy(t *testing.T) {
	pol, _, err := resolveLicenseAllowlist([]string{"permissive"})
	if err != nil {
		t.Fatalf("resolveLicenseAllowlist: %v", err)
	}
	pol.Mode = licenseGateEnforce

	got := licensePolicyWarning(pol, 12, 3)
	if strings.Contains(got, "cicd default") {
		t.Errorf("a caller-supplied allowlist must not be reported as the default:\n%s", got)
	}
	for _, want := range []string{"mode gate", "caller", "3 outside policy"} {
		if !strings.Contains(got, want) {
			t.Errorf("policy warning is missing %q:\n%s", want, got)
		}
	}
}
