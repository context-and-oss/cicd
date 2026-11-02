package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// mustAllower resolves an allowlist that is expected to be valid.
func mustAllower(t *testing.T, entries ...string) (licensePolicy, *licenseAllower) {
	t.Helper()
	pol, al, err := resolveLicenseAllowlist(entries)
	if err != nil {
		t.Fatalf("resolveLicenseAllowlist(%v): %v", entries, err)
	}
	return pol, al
}

// TestUnknownIsNotAnAllowableCategory is the breaking change, stated. It used
// to be accepted, and accepting it is an off switch: `unknown` means Trivy
// could not classify a declaration, so allowing it allows the next
// unclassifiable one too.
func TestUnknownIsNotAnAllowableCategory(t *testing.T) {
	for _, entry := range []string{"unknown", "UNKNOWN", " Unknown "} {
		_, _, err := resolveLicenseAllowlist([]string{entry})
		if err == nil {
			t.Fatalf("resolveLicenseAllowlist(%q) accepted the off switch", entry)
		}
		// The error has to carry the route that replaces it, or a consumer who
		// relied on it has a broken pipeline and no next step.
		for _, want := range []string{"could not classify", "by name", "BlueOak-1.0.0"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error for %q does not mention %q: %v", entry, want, err)
			}
		}
	}
	if licenseCategoryAllowable(licenseUnknown) {
		t.Error("licenseCategoryAllowable admits unknown")
	}
	if !licenseCategoryKnown(licenseUnknown) {
		t.Error("licenseCategoryKnown must still admit unknown — trivy emits it")
	}
}

// TestASPDXShapedNameIsAllowedGlobally is the BlueOak-1.0.0 case from the licence-policy report: a
// permissive licence simply absent from Trivy's table, which lands in
// `unknown` and has no category a consumer could allow without allowing
// everything unclassifiable.
func TestASPDXShapedNameIsAllowedGlobally(t *testing.T) {
	pol, al := mustAllower(t, "BlueOak-1.0.0")
	if !pol.Defaulted {
		t.Error("naming only a license must keep cicd's default categories, and say so")
	}
	if got := pol.AllowedCategories; len(got) != len(defaultLicenseAllowlist) {
		t.Errorf("AllowedCategories = %v, want the defaults kept", got)
	}
	doc := licenseDoc(
		`{"Category":"unknown","Name":"BlueOak-1.0.0","PkgName":"jackspeak","FilePath":"package-lock.json"}`,
		`{"Category":"unknown","Name":"BlueOak-1.0.0","PkgName":"path-scurry","FilePath":"package-lock.json"}`,
	)
	res, err := evaluateLicenses(doc, pol, nil, al)
	if err != nil {
		t.Fatalf("evaluateLicenses: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings = %+v, want none", res.Findings)
	}
	if res.AllowedByName != 2 {
		t.Errorf("AllowedByName = %d, want 2", res.AllowedByName)
	}
	if res.Scanned != 2 {
		t.Errorf("Scanned = %d, want 2 — an allowed declaration was still scanned", res.Scanned)
	}
	if al.inertWarnings() != nil {
		t.Errorf("an allowance that covered two declarations warned: %v", al.inertWarnings())
	}
}

// TestAnUnshapedNameMustBeScopedToAPackage is the `SEE LICENSE IN LICENSE`
// case. It is not a licence name, it is an instruction to open a file, and it
// recurs verbatim across unrelated packages — so a global allowance for it
// would silence packages the consumer has never opened.
func TestAnUnshapedNameMustBeScopedToAPackage(t *testing.T) {
	_, _, err := resolveLicenseAllowlist([]string{"SEE LICENSE IN LICENSE"})
	if err == nil {
		t.Fatal("a sentence was accepted as a global license allowance")
	}
	if !strings.Contains(err.Error(), "<package>=") {
		t.Errorf("the error does not say how to scope it: %v", err)
	}

	pol, al := mustAllower(t, "example-sdk=SEE LICENSE IN LICENSE")
	doc := licenseDoc(
		`{"Category":"unknown","Name":"SEE LICENSE IN LICENSE","PkgName":"example-sdk"}`,
		`{"Category":"unknown","Name":"SEE LICENSE IN LICENSE","PkgName":"some-other-pkg"}`,
	)
	res, err := evaluateLicenses(doc, pol, nil, al)
	if err != nil {
		t.Fatalf("evaluateLicenses: %v", err)
	}
	if res.AllowedByName != 1 {
		t.Errorf("AllowedByName = %d, want 1 — the scope must not reach the other package", res.AllowedByName)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %+v, want the unscoped package still reported", res.Findings)
	}
	if !strings.Contains(res.Findings[0].Message, "some-other-pkg") {
		t.Errorf("the surviving finding is not the other package: %q", res.Findings[0].Message)
	}
}

// TestANamedAllowanceNeverWidens is rule 1. An allowance names a declaration;
// it cannot admit the category that declaration belongs to, and it cannot
// silence a different declaration of the same category.
func TestANamedAllowanceNeverWidens(t *testing.T) {
	pol, al := mustAllower(t, "BlueOak-1.0.0")
	doc := licenseDoc(
		`{"Category":"unknown","Name":"BlueOak-1.0.0","PkgName":"a"}`,
		`{"Category":"unknown","Name":"WTF-IS-THIS","PkgName":"b"}`,
		`{"Category":"restricted","Name":"GPL-3.0","PkgName":"c"}`,
	)
	res, err := evaluateLicenses(doc, pol, nil, al)
	if err != nil {
		t.Fatalf("evaluateLicenses: %v", err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("findings = %+v, want the other two still reported", res.Findings)
	}
	names := res.Findings[0].Message + " " + res.Findings[1].Message
	for _, want := range []string{"WTF-IS-THIS", "GPL-3.0"} {
		if !strings.Contains(names, want) {
			t.Errorf("%s was silenced by an allowance that does not name it", want)
		}
	}
}

// TestAnAllowanceIsMatchedExactly states the deliberate limit: cicd does not
// evaluate SPDX operands, because it owns no category table and inventing one
// to decide that `MIT` covers `MIT OR GPL-3.0` would widen rather than narrow.
func TestAnAllowanceIsMatchedExactly(t *testing.T) {
	pol, al := mustAllower(t, "MIT OR Apache-2.0")
	doc := licenseDoc(
		`{"Category":"unknown","Name":"MIT  OR   Apache-2.0","PkgName":"whitespace"}`,
		`{"Category":"unknown","Name":"mit or apache-2.0","PkgName":"case"}`,
		`{"Category":"unknown","Name":"MIT OR GPL-3.0","PkgName":"different"}`,
	)
	res, err := evaluateLicenses(doc, pol, nil, al)
	if err != nil {
		t.Fatalf("evaluateLicenses: %v", err)
	}
	// Whitespace collapses and case does not matter: those are the same
	// declaration written differently, not a different declaration.
	if res.AllowedByName != 2 {
		t.Errorf("AllowedByName = %d, want 2 (whitespace and case are normalised)", res.AllowedByName)
	}
	if len(res.Findings) != 1 || !strings.Contains(res.Findings[0].Message, "GPL-3.0") {
		t.Errorf("findings = %+v, want only the different expression", res.Findings)
	}
}

// TestAnAllowanceThatCoveredNothingWarns is rule 3, and the same rule
// licenseexclude.go applies to path patterns: a stale allowance and a clean
// tree are otherwise the same observation.
func TestAnAllowanceThatCoveredNothingWarns(t *testing.T) {
	pol, al := mustAllower(t, "BlueOak-1.0.0", "example-sdk=SEE LICENSE IN LICENSE")
	if _, err := evaluateLicenses(licenseDoc(mitEntry), pol, nil, al); err != nil {
		t.Fatalf("evaluateLicenses: %v", err)
	}
	warnings := al.inertWarnings()
	if len(warnings) != 2 {
		t.Fatalf("warnings = %v, want one per unused allowance", warnings)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "BlueOak-1.0.0") || !strings.Contains(joined, "example-sdk") {
		t.Errorf("warnings do not quote the consumer's own entries: %v", warnings)
	}
	// The scoped one gets the hint that matters for it: the package id, not the
	// declaration, is the half a consumer types rather than copies.
	if !strings.Contains(joined, "the package id as the report spells it") {
		t.Errorf("the scoped allowance has no scope-specific hint: %v", warnings)
	}
}

// TestACategoryAllowedDeclarationDoesNotConsumeAnAllowance pins the ordering
// inside evaluateLicenses. If the allowance were checked first, one that covers
// nothing the category policy did not already cover would report hits and never
// warn — a stale allowance that looks live.
func TestACategoryAllowedDeclarationDoesNotConsumeAnAllowance(t *testing.T) {
	pol, al := mustAllower(t, "notice", "MIT")
	if _, err := evaluateLicenses(licenseDoc(mitEntry), pol, nil, al); err != nil {
		t.Fatalf("evaluateLicenses: %v", err)
	}
	if got := al.hitsByAllowance()["MIT"]; got != 0 {
		t.Errorf("MIT allowance recorded %d hit(s) for a declaration `notice` already allowed", got)
	}
	if len(al.inertWarnings()) != 1 {
		t.Errorf("the redundant allowance did not warn: %v", al.inertWarnings())
	}
}

// TestTheAllowancesReachTheEvidencePayload is rule 3's other half. The verdict
// is unfalsifiable without it: "passed" with three declarations named and
// accepted is the same word as "passed" with none.
func TestTheAllowancesReachTheEvidencePayload(t *testing.T) {
	pol, al := mustAllower(t, "BlueOak-1.0.0", "example-sdk=SEE LICENSE IN LICENSE")
	doc := licenseDoc(`{"Category":"unknown","Name":"BlueOak-1.0.0","PkgName":"jackspeak"}`)
	res, err := evaluateLicenses(doc, pol, nil, al)
	if err != nil {
		t.Fatalf("evaluateLicenses: %v", err)
	}
	var payload struct {
		Policy struct {
			AllowedNames []string `json:"allowedNames"`
		} `json:"policy"`
		AllowedByName   int            `json:"allowedByName"`
		AllowedNameHits map[string]int `json:"allowedNameHits"`
	}
	if err := json.Unmarshal(res.Report, &payload); err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	if len(payload.Policy.AllowedNames) != 2 {
		t.Errorf("allowedNames = %v, want both entries", payload.Policy.AllowedNames)
	}
	if payload.AllowedByName != 1 {
		t.Errorf("allowedByName = %d, want 1", payload.AllowedByName)
	}
	// The zero is in the payload too. An allowance that covered nothing is the
	// one a reader most needs to see, and omitting zeroes would hide exactly it.
	if payload.AllowedNameHits["BlueOak-1.0.0"] != 1 {
		t.Errorf("hits = %v, want BlueOak-1.0.0 at 1", payload.AllowedNameHits)
	}
	if got, ok := payload.AllowedNameHits["example-sdk=SEE LICENSE IN LICENSE"]; !ok || got != 0 {
		t.Errorf("hits = %v, want the unused allowance present at 0", payload.AllowedNameHits)
	}
	if w := licensePolicyWarning(pol, res.Scanned, 0); !strings.Contains(w, "allowed by name") {
		t.Errorf("the policy warning does not state the named allowances: %q", w)
	}
}

// TestAMisspelledCategoryIsStillRejected is the regression the named-allowance
// feature could have introduced. Before it, every non-category entry errored,
// so `permisive` was caught. A bare lowercase word is indistinguishable from a
// category, so it must keep erroring rather than become an allowance for a
// licence nobody has ever declared.
func TestAMisspelledCategoryIsStillRejected(t *testing.T) {
	for _, typo := range []string{"permisive", "restrictd", "reciprocol", "notce"} {
		_, _, err := resolveLicenseAllowlist([]string{typo})
		if err == nil {
			t.Fatalf("resolveLicenseAllowlist(%q) accepted a misspelled category as a license name", typo)
		}
		if !strings.Contains(err.Error(), "misspelling") {
			t.Errorf("error for %q does not name the ambiguity: %v", typo, err)
		}
	}
	// And the documented cost: a genuinely lowercase SPDX identifier has to be
	// scoped. Loud, with the remedy in the message.
	if _, _, err := resolveLicenseAllowlist([]string{"curl"}); err == nil {
		t.Error("a lowercase identifier was allowed globally, reopening the typo hole")
	}
	if _, _, err := resolveLicenseAllowlist([]string{"libcurl=curl"}); err != nil {
		t.Errorf("a scoped lowercase identifier must be accepted: %v", err)
	}
}

// TestSPDXShapeAcceptsIdentifiersAndRejectsProse pins the shape rule directly,
// including the residue: a single token cannot be told from an identifier, so
// npm's UNLICENSED marker passes. Stated as a test rather than left to be
// discovered.
func TestSPDXShapeAcceptsIdentifiersAndRejectsProse(t *testing.T) {
	for _, ok := range []string{
		"MIT", "BlueOak-1.0.0", "Apache-2.0", "MIT OR Apache-2.0",
		"GPL-2.0+ WITH Classpath-exception-2.0", "(MIT OR Apache-2.0)",
		"MIT AND BSD-3-Clause", "UNLICENSED",
	} {
		if !looksLikeSPDXExpression(ok) {
			t.Errorf("looksLikeSPDXExpression(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{
		"SEE LICENSE IN LICENSE", "MIT OR", "OR MIT", "Copyright Acme Inc",
		"", "   ", "see the LICENSE file", "MIT MIT",
	} {
		if looksLikeSPDXExpression(bad) {
			t.Errorf("looksLikeSPDXExpression(%q) = true, want false", bad)
		}
	}
}

// TestMalformedScopedEntriesAreRejected keeps a half-typed entry from becoming
// a global allowance by accident, which is the one direction that widens.
func TestMalformedScopedEntriesAreRejected(t *testing.T) {
	for _, bad := range []string{"=MIT", "example-sdk=", "  =  "} {
		if _, _, err := resolveLicenseAllowlist([]string{bad}); err == nil {
			t.Errorf("resolveLicenseAllowlist(%q) accepted a malformed scoped entry", bad)
		}
	}
}

// TestAnAllowlistNamingNothingIsRejected keeps the old behaviour: whitespace is
// not a policy, and silently using the default would report a policy the
// consumer did not write.
func TestAnAllowlistNamingNothingIsRejected(t *testing.T) {
	if _, _, err := resolveLicenseAllowlist([]string{"  ", ""}); err == nil {
		t.Fatal("an allowlist of whitespace was accepted")
	}
}

// TestAllowSummaryIsEmittedEvenWhenItCoveredNothing: "no allowance" and "an
// allowance that covered nothing" are different runs, and the evidence has to
// tell them apart.
func TestAllowSummaryIsEmittedEvenWhenItCoveredNothing(t *testing.T) {
	_, al := mustAllower(t, "BlueOak-1.0.0")
	if s := licenseAllowSummary(al, 0); !strings.Contains(s, "0 license declaration(s) allowed") {
		t.Errorf("summary = %q, want it emitted at zero", s)
	}
	_, none := mustAllower(t, "notice")
	if s := licenseAllowSummary(none, 0); s != "" {
		t.Errorf("summary = %q, want nothing when no allowance was configured", s)
	}
	// A nil allower is reached from every call site that never resolved one.
	if s := licenseAllowSummary(nil, 0); s != "" {
		t.Errorf("summary = %q, want nothing for a nil allower", s)
	}
	if (*licenseAllower)(nil).match("pkg", "MIT") {
		t.Error("a nil allower matched")
	}
}

// TestADeclarationWithNoNameIsNeverAllowed: a row with no licence text cannot
// be the declaration a consumer read and accepted, and allowing it on a guess
// would drop a finding nobody asked to drop.
func TestADeclarationWithNoNameIsNeverAllowed(t *testing.T) {
	pol, al := mustAllower(t, "BlueOak-1.0.0")
	res, err := evaluateLicenses(licenseDoc(`{"Category":"unknown","Name":"","PkgName":"anon"}`), pol, nil, al)
	if err != nil {
		t.Fatalf("evaluateLicenses: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Errorf("findings = %+v, want the nameless declaration still reported", res.Findings)
	}
}

// TestDuplicateAllowancesCollapse mirrors newLicenseExcluder: composing two
// lists of allowances must not fail, and the duplicate must not double-count.
func TestDuplicateAllowancesCollapse(t *testing.T) {
	_, al := mustAllower(t, "BlueOak-1.0.0", "blueoak-1.0.0", "BlueOak-1.0.0")
	if len(al.allowances) != 1 {
		t.Errorf("allowances = %+v, want the duplicates collapsed", al.allowances)
	}
}
