// Named licence allowances: the half of --license-allow that names a licence
// rather than a category.
//
// A declaration in `unknown` needs individual review; the remedies a
// category-granular allowlist offers are too broad:
//
//   - `--license-allow unknown` switches the check off. `unknown` is not a
//     licence tier, it is "Trivy could not classify this", so allowing it
//     allows the next unclassifiable declaration too — including the one nobody
//     has looked at yet. That is the off switch this module refuses to have, so
//     `unknown` is not an allowable category at all.
//   - `--license-allow restricted` accepts GPL; it does not target an
//     unclassified declaration. As an independent example, `BlueOak-1.0.0`
//     names a permissive licence absent from the pinned Trivy's table. Separately,
//     `SEE LICENSE IN LICENSE` is a file pointer, not a licence name, and
//     requires reading that package's licence. Neither example justifies
//     allowing an entire category.
//
// So a consumer may name the declaration itself. Three rules make that safe,
// and they are what this file is:
//
//  1. It NARROWS, never widens. A named allowance can only stop a declaration
//     that is already being reported from being reported. It cannot admit a
//     category, cannot reach --ignored-licenses, and cannot make a licence
//     Trivy never saw appear in the report.
//  2. An unclassifiable declaration is allowable only by NAME, never by
//     category, and an ambiguous name must be SCOPED to a package. A global
//     allowance has to look like an SPDX expression (`BlueOak-1.0.0`,
//     `MIT OR Apache-2.0`); anything else — `SEE LICENSE IN LICENSE`, a company
//     name, a sentence — must be written `pkg=<declaration>` so it can only
//     ever silence the one package its author read.
//  3. Nothing is allowed silently. Every allowance is recorded in the evidence
//     payload with the number of declarations it covered, and one that covered
//     nothing warns — the same rule licenseexclude.go applies to path patterns,
//     for the same reason: a stale allowance and a clean tree are otherwise the
//     same observation.
//
// Matching is on the EXACT declared expression, case-insensitively, with runs
// of whitespace collapsed. It does not parse SPDX operands. cicd has no
// category table of its own — licenseflags.go pins `--ignored-licenses ""`
// precisely so the taxonomy stays Trivy's — so evaluating `MIT OR GPL-3.0`
// would mean inventing one, and an allowance for `MIT` that silently covered
// `MIT OR GPL-3.0` would widen rather than narrow, which is rule 1. An
// allowance for a compound expression therefore names that whole expression.
//
// Untagged, no Dagger: licenseallow_test.go pins all of it.
package main

import (
	"fmt"
	"regexp"
	"strings"
)

// licenseAllowance is one named allowance: a declaration the consumer has read
// and accepted, optionally scoped to the package it was read in.
type licenseAllowance struct {
	// Raw is what the consumer typed, kept verbatim for every message. A
	// warning that reprints a normalised form is a warning whose subject the
	// reader cannot find in their own pipeline definition.
	Raw string
	// Name is the declared expression, whitespace-collapsed.
	Name string
	// Pkg is the package this allowance is scoped to, empty for a global one.
	Pkg  string
	hits int
}

// spdxIDRe is one SPDX licence identifier or `LicenseRef-` token. Deliberately
// a shape check and not a list: cicd ships no SPDX licence list and must not
// start, or it becomes a second table to keep in step with Trivy's.
var spdxIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+-]*$`)

// spdxOperators are the three tokens that may sit between identifiers.
var spdxOperators = map[string]bool{"AND": true, "OR": true, "WITH": true}

// normaliseLicenseName collapses whitespace so `MIT  OR\tApache-2.0` and
// `MIT OR Apache-2.0` are the same allowance. Case is left alone here and
// handled at comparison time, so every message can quote the consumer's own
// spelling.
func normaliseLicenseName(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// looksLikeSPDXExpression reports whether a name may be allowed globally.
//
// The rule is alternation: identifier, operator, identifier, … Parentheses are
// stripped first, since SPDX permits them and they carry no meaning for a shape
// check. `BlueOak-1.0.0` passes. `SEE LICENSE IN LICENSE` does not, because its
// second token is not an operator — and that is the case the rule exists for: a
// declaration like that means "read the file", it says nothing about what the
// licence is, and it recurs verbatim across unrelated packages. Allowing it
// globally would silence every package that ever writes it, including ones the
// consumer has never opened.
//
// Residue, stated rather than fixed: a single token is indistinguishable from
// an identifier, so `UNLICENSED` — npm's marker for "not published under any
// licence" — passes this check and can be allowed globally. Closing it needs
// the SPDX licence list, which is the table this module refuses to own. A
// consumer who writes it has typed a word that names no licence, and the
// allowance is disclosed in the payload with its hit count either way.
func looksLikeSPDXExpression(name string) bool {
	cleaned := strings.NewReplacer("(", " ", ")", " ").Replace(name)
	tokens := strings.Fields(cleaned)
	if len(tokens) == 0 || len(tokens)%2 == 0 {
		// An even token count cannot alternate id/op/id, and zero tokens is not
		// an expression at all.
		return false
	}
	for i, tok := range tokens {
		if i%2 == 1 {
			if !spdxOperators[strings.ToUpper(tok)] {
				return false
			}
			continue
		}
		if !spdxIDRe.MatchString(tok) || spdxOperators[strings.ToUpper(tok)] {
			return false
		}
	}
	return true
}

// lowercaseWordRe is a single token of nothing but lowercase ASCII letters —
// the shape a Trivy category has, and the shape a misspelling of one has.
var lowercaseWordRe = regexp.MustCompile(`^[a-z]+$`)

// looksLikeCategoryTypo reports whether a global allowance could equally be
// read as a category the consumer meant to name.
func looksLikeCategoryTypo(name string) bool {
	return lowercaseWordRe.MatchString(name)
}

// parseLicenseAllowance turns one `--license-allow` entry that is not a
// category into an allowance, or explains why it cannot be one.
//
// The `=` split is on the FIRST separator, because a declaration may contain
// one — `SEE LICENSE IN LICENSE` does not, but `LicenseRef-foo=bar` could — and
// a package name may not.
func parseLicenseAllowance(raw string) (licenseAllowance, error) {
	trimmed := strings.TrimSpace(raw)
	pkg := ""
	name := trimmed
	if idx := strings.Index(trimmed, "="); idx >= 0 {
		pkg = strings.TrimSpace(trimmed[:idx])
		name = strings.TrimSpace(trimmed[idx+1:])
		if pkg == "" {
			return licenseAllowance{}, fmt.Errorf(
				"license-allow entry %q starts with '='; write it as <package>=<declaration>", raw)
		}
		if name == "" {
			return licenseAllowance{}, fmt.Errorf(
				"license-allow entry %q names a package but no declaration; "+
					"write it as <package>=<declaration>", raw)
		}
	}
	name = normaliseLicenseName(name)
	if name == "" {
		return licenseAllowance{}, fmt.Errorf("license-allow entry %q is empty", raw)
	}
	if pkg == "" && looksLikeCategoryTypo(name) {
		// The reason this is an error and not a global allowance: a category and
		// a bare lowercase word are indistinguishable, so `--license-allow
		// permisive` would otherwise stop being a rejected typo and quietly
		// become an allowance for a licence nobody has ever declared. The old
		// behaviour — every non-category entry rejected — caught it; letting
		// names through reopens that door unless this closes it.
		//
		// The cost is that a genuinely lowercase SPDX identifier (`curl`,
		// `psutils`) cannot be allowed globally. That is a loud failure with the
		// remedy in the message, which is the trade this module makes every
		// time: a narrower allowance that has to be typed out beats a wider one
		// that happens by accident.
		return licenseAllowance{}, fmt.Errorf(
			"license-allow names %q, which is neither an allowable category nor "+
				"distinguishable from a misspelling of one. Allowable categories are %s. "+
				"If %q is a license identifier, scope it to the package you read it in: "+
				"--license-allow '<package>=%s'",
			raw, strings.Join(allowableLicenseCategories, ", "), name, name)
	}
	if pkg == "" && !looksLikeSPDXExpression(name) {
		return licenseAllowance{}, fmt.Errorf(
			"license-allow names %q, which is neither a Trivy license category nor an "+
				"SPDX expression, so it cannot be allowed for every package. Scope it to "+
				"the package you read it in: --license-allow '<package>=%s'. Allowed "+
				"categories are %s",
			raw, name, strings.Join(allowableLicenseCategories, ", "))
	}
	return licenseAllowance{Raw: trimmed, Name: name, Pkg: pkg}, nil
}

// licenseAllower holds the named allowances and records which ones covered a
// declaration, so a stale one can be reported rather than assumed harmless.
type licenseAllower struct {
	allowances []licenseAllowance
}

// newLicenseAllower keeps declaration order and drops exact duplicates.
//
// A duplicate is not an error, for licenseexclude.go's reason: composing two
// lists of allowances must not fail for no reason.
func newLicenseAllower(allowances []licenseAllowance) *licenseAllower {
	al := &licenseAllower{}
	seen := map[string]bool{}
	for _, a := range allowances {
		key := strings.ToLower(a.Pkg) + "\x00" + strings.ToLower(a.Name)
		if seen[key] {
			continue
		}
		seen[key] = true
		al.allowances = append(al.allowances, a)
	}
	return al
}

func (al *licenseAllower) empty() bool { return al == nil || len(al.allowances) == 0 }

// match reports whether a declaration is allowed by name, recording which
// allowance did it.
//
// Case-insensitive on both fields. For the licence name that is SPDX's own
// rule. For the package name it is a deliberate small widening: NuGet package
// ids are case-insensitive, npm's are not, and cicd cannot tell which ecosystem
// a row came from — the cost of getting it wrong is an allowance covering a
// package spelled the same way in a different case, which is the same package
// everywhere this has been measured.
func (al *licenseAllower) match(pkg, name string) bool {
	if al == nil {
		return false
	}
	n := normaliseLicenseName(name)
	if n == "" {
		// A declaration with no name cannot be the one a consumer read and
		// accepted, and allowing it on a guess would drop a finding nobody
		// asked to drop.
		return false
	}
	p := strings.TrimSpace(pkg)
	for i := range al.allowances {
		a := &al.allowances[i]
		if !strings.EqualFold(a.Name, n) {
			continue
		}
		if a.Pkg != "" && !strings.EqualFold(a.Pkg, p) {
			continue
		}
		a.hits++
		return true
	}
	return false
}

// raws is every allowance as the consumer wrote it, for the evidence payload.
func (al *licenseAllower) raws() []string {
	if al == nil {
		return nil
	}
	out := make([]string, 0, len(al.allowances))
	for _, a := range al.allowances {
		out = append(out, a.Raw)
	}
	return out
}

// hitsByAllowance is the disclosure rule 3 requires: every allowance and the
// number of declarations it covered, in the payload, including the zeroes.
func (al *licenseAllower) hitsByAllowance() map[string]int {
	if al.empty() {
		return nil
	}
	out := map[string]int{}
	for _, a := range al.allowances {
		out[a.Raw] = a.hits
	}
	return out
}

// inertWarnings names every allowance that covered nothing.
//
// A scoped allowance gets a hint naming the package, because the mistake worth
// catching is a package id that does not match the ecosystem's spelling — the
// declaration is usually copied out of the report and correct, while the
// package name is typed.
func (al *licenseAllower) inertWarnings() []string {
	if al == nil {
		return nil
	}
	var out []string
	for _, a := range al.allowances {
		if a.hits > 0 {
			continue
		}
		msg := fmt.Sprintf("license-allow: %q allowed no license declaration", a.Raw)
		if a.Pkg != "" {
			msg += fmt.Sprintf("; the declaration is matched exactly, and the scope %q "+
				"must be the package id as the report spells it", a.Pkg)
		} else {
			msg += "; the declaration is matched exactly, so a compound expression must be named in full"
		}
		out = append(out, msg)
	}
	return out
}

// licenseAllowSummary states what the named allowances covered, and is emitted
// whenever any was configured — including when they covered nothing, because
// "no allowance" and "an allowance that covered nothing" are different runs.
func licenseAllowSummary(al *licenseAllower, allowed int) string {
	if al.empty() {
		return ""
	}
	return fmt.Sprintf(
		"license-allow: %d license declaration(s) allowed by %d named allowance(s) (%s); "+
			"a named allowance narrows the report and can never admit a category",
		allowed, len(al.allowances), strings.Join(al.raws(), ", "))
}
