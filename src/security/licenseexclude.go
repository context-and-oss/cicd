// Path exclusions for the license scan, and the rules that keep an exclusion
// from becoming the hole this module spends the rest of its effort closing.
//
// The need is ordinary: a repository vendors something whose licenses are not
// its problem — an internal documentation site, a fixture tree, a vendored
// sample — and every run reports licenses nobody will ever act on.
//
// The danger is not ordinary. licenseflags.go pins `--ignored-licenses ""`
// precisely so a consumer cannot take the license report to zero from a file
// cicd honours, and a path exclusion is the same power reached by a different
// road: "exclude **" is a green license scan over nothing. Three rules follow
// from that, and they are what this file is:
//
//  1. It narrows SCOPE, never FINDINGS. Patterns match a path. There is no way
//     to exclude a license by name or by category — that is the door
//     --ignored-licenses keeps shut, and this must not be a second one.
//  2. Nothing is excluded silently. Every exclusion is counted, the count is
//     reported next to the scanned count, and the patterns themselves are
//     written into the evidence payload. A reader can always see that a filter
//     ran and how much it removed.
//  3. A pattern that matched nothing says so. A typo is otherwise
//     indistinguishable from a clean tree, and "the filter did nothing" and
//     "there was nothing to filter" are the two readings that must never
//     collapse into one.
//
// The filter runs on the REPORT, not on the tree. Trivy could have been handed
// --skip-dirs, which would be faster: the excluded tree is never read. It was
// rejected because the count in rule 2 is not knowable that way — a scan that
// never saw a file cannot say how many licenses it skipped, so an over-broad
// pattern would produce a clean, fast, empty report with nothing anywhere
// saying why. Paying for the full scan buys the number that makes the exclusion
// auditable. --skip-dirs is also settable from a consumer trivy.yaml, which
// would put rule 1 back in the consumer's hands.
//
// Untagged, no Dagger: licenseexclude_test.go pins all of it.
package main

import (
	"fmt"
	"regexp"
	"strings"
)

// licenseExcluder holds compiled patterns and records which of them ever
// matched, so an inert pattern can be reported rather than assumed harmless.
type licenseExcluder struct {
	patterns []string
	res      []*regexp.Regexp
	hits     []int
}

// newLicenseExcluder compiles the caller's patterns.
//
// Validation is strict and errors rather than skipping, because every rejected
// shape is a pipeline-definition mistake whose silent form is an exclusion that
// matches nothing — and an exclusion that matches nothing looks exactly like a
// tree with nothing to exclude. Same reasoning as validateLicenseGate: a typo
// must not quietly become the permissive value.
func newLicenseExcluder(patterns []string) (*licenseExcluder, error) {
	ex := &licenseExcluder{}
	seen := map[string]bool{}
	for _, raw := range patterns {
		p := strings.TrimSpace(raw)
		switch {
		case p == "":
			return nil, fmt.Errorf("license-exclude: empty pattern; remove the entry rather than passing a blank one")
		case strings.HasPrefix(p, "/"):
			return nil, fmt.Errorf("license-exclude: pattern %q is absolute; patterns match paths relative to the scanned root", raw)
		case strings.Contains(p, ".."):
			return nil, fmt.Errorf("license-exclude: pattern %q contains '..'; patterns match paths relative to the scanned root", raw)
		}
		p = strings.TrimPrefix(p, "./")
		if seen[p] {
			// Not an error: a duplicate is harmless and rejecting it would make
			// composing two lists of patterns fail for no reason.
			continue
		}
		seen[p] = true
		ex.patterns = append(ex.patterns, p)
		ex.res = append(ex.res, compileLicenseGlob(p))
		ex.hits = append(ex.hits, 0)
	}
	return ex, nil
}

// compileLicenseGlob translates one glob into an anchored regexp.
//
//	`*`   any run of characters within one path segment
//	`**`  any run of characters including separators
//	`?`   one character within one path segment
//
// `**/` also matches zero segments, so `**/node_modules/**` catches
// `node_modules/x` as well as `Client/node_modules/x`. Every other character is
// quoted, so a pattern can never smuggle a regexp in — `[a-z]` is a literal
// bracket expression here and not a character class. That is a deliberate
// omission: bracket classes buy little and the failure mode of a
// half-implemented one is a pattern that matches more than its author read it
// to.
//
// Cannot fail: every branch either emits a fixed fragment or a QuoteMeta'd
// literal, so the result is always a valid expression.
func compileLicenseGlob(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString(`^`)
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; c {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				i++
				if i+1 < len(pattern) && pattern[i+1] == '/' {
					i++
					b.WriteString(`(?:.*/)?`)
					continue
				}
				b.WriteString(`.*`)
				continue
			}
			b.WriteString(`[^/]*`)
		case '?':
			b.WriteString(`[^/]`)
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString(`$`)
	return regexp.MustCompile(b.String())
}

// match reports whether path is excluded, recording which pattern did it.
func (ex *licenseExcluder) match(path string) bool {
	if ex == nil {
		return false
	}
	// A finding with no path cannot be matched by a path pattern, and
	// excluding it on a guess would drop a license nobody asked to drop.
	p := strings.TrimPrefix(strings.TrimSpace(path), "./")
	if i := ex.index(p); i >= 0 {
		ex.hits[i]++
		return true
	}
	return false
}

// covers reports whether match would exclude path, without recording a hit.
// For a pass that only counts what an exclusion removed from view — the
// dependency coverage — so a pattern that removed no declaration stays inert.
func (ex *licenseExcluder) covers(path string) bool {
	if ex == nil {
		return false
	}
	return ex.index(strings.TrimPrefix(strings.TrimSpace(path), "./")) >= 0
}

// index is the first pattern matching an already-trimmed path, or -1. An empty
// path matches nothing, for match's reason.
func (ex *licenseExcluder) index(p string) int {
	if p == "" {
		return -1
	}
	for i, re := range ex.res {
		if re.MatchString(p) {
			return i
		}
	}
	return -1
}

func (ex *licenseExcluder) empty() bool { return ex == nil || len(ex.patterns) == 0 }

// inertWarnings names every pattern that excluded nothing. Rule 3: a typo and a
// clean tree are otherwise the same observation.
//
// The hint is attached only to a pattern with no wildcard at all, which is the
// mistake worth catching — `--license-exclude docs` reads like a directory and
// matches only a file called exactly `docs`.
func (ex *licenseExcluder) inertWarnings() []string {
	if ex == nil {
		return nil
	}
	var out []string
	for i, p := range ex.patterns {
		if ex.hits[i] > 0 {
			continue
		}
		msg := fmt.Sprintf("license-exclude: pattern %q matched no license declaration", p)
		if !strings.ContainsAny(p, "*?") {
			msg += fmt.Sprintf("; patterns match whole file paths, so a directory needs a wildcard — %q", p+"/**")
		}
		out = append(out, msg)
	}
	return out
}

// licenseExcludeSummary states what the filter removed, and is emitted whenever
// any pattern was configured — including when it removed nothing, because "no
// filter" and "a filter that found nothing" are different runs.
func licenseExcludeSummary(ex *licenseExcluder, excluded int) string {
	if ex.empty() {
		return ""
	}
	return fmt.Sprintf(
		"license-exclude: %d license declaration(s) excluded by %d path pattern(s) (%s); excluded declarations are not scanned against the policy",
		excluded, len(ex.patterns), strings.Join(ex.patterns, ", "))
}
