// Resolving --include, and disclosing what it left out.
//
// Deliberately untagged (no //go:build !unit_test): mapping a caller-supplied
// language name onto a language, and diffing what was asked for against what is
// present, needs no Dagger (markers.go / nodeproject.go precedent). lint.go,
// where this used to live, is excluded by the unit_test tag, so none of it could
// be driven by a test.
//
// This file exists because --include is the one way a consumer can reduce what
// cicd looks at, and it used to be the only reduction in this repository that
// left no trace. Two silences, one root:
//
//   - detectLanguages had a switch with no default arm, so `--include golang`
//     resolved to an empty language set, the per-language leg loop in Check
//     never iterated, allRan stayed vacuously true, and
//     gatedPassed(true, true, threshold) returned passed=true over a repository
//     where nothing was linted and no test ran. A one-character typo produced a
//     green quality gate. That is the founding doctrine — a tool that could not
//     run must never read as clean — arriving through a config value instead of
//     a crashed tool, and it is worse than a crashed tool, because no tool was
//     even asked.
//   - the include branch returned before probing for marker files, so an
//     envelope from `--include go` on a repository containing package.json was
//     byte-identical to one from a repository that only contains Go.
//
// So an unrecognised name is now an error at the module boundary rather than a
// silent drop, and an excluded language says so in the envelope's warnings the
// way intent.Check says `intent-gate: NOT REQUIRED …` — notify renders warnings
// verbatim into the Teams card and the PR comment, so the disclosure reaches a
// reviewer rather than a log.
//
// Plain strings throughout, not the module's language type: that type is
// declared in lint.go, which the unit_test tag excludes (markerLanguage carries
// the same constraint for the same reason).
package main

import (
	"fmt"
	"sort"
	"strings"
)

// canonicalLanguages is the enum order every language list in this module is
// reported in, so `--include node,go` and `--include go,node` produce the same
// evidence. autoDetectLanguages walks the same order.
var canonicalLanguages = []string{"go", "node", "python", "dotnet"}

// languageAliases maps every accepted --include spelling onto a canonical
// language name. They are listed here rather than in a switch so
// acceptedIncludeNames can print the accepted set, and so an error message cannot
// fall out of step with what is actually accepted.
//
// This is exactly the set detectLanguages has always accepted, deliberately not
// one name wider. Obvious synonyms — golang, javascript, js, cs, .net — were
// tried and reverted: the same list is carried in a shell guard in
// .github/workflows/precommit.yml (added by CAPS-007 as a patch over this very hole)
// and documented in templates/azure-devops/precommit.yml and
// docs/reference/index.md, so a name accepted here and refused there would be a
// contradiction between two gates on the same input, which is a worse consumer
// experience than a clear error naming the accepted set. Widening it means
// widening all four together, on purpose.
var languageAliases = map[string]string{
	"go":         "go",
	"node":       "node",
	"nodejs":     "node",
	"typescript": "node",
	"ts":         "node",
	"python":     "python",
	"py":         "python",
	"dotnet":     "dotnet",
	"csharp":     "dotnet",
	"c#":         "dotnet",
}

// acceptedIncludeNames renders the accepted spellings grouped by the language
// they resolve to, in canonical order, for an error a caller can act on without
// reading this source.
func acceptedIncludeNames() string {
	groups := make([]string, 0, len(canonicalLanguages))
	for _, canonical := range canonicalLanguages {
		var names []string
		for alias, target := range languageAliases {
			if target == canonical {
				names = append(names, alias)
			}
		}
		sort.Strings(names)
		groups = append(groups, strings.Join(names, "|"))
	}
	return strings.Join(groups, ", ")
}

// resolveIncludeNames maps caller-supplied names onto canonical language names,
// deduplicated and in canonical order.
//
// An unrecognised name is an error, not a drop. It is reported with every
// unrecognised name at once: a caller who mistyped two entries of a four-entry
// list should learn both from one run, since each round trip costs a pipeline.
//
// A non-empty include therefore always resolves to at least one language, which
// is what closes the caller-mistake half of the zero-language false pass —
// closes it harder than a passed=false verdict would, because no envelope is
// produced at all and there is nothing to mistake for a gate result.
func resolveIncludeNames(include []string) ([]string, error) {
	seen := map[string]bool{}
	var unknown []string
	for _, name := range include {
		key := strings.ToLower(strings.TrimSpace(name))
		canonical, ok := languageAliases[key]
		if !ok {
			// The empty string lands here too, which is right: `--include ""`
			// asks for a language whose name is nothing, and silently treating
			// it as "everything" or "nothing" is the behaviour being removed.
			unknown = append(unknown, fmt.Sprintf("%q", name))
			continue
		}
		seen[canonical] = true
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf(
			"unrecognised --include language %s: accepted names are %s. "+
				"An unrecognised name used to be dropped silently, which left an "+
				"empty language set that linted nothing, ran no tests and reported "+
				"the quality gate as passed",
			strings.Join(unknown, ", "), acceptedIncludeNames())
	}

	resolved := make([]string, 0, len(seen))
	for _, canonical := range canonicalLanguages {
		if seen[canonical] {
			resolved = append(resolved, canonical)
		}
	}
	return resolved, nil
}

// excludedLanguageWarnings names every language present in the source tree that
// --include left out, one warning each, quoting the marker file that proves it
// was there.
//
// markerByLanguage is the evidence, not a formality: "node detected" is a claim
// a reader has to take on trust, while "node detected (package.json)" can be
// checked, and a marker four directories down is exactly the case where a
// consumer's mental model of their own repository is wrong.
func excludedLanguageWarnings(included, detected []string, markerByLanguage map[string]string) []string {
	if len(included) == 0 {
		return nil
	}
	inScope := map[string]bool{}
	for _, l := range included {
		inScope[l] = true
	}
	var warnings []string
	for _, canonical := range canonicalLanguages {
		if inScope[canonical] {
			continue
		}
		found := false
		for _, d := range detected {
			if d == canonical {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		marker := markerByLanguage[canonical]
		if marker == "" {
			marker = "a language marker file"
		}
		warnings = append(warnings, fmt.Sprintf(
			"quality: NOT SCANNED — %s detected (%s) but excluded by --include %s",
			canonical, marker, strings.Join(included, ",")))
	}
	return warnings
}

// noLanguageDetectedWarning is what Check reports when auto-detection finds
// nothing: no leg ran, so the gate passed over no work, and the envelope would
// otherwise be indistinguishable from one where every leg ran and found nothing.
//
// A warning rather than an error, and the reasoning is the reason the caller
// mistake above is an error instead. After resolveIncludeNames, a non-empty
// --include can never produce an empty language set, so the only way to arrive
// here is auto-detection on a tree carrying no marker file — a documentation-only
// repository, or one written in a language this module does not lint. Both are
// legitimate states, and both consume the composites for the security scan and
// the intent gate. Failing them would be a permanent red with no remedy
// available to the consumer: `--fail-on NONE` deliberately does not suppress a
// non-run, so the one knob they would reach for cannot clear it either.
//
// The precedent is intent.Check, which runs when it was not required and returns
// `intent-gate: NOT REQUIRED …` rather than either failing or staying silent.
func noLanguageDetectedWarning() string {
	return fmt.Sprintf(
		"quality: NO LANGUAGE DETECTED — nothing was linted and no unit tests ran, "+
			"so this gate passed over no work. Searched %d directory levels for %s. "+
			"Pass --include (%s) to name a language whose marker file sits deeper "+
			"than that, or read this as confirmation that no language this module "+
			"lints is present.",
		markerSearchDepth, strings.Join(markerFileNames, ", "), acceptedIncludeNames())
}
