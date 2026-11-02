package main

import (
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// isARMTemplate returns true for filenames that are likely Azure ARM templates.
// Avoids matching generic JSON files (package.json, tsconfig.json, findings.json, etc.).
func isARMTemplate(name string) bool {
	lower := strings.ToLower(name)
	armNames := []string{"azuredeploy.json", "maintemplate.json", "createuidefinition.json", "template.json"}
	return slices.Contains(armNames, lower) ||
		strings.HasSuffix(lower, ".arm.json") ||
		strings.HasSuffix(lower, ".template.json")
}

// diffChangeScope reads the change set a change-scoped infra scan is limited
// to. scopedToDiff is false only for a diff that states no change set (empty),
// which scans the whole tree.
//
// A diff that cannot be read is refused, the way resolveInfraScope refuses a
// scope it does not know. It used to yield no paths, and no paths read as "the
// change touched no infrastructure": a --no-prefix diff that edited a
// Dockerfile came back NOTHING IN SCOPE, SKIPPED, passed. The reverse held
// too: a git diff that only deleted files yielded no paths and so scanned the
// whole tree, failing a pull request on debt it never touched. It is a known,
// empty change set now.
func diffChangeScope(diff string) (changed map[string]bool, scopedToDiff bool, err error) {
	paths, known, err := parseDiffPaths(diff)
	if err != nil || !known {
		return nil, false, err
	}
	return paths.surviving, true, nil
}

// isTerraform reports a Terraform or other HCL file: .tf, .tf.json and .hcl.
//
// These used to go to risk.azure under the hcl2 parser, and every rule in that
// namespace iterates input.resources, the ARM array. HCL2 parses to
// input.resource, so each rule evaluated and passed vacuously — a one-resource
// main.tf measured successes: 24 and read CLEAN. A rule count cannot tell a
// vacuous pass from a real one, so the files are not handed to conftest at all
// until a policy reads HCL2; planInfraScan records them as not assessed
// instead. See specs/report-terraform-as-not-assessed.md.
func isTerraform(name string) bool {
	return strings.HasSuffix(name, ".tf") || strings.HasSuffix(name, ".tf.json") ||
		strings.HasSuffix(name, ".hcl")
}

// infraFileType maps a filename to the conftest --parser and --namespace values.
// Returns ("", "") if the file should be skipped. Terraform is skipped here and
// reported by planInfraScan: no policy under policy/infra reads HCL2.
func infraFileType(name string) (inputType, namespace string) {
	switch {
	case name == "Dockerfile" || strings.HasPrefix(name, "Dockerfile."):
		return "dockerfile", "risk.docker"
	case isARMTemplate(name):
		return "json", "risk.azure"
	case strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml"):
		return "yaml", "risk.pipeline"
	}
	return "", ""
}

// infraGroup is one conftest invocation: every file that shares a parser and a
// namespace is evaluated together.
type infraGroup struct {
	Parser    string
	Namespace string
	Paths     []string
}

// infraScan is what the infra pass will evaluate, and what it could have.
//
// Candidates and Scanned are separate because a count of findings is only a
// measurement once the denominator is stated. They differ only when the scan
// was scoped to a change set, and that difference is the whole of the defect:
// a repository holding eight parseable infrastructure files, none of them
// touched by the push, reported `examined: {count: 0}` and outcome SKIPPED —
// the same two values a repository with no infrastructure at all reports. One
// of those is a resting state and the other is a scan that looked at nothing
// while there was plainly something to look at.
type infraScan struct {
	Groups []infraGroup
	// Candidates is how many files this scanner can parse at all, counted
	// before any scoping. Files conftest has no parser for are not candidates:
	// the denominator has to be what this tool could have examined, or a
	// repository of Bicep — which conftest cannot read — would report a large
	// total that no change could ever move.
	Candidates int
	// Scanned is how many files were handed to conftest.
	Scanned int
	// ScopedToDiff records whether a change set narrowed the set. It is what
	// makes Candidates > Scanned a deliberate narrowing rather than a defect.
	ScopedToDiff bool
	// NotAssessed is the Terraform/HCL files in this scan's scope, sorted. They
	// are not candidates, for the Bicep reason above: no policy here reads
	// them, so no change could move a denominator they were part of. They are
	// listed rather than dropped because the one file type conftest *can* parse
	// and no rule reads is the case where silence reads as a clean result.
	NotAssessed []string
}

// planInfraScan classifies every file in the tree, counts the ones this scanner
// can parse, and then applies the change-set scope.
//
// The order is load-bearing and is the fix for the second half of that defect. The
// original loop filtered by the change set *first* and classified second, so a
// file the scan never looked at was never classified either — the candidate
// count existed nowhere, and there was nothing to state the zero against.
//
// Groups come back in a stable order (parser, then namespace). The original
// iterated a map, so the order violations arrived in — and therefore the order
// they survive `combined.findings`' 1000-row cap in — changed between two runs
// over an identical tree.
func planInfraScan(paths []string, changed map[string]bool, scopedToDiff bool) infraScan {
	scan := infraScan{ScopedToDiff: scopedToDiff}
	byKey := map[string]*infraGroup{}
	var keys []string
	for _, rel := range paths {
		rel = strings.TrimSpace(rel)
		if rel == "" {
			continue
		}
		base := filepath.Base(rel)
		if isTerraform(base) {
			if !scopedToDiff || changed[rel] {
				scan.NotAssessed = append(scan.NotAssessed, rel)
			}
			continue
		}
		parser, namespace := infraFileType(base)
		if parser == "" {
			continue
		}
		scan.Candidates++
		// Scope: skip infra files this change did not touch. Pre-existing debt
		// in an untouched file is the previous run's problem, not this pull
		// request's — a precommit rationale, which is why the commit stage no
		// longer asks for it (see src/stage-2, --infra-scope).
		if scopedToDiff && !changed[rel] {
			continue
		}
		key := parser + ":" + namespace
		if byKey[key] == nil {
			byKey[key] = &infraGroup{Parser: parser, Namespace: namespace}
			keys = append(keys, key)
		}
		byKey[key].Paths = append(byKey[key].Paths, rel)
		scan.Scanned++
	}
	sort.Strings(keys)
	sort.Strings(scan.NotAssessed)
	for _, k := range keys {
		scan.Groups = append(scan.Groups, *byKey[k])
	}
	return scan
}

// infraScopeWarnings states what the scan did not look at.
//
// Nothing is said when the scan was not scoped, or when the scope excluded
// nothing: a line on every run is noise, and `examined` already carries the
// numbers for a reader who wants them. The two cases below are the ones where
// the numbers alone are misread.
//
// The zero case is a warning and not an error on purpose. Nothing went wrong —
// the operator asked for a change-scoped scan and got one — but SKIPPED over a
// non-empty candidate set is the one outcome that reads as "this repository has
// no infrastructure", which is the sentence the consumer read off its own board for
// weeks.
func infraScopeWarnings(scan infraScan) []string {
	if !scan.ScopedToDiff || scan.Candidates == scan.Scanned {
		return nil
	}
	unexamined := scan.Candidates - scan.Scanned
	if scan.Scanned == 0 {
		return []string{fmt.Sprintf("risk: NOTHING IN SCOPE — the infrastructure scan was scoped to this "+
			"change and the change touched no infrastructure file a policy reads, so conftest evaluated 0 of the %d "+
			"parseable infrastructure file(s) in the tree. The outcome is SKIPPED because nothing was "+
			"examined, not because there is nothing to examine: a misconfiguration that predates this "+
			"scan, or one that became a misconfiguration when a policy was added rather than when the "+
			"file changed, is not visible here. Run the commit stage, which scans the whole tree.",
			scan.Candidates)}
	}
	return []string{fmt.Sprintf("risk: PARTIAL SCOPE — the infrastructure scan was scoped to this change, "+
		"so conftest evaluated %d of the %d parseable infrastructure file(s) in the tree and %d were not "+
		"looked at. A clean result here is a statement about the files this change touched, not about the "+
		"repository's infrastructure.", scan.Scanned, scan.Candidates, unexamined)}
}

// infraPlanWarnings is every line the scan plan owes the envelope: what the
// scope left out, then what no policy reads. One call, so Validate's wiring is
// the thing the unit tests drive.
func infraPlanWarnings(scan infraScan) []string {
	out := infraScopeWarnings(scan)
	if w := terraformNotAssessedWarning(scan); w != "" {
		out = append(out, w)
	}
	return out
}

// terraformNotAssessedWarning names the Terraform/HCL files in scope that no
// policy evaluated, or "" when there are none.
//
// A warning and not an error, by the partial-input precedent: conftest ran and
// what it read is real, so the verdict stays graded over the other files. A
// tree holding only Terraform examines nothing and reads SKIPPED, which passes
// at every threshold — the consumer cannot clear this by changing code, so it
// must not fail. What it must not do is read CLEAN, and without this line
// SKIPPED over 0 of 0 is what a repository with no infrastructure reports.
func terraformNotAssessedWarning(scan infraScan) string {
	if len(scan.NotAssessed) == 0 {
		return ""
	}
	where := "in the tree"
	if scan.ScopedToDiff {
		where = "touched by this change"
	}
	return fmt.Sprintf("risk: TERRAFORM NOT ASSESSED — %d Terraform/HCL file(s) %s (%s) were not "+
		"evaluated. The infrastructure policies are written for ARM templates (input.resources) and no "+
		"rule reads HCL2, so evaluating them would pass every rule without checking anything. They are "+
		"left out of the examined count, and a clean result here says nothing about them.",
		len(scan.NotAssessed), where, namedSample(scan.NotAssessed, 3))
}

// The two infrastructure scan scopes. A change-scoped scan evaluates only the
// files the supplied diff touched; a tree-scoped scan evaluates every file in
// the checkout that conftest can parse.
const (
	infraScopeChanged = "changed"
	infraScopeTree    = "tree"
)

// resolveInfraScope answers whether the caller asked for a change-scoped scan,
// and refuses to guess.
//
// An unrecognised value is a hard error rather than a fallback to either scope,
// because both wrong answers are silent: falling back to "tree" turns a typo
// into a scan nobody asked for, and falling back to "changed" turns it into a
// scan that quietly looks at almost nothing — which is the defect this
// parameter exists to end. The switch has no default arm; a new scope
// that is not handled here fails to compile rather than resolving to one of
// these two.
func resolveInfraScope(scope string) (scopedToDiff bool, err error) {
	switch strings.TrimSpace(scope) {
	case "", infraScopeChanged:
		// Empty is the default arriving over the wire: Dagger's Go client drops
		// an optional argument holding its zero value, so a caller that passes
		// "changed" explicitly and one that passes nothing are indistinguishable
		// here, and both must mean the same thing.
		return true, nil
	case infraScopeTree:
		return false, nil
	}
	return false, fmt.Errorf("invalid infraScope %q: must be %q or %q", scope, infraScopeChanged, infraScopeTree)
}
