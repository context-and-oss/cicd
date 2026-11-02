// Node project-root resolution.
//
// Deliberately untagged (no //go:build !unit_test): picking which directory
// ESLint runs in is pure path arithmetic over the marker-file search output, so
// nodeproject_test.go can drive it with `go test -tags unit_test ./...`.
package main

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
)

// The total project budget is `--node-project-limit`, whose default (4) is the
// `+default=` pragma on Check in main.go. Each independent root costs an
// install and a check, so this is distinct from concurrent execution. Consumers
// may raise it for independent apps or select an application boundary; a
// workspace is useful only when it matches their repo. Exceeding the limit
// fails visibly (nodeProjectLimitError) rather than reporting partial checks
// clean.

// nodeVendorDirs are directories holding installed third-party packages. A
// package.json inside one describes a dependency, never the consumer's project,
// and linting a dependency tree is both meaningless and enormous.
//
// Build output (dist/, build/, .next/) is deliberately *not* excluded. Skipping
// a directory means reporting less than the tree contains, and the ancestor rule
// below already handles the realistic case: a repo that generates dist/ has a
// root package.json, so the generated package is nested beneath a governing
// project. If generated output is independent, ESLint's own ignore config is the
// consumer's lever — cicd guessing on their behalf is how a real source
// directory silently stops being linted.
var nodeVendorDirs = map[string]bool{
	"node_modules":     true,
	"bower_components": true,
	".yarn":            true,
	".git":             true,
}

// nodeProjectDirs resolves which directories ESLint should run in from the
// output of the marker-file search, as paths relative to root ("." for root
// itself), sorted and deduplicated.
//
// Why this exists: autoDetectLanguages returns languages and throws the
// locations away, so the Node leg always ran at the mount root. On a monorepo
// whose package.json lives in Client/ that meant `node` was detected (the search
// is depth-4) and then linted at a root with no package.json and no
// node_modules — exit 127. Honest since eslintRunError, but still unable to lint
// the repo at all.
//
// Every package.json with no package-bearing ancestor is a project. A root
// package.json therefore still beats everything, which is what npm/pnpm/yarn
// workspaces need: the root is the workspace root, its config governs the whole
// tree, and its node_modules is where the hoisted ESLint lives. Without a root
// package, unrelated project roots are all kept even when they sit at different
// depths. That matters for a repository that stores three apps directly under
// the root and a fourth under a grouping directory: depth alone does not make
// the fourth app part of any shallower sibling.
func nodeProjectDirs(root string, lines []string) []string {
	found := map[string]bool{}

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || path.Base(line) != "package.json" {
			continue
		}
		dir := path.Dir(line)
		rel, ok := relativeToRoot(root, dir)
		if !ok || hasVendorSegment(rel) {
			continue
		}
		found[rel] = true
	}

	dirs := make([]string, 0, len(found))
	for d := range found {
		if hasNodeProjectAncestor(d, found) {
			continue
		}
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	return dirs
}

// hasNodeProjectAncestor reports whether another discovered package.json
// governs dir. Checking the complete set rather than only the immediately
// preceding path keeps the decision independent of find output order.
func hasNodeProjectAncestor(dir string, found map[string]bool) bool {
	if dir == "." {
		return false
	}
	for ancestor := path.Dir(dir); ; ancestor = path.Dir(ancestor) {
		if found[ancestor] {
			return true
		}
		if ancestor == "." {
			return false
		}
	}
}

// relativeToRoot expresses dir relative to root, reporting false for anything
// outside it. A path outside the mount cannot be linted, and silently rewriting
// it would be worse than dropping it.
func relativeToRoot(root, dir string) (string, bool) {
	root = strings.TrimSuffix(path.Clean(root), "/")
	dir = path.Clean(dir)
	switch {
	case dir == root:
		return ".", true
	case strings.HasPrefix(dir, root+"/"):
		return strings.TrimPrefix(dir, root+"/"), true
	default:
		return "", false
	}
}

func hasVendorSegment(rel string) bool {
	for _, seg := range strings.Split(rel, "/") {
		if nodeVendorDirs[seg] {
			return true
		}
	}
	return false
}

// nodeProjectLimitError reports the projects that would have gone unlinted, or
// "" when the set is within the limit. The message names the count and the
// remedy: a truncated lint that reads as clean is not an option, so this fails
// the gate instead.
func nodeProjectLimitError(dirs []string, limit int) string {
	if len(dirs) <= limit {
		return ""
	}
	return "eslint: " + strconv.Itoa(len(dirs)) + " independent Node projects found (" +
		strings.Join(dirs, ", ") + ") — more than cicd will install and lint in one run (" +
		strconv.Itoa(limit) + "). Raise --node-project-limit to explicitly allow more projects, or use application-scoped pipelines"
}

// mergeEslintVersions summarises the ESLint versions that actually ran across
// the linted projects. Sibling projects can pin different versions, and the
// envelope has one Tool.Version field, so the honest summary is every distinct
// version rather than whichever project happened to run first. Per-project
// versions are still carried exactly on each SARIF run's tool driver.
func mergeEslintVersions(raw []string) string {
	seen := map[string]bool{}
	var versions []string
	for _, r := range raw {
		v := eslintVersionLabel(r)
		if v == "unknown" || seen[v] {
			continue
		}
		seen[v] = true
		versions = append(versions, v)
	}
	if len(versions) == 0 {
		return "unknown"
	}
	sort.Strings(versions)
	return strings.Join(versions, ",")
}

// nodeProjectLabel prefixes a diagnostic with the project it came from. Root
// stays unprefixed so the single-project case reads exactly as before.
func nodeProjectLabel(dir, msg string) string {
	if dir == "." {
		return msg
	}
	return dir + ": " + msg
}

// nodeCoverage is one project's coverage reading.
type nodeCoverage struct {
	Percent float64
	Lines   int
}

// mergeNodeCoverage combines per-project coverage into the single figure the
// envelope carries, and the coverable-line total the ratchet's min-lines guard
// reads.
//
// Weighted by coverable lines, not averaged: a 100%-covered 5-line project must
// not drag a 40%-covered 5000-line project up to 70%, which is what an
// unweighted mean does and is a false pass wearing a percentage. Projects with
// no coverable lines carry no weight — their percentage is arbitrary — but if
// *every* project reports zero lines the unweighted mean is all there is, and
// that degenerate case must keep behaving exactly as the single-project path did
// before.
func mergeNodeCoverage(cov []nodeCoverage) (*float64, *int) {
	if len(cov) == 0 {
		return nil, nil
	}

	totalLines, weighted := 0, 0.0
	for _, c := range cov {
		if c.Lines <= 0 {
			continue
		}
		totalLines += c.Lines
		weighted += c.Percent * float64(c.Lines)
	}

	if totalLines > 0 {
		pct := weighted / float64(totalLines)
		return &pct, &totalLines
	}

	sum := 0.0
	for _, c := range cov {
		sum += c.Percent
	}
	pct := sum / float64(len(cov))
	return &pct, nil
}

func validateNodeProjectLimit(limit int) error {
	if limit < 1 {
		return fmt.Errorf("node-project-limit must be positive, got %d", limit)
	}
	return nil
}
