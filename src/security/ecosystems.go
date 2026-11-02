// Ecosystem reconciliation: which dependency ecosystems the scanned tree
// *declares* against which ones Trivy could actually *resolve a dependency graph
// from*.
//
// Deliberately untagged (no //go:build !unit_test): this is filename matching,
// exit-status classification and message construction, none of which needs
// Dagger, so ecosystems_test.go can drive it under
// `go test -tags unit_test ./...`.
//
// Why this file exists. Trivy reads .NET dependencies only from
// packages.lock.json, packages.config or a *.deps.json. NuGet writes none of
// those unless a project opts in, so a repository of twenty .csproj files
// commonly commits no NuGet graph at all — and a Trivy filesystem scan of that
// tree reports zero vulnerabilities and a CycloneDX document with no .NET
// components. Both are byte-for-byte what a genuinely clean .NET repository
// produces. That is this module's founding failure class ("a tool that could not
// run must never read as clean") arriving through a missing *input* rather than a
// missing flag or a crashed binary, and it is invisible whenever some *other*
// ecosystem in the same repository does resolve: a mixed C#/npm repository gets
// its npm packages scanned, a structurally valid npm-only SBOM, and a green
// dependency verdict over unscanned C#.
//
// The reconciliation is deliberately built on the *resolvable input*, not on the
// empty output, because the inverse false alarm is just as damaging: a genuinely
// dependency-free project exists, and failing it would get the check switched off
// within a week. The three file sets below keep the two apart, and the presence of
// a lockfile is directly observable rather than a judgement call:
//
//	lockfile absent   → cicd cannot see the dependency graph → non-run, fail loud
//	lockfile present  → cicd looked, and there was nothing    → genuine pass
package main

import (
	"errors"
	"strconv"
	"strings"
)

const (
	dependencyNotApplicableWarning = "Dependency vulnerabilities: NOT APPLICABLE — no supported dependency manifests or lockfiles were found in the scanned tree."
	inventoryNotApplicableWarning  = "Source SBOM: NOT APPLICABLE — no supported dependency manifests or lockfiles were found in the scanned tree."
)

// depEcosystem describes one dependency ecosystem in three parts that must never
// be conflated:
//
//   - markers    files that prove the ecosystem is *present* in the repository.
//   - inputs     files Trivy can actually *resolve a dependency graph from*.
//   - trivyTypes the Result.Type values Trivy stamps when it did resolve one.
//
// For .NET, Python-with-pyproject and Node the first two sets are disjoint, which
// is the whole problem: a .csproj declares NuGet dependencies and Trivy cannot
// read one, so "there is .NET here" and "the .NET dependencies were examined" are
// two different facts that a zero-vulnerability report cannot tell apart. For Go
// they are the same file, which is why the Go entry structurally cannot fire.
type depEcosystem struct {
	// name is the language name quality.Check's --include already uses, so one
	// vocabulary describes detection across the repository.
	name string
	// markerWhat names the marker files in prose, for the message.
	markerWhat string
	markers    []string
	// listings are the markers that only list other markers and declare no
	// dependency of their own: a solution file names projects, and the
	// projects declare the packages. A tree whose markers are all listings has
	// the ecosystem's build layout and nothing to resolve, so listingsOnly
	// reports it apart from a tree whose graph could not be read.
	listings []string
	// inputsWhat spells the resolvable inputs out, because a consumer cannot act
	// on "no lockfile" without being told which filenames count.
	inputsWhat string
	inputs     []string
	trivyTypes []string
	// remedy is the command or setting that makes this green. A gate whose
	// message a consumer cannot act on gets suppressed rather than fixed.
	remedy string
}

// depEcosystems is the reconciliation table.
//
// It covers the whole class rather than the .NET instance that exposed it,
// because the hazard is structural — any ecosystem whose dependency declaration
// is not itself a file Trivy can resolve has it — and because the table costs the
// same either way. Only Go is naturally immune: Trivy's gomod analyser parses
// go.mod itself, so the marker *is* the input and the Go entry can never fire. It
// is listed anyway, so the immunity is a stated property of the table rather than
// an omission somebody later reads as an oversight.
//
// Maintenance risk, named because nothing detects it automatically: a future
// Trivy can learn a new lockfile format or rename a Result.Type. A new lockfile
// missing from `inputs` produces a false alarm (loud, with a remedy the consumer
// may not need); a renamed Type only weakens the exculpating check, which cannot
// create one on its own. When bumping trivyVersion, re-read Trivy's supported
// language list.
func depEcosystems() []depEcosystem {
	return []depEcosystem{
		{
			name:       "go",
			markerWhat: "go.mod file(s)",
			markers:    []string{"go.mod"},
			inputsWhat: "go.mod",
			// The marker is the input: Trivy's gomod analyser reads go.mod
			// directly, so a detected Go module is always a resolvable one and
			// this entry cannot report a non-run. Kept for that statement.
			inputs:     []string{"go.mod"},
			trivyTypes: []string{"gomod", "gobinary"},
			remedy:     "commit go.mod (and go.sum) at the module root",
		},
		{
			name:       "node",
			markerWhat: "package.json file(s)",
			markers:    []string{"package.json"},
			inputsWhat: "package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml or bun.lock",
			inputs: []string{
				"package-lock.json", "npm-shrinkwrap.json",
				"yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb",
			},
			trivyTypes: []string{"npm", "yarn", "pnpm", "bun", "node-pkg"},
			remedy:     "commit the lockfile your package manager already writes — `npm install` writes package-lock.json, yarn writes yarn.lock, pnpm writes pnpm-lock.yaml — and take it out of .gitignore",
		},
		{
			name:       "python",
			markerWhat: "pyproject.toml/setup.py file(s)",
			markers:    []string{"pyproject.toml", "setup.py", "requirements.txt"},
			inputsWhat: "requirements.txt, poetry.lock, Pipfile.lock, uv.lock or pdm.lock",
			inputs: []string{
				"requirements.txt", "poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock",
			},
			trivyTypes: []string{"pip", "pipenv", "poetry", "uv", "pdm", "python-pkg", "conda-pkg"},
			remedy:     "commit the lockfile your tool writes (`poetry lock`, `uv lock`, `pipenv lock`) or a pinned requirements.txt (`pip freeze > requirements.txt`)",
		},
		{
			name:       "dotnet",
			markerWhat: "project/solution file(s)",
			// .fsproj and .vbproj are included even though src/internal/detect
			// looks only for .csproj and .sln: they declare NuGet dependencies
			// identically, and the question here is whether NuGet was scanned,
			// not which linter to run. A pure-F# repository is exactly as
			// unscanned as a C# one, and reporting it needs the same two lines.
			markers:    []string{"*.csproj", "*.fsproj", "*.vbproj", "*.sln", "*.slnx"},
			listings:   []string{"*.sln", "*.slnx"},
			inputsWhat: "packages.lock.json, packages.config or *.deps.json",
			inputs:     []string{"packages.lock.json", "packages.config", "*.deps.json"},
			trivyTypes: []string{"nuget", "dotnet-core"},
			remedy:     "set <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile> in each project (or a Directory.Build.props), run `dotnet restore --use-lock-file`, and commit the generated packages.lock.json files",
		},
	}
}

// depProbe* are the fixed paths the marker probe writes to. Nothing consumer-
// supplied reaches them.
const (
	depProbeOutPath  = "/tmp/dep-probe.out"
	depProbeErrPath  = "/tmp/dep-probe.err"
	depProbeExitPath = "/tmp/dep-probe.exit"
)

// dependencyProbeScript renders the shell body of the marker probe.
//
// The pattern list is derived from depEcosystems() rather than written out again,
// so the files the probe searches for and the files the verdict reasons about
// cannot drift. Every pattern is a cicd constant — depProbePatternsAreShellSafe
// in the unit suite proves it, so single-quoting them is sound and no consumer
// value is ever spliced into this body.
//
// The exit status, stdout and stderr go to files and are classified in Go rather
// than being swallowed with `2>/dev/null || true`. A probe that could not list
// the tree leaves "which ecosystems are present" unknown, and unknown must fail
// the gate — not silently agree that nothing is present, which is the shape of
// false pass this whole file exists to close.
func dependencyProbeScript(mount string) string {
	var expr []string
	for i, pattern := range depProbePatterns() {
		if i > 0 {
			expr = append(expr, "-o")
		}
		expr = append(expr, "-name", "'"+pattern+"'")
	}
	return ": > " + depProbeOutPath + "\n" +
		"find " + mount + " -type f \\( " + strings.Join(expr, " ") + " \\) > " +
		depProbeOutPath + " 2>" + depProbeErrPath + "\n" +
		"echo $? > " + depProbeExitPath + "\n" +
		"exit 0"
}

// depProbePatterns is every marker and every resolvable input, deduplicated and
// in table order.
func depProbePatterns() []string {
	var out []string
	seen := map[string]bool{}
	for _, e := range depEcosystems() {
		for _, p := range append(append([]string{}, e.markers...), e.inputs...) {
			if seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// resultlessDependencyScanIsNotApplicable separates a dependency-free tree
// from a scanner failure. files comes from the independent dependency-input
// probe, not from Trivy: using Trivy's empty output to justify itself would turn
// an unsupported or broken analyser into a false N/A.
//
// The caller invokes this only when the probe itself completed successfully.
// Any non-blank probe line is a marker or resolvable input from depEcosystems,
// and therefore makes a resultless Trivy report an error.
//
// A listing (a solution file) is the one probe line that does not count: it
// declares no dependency, and a tree that also holds what it lists has that
// file's own line to make the report an error.
func resultlessDependencyScanIsNotApplicable(files []string, scanErr error) bool {
	if !errors.Is(scanErr, errTrivyNoTargets) {
		return false
	}
	for _, file := range files {
		file = strings.TrimSpace(file)
		if file != "" && !isListing(file) {
			return false
		}
	}
	return true
}

// isListing reports whether a probe line is a listing of any ecosystem.
func isListing(line string) bool {
	for _, e := range depEcosystems() {
		if matchesAnyBase(baseName(line), e.listings) {
			return true
		}
	}
	return false
}

// listingsOnly returns the ecosystem's markers when every one of them is a
// listing, or nil. Only the probe decides it, never what a restore later
// found: a project under bin/ or obj/ is still a project here, so a restore
// that skips it stays an error rather than becoming this.
func (e depEcosystem) listingsOnly(mount string, files []string) []string {
	markers := matchDependencyFiles(mount, files, e.markers)
	if len(markers) == 0 || len(e.listings) == 0 {
		return nil
	}
	for _, m := range markers {
		if !matchesAnyBase(baseName(m), e.listings) {
			return nil
		}
	}
	return markers
}

// dotnetSolutionsWithoutProjects returns the solution files of a tree that
// holds no C#, F# or VB project anywhere, or nil.
func dotnetSolutionsWithoutProjects(mount string, files []string) []string {
	for _, e := range depEcosystems() {
		if e.name == "dotnet" {
			return e.listingsOnly(mount, files)
		}
	}
	return nil
}

// dependencyDeclarations is the probe narrowed to the files that declare or
// resolve a dependency: every marker and input, less the listings of an
// ecosystem whose markers are all listings. The licence row names these as
// inputs it read nothing from, and a solution with no project is not one.
func dependencyDeclarations(mount string, files []string) []string {
	drop := map[string]bool{}
	for _, e := range depEcosystems() {
		for _, l := range e.listingsOnly(mount, files) {
			drop[l] = true
		}
	}
	var out []string
	for _, f := range matchDependencyFiles(mount, files, depProbePatterns()) {
		if !drop[f] {
			out = append(out, f)
		}
	}
	return out
}

// dependencyNotApplicableResult builds the complete two-concern answer for a
// proven dependency-free tree. Keeping this out of the Dagger entrypoint makes
// the exact evidence payload testable: the vulnerability and SBOM rows each
// need their own warning, and neither may claim an examined count or inventory.
func dependencyNotApplicableResult(files []string, scanErr error, scanWarnings []string) (trivyResult, bool) {
	if !resultlessDependencyScanIsNotApplicable(files, scanErr) {
		return trivyResult{}, false
	}
	return trivyResult{
		Skipped:           true,
		Warnings:          append(append([]string{}, scanWarnings...), dependencyNotApplicableWarning),
		InventoryWarnings: []string{inventoryNotApplicableWarning},
	}, true
}

// dependencyProbeRunError classifies the probe's exit status. `find` exits 0 when
// it walked the tree; anything else means part of the tree was not listed, so the
// answer is unknown rather than "nothing found".
func dependencyProbeRunError(exitCode, stderr string) string {
	code := strings.TrimSpace(exitCode)
	if code == "" {
		return "security dependency scan: the dependency-input probe recorded no exit status, " +
			"so which ecosystems the source tree declares is unknown"
	}
	if code == "0" {
		return ""
	}
	msg := "security dependency scan: the dependency-input probe exited " + code +
		", so which ecosystems the source tree declares is unknown and an ecosystem " +
		"Trivy resolved nothing from cannot be told apart from one with nothing to resolve"
	if s := strings.TrimSpace(stderr); s != "" {
		msg += ": " + firstLine(s)
	}
	return msg
}

// ecosystemVerdict is one unresolved ecosystem: the name alongside the message.
type ecosystemVerdict struct {
	Name    string
	Message string
}

// unresolvedEcosystems is the verdict: one entry per ecosystem the tree
// declares and Trivy resolved no dependency graph for, the name kept beside the
// message because a caller that did something about a specific ecosystem — the
// .NET restore fallback is the only one — has to be able to tell which message
// it may add a sentence to. Matching on the message text instead would make the
// wording of an error load-bearing.
//
// Three conditions must all hold before an ecosystem is reported, and the order
// is the design:
//
//  1. a marker file is present — the ecosystem is in this repository — and
//     not only listings of markers that are absent;
//  2. no resolvable input is present anywhere in the scanned tree — cicd can see
//     that Trivy had nothing to read, rather than inferring it from an empty
//     report;
//  3. Trivy reported no resolved packages for the ecosystem either.
//
// Condition 3 can only ever *exculpate*. It is there for the cases where Trivy
// resolves packages from something that is not on any lockfile list — a committed
// node_modules tree, a vendored dependency directory — and it is never allowed to
// *create* a report, because "Trivy's output was empty" is exactly the signal that
// cannot distinguish the two states this check exists to separate.
func unresolvedEcosystems(mount string, files, resolvedTypes []string) []ecosystemVerdict {
	resolved := map[string]bool{}
	for _, t := range resolvedTypes {
		if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
			resolved[t] = true
		}
	}

	var out []ecosystemVerdict
	for _, e := range depEcosystems() {
		markers := matchDependencyFiles(mount, files, e.markers)
		if len(markers) == 0 {
			continue
		}
		if len(e.listingsOnly(mount, files)) > 0 {
			// Nothing declares a dependency, so there is no graph to miss.
			// The caller states the listings in a warning of its own.
			continue
		}
		if len(matchDependencyFiles(mount, files, e.inputs)) > 0 {
			continue
		}
		if anyResolved(resolved, e.trivyTypes) {
			continue
		}
		out = append(out, ecosystemVerdict{Name: e.name, Message: e.unresolvedMessage(markers)})
	}
	return out
}

func anyResolved(resolved map[string]bool, types []string) bool {
	for _, t := range types {
		if resolved[t] {
			return true
		}
	}
	return false
}

// unresolvedMessage states the fact, why the zero is not a clean verdict, and
// the way out. All three halves are load-bearing: a consumer who cannot act on
// the message suppresses the check instead of fixing the gap, and a consumer who
// is not told that zero findings meant "nothing was read" has learnt nothing.
func (e depEcosystem) unresolvedMessage(markers []string) string {
	return "security dependency scan: " + e.name + " is present in the scanned tree (" +
		strconv.Itoa(len(markers)) + " " + e.markerWhat + ", e.g. " +
		strings.Join(firstN(markers, 3), ", ") + ") but trivy resolved no " + e.name +
		" dependency graph from it — no " + e.inputsWhat + " was found anywhere in the " +
		"scanned tree, so this scan examined none of those dependencies and its zero " +
		"vulnerabilities are not a clean verdict for them. Fix: " + e.remedy + "."
}

// matchDependencyFiles returns the probe lines whose basename matches any of the
// patterns, as paths relative to the mount, in the order the probe reported them.
func matchDependencyFiles(mount string, files, patterns []string) []string {
	var out []string
	for _, line := range files {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !matchesAnyBase(baseName(line), patterns) {
			continue
		}
		out = append(out, relativeToMount(mount, line))
	}
	return out
}

// matchesAnyBase matches a basename against the table's patterns. Two forms only,
// which is why this is not filepath.Match: an exact filename, or a leading `*`
// followed by a literal suffix. A bare `*.deps.json` must not match a file
// actually called `.deps.json`, hence the length test — an extension pattern
// describes "<something>.deps.json".
func matchesAnyBase(base string, patterns []string) bool {
	for _, p := range patterns {
		if strings.HasPrefix(p, "*") {
			suffix := p[1:]
			if len(base) > len(suffix) && strings.HasSuffix(base, suffix) {
				return true
			}
			continue
		}
		if base == p {
			return true
		}
	}
	return false
}

func baseName(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// relativeToMount strips the container mount prefix so the evidence names paths a
// consumer recognises in their own repository, never /src/....
func relativeToMount(mount, p string) string {
	trimmed := strings.TrimPrefix(p, strings.TrimSuffix(mount, "/")+"/")
	if trimmed == "" {
		return p
	}
	return trimmed
}

func firstN(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return append(append([]string{}, in[:n]...), "…")
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

// joinEcosystemErrors folds the per-ecosystem messages into the single error
// runTrivyFS can return.
//
// One error rather than one envelope entry each: main.go and archive.go turn each
// non-nil leg error into one errors[] string, and widening that plumbing is a
// change to the shared aggregation path rather than to this leg. Each message is
// a complete sentence, so a joined string still reads as a list of independent
// facts.
//
// The separator is a space and not errors.Join's newline on purpose: notify
// renders each errors[] entry as one markdown list item, and an embedded newline
// breaks the item in the PR comment.
func joinEcosystemErrors(msgs []string) string {
	return strings.Join(msgs, " ")
}
