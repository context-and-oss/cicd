package main

// testlegs.go holds the pure logic behind quality.Test's witnessed test legs:
// parsing and validating the --test-legs document, folding per-leg coverage
// into the per-language maps the ratchet reads, and naming the languages that
// were detected in the tree but witnessed by no leg.
//
// Deliberately untagged (no //go:build !unit_test), like coverage.go and
// nodeproject.go: this is where the rules a reviewer has to trust live, so
// `go test -tags unit_test` must be able to reach them without a Dagger
// session. byotest.go keeps only the container work.
//
// Why any of this exists: Test used to take exactly one command, run it in
// exactly one container, and harvest exactly one coverage report. The
// container came from `langs[0]` — the first entry of the fixed order
// (go, node, python, dotnet) in autoDetectLanguages — so on a repo with both
// a package.json and a .csproj the witnessed stack was decided by that
// literal ordering rather than by anything about the repository. The other
// stack was simply not tested, and the envelope said so nowhere: it listed
// every detected language under `languages` and reported passed=true. A
// partial test run that renders identically to a complete one is the same
// false pass as a scanner that could not run reporting zero findings.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// testLegLimit caps how many legs one Test call will run. Every leg costs its
// own container pull, its own dependency restore and its own test run, and at
// most --parallelism (1 to 4, default 1) of them run at once, so N legs is up
// to N times the wall clock against the 5-10 minute pre-commit budget
// (docs/explanation/continuous-delivery/quality-gates/precommit-gates.md).
//
// Over the limit is an error, never a truncated run — the node-project-limit
// precedent: witnessing 8 of 30 legs while reporting no failures is exactly
// the partial-reads-as-complete result this file exists to prevent.
const testLegLimit = 8

// testLegEnv carries the leg's label into its own container. Labels are
// unique, so it is also what makes two legs with the same image and command
// two executions: without it the engine runs one and hands both rows its
// result, and the evidence would report two durations for a single run.
// Measured: two identical legs at --parallelism 2 read the same durationMs to
// the millisecond.
const testLegEnv = "CICD_TEST_LEG"

// legacyLegLabel names the single leg synthesised from --test-cmd. It only
// ever appears in the genericReport: with one leg, warnings and errors keep
// the unprefixed wording they had before legs existed, so a single-command
// consumer's evidence is byte-identical to the previous release.
const legacyLegLabel = "test-cmd"

// legLanguages are the only values a declared leg's `language` may take.
//
// Deliberately not the alias set detectLanguages accepts for --include
// (nodejs, ts, py, c#, …): a leg's language is also the key its coverage
// lands under in coverageByLanguage, which is the one document format
// parseBaselineCoverage reads, so an alias would let two spellings of one
// language produce two baseline keys that never compare against each other.
// The four canonical values are what the envelope, the ratchet and
// ResolveToolchain all already speak.
var legLanguages = []string{"go", "node", "python", "dotnet"}

// maxLegLabelLen bounds a label because the label is rendered into
// single-line warnings and error strings that notify puts verbatim into a PR
// comment.
const maxLegLabelLen = 64

// testLeg is one witnessed test execution: a command, the language whose
// toolchain container it runs in, and the coverage report it writes.
//
// There is deliberately no working-directory field: `cd sub && npm ci && npm
// test` in Cmd already expresses it, and a second way to say the same thing is
// a drift waiting to happen.
type testLeg struct {
	// Label identifies the leg in evidence, in warnings and in errors. It is
	// the stable identity across runs, so renaming a leg renames it in the
	// next run's evidence too.
	Label string `json:"label"`
	// Language selects the toolchain image (ADR-004) and keys this leg's
	// coverage in coverageByLanguage.
	Language string `json:"language"`
	// Cmd is handed to `sh -c` verbatim in the resolved container.
	Cmd string `json:"cmd"`
	// CoveragePath is the report the command writes — absolute, or relative to
	// the source root. Empty means this leg measures no coverage.
	//
	// A filename pattern is accepted too; see coverageglob.go. It exists because
	// a leg on Microsoft.Testing.Platform cannot name its own report — the runner
	// guid-names one per test application, and the guid is what stops two of them
	// overwriting each other's numbers.
	CoveragePath string `json:"coveragePath"`
	// ToolchainImage overrides image resolution for this leg alone — the only
	// digest-pinnable level (ADR-004), now per leg rather than per run.
	ToolchainImage string `json:"toolchainImage"`
	// Services are the dependency containers the engine binds beside this
	// leg's own, each reachable at its alias. Empty is the ordinary case and
	// changes nothing: a leg that declares none behaves exactly as it did
	// before services existed, down to the bytes of its report.
	//
	// Everything decided about them lives in services.go. A service that was
	// declared and did not become usable is an errors[] entry, which makes the
	// leg a non-run — see foldServiceProbe for why that is not a warning.
	Services []serviceSpec `json:"services,omitempty"`
}

// parseTestLegs decodes and validates the --test-legs document: a JSON array
// of leg objects. An empty/whitespace input yields no legs and no error — the
// caller then falls back to the single --test-cmd leg.
//
// Decoding is strict (DisallowUnknownFields) on purpose. A misspelled
// "coveragepath" under a tolerant decoder is silently a leg with no coverage
// at all, which the ratchet then reports as skipped rather than as a typo —
// the configuration equivalent of a tool that could not run reading as clean.
// Every rejection is a hard error before any container is built, and names the
// leg index so a 6-leg document says which one is wrong.
func parseTestLegs(raw string) ([]testLeg, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}

	dec := json.NewDecoder(strings.NewReader(trimmed))
	dec.DisallowUnknownFields()
	var legs []testLeg
	if err := dec.Decode(&legs); err != nil {
		return nil, fmt.Errorf(
			"test-legs: %w — expected a JSON array of objects with the keys label, language, cmd, coveragePath, toolchainImage, services (all but label, language and cmd optional); a service object takes alias, image, port, env, readyCmd, readyTimeout",
			err)
	}
	if dec.More() {
		return nil, fmt.Errorf("test-legs: trailing content after the JSON array — pass exactly one array")
	}
	if err := checkServiceKeyCase(trimmed); err != nil {
		return nil, err
	}

	if len(legs) == 0 {
		return nil, fmt.Errorf(
			"test-legs: the array declares no legs, which would witness nothing while looking configured — declare at least one leg, or omit test-legs and use test-cmd")
	}
	if len(legs) > testLegLimit {
		return nil, fmt.Errorf(
			"test-legs: %d legs exceeds the limit of %d — each leg is its own container and its own test run, and at most --parallelism of them run at once, so this would blow the pre-commit time budget; witnessing only some of them and reporting success is worse, so this is an error rather than a truncated run",
			len(legs), testLegLimit)
	}

	seen := map[string]int{}
	for i := range legs {
		leg := &legs[i]
		leg.Label = strings.TrimSpace(leg.Label)
		leg.Language = strings.ToLower(strings.TrimSpace(leg.Language))
		leg.CoveragePath = strings.TrimSpace(leg.CoveragePath)
		leg.ToolchainImage = strings.TrimSpace(leg.ToolchainImage)
		// Cmd keeps its whitespace: it goes to `sh -c` verbatim.

		if leg.Label == "" {
			return nil, fmt.Errorf("test-legs[%d]: label must not be empty — it is how this leg is named in the evidence", i)
		}
		if !validLegLabel(leg.Label) {
			return nil, fmt.Errorf(
				"test-legs[%d]: label %q must be 1-%d characters of letters, digits, dot, dash or underscore — a label is rendered into single-line warnings and errors, so it cannot carry newlines or separators",
				i, leg.Label, maxLegLabelLen)
		}
		if prev, dup := seen[leg.Label]; dup {
			return nil, fmt.Errorf(
				"test-legs[%d]: label %q is already used by test-legs[%d] — labels identify a leg in the evidence and must be unique",
				i, leg.Label, prev)
		}
		seen[leg.Label] = i

		if strings.TrimSpace(leg.Cmd) == "" {
			return nil, fmt.Errorf("test-legs[%d] (%s): cmd must not be empty", i, leg.Label)
		}
		if !validLegLanguage(leg.Language) {
			return nil, fmt.Errorf(
				"test-legs[%d] (%s): language %q is not one of %s — the language keys this leg's coverage in coverageByLanguage and selects its toolchain image, so aliases are not accepted",
				i, leg.Label, leg.Language, strings.Join(legLanguages, ", "))
		}
		if err := validateServices(fmt.Sprintf("test-legs[%d] (%s)", i, leg.Label), leg.Services); err != nil {
			return nil, err
		}
	}

	return legs, nil
}

// validLegLabel reports whether label is a safe single-token identity.
func validLegLabel(label string) bool {
	if label == "" || len(label) > maxLegLabelLen {
		return false
	}
	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

// validLegLanguage reports whether lang is one of the four canonical values.
func validLegLanguage(lang string) bool {
	for _, l := range legLanguages {
		if l == lang {
			return true
		}
	}
	return false
}

// exclusiveTestInput enforces that exactly one of test-cmd / test-legs is
// given.
//
// Both set is an error rather than a precedence rule: silently preferring one
// runs half of what the caller asked for and reports success, and a consumer
// migrating from test-cmd to test-legs is exactly the person who would leave
// both in place. Neither set is an error too — Test's whole job is witnessing
// a command, so there is nothing to witness.
func exclusiveTestInput(testCmd string, legs []testLeg) error {
	hasCmd := strings.TrimSpace(testCmd) != ""
	switch {
	case hasCmd && len(legs) > 0:
		return fmt.Errorf(
			"test-cmd and test-legs are mutually exclusive — test-legs supersedes test-cmd (and coverage-path / toolchain-image, which it carries per leg); drop test-cmd, or drop test-legs")
	case !hasCmd && len(legs) == 0:
		return fmt.Errorf("exactly one of test-cmd or test-legs must be set")
	}
	return nil
}

// legsExcludeCoveragePath refuses a run-wide coverage-path alongside declared
// legs.
//
// A leg carries its own coveragePath, so the run-wide one cannot be honoured —
// and silently ignoring it means the consumer named a report they believe is
// harvested while the ratchet skips for want of one. Nothing else in the surface
// consumes coverage-path, so refusing costs a flag move and buys a certainty.
//
// toolchain-image is deliberately NOT refused the same way: in the commit
// composite that one flag also selects the archive build's image (ADR-004), so
// refusing it would make `--artifact archive` and test-legs mutually exclusive
// for no good reason. It is warned about in the envelope instead — see
// toolchainImageIgnoredWarning.
func legsExcludeCoveragePath(coveragePath string, legs []testLeg) error {
	if strings.TrimSpace(coveragePath) == "" || len(legs) == 0 {
		return nil
	}
	return fmt.Errorf(
		"coverage-path cannot be combined with test-legs: each leg names the report it writes, so a run-wide path could not be harvested and the coverage it promises would silently never be measured — move it into the leg's coveragePath")
}

// toolchainImageLegScopeWarning is the envelope line for how a run-wide
// toolchain-image relates to declared legs. See legsExcludeCoveragePath for why
// this one warns rather than fails. A prepared leg is the one exception to the
// normal per-leg resolution rule: it inherits the container built from the
// run-wide image, so calling that image ignored would contradict the execution.
func toolchainImageLegScopeWarning(image, preparedTestLabel string) string {
	if preparedTestLabel != "" {
		return fmt.Sprintf(
			"byo-test: toolchain-image %s supplies prepared test leg %q; every other test leg resolves its own image from its language, or from its own toolchainImage.",
			image, preparedTestLabel)
	}
	return fmt.Sprintf(
		"byo-test: toolchain-image %s does not apply to test-legs — each leg resolves its own image from its language, or from its own toolchainImage. No test leg ran in %s.",
		image, image)
}

// toolchainNoteWarning is the envelope line for a version file cicd read off
// the consumer's tree and could not use.
//
// It fires on that state only. A repository with no .nvmrc and no global.json
// gets no line at all, so silence here keeps meaning something specific — this
// tree pins no toolchain version — rather than meaning nothing. That is the
// opposite call from dotnetLegScopeWarning, which fires on every .NET leg, and
// the difference is where the information sits: there, every run is in the same
// epistemic position and an absence would carry none, so the line has to be
// unconditional. Here the absence *is* the answer, and an unconditional line
// would destroy it.
//
// What it replaces is a genuine indistinguishability. ResolveToolchain returned
// a bare image, so a global.json cicd parsed and rejected, a global.json
// carrying only a Microsoft.Testing.Platform runner opt-in, and no global.json
// at all all produced the identical string with no trace anywhere that a file
// had been read. The middle one is not hypothetical: it is the shape this
// repository's own runner guidance tells a consumer to write, and it lands on
// the pinned 8.0 band, which predates the opt-in and cannot honour it.
//
// A warning and never an error, for notWitnessedWarning's reason: nothing
// failed to run, a default band is frequently the right band, and --fail-on
// NONE cannot clear a non-run — so failing here would be a permanent red on a
// repository doing nothing wrong.
//
// Single line, and no backtick in it, because notify/render.go renders each
// warning into a markdown code span. The quoted value inside note comes from
// quoteFileValue, which uses %q and is bounded for the same reason.
func toolchainNoteWarning(qualifier, note string) string {
	return fmt.Sprintf(
		"%s: TOOLCHAIN NOT RESOLVED FROM THE TREE — %s. cicd read that file and could not use it, which is not the same state as the file being absent, and the two used to look identical here. Pass toolchain-image, or correct the file, if that image is not the one this command needs.",
		qualifier, note)
}

// toolchainNoteWarnings is the disclosure for a whole run: one line per leg
// whose image came from a version file cicd read and could not use, and nothing
// for any other leg.
//
// It lives here, in the untagged file, rather than inline in byotest.go, for
// include.go's reason. The invariant worth asserting is a biconditional — a
// warning appears if and only if a resolution carries a note — and a loop
// behind //go:build !unit_test cannot be asked about it. That is the shape that
// let a switch with no default arm resolve --include golang to an empty
// language set and report passed=true.
func toolchainNoteWarnings(legs []testLeg, resolutions []ToolchainResolution) []string {
	// Two slices indexed in step, so a length mismatch would silently drop or
	// misattribute a disclosure. Refuse rather than guess: attributing one
	// leg's toolchain to another is worse than the silence being replaced.
	if len(legs) != len(resolutions) {
		return nil
	}
	var out []string
	for i, res := range resolutions {
		if res.Note == "" {
			continue
		}
		out = append(out, toolchainNoteWarning(legScopeQualifier(legs[i].Label, len(legs)), res.Note))
	}
	return out
}

// legacyTestLeg builds the single leg that reproduces the pre-legs behaviour
// of --test-cmd: the command runs in the container resolved from the *first*
// detected language, and writes one coverage report keyed under that same
// language.
//
// The language is returned as detected, not guessed: with nothing detected it
// is empty, which keeps the "unknown" coverage key and the existing
// could-not-resolve-a-toolchain error exactly as they were.
func legacyTestLeg(testCmd, coveragePath, toolchainImage string, detected []string) testLeg {
	primary := ""
	if len(detected) > 0 {
		primary = detected[0]
	}
	return testLeg{
		Label:          legacyLegLabel,
		Language:       primary,
		Cmd:            testCmd,
		CoveragePath:   coveragePath,
		ToolchainImage: toolchainImage,
	}
}

// orderByLanguage sorts languages into the canonical legLanguages order, with
// anything unrecognised sorted alphabetically after them. Evidence has to be
// stable across runs, and Go map iteration is not.
func orderByLanguage(langs []string) []string {
	rank := map[string]int{}
	for i, l := range legLanguages {
		rank[l] = i
	}
	out := append([]string(nil), langs...)
	sort.SliceStable(out, func(i, j int) bool {
		ri, oki := rank[out[i]]
		rj, okj := rank[out[j]]
		switch {
		case oki && okj:
			return ri < rj
		case oki:
			return true
		case okj:
			return false
		default:
			return out[i] < out[j]
		}
	})
	return out
}

// witnessedLanguages returns the distinct languages the legs cover, in
// canonical order. Legs with no language (the legacy leg on a tree where
// nothing was detected) contribute nothing.
func witnessedLanguages(legs []testLeg) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, leg := range legs {
		if leg.Language == "" || seen[leg.Language] {
			continue
		}
		seen[leg.Language] = true
		out = append(out, leg.Language)
	}
	return orderByLanguage(out)
}

// unwitnessedLanguages returns the languages present in detected that no leg
// witnesses, in detection order.
//
// This is the fact the old envelope could not express. It is reported as a
// warning rather than an error on purpose — see notWitnessedWarning.
func unwitnessedLanguages(detected, witnessed []string) []string {
	covered := map[string]bool{}
	for _, w := range witnessed {
		covered[w] = true
	}
	out := []string{}
	for _, d := range detected {
		if d == "" || covered[d] {
			continue
		}
		covered[d] = true // a repeated marker must not repeat the warning
		out = append(out, d)
	}
	return out
}

// notWitnessedWarning is the line an audit reads to tell a partially
// witnessed repository from a fully witnessed one.
//
// Warning, not error, and deliberately so. The doctrine it has to answer to is
// "a tool that could not run must never read as clean" — but nothing here
// failed to run: the caller never asked for that language to be tested, which
// is the case lintLanguage's default branch already settles ("nothing was
// asked of a tool, so nothing failed to run", ran=true), and which the intent
// gate settles the same way one layer up — an unasked gate reports loudly and
// does not fail. Making it an error would also turn a version bump red for
// every repository carrying an incidental marker file (a docs/package.json in
// a Go service), which trades one silent wrong answer for a loud wrong answer.
//
// What must never happen is silence, and that is what this fixes: the line is
// unconditional, notify renders warnings verbatim into the PR comment, and the
// envelope's `languages` now lists what was witnessed rather than what was
// detected. The remedies are named because the fix is one flag either way.
func notWitnessedWarning(unwitnessed, witnessed []string) string {
	attested := "no language at all"
	if len(witnessed) > 0 {
		attested = "tests for " + strings.Join(witnessed, ", ") + " only"
	}
	return fmt.Sprintf(
		"byo-test: NOT WITNESSED — %s detected in the source tree but no test leg runs its tests, so this evidence attests %s. Give each language its own command, image and coverage report with test-legs, or narrow detection with include.",
		strings.Join(unwitnessed, ", "), attested)
}

// legPrefix is the label warnings and errors from a leg are qualified with.
// With a single leg it is empty, so a --test-cmd consumer's evidence keeps the
// exact strings it had before legs existed; the label only earns its space
// once there is more than one leg to tell apart.
func legPrefix(label string, legCount int) string {
	if legCount <= 1 {
		return ""
	}
	return "test-leg " + label
}

// mergeLegCoverage folds per-leg coverage readings into the per-language maps
// the envelope carries and the ratchet compares.
//
// Legs sharing a language are combined by mergeNodeCoverage, the same
// coverable-line weighting the multi-project Node lint leg uses, for the same
// measured reason: an unweighted mean lets a 100%-covered 5-line package drag
// a 40%-covered 5000-line package up to 70%, which is a false pass wearing a
// percentage.
//
// The key stays the language, never the leg label. coverageByLanguage is the
// only shape parseBaselineCoverage accepts, and the baseline is a previous
// run's combined-evidence.json, so keying on labels would compare this run's
// labels against a document that has none — a ratchet that silently compares
// nothing.
func mergeLegCoverage(byLang map[string][]nodeCoverage) (map[string]float64, map[string]int) {
	pcts := map[string]float64{}
	lines := map[string]int{}
	for lang, readings := range byLang {
		pct, coverable := foldCoverage(readings)
		if pct == nil {
			continue
		}
		pcts[lang] = *pct
		if coverable != nil {
			lines[lang] = *coverable
		}
	}
	return pcts, lines
}

// foldCoverage reduces coverage readings to one figure and one coverable-line
// total, delegating to mergeNodeCoverage for the weighting.
//
// One reading short-circuits deliberately. Floating point does not guarantee
// that x*n/n returns x, and a single-leg run's coverage figure has to be the
// number the tool reported rather than a round-trip of it — the pre-legs
// evidence for a single test command stays byte-identical.
func foldCoverage(readings []nodeCoverage) (*float64, *int) {
	if len(readings) == 1 {
		pct := readings[0].Percent
		if readings[0].Lines > 0 {
			lines := readings[0].Lines
			return &pct, &lines
		}
		return &pct, nil
	}
	return mergeNodeCoverage(readings)
}

// declaredCoveragePaths lists the coverage reports the legs said they would
// write, for the ratchet's no-coverage-output skip message. Empty when no leg
// declared one, so applyRatchet's own "(no coverage-path configured)" wording
// still applies — with a single leg the message is what it always was.
func declaredCoveragePaths(legs []testLeg) string {
	paths := make([]string, 0, len(legs))
	for _, leg := range legs {
		if leg.CoveragePath != "" {
			paths = append(paths, leg.CoveragePath)
		}
	}
	return strings.Join(paths, ", ")
}

// legReport is one leg's record in the envelope's genericReport.
//
// The command itself is deliberately absent. It is consumer-authored text that
// can carry a credential inline (`npm config set //feed/:_authToken=… && npm
// test`), and this repository does not let a credential reach an envelope. The
// label, language and image identify the leg without quoting it.
type legReport struct {
	Label    string `json:"label"`
	Language string `json:"language,omitempty"`
	Image    string `json:"image"`
	// Ran is false when the container never completed under our control — a
	// non-run, which no threshold may report as passed.
	Ran bool `json:"ran"`
	// ExitCode is the command's own exit status. Nil when the leg did not run:
	// there is no exit code in that case, and a fabricated 0 would say the
	// opposite of what happened.
	ExitCode *int `json:"exitCode,omitempty"`
	// Tests is this leg's runner accounting when its console summary was
	// recognised. It remains per-leg here even though TestsByLanguage merges
	// siblings, so the producer artifact can still explain which command
	// contributed which tests.
	Tests            *TestCounts `json:"tests,omitempty"`
	CoveragePath     string      `json:"coveragePath,omitempty"`
	CoverageMeasured bool        `json:"coverageMeasured"`
	CoveragePercent  *float64    `json:"coveragePercent,omitempty"`
	CoverageLines    *int        `json:"coverageLines,omitempty"`

	// CoverageDocumentsMerged is how many coverage documents this leg's harvest
	// folded into its reading. Nil means no patterned harvest ran at all, which
	// is not the same claim as a harvest that merged nothing — omitempty on a
	// plain int would have collapsed the two.
	CoverageDocumentsMerged *int `json:"coverageDocumentsMerged,omitempty"`

	// ProjectsDiscovered and TestProjectsDiscovered are the .NET denominator: how
	// many project files the source tree holds and how many of them carry a test
	// marker. Present only for a leg naming dotnet, and nil when the sweep that
	// would have answered could not run — a zero there would describe an empty
	// tree, which is a different tree from one nobody looked at.
	//
	// Deliberately two counts and no ratio. cicd cannot know how many projects a
	// consumer's own command should have run, so the envelope carries the numbers
	// and dotnetLegScopeWarning states in prose what they do and do not license.
	ProjectsDiscovered     *int `json:"projectsDiscovered,omitempty"`
	TestProjectsDiscovered *int `json:"testProjectsDiscovered,omitempty"`

	// ToolchainFrom names which ADR-004 level produced Image: explicit, nvmrc,
	// global-json or default. Image alone cannot say — mcr.microsoft.com/dotnet/sdk:8.0
	// is both the band a global.json can ask for and the band a repository gets
	// for asking nothing.
	ToolchainFrom string `json:"toolchainFrom,omitempty"`
	// ToolchainNote is set only when a version file was present and did not
	// determine Image. It is the structured half of toolchainNoteWarning, and
	// it is here for the reason name-the-scope-a-byo-leg-witnessed gives: a
	// consumer who chooses to compare two envelopes should be able to see this
	// change without reading prose.
	ToolchainNote string `json:"toolchainNote,omitempty"`

	// Services is one row per service this leg declared: what was asked for,
	// whether it became usable, and by which claim. Absent — not empty — when
	// the leg declared none, so a leg with no dependencies keeps the exact
	// report it had before services existed.
	//
	// Audit-bundle only: cross-cutting/evidence drops genericReport, so the
	// sentence a human reads comes from errors[]. This is the structured half,
	// here for the reason ToolchainNote is: a consumer comparing two envelopes
	// should be able to see a service stop being ready without matching prose.
	Services []serviceReport `json:"services,omitempty"`

	// DurationMS is the leg's wall clock in milliseconds. Under --parallelism
	// the legs overlap, so their sum is not the run's duration and a slow leg
	// may have been waiting on its siblings. Omitted when not measured.
	DurationMS int64 `json:"durationMs,omitempty"`
}

// legsReport is the genericReport payload (genericFormat "byo-test-legs").
//
// It carries the detected/witnessed/unwitnessed triple as structure, not only
// as a warning string, so a machine reading the audit can tell a partial run
// from a complete one without matching prose. Every slice is initialised:
// `null` where an array belongs says nothing at all, where `[]` says "asked,
// and the answer is none".
type legsReport struct {
	Format               string      `json:"format"`
	DetectedLanguages    []string    `json:"detectedLanguages"`
	WitnessedLanguages   []string    `json:"witnessedLanguages"`
	UnwitnessedLanguages []string    `json:"unwitnessedLanguages"`
	Legs                 []legReport `json:"legs"`
}

// legsReportFormat is the genericFormat value identifying the payload above.
const legsReportFormat = "byo-test-legs"

// newLegsReport assembles the payload with every slice non-nil.
func newLegsReport(detected, witnessed, unwitnessed []string, legs []legReport) legsReport {
	return legsReport{
		Format:               legsReportFormat + "/1.1",
		DetectedLanguages:    nonNilStrings(detected),
		WitnessedLanguages:   nonNilStrings(witnessed),
		UnwitnessedLanguages: nonNilStrings(unwitnessed),
		Legs:                 nonNilLegs(legs),
	}
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func nonNilLegs(in []legReport) []legReport {
	if in == nil {
		return []legReport{}
	}
	return in
}
