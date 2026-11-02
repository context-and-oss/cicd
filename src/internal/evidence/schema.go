package evidence

import (
	"encoding/json"
	"time"
)

// SchemaVersion names the wire shape below. It is semver over the SHAPE, not
// over cicd: a property appearing anywhere reachable from Envelope is a MINOR
// bump, and a property disappearing or changing meaning is a MAJOR one.
//
// It moves under a gate. schema_version_test.go records the exact property set
// each version describes and fails until a shape change and a version change
// arrive together — because this constant stood at 1.0.0 through the addition
// of Sources, Tests, TestsByLanguage and SourceStatus.Scope, and a consumer
// that believed it read sources[], got undefined, and rendered a clean report
// out of absent data.
//
// 1.1.0 is the first version this repository can prove describes what it
// ships. 1.0.0 named several different shapes over its life and no consumer
// should treat it as identifying any one of them.
const SchemaVersion = "1.6.0"

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityNone     Severity = "NONE"
)

// Outcome is what a tool found, before any gate was applied to it.
//
// Passed answers a different question: "should this block the pipeline?". Under
// `fail-on: NONE` that question has one answer whatever the tool saw, which is
// the caller's choice and is working as documented — see
// specs/none-suppresses-findings-not-nonruns.md. But it leaves a consumer with
// no machine-readable way to ask the other question, "what happened?".
//
// A real run showed the cost. The consumer's shadow pipeline runs with
// `fail-on: NONE`, and its evidence reported passed:true for the test source
// while errors[] carried "dotnet test failed (exit 1)". Both statements are
// correct. Neither is readable: a report generator that wants to say "the tests
// failed" has to substring-match English in errors[], and a workflow log that
// renders passed:true says the opposite of what happened.
//
// So the two verdicts travel side by side. Passed keeps its meaning exactly —
// no gate behaviour changes with this type — and Outcome states the un-gated
// result the gate was applied to.
//
// The zero value is the empty string, and it means "this producer did not say",
// not "nothing happened". That is deliberate: a bool named `ran` would have
// defaulted to false, so every producer not yet updated would have claimed its
// tool did not run — an absent signal read as a verdict, which is the failure
// class this repository exists to catch. An absent string cannot be mistaken
// for a verdict. Producers are converted one at a time and consumers can tell
// which have been.
// Concern is the question a tool answers, phrased the way the reader of a
// security report asks it: "what about SAST?", "what about our licences?".
//
// The evidence bundle is indexed by PRODUCING MODULE — parts/NN-security.json,
// parts/NN-quality.json — because that is how the pipeline is built. Nobody
// receiving a report asks it that way. The two axes are not the same and
// neither is derivable from the other: `security` alone answers four concerns,
// and "tests" arrives from five runners across two modules. A reader who wants
// the SAST verdict has to know that Semgrep lives inside the same envelope as
// Trivy and Gitleaks, and that knowledge is pipeline trivia they should never
// need.
//
// The concern is DECLARED by the producer, never mapped from the tool name by
// the aggregator. A lookup table keyed on (module, scope, tool) is the same
// mistake as deriving Outcome from Passed: it is a guess wearing a verdict's
// clothes, and its failure mode is silent — a tool added to security next year
// gets filed under whatever the table's fuzzy match returns, and the report
// reads as complete while a whole concern is misplaced. The tool that knows
// what it is says so.
//
// The zero value is the empty string, meaning "this producer did not say", for
// the same reason Outcome's is. An unclassified row is collected and reported
// as unclassified rather than dropped or guessed at, so a producer that gains a
// tool without declaring its concern is loud instead of quiet.
type Concern string

const (
	// ConcernSAST: static analysis of first-party source.
	ConcernSAST Concern = "sast"
	// ConcernSCA: known vulnerabilities in resolved dependencies. One concern
	// across source, archive and image scopes — a report answers "what about
	// our dependencies?" once, and Scope tells the three runs apart.
	ConcernSCA Concern = "sca"
	// ConcernSecrets: credentials committed to the tree or its history.
	ConcernSecrets Concern = "secrets"
	// ConcernLicenses: licence obligations of resolved dependencies.
	ConcernLicenses Concern = "licenses"
	// ConcernSBOM: the component inventory itself, and its publication.
	ConcernSBOM Concern = "sbom"
	// ConcernLint: style and correctness checks over first-party source.
	ConcernLint Concern = "lint"
	// ConcernTests: executed test suites and their results.
	ConcernTests Concern = "tests"
	// ConcernCoverage: how much of the source the tests reached. Kept apart
	// from ConcernTests because a green suite over 2% of the tree and a green
	// suite over 90% are the same row under one concern and different facts.
	ConcernCoverage Concern = "coverage"
	// ConcernIaC: policy over infrastructure and pipeline definitions.
	ConcernIaC Concern = "iac"
	// ConcernDAST: analysis of the running application.
	ConcernDAST Concern = "dast"
)

type Outcome string

const (
	// OutcomeClean: the tool ran and reported nothing.
	OutcomeClean Outcome = "CLEAN"
	// OutcomeSkipped: the check did not run, and that was a legitimate
	// choice rather than a failure — an opt-in gate left off, a selector
	// that asked for no artifact, a scanner with nothing in scope to look
	// at.
	//
	// This is the value the first draft of this type was missing, and the
	// omission reproduced the exact bug the type exists to kill. Three
	// producers reach an envelope having done no work: risk with
	// infraFilesScanned=0, intent with required=false, and build under
	// `--artifact none`. Each reports passed=true and zero findings, so
	// each folded to CLEAN — three green ticks on a report for three
	// checks that never ran. noartifact.go states the doctrine in its own
	// file comment: "a tool that could not run must never read as clean".
	//
	// SKIPPED is not ERROR. Nothing went wrong; there was nothing to do,
	// or the caller asked for nothing to be done. A report renders it as
	// coverage the run does not have, not as a fault to chase.
	OutcomeSkipped Outcome = "SKIPPED"
	// OutcomeFindings: the tool ran and reported findings, at any severity.
	// Whether those findings trip the gate is Passed's business, not this
	// field's.
	OutcomeFindings Outcome = "FINDINGS"
	// OutcomeFailed: the tool ran, and the thing it was run against failed.
	// A test suite with failing tests is the case this exists for: zero
	// findings, a real failure, and no other field that says so.
	OutcomeFailed Outcome = "FAILED"
	// OutcomeError: the tool did not produce a usable result. This is the
	// ran=false of gatedPassed — a scanner that could not execute, an
	// unreadable exit status, an unparseable report.
	OutcomeError Outcome = "ERROR"
)

// ValidSeverity returns true if s is a recognised severity level.
func ValidSeverity(s Severity) bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityNone:
		return true
	}
	return false
}

type ToolInfo struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Args    []string `json:"args,omitempty"`
}

type RepoContext struct {
	RepoURL   string `json:"repoUrl"`
	CommitSHA string `json:"commitSha"`
	Branch    string `json:"branch"`
	Tag       string `json:"tag,omitempty"`
	// AppID and SourcePaths describe a caller-declared application boundary.
	// Absent in repository mode. The declaration is not an inferred graph.
	AppID       string   `json:"appId,omitempty"`
	SourcePaths []string `json:"sourcePaths,omitempty"`
}

// Finding is a single normalised, human-readable diagnostic. It is the
// detail behind the FindingsBySeverity counts: the aggregator
// (cross-cutting/evidence) extracts these from each module's SARIF and
// genericReport payloads so the combined envelope, PR comment, job summary
// and CI gate step can show *what* tripped the gate, not just how many.
//
// Counts in FindingsBySeverity remain authoritative for the gate decision;
// Findings is best-effort detail (a module may report a count without a
// payload the aggregator can parse).
// Line is the 1-based line ArtifactPath's finding sits on, 0 when the
// producing tool reported none. It is part of the identity of a finding, not
// decoration: without it two different secrets in one .env file, or two lint
// errors in one function, are byte-identical rows that dedupeFindings collapses
// into one — under-reporting that looks exactly like a cleaner tree.
type Finding struct {
	Severity     Severity `json:"severity"`
	Tool         string   `json:"tool,omitempty"`
	Rule         string   `json:"rule,omitempty"`
	Message      string   `json:"message"`
	ArtifactPath string   `json:"artifactPath,omitempty"`
	Line         int      `json:"line,omitempty"`
}

// TestCounts is the executed-test accounting for one suite.
//
// The fields travel as one value rather than as parallel maps on the envelope,
// and that is a deliberate response to how CoverageByLanguage and
// CoverageLinesByLanguage went wrong: two last-writer-wins maps holding halves
// of one claim can be merged apart, pairing one run's numerator with another
// run's denominator. Numbers that must agree belong in a value that cannot be
// split, so aggregation has no opportunity to mismatch them.
//
// Passed + Failed + Skipped need not equal Total. Runners report what their
// tool reports, and a tool that lost a result to a crash should show the gap
// rather than have cicd balance the books on its behalf.
type TestCounts struct {
	// Total is the number of tests the tool knew about.
	Total int `json:"total"`
	// Passed is the number that ran and succeeded.
	Passed int `json:"passed"`
	// Failed is the number that ran and failed.
	Failed int `json:"failed"`
	// Skipped is the number the tool did not execute.
	Skipped int `json:"skipped"`
	// DurationMS is the wall-clock time of the suite, when the runner measured it.
	DurationMS int64 `json:"durationMs,omitempty"`
}

// Examined is how much a tool actually looked at, in whatever unit that tool
// counts in.
//
// It is the denominator a zero finding count needs. "0 vulnerabilities" and "0
// licences outside policy" are the same two words whether the scanner read
// three thousand components or reached none of them, and a customer report
// built on findingsCount alone cannot tell those apart — the same conflation
// Outcome fixes for the verdict, one level down in the numbers.
//
// The live case: a consumer's licence scan reported a few hundred licences
// scanned and 0 outside policy beside an SBOM listing thousands of components. Both figures are
// correct and the gap between them is the whole story, but it lived in an
// English warning string and a separate file.
//
// A pointer, and absent means the producer did not say — not that it examined
// nothing. Count carries that claim, and Count=0 inside a present Examined is a
// real statement: the tool looked and there was nothing in scope.
type Examined struct {
	// Unit names what is being counted, in the producer's own words —
	// "licence declarations", "infrastructure files", "components". Without
	// it a bare number is unreportable.
	Unit string `json:"unit"`
	// Count is how many units the tool processed.
	Count int `json:"count"`
	// Total is how many units existed in scope, when the tool knows. Zero
	// means it did not say, which is why this one is omitempty and Count is
	// not: a tool that cannot see its own denominator must not imply one.
	Total int `json:"total,omitempty"`
}

// SourceStatus summarises one source verdict behind a combined Passed, so the
// combined verdict can say WHICH gate produced it — the combined Passed is an
// AND across sources, and without this list a caller reading the combined
// envelope cannot tell a SAST failure from a coverage regression. Counts carry
// no omitempty because an absent count and a zero count are different claims:
// "no errors" must stay distinguishable from "nobody counted".
//
// A source is USUALLY one merged envelope, but not always. A module that fuses
// several tools under one envelope — security.ScanSource runs Semgrep, Gitleaks
// and Trivy behind a single `security-source` verdict — declares its
// constituents here itself, and the aggregator propagates those rows instead of
// synthesising one row for the envelope. Without that a consumer cannot express
// "SAST clean, SCA failed": it has to reconstruct the split by string-matching
// Finding.Tool, which recovers findings but never recovers a per-tool verdict,
// because the per-tool verdict was not written down anywhere.
type SourceStatus struct {
	ModuleName string `json:"moduleName"`
	Stage      string `json:"stage"`
	Tool       string `json:"tool,omitempty"`
	// Scope names the fused envelope a per-tool row came from
	// ("security-source", "security-archive"). Empty when the row IS the
	// envelope, which is the ordinary case.
	//
	// One scanner over two scopes is otherwise indistinguishable, and that
	// ambiguity reaches customers: a release report renders "gitleaks, gitleaks"
	// because both scopes emit a Gitleaks run and neither says which scope it
	// ran in.
	Scope string `json:"scope,omitempty"`
	// Concern is the question this row answers — "sast", "sca", "coverage".
	// Declared by the producer; see Concern. Empty means the producer did not
	// say, and the aggregator files the row under "unclassified" rather than
	// guessing from Tool.
	Concern Concern `json:"concern,omitempty"`
	Passed  bool    `json:"passed"`
	// Outcome is what this tool found, before the gate. Empty when the
	// producer has not been converted; see Outcome's own comment for why
	// absent is the safe default here and `ran bool` was not.
	Outcome Outcome `json:"outcome,omitempty"`
	// Examined is how much this tool looked at. Absent when it did not say.
	Examined *Examined `json:"examined,omitempty"`
	// Rules is which rules this tool applied, for a tool whose rule set can
	// change under a fixed commit. Absent when the tool did not say.
	Rules         *RuleSet `json:"rules,omitempty"`
	FindingsCount int      `json:"findingsCount"`
	ErrorsCount   int      `json:"errorsCount"`
	WarningsCount int      `json:"warningsCount"`
}

// RuleSet is the second denominator a finding count needs: Examined says what
// the tool read, RuleSet says what it read it with.
//
// A pattern scanner's zero is a measurement over both. The same commit scanned
// with Semgrep's live p/security-audit applied 725 rules one day and 225 three
// days later, and both reports said zero findings with the same file count
// beside them. Recording the rules is what makes that drift visible; pinning
// them (Pinned) is what stops it.
type RuleSet struct {
	// Count is how many distinct rules the tool reported as loaded.
	Count int `json:"count"`
	// ByLanguage splits Count by the language directory a rule's id names,
	// so a pack that lost every Python rule is visible as such.
	ByLanguage map[string]int `json:"byLanguage,omitempty"`
	// Pinned names the fixed source of the rules the tool was held to, when
	// there is one. A pinned set that loaded fewer rules than it declares is
	// a non-run, never a smaller clean result.
	Pinned string `json:"pinned,omitempty"`
	// Unpinned names the rule sources fetched at run time that nothing pins.
	// Their rules are counted in Count but cannot be verified.
	Unpinned []string `json:"unpinned,omitempty"`
}

// ConcernRollup is one concern's whole answer, folded from the rows that
// declared it.
//
// It carries counts and a verdict, never the rows themselves. The rows are
// already in Envelope.Sources and the findings are already in Findings;
// repeating them here would grow the largest document in the bundle to say
// nothing new, and would create a second copy that can disagree with the
// first. Tools is a count for exactly that reason — it says how many rows
// stand behind the verdict without restating them.
type ConcernRollup struct {
	// Concern is empty on the rollup covering rows whose producer declared
	// none. That group is reported rather than dropped; see Concern.
	Concern Concern `json:"concern,omitempty"`
	// Passed is the AND over the rows, and Outcome is the worst of them —
	// the same two folds the combined envelope itself uses, because a
	// concern is a subset of the same rows and any other fold would let the
	// two verdicts disagree about one run.
	Passed  bool    `json:"passed"`
	Outcome Outcome `json:"outcome,omitempty"`
	// Examined is summed only when every row counts in the same unit and
	// every row states one. Absent otherwise, because a denominator summed
	// over the tools that answered understates the concern by whatever the
	// silent ones looked at, and an understated denominator flatters the
	// findings sitting next to it.
	Examined      *Examined `json:"examined,omitempty"`
	FindingsCount int       `json:"findingsCount"`
	ErrorsCount   int       `json:"errorsCount"`
	WarningsCount int       `json:"warningsCount"`
	Tools         int       `json:"tools"`
}

// ConcernReport is the run seen by question rather than by module.
//
// NotAnswered is the half that keeps this from becoming the failure it was
// built to fix. A reader shown seven concerns can see which seven are there;
// they cannot see that ten exist, so an absent SAST rollup reads identically
// to a clean one. Listing the unanswered concerns supplies the denominator the
// list itself cannot.
//
// It is deliberately not a verdict, and the name says so. Nothing here knows
// which concerns a given pipeline OUGHT to answer — a repository with no
// infrastructure has no IaC leg and is not missing one. Calling those absences
// defects would be inventing a denominator, which is the same mistake one
// level up. This states the two things it knows: these questions exist, this
// run answered these.
type ConcernReport struct {
	Answered    []ConcernRollup `json:"answered"`
	NotAnswered []Concern       `json:"notAnswered"`
}

// Envelope is the top-level evidence artifact returned by every module function.
// Tool-specific payloads (SARIF, CycloneDX) are embedded as raw JSON so this
// struct does not need to know each format's internal schema.
type Envelope struct {
	SchemaVersion string `json:"schemaVersion"`

	ModuleName string      `json:"moduleName"`
	Stage      string      `json:"stage"`
	Tool       ToolInfo    `json:"tool"`
	Repo       RepoContext `json:"repo"`

	TimestampUTC time.Time `json:"timestampUtc"`
	DurationMS   int64     `json:"durationMs"`
	Languages    []string  `json:"languages,omitempty"`

	Passed bool `json:"passed"`
	// Outcome is what this module found, before the gate — the un-gated
	// counterpart to Passed. A module that declares Sources states the same
	// thing per tool there; this is the envelope-wide roll-up, and the only
	// place a module that does NOT split into per-tool rows can say it.
	//
	// Empty when the producer has not been converted. The aggregator
	// propagates it rather than deriving it: passed, findingsCount and
	// errors[] cannot distinguish "the tests failed" from "the scanner
	// crashed" from "it found things", so anything derived here would be a
	// guess wearing a verdict's clothes.
	Outcome Outcome `json:"outcome,omitempty"`
	// Concern is the question this module answers, for a module whose work
	// falls under exactly one. A module fusing several tools states it per
	// tool in Sources instead — an envelope-wide concern over a mixed set
	// would file Semgrep's verdict under whichever concern was written first.
	//
	// Set only where it is unambiguous, and absent otherwise: see Concern for
	// why an unclassified row is better than a guessed one.
	Concern Concern `json:"concern,omitempty"`
	// Examined is how much this module looked at, for a module whose work
	// has a single countable unit. A module fusing several tools states it
	// per tool in Sources instead — an envelope-wide figure summed across
	// different units would be a number with no meaning.
	Examined           *Examined        `json:"examined,omitempty"`
	FailOnSeverity     Severity         `json:"failOnSeverity,omitempty"`
	FindingsCount      int              `json:"findingsCount"`
	FindingsBySeverity map[Severity]int `json:"findingsBySeverity,omitempty"`

	// Findings holds normalised, human-readable detail for the counts above.
	// Populated by the aggregator from each module's SARIF / genericReport
	// payloads; absent on individual module envelopes.
	Findings []Finding `json:"findings,omitempty"`

	// Sources lists the per-source verdicts behind the combined Passed, in
	// input order. Populated by the aggregator only, like Findings; absent on
	// individual module envelopes.
	Sources []SourceStatus `json:"sources,omitempty"`

	// Concerns is Sources re-folded by the question each row answers, so a
	// consumer holding nothing but this file can report "SAST clean, SCA
	// failed" without knowing which module runs which scanner.
	//
	// The aggregator folds it rather than the consumer, for the same reason
	// the aggregator folds Passed and Outcome: concerns/index.json in the
	// evidence bundle and the pull request comment are read side by side by
	// the same person, and two independent folds of the same rows can come to
	// disagree with nothing anywhere failing. One fold, two renderings.
	//
	// Populated by the aggregator only; nil on individual module envelopes,
	// which means "nobody folded this" rather than "no concern was answered".
	// An aggregator that folded and found nothing declared still writes a
	// report — an empty Answered beside a full NotAnswered.
	Concerns *ConcernReport `json:"concerns,omitempty"`

	// Tests is the executed-test accounting for the suite this envelope covers.
	// Present only when the runner could account for its own run; a runner that
	// executed tests but could not be counted must leave this nil rather than
	// report zeros, because zero executed is indistinguishable from a suite that
	// was never collected — the "setup-only false pass" that
	// scripts/test-module-units.sh guards against in cicd's own suite.
	Tests *TestCounts `json:"tests,omitempty"`

	// TestsByLanguage holds the per-language accounting, keyed by language.
	// Present on the combined quality envelope when the test leg ran.
	TestsByLanguage map[string]TestCounts `json:"testsByLanguage,omitempty"`

	// CoveragePercent is the line/statement coverage percentage (0–100).
	// Present only when the module measured coverage (quality module, test step).
	// On the combined envelope it is derived instead of copied: it is the
	// per-language percentages weighted by CoverageLinesByLanguage, and it is
	// withheld entirely when those weights are incomplete — an unweighted mean
	// over languages is a number about no run that ever happened.
	CoveragePercent *float64 `json:"coveragePercent,omitempty"`

	// CoverageLines is the total number of coverable lines/statements measured by the test tool.
	// Present only when the module measured coverage (quality module, test step).
	// On the combined envelope it is derived alongside CoveragePercent and shares
	// its withholding rule exactly: it is the denominator that percentage is of,
	// so a total covering only some of the languages must never be published
	// beside a percentage presented as covering all of them.
	CoverageLines *int `json:"coverageLines,omitempty"`

	// CoverageByLanguage holds per-language coverage percentages (0–100).
	// Present on the combined quality envelope when multiple languages are detected.
	CoverageByLanguage map[string]float64 `json:"coverageByLanguage,omitempty"`

	// CoverageLinesByLanguage holds per-language coverable line/statement counts.
	// Present on the combined quality envelope; used alongside CoverageByLanguage
	// to determine whether the coverage gate applies (see coverageMinLines) and to
	// weight the combined CoveragePercent.
	//
	// A language's entry here describes that language's entry in
	// CoverageByLanguage, so the two must only ever be written as a pair from one
	// envelope. Both are last-writer-wins on merge, and a percentage paired with a
	// different run's line count yields a plausible-looking figure that is about
	// nothing. Aggregation enforces this; see buildCombined.
	CoverageLinesByLanguage map[string]int `json:"coverageLinesByLanguage,omitempty"`

	// CoverageBaselineByLanguage holds the per-language baseline coverage
	// percentages (0–100) the ratchet compared against.
	// Present only when a baseline was supplied (quality module, test step).
	CoverageBaselineByLanguage map[string]float64 `json:"coverageBaselineByLanguage,omitempty"`

	// CoverageRatchet records the ratchet verdict: "pass", "fail",
	// "skipped:no-baseline", "skipped:no-coverage-output" or "skipped:warn-mode".
	// Present only when the module ran the coverage ratchet (quality module, test step).
	CoverageRatchet string `json:"coverageRatchet,omitempty"`

	// SARIFReport holds a SARIF 2.1.0 JSON document.
	// Present on: lint, sast, secrets-scan (both stages).
	SARIFReport json.RawMessage `json:"sarifReport,omitempty"`

	// CycloneDXReport holds a CycloneDX JSON document.
	// Present on: vuln-scan (both stages), sbom.
	CycloneDXReport json.RawMessage `json:"cyclonedxReport,omitempty"`

	// GenericReport holds arbitrary structured tool output for modules that do
	// not produce SARIF or CycloneDX (e.g. markdownlint, licence scanners).
	// GenericFormat identifies the payload schema (e.g. "markdownlint", "spdx-lite").
	GenericReport json.RawMessage `json:"genericReport,omitempty"`
	GenericFormat string          `json:"genericFormat,omitempty"`

	// RawOutputRef is a path to the verbose tool stdout+stderr file exported
	// from the Dagger pipeline.
	RawOutputRef string `json:"rawOutputRef,omitempty"`

	// Warnings carries non-fatal diagnostics — e.g. missing bootstrap files
	// or skipped optional steps. Pipelines should not fail because Warnings
	// is non-empty; rendering surfaces these under a "Warnings" heading so
	// they don't look like errors. Errors[] remains for hard failures.
	Warnings []string `json:"warnings,omitempty"`

	Errors []string `json:"errors,omitempty"`
}
