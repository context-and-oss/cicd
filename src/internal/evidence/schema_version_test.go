package evidence_test

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/context-and-oss/cicd/internal/evidence"
)

// SchemaVersion sat at 1.0.0 while the envelope grew Sources, Tests,
// TestsByLanguage and SourceStatus.Scope. It was not forgotten once; it was
// never a decision at all, because nothing made adding a field ask the
// question. The cost landed on a consumer: the first consumer
// renderer checked schemaVersion for equality, believed it, read sources[],
// got undefined, defaulted to an empty array and rendered a clean report from
// absent data. That reached a pushed commit.
//
// The repair is not a better version string. It is that the wire shape and the
// version that names it can no longer move independently: shapeHistory records
// what each version's shape IS, and TestTheDeclaredVersionDescribesTheShape
// fails until a shape change and a version change arrive in the same commit.
//
// What this cannot do is prove a released version's shape. shapeHistory is a
// claim in the repository, and a contributor is free to edit the current row
// instead of adding a new one. The gate makes the change deliberate — the
// diff says "I am altering what 1.1.0 means" in the same breath — which is
// the whole distance between this defect and its absence. It is not a proof,
// and it is not presented as one.

// shapeRow is one released schema version and the complete wire shape it
// describes: every JSON property reachable from Envelope, as
// "<GoStructName>.<jsonName>", sorted.
//
// Nested structs are included because a consumer reads them too. Scope was
// added to SourceStatus, not to Envelope, and it changed what a consumer sees
// just as much as a top-level field would have.
type shapeRow struct {
	version string
	props   []string
}

// shapeHistory is append-only, oldest first. The last row must describe the
// shape that ships; see TestTheDeclaredVersionIsTheLastRow.
//
// It starts at 1.1.0 on purpose. 1.0.0's DECLARED shape is not recoverable
// from this repository — the only measurement of it is a runtime envelope from
// commit.yml@v1.13.2, which records the fields that run POPULATED, a strictly
// smaller thing than the fields the struct declared. Seeding a 1.0.0 row from
// it would put a fabricated set behind a gate whose entire purpose is to stop
// shape claims being fabricated.
var shapeHistory = []shapeRow{
	{
		version: "1.1.0",
		props: []string{
			"Envelope.coverageBaselineByLanguage",
			"Envelope.coverageByLanguage",
			"Envelope.coverageLines",
			"Envelope.coverageLinesByLanguage",
			"Envelope.coveragePercent",
			"Envelope.coverageRatchet",
			"Envelope.cyclonedxReport",
			"Envelope.durationMs",
			"Envelope.errors",
			"Envelope.failOnSeverity",
			"Envelope.findings",
			"Envelope.findingsBySeverity",
			"Envelope.findingsCount",
			"Envelope.genericFormat",
			"Envelope.genericReport",
			"Envelope.languages",
			"Envelope.moduleName",
			"Envelope.passed",
			"Envelope.rawOutputRef",
			"Envelope.repo",
			"Envelope.sarifReport",
			"Envelope.schemaVersion",
			"Envelope.sources",
			"Envelope.stage",
			"Envelope.tests",
			"Envelope.testsByLanguage",
			"Envelope.timestampUtc",
			"Envelope.tool",
			"Envelope.warnings",
			"Finding.artifactPath",
			"Finding.line",
			"Finding.message",
			"Finding.rule",
			"Finding.severity",
			"Finding.tool",
			"RepoContext.branch",
			"RepoContext.commitSha",
			"RepoContext.repoUrl",
			"RepoContext.tag",
			"SourceStatus.errorsCount",
			"SourceStatus.findingsCount",
			"SourceStatus.moduleName",
			"SourceStatus.passed",
			"SourceStatus.scope",
			"SourceStatus.stage",
			"SourceStatus.tool",
			"SourceStatus.warningsCount",
			"TestCounts.durationMs",
			"TestCounts.failed",
			"TestCounts.passed",
			"TestCounts.skipped",
			"TestCounts.total",
			"ToolInfo.args",
			"ToolInfo.name",
			"ToolInfo.version",
		},
	},
	{
		// Outcome and examined, on the envelope and on every source row:
		// what the tool found before the gate, and how much it looked at.
		// Additive — passed keeps its meaning and no consumer of 1.1.0 reads
		// a different value for anything it already read. Every added
		// property is omitempty, so a producer that has not been converted
		// emits nothing rather than a wrong verdict or a confident zero.
		version: "1.2.0",
		props: []string{
			"Envelope.coverageBaselineByLanguage",
			"Envelope.coverageByLanguage",
			"Envelope.coverageLines",
			"Envelope.coverageLinesByLanguage",
			"Envelope.coveragePercent",
			"Envelope.coverageRatchet",
			"Envelope.cyclonedxReport",
			"Envelope.durationMs",
			"Envelope.errors",
			"Envelope.examined",
			"Envelope.failOnSeverity",
			"Envelope.findings",
			"Envelope.findingsBySeverity",
			"Envelope.findingsCount",
			"Envelope.genericFormat",
			"Envelope.genericReport",
			"Envelope.languages",
			"Envelope.moduleName",
			"Envelope.outcome",
			"Envelope.passed",
			"Envelope.rawOutputRef",
			"Envelope.repo",
			"Envelope.sarifReport",
			"Envelope.schemaVersion",
			"Envelope.sources",
			"Envelope.stage",
			"Envelope.tests",
			"Envelope.testsByLanguage",
			"Envelope.timestampUtc",
			"Envelope.tool",
			"Envelope.warnings",
			"Examined.count",
			"Examined.total",
			"Examined.unit",
			"Finding.artifactPath",
			"Finding.line",
			"Finding.message",
			"Finding.rule",
			"Finding.severity",
			"Finding.tool",
			"RepoContext.branch",
			"RepoContext.commitSha",
			"RepoContext.repoUrl",
			"RepoContext.tag",
			"SourceStatus.errorsCount",
			"SourceStatus.examined",
			"SourceStatus.findingsCount",
			"SourceStatus.moduleName",
			"SourceStatus.outcome",
			"SourceStatus.passed",
			"SourceStatus.scope",
			"SourceStatus.stage",
			"SourceStatus.tool",
			"SourceStatus.warningsCount",
			"TestCounts.durationMs",
			"TestCounts.failed",
			"TestCounts.passed",
			"TestCounts.skipped",
			"TestCounts.total",
			"ToolInfo.args",
			"ToolInfo.name",
			"ToolInfo.version",
		},
	},
	{
		// 1.3.0 adds Concern to both Envelope and SourceStatus: the question a
		// tool answers, so the bundle can be indexed the way a report is read
		// rather than the way the pipeline is built. Additive and omitempty —
		// a producer that declares no concern emits nothing, and the aggregator
		// files its row under "unclassified" rather than guessing one.
		version: "1.3.0",
		props: []string{
			"Envelope.concern",
			"Envelope.coverageBaselineByLanguage",
			"Envelope.coverageByLanguage",
			"Envelope.coverageLines",
			"Envelope.coverageLinesByLanguage",
			"Envelope.coveragePercent",
			"Envelope.coverageRatchet",
			"Envelope.cyclonedxReport",
			"Envelope.durationMs",
			"Envelope.errors",
			"Envelope.examined",
			"Envelope.failOnSeverity",
			"Envelope.findings",
			"Envelope.findingsBySeverity",
			"Envelope.findingsCount",
			"Envelope.genericFormat",
			"Envelope.genericReport",
			"Envelope.languages",
			"Envelope.moduleName",
			"Envelope.outcome",
			"Envelope.passed",
			"Envelope.rawOutputRef",
			"Envelope.repo",
			"Envelope.sarifReport",
			"Envelope.schemaVersion",
			"Envelope.sources",
			"Envelope.stage",
			"Envelope.tests",
			"Envelope.testsByLanguage",
			"Envelope.timestampUtc",
			"Envelope.tool",
			"Envelope.warnings",
			"Examined.count",
			"Examined.total",
			"Examined.unit",
			"Finding.artifactPath",
			"Finding.line",
			"Finding.message",
			"Finding.rule",
			"Finding.severity",
			"Finding.tool",
			"RepoContext.branch",
			"RepoContext.commitSha",
			"RepoContext.repoUrl",
			"RepoContext.tag",
			"SourceStatus.concern",
			"SourceStatus.errorsCount",
			"SourceStatus.examined",
			"SourceStatus.findingsCount",
			"SourceStatus.moduleName",
			"SourceStatus.outcome",
			"SourceStatus.passed",
			"SourceStatus.scope",
			"SourceStatus.stage",
			"SourceStatus.tool",
			"SourceStatus.warningsCount",
			"TestCounts.durationMs",
			"TestCounts.failed",
			"TestCounts.passed",
			"TestCounts.skipped",
			"TestCounts.total",
			"ToolInfo.args",
			"ToolInfo.name",
			"ToolInfo.version",
		},
	},
	{
		// 1.4.0 adds Envelope.Concerns: Sources re-folded by the question each
		// row answers, so a consumer holding only combined-evidence.json can
		// report "SAST clean, SCA failed" without a table mapping scanners to
		// modules. The aggregator folds it rather than the consumer, because
		// concerns/index.json in the bundle and the pull request comment are
		// read side by side and two folds of one set of rows drift apart with
		// nothing failing. Additive and omitempty — a module envelope omits it,
		// which means nobody folded it, not that no concern was answered.
		version: "1.4.0",
		props: []string{
			"ConcernReport.answered",
			"ConcernReport.notAnswered",
			"ConcernRollup.concern",
			"ConcernRollup.errorsCount",
			"ConcernRollup.examined",
			"ConcernRollup.findingsCount",
			"ConcernRollup.outcome",
			"ConcernRollup.passed",
			"ConcernRollup.tools",
			"ConcernRollup.warningsCount",
			"Envelope.concern",
			"Envelope.concerns",
			"Envelope.coverageBaselineByLanguage",
			"Envelope.coverageByLanguage",
			"Envelope.coverageLines",
			"Envelope.coverageLinesByLanguage",
			"Envelope.coveragePercent",
			"Envelope.coverageRatchet",
			"Envelope.cyclonedxReport",
			"Envelope.durationMs",
			"Envelope.errors",
			"Envelope.examined",
			"Envelope.failOnSeverity",
			"Envelope.findings",
			"Envelope.findingsBySeverity",
			"Envelope.findingsCount",
			"Envelope.genericFormat",
			"Envelope.genericReport",
			"Envelope.languages",
			"Envelope.moduleName",
			"Envelope.outcome",
			"Envelope.passed",
			"Envelope.rawOutputRef",
			"Envelope.repo",
			"Envelope.sarifReport",
			"Envelope.schemaVersion",
			"Envelope.sources",
			"Envelope.stage",
			"Envelope.tests",
			"Envelope.testsByLanguage",
			"Envelope.timestampUtc",
			"Envelope.tool",
			"Envelope.warnings",
			"Examined.count",
			"Examined.total",
			"Examined.unit",
			"Finding.artifactPath",
			"Finding.line",
			"Finding.message",
			"Finding.rule",
			"Finding.severity",
			"Finding.tool",
			"RepoContext.branch",
			"RepoContext.commitSha",
			"RepoContext.repoUrl",
			"RepoContext.tag",
			"SourceStatus.concern",
			"SourceStatus.errorsCount",
			"SourceStatus.examined",
			"SourceStatus.findingsCount",
			"SourceStatus.moduleName",
			"SourceStatus.outcome",
			"SourceStatus.passed",
			"SourceStatus.scope",
			"SourceStatus.stage",
			"SourceStatus.tool",
			"SourceStatus.warningsCount",
			"TestCounts.durationMs",
			"TestCounts.failed",
			"TestCounts.passed",
			"TestCounts.skipped",
			"TestCounts.total",
			"ToolInfo.args",
			"ToolInfo.name",
			"ToolInfo.version",
		},
	},
	{
		version: "1.5.0",
		props: []string{
			"ConcernReport.answered",
			"ConcernReport.notAnswered",
			"ConcernRollup.concern",
			"ConcernRollup.errorsCount",
			"ConcernRollup.examined",
			"ConcernRollup.findingsCount",
			"ConcernRollup.outcome",
			"ConcernRollup.passed",
			"ConcernRollup.tools",
			"ConcernRollup.warningsCount",
			"Envelope.concern",
			"Envelope.concerns",
			"Envelope.coverageBaselineByLanguage",
			"Envelope.coverageByLanguage",
			"Envelope.coverageLines",
			"Envelope.coverageLinesByLanguage",
			"Envelope.coveragePercent",
			"Envelope.coverageRatchet",
			"Envelope.cyclonedxReport",
			"Envelope.durationMs",
			"Envelope.errors",
			"Envelope.examined",
			"Envelope.failOnSeverity",
			"Envelope.findings",
			"Envelope.findingsBySeverity",
			"Envelope.findingsCount",
			"Envelope.genericFormat",
			"Envelope.genericReport",
			"Envelope.languages",
			"Envelope.moduleName",
			"Envelope.outcome",
			"Envelope.passed",
			"Envelope.rawOutputRef",
			"Envelope.repo",
			"Envelope.sarifReport",
			"Envelope.schemaVersion",
			"Envelope.sources",
			"Envelope.stage",
			"Envelope.tests",
			"Envelope.testsByLanguage",
			"Envelope.timestampUtc",
			"Envelope.tool",
			"Envelope.warnings",
			"Examined.count",
			"Examined.total",
			"Examined.unit",
			"Finding.artifactPath",
			"Finding.line",
			"Finding.message",
			"Finding.rule",
			"Finding.severity",
			"Finding.tool",
			"RepoContext.appId",
			"RepoContext.branch",
			"RepoContext.commitSha",
			"RepoContext.repoUrl",
			"RepoContext.sourcePaths",
			"RepoContext.tag",
			"SourceStatus.concern",
			"SourceStatus.errorsCount",
			"SourceStatus.examined",
			"SourceStatus.findingsCount",
			"SourceStatus.moduleName",
			"SourceStatus.outcome",
			"SourceStatus.passed",
			"SourceStatus.scope",
			"SourceStatus.stage",
			"SourceStatus.tool",
			"SourceStatus.warningsCount",
			"TestCounts.durationMs",
			"TestCounts.failed",
			"TestCounts.passed",
			"TestCounts.skipped",
			"TestCounts.total",
			"ToolInfo.args",
			"ToolInfo.name",
			"ToolInfo.version",
		},
	},
	{
		version: "1.6.0",
		props: []string{
			"ConcernReport.answered",
			"ConcernReport.notAnswered",
			"ConcernRollup.concern",
			"ConcernRollup.errorsCount",
			"ConcernRollup.examined",
			"ConcernRollup.findingsCount",
			"ConcernRollup.outcome",
			"ConcernRollup.passed",
			"ConcernRollup.tools",
			"ConcernRollup.warningsCount",
			"Envelope.concern",
			"Envelope.concerns",
			"Envelope.coverageBaselineByLanguage",
			"Envelope.coverageByLanguage",
			"Envelope.coverageLines",
			"Envelope.coverageLinesByLanguage",
			"Envelope.coveragePercent",
			"Envelope.coverageRatchet",
			"Envelope.cyclonedxReport",
			"Envelope.durationMs",
			"Envelope.errors",
			"Envelope.examined",
			"Envelope.failOnSeverity",
			"Envelope.findings",
			"Envelope.findingsBySeverity",
			"Envelope.findingsCount",
			"Envelope.genericFormat",
			"Envelope.genericReport",
			"Envelope.languages",
			"Envelope.moduleName",
			"Envelope.outcome",
			"Envelope.passed",
			"Envelope.rawOutputRef",
			"Envelope.repo",
			"Envelope.sarifReport",
			"Envelope.schemaVersion",
			"Envelope.sources",
			"Envelope.stage",
			"Envelope.tests",
			"Envelope.testsByLanguage",
			"Envelope.timestampUtc",
			"Envelope.tool",
			"Envelope.warnings",
			"Examined.count",
			"Examined.total",
			"Examined.unit",
			"Finding.artifactPath",
			"Finding.line",
			"Finding.message",
			"Finding.rule",
			"Finding.severity",
			"Finding.tool",
			"RepoContext.appId",
			"RepoContext.branch",
			"RepoContext.commitSha",
			"RepoContext.repoUrl",
			"RepoContext.sourcePaths",
			"RepoContext.tag",
			"RuleSet.byLanguage",
			"RuleSet.count",
			"RuleSet.pinned",
			"RuleSet.unpinned",
			"SourceStatus.concern",
			"SourceStatus.errorsCount",
			"SourceStatus.examined",
			"SourceStatus.findingsCount",
			"SourceStatus.moduleName",
			"SourceStatus.outcome",
			"SourceStatus.passed",
			"SourceStatus.rules",
			"SourceStatus.scope",
			"SourceStatus.stage",
			"SourceStatus.tool",
			"SourceStatus.warningsCount",
			"TestCounts.durationMs",
			"TestCounts.failed",
			"TestCounts.passed",
			"TestCounts.skipped",
			"TestCounts.total",
			"ToolInfo.args",
			"ToolInfo.name",
			"ToolInfo.version",
		},
	},
	{
		version: "1.7.0",
		props: []string{
			"ConcernReport.answered",
			"ConcernReport.notAnswered",
			"ConcernRollup.concern",
			"ConcernRollup.errorsCount",
			"ConcernRollup.examined",
			"ConcernRollup.findingsCount",
			"ConcernRollup.outcome",
			"ConcernRollup.passed",
			"ConcernRollup.tools",
			"ConcernRollup.warningsCount",
			"Envelope.concern",
			"Envelope.concerns",
			"Envelope.coverageBaselineByLanguage",
			"Envelope.coverageByLanguage",
			"Envelope.coverageLines",
			"Envelope.coverageLinesByLanguage",
			"Envelope.coveragePercent",
			"Envelope.coverageRatchet",
			"Envelope.cyclonedxReport",
			"Envelope.durationMs",
			"Envelope.errors",
			"Envelope.examined",
			"Envelope.failOnSeverity",
			"Envelope.findings",
			"Envelope.findingsBySeverity",
			"Envelope.findingsCount",
			"Envelope.genericFormat",
			"Envelope.genericReport",
			"Envelope.languages",
			"Envelope.moduleName",
			"Envelope.outcome",
			"Envelope.passed",
			"Envelope.rawOutputRef",
			"Envelope.repo",
			"Envelope.sarifReport",
			"Envelope.schemaVersion",
			"Envelope.sources",
			"Envelope.stage",
			"Envelope.tests",
			"Envelope.testsByLanguage",
			"Envelope.timestampUtc",
			"Envelope.tool",
			"Envelope.warnings",
			"Examined.count",
			"Examined.total",
			"Examined.unit",
			"Finding.artifactPath",
			"Finding.category",
			"Finding.classificationSource",
			"Finding.concern",
			"Finding.confidence",
			"Finding.line",
			"Finding.message",
			"Finding.rule",
			"Finding.severity",
			"Finding.subcategories",
			"Finding.tool",
			"Finding.weaknessIds",
			"RepoContext.appId",
			"RepoContext.branch",
			"RepoContext.commitSha",
			"RepoContext.repoUrl",
			"RepoContext.sourcePaths",
			"RepoContext.tag",
			"RuleSet.byLanguage",
			"RuleSet.count",
			"RuleSet.pinned",
			"RuleSet.unpinned",
			"SourceStatus.concern",
			"SourceStatus.errorsCount",
			"SourceStatus.examined",
			"SourceStatus.findingsCount",
			"SourceStatus.moduleName",
			"SourceStatus.outcome",
			"SourceStatus.passed",
			"SourceStatus.rules",
			"SourceStatus.scope",
			"SourceStatus.stage",
			"SourceStatus.tool",
			"SourceStatus.warningsCount",
			"TestCounts.durationMs",
			"TestCounts.failed",
			"TestCounts.passed",
			"TestCounts.skipped",
			"TestCounts.total",
			"ToolInfo.args",
			"ToolInfo.name",
			"ToolInfo.version",
		},
	},
}

// wireShape derives the shape that ships, by reflection over the structs
// themselves rather than over schema.json. Deriving it from the schema would
// make this test agree with the schema and say nothing about the bytes a
// module writes; the schema is held to the structs separately, by
// TestSchemaJSONPropertiesMatchStructTags.
//
// The walk is confined to structs declared in this package. That is what keeps
// time.Time out — reflecting into it would yield its unexported wall/ext/loc
// fields, which serialise as an RFC 3339 string and are not part of any
// consumer's view. A struct newly reached from Envelope is picked up with no
// change here, which is the property that makes this gate hold.
func wireShape() []string {
	pkg := reflect.TypeOf(evidence.Envelope{}).PkgPath()
	seen := map[reflect.Type]bool{}
	var out []string

	var walk func(reflect.Type)
	walk = func(ty reflect.Type) {
		for ty.Kind() == reflect.Pointer || ty.Kind() == reflect.Slice ||
			ty.Kind() == reflect.Array || ty.Kind() == reflect.Map {
			ty = ty.Elem()
		}
		if ty.Kind() != reflect.Struct || ty.PkgPath() != pkg || seen[ty] {
			return
		}
		seen[ty] = true
		for _, f := range goFieldsOf(ty) {
			out = append(out, ty.Name()+"."+f.name)
			walk(f.typ)
		}
	}

	walk(reflect.TypeOf(evidence.Envelope{}))
	sort.Strings(out)
	return out
}

type semver struct{ major, minor, patch int }

func parseSemver(s string) (semver, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return semver{}, fmt.Errorf("%q is not major.minor.patch", s)
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || (len(p) > 1 && p[0] == '0') {
			return semver{}, fmt.Errorf("%q has a non-numeric or non-canonical component %q", s, p)
		}
		out[i] = n
	}
	return semver{out[0], out[1], out[2]}, nil
}

func (v semver) less(o semver) bool {
	if v.major != o.major {
		return v.major < o.major
	}
	if v.minor != o.minor {
		return v.minor < o.minor
	}
	return v.patch < o.patch
}

// progressionProblems is the versioning policy, executable. It is a pure
// function over a table so the policy itself can be tested against fabricated
// histories; shapeHistory is then just one more input. A policy asserted only
// against the real table would be a policy no mutation can reach — every
// fabricated case below would have had to be a real schema change to write.
//
// The rules, and why each one is a rule:
//
//   - Every version parses as canonical major.minor.patch. A consumer that
//     compares versions has to parse them, and "1.1" or "01.1.0" makes two
//     parsers disagree about the same string.
//   - Versions ascend strictly. A history that goes backwards cannot answer
//     "is this envelope newer than the one I understand".
//   - A property may only disappear across a MAJOR bump. Removing a field a
//     consumer reads, under a version they were told was compatible, is the
//     original defect pointed the other way.
//   - A property may only appear across at least a MINOR bump. This is the
//     rule that was missing.
//   - A new version must change the shape. A version that moves while the
//     shape stands still teaches consumers that the number is noise, which is
//     how a number stops being consulted.
//
// A patch bump is therefore reachable only by a shape-neutral change, and the
// last rule then rejects it. That is intentional: this table describes shape,
// so within it a patch has nothing to say. It is not a claim that the envelope
// can never have a patch release — only that such a release does not appear
// here, and the error message says so rather than looking like a bug.
func progressionProblems(rows []shapeRow) []string {
	var problems []string
	report := func(f string, a ...any) { problems = append(problems, fmt.Sprintf(f, a...)) }

	if len(rows) == 0 {
		return []string{"the history is empty: at least the shipping version must be recorded"}
	}

	parsed := make([]semver, len(rows))
	for i, r := range rows {
		v, err := parseSemver(r.version)
		if err != nil {
			report("row %d: %v", i, err)
			continue
		}
		parsed[i] = v

		if !sort.StringsAreSorted(r.props) {
			report("row %d (%s): props are not sorted; keep them sorted so a diff shows the shape change", i, r.version)
		}
		for j := 1; j < len(r.props); j++ {
			if r.props[j] == r.props[j-1] {
				report("row %d (%s): %q is listed twice", i, r.version, r.props[j])
			}
		}
	}

	for i := 1; i < len(rows); i++ {
		prev, cur := rows[i-1], rows[i]
		pv, cv := parsed[i-1], parsed[i]

		if !pv.less(cv) {
			report("row %d: %s does not come after %s", i, cur.version, prev.version)
		}

		added, removed := diffSets(prev.props, cur.props)

		if len(added) == 0 && len(removed) == 0 {
			report("row %d: %s declares the same shape as %s; a version that moves while the shape stands still tells a consumer nothing",
				i, cur.version, prev.version)
			continue
		}
		if cv.major != pv.major {
			continue // a major bump may do anything to the shape.
		}
		if len(removed) > 0 {
			report("row %d: %s removes %v from %s without a major bump",
				i, cur.version, removed, prev.version)
		}
		if len(added) > 0 && cv.minor == pv.minor {
			report("row %d: %s adds %v to %s without a minor bump",
				i, cur.version, added, prev.version)
		}
	}

	return problems
}

// diffSets reports what cur gained and lost relative to prev.
func diffSets(prev, cur []string) (added, removed []string) {
	in := func(hay []string, needle string) bool {
		for _, h := range hay {
			if h == needle {
				return true
			}
		}
		return false
	}
	for _, c := range cur {
		if !in(prev, c) {
			added = append(added, c)
		}
	}
	for _, p := range prev {
		if !in(cur, p) {
			removed = append(removed, p)
		}
	}
	return added, removed
}

func TestTheDeclaredVersionIsTheLastRow(t *testing.T) {
	if len(shapeHistory) == 0 {
		t.Fatal("shapeHistory is empty")
	}
	last := shapeHistory[len(shapeHistory)-1]
	if last.version != evidence.SchemaVersion {
		t.Fatalf("SchemaVersion is %q but the newest shapeHistory row is %q.\n"+
			"Append a row for %q, or correct SchemaVersion — one of the two is behind.",
			evidence.SchemaVersion, last.version, evidence.SchemaVersion)
	}
}

// The gate. A field added to any struct the envelope reaches turns this red,
// and the only ways out are to append a row with a bumped version or to state,
// by editing the current row, that the version's meaning is being changed.
func TestTheDeclaredVersionDescribesTheShape(t *testing.T) {
	got := wireShape()
	want := shapeHistory[len(shapeHistory)-1].props

	added, removed := diffSets(want, got)
	if len(added) == 0 && len(removed) == 0 {
		return
	}

	var b strings.Builder
	fmt.Fprintf(&b, "the wire shape no longer matches what schemaVersion %s claims.\n", evidence.SchemaVersion)
	if len(added) > 0 {
		fmt.Fprintf(&b, "  new in the structs, absent from the history: %v\n", added)
		fmt.Fprintf(&b, "  -> this is an additive change: bump the MINOR of SchemaVersion and append a row.\n")
	}
	if len(removed) > 0 {
		fmt.Fprintf(&b, "  in the history, gone from the structs: %v\n", removed)
		fmt.Fprintf(&b, "  -> this removes something a consumer may read: bump the MAJOR of SchemaVersion and append a row.\n")
	}
	fmt.Fprintf(&b, "Remember `make sync-schema` and schema.json's const.\nThe shipping shape, ready to paste:\n")
	for _, p := range got {
		fmt.Fprintf(&b, "\t\t\t%q,\n", p)
	}
	t.Fatal(b.String())
}

func TestTheRealHistoryObeysThePolicy(t *testing.T) {
	if problems := progressionProblems(shapeHistory); len(problems) > 0 {
		t.Fatalf("shapeHistory violates the versioning policy:\n  %s", strings.Join(problems, "\n  "))
	}
}

// schema.json names the version it describes, so a consumer validating against
// a pinned copy of it is told when the copy is the wrong one. It carries
// additionalProperties:false, which means every additive field makes a pinned
// schema reject an envelope that is in fact valid — the version const is how
// that rejection reads as "fetch the newer schema" instead of "the producer is
// broken".
func TestSchemaJSONNamesTheVersionItDescribes(t *testing.T) {
	doc := loadSchema(t)
	def, ok := doc.Defs["evidence-envelope-v1"]
	if !ok {
		t.Fatal("schema.json has no evidence-envelope-v1 definition")
	}
	prop, ok := def.Properties["schemaVersion"]
	if !ok {
		t.Fatal("evidence-envelope-v1 declares no schemaVersion property")
	}
	if prop.Const != evidence.SchemaVersion {
		t.Fatalf("schema.json pins schemaVersion const to %q, the code ships %q",
			prop.Const, evidence.SchemaVersion)
	}
}

// The $defs key is major-versioned (evidence-envelope-v1). A minor bump must
// not move it, or every consumer's $ref breaks on a compatible change; a major
// bump must, which is the point of the name. Asserted so the next major does
// not quietly leave a v1 key describing a v2 envelope.
func TestTheDefinitionKeyTracksTheMajorVersion(t *testing.T) {
	v, err := parseSemver(evidence.SchemaVersion)
	if err != nil {
		t.Fatalf("SchemaVersion %q: %v", evidence.SchemaVersion, err)
	}
	want := fmt.Sprintf("evidence-envelope-v%d", v.major)
	doc := loadSchema(t)
	if _, ok := doc.Defs[want]; !ok {
		t.Fatalf("SchemaVersion is %q so schema.json should define %q; it defines %v",
			evidence.SchemaVersion, want, sortedKeys(doc.Defs))
	}
}

func sortedKeys(m map[string]schemaDefinition) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- the policy itself, against fabricated histories ---

func TestAnAddedPropertyWithoutAMinorBumpIsRejected(t *testing.T) {
	problems := progressionProblems([]shapeRow{
		{version: "1.1.0", props: []string{"Envelope.a"}},
		{version: "1.1.1", props: []string{"Envelope.a", "Envelope.b"}},
	})
	assertProblem(t, problems, "without a minor bump")
}

func TestARemovedPropertyWithoutAMajorBumpIsRejected(t *testing.T) {
	problems := progressionProblems([]shapeRow{
		{version: "1.1.0", props: []string{"Envelope.a", "Envelope.b"}},
		{version: "1.2.0", props: []string{"Envelope.a"}},
	})
	assertProblem(t, problems, "without a major bump")
}

func TestAMajorBumpMayRemoveAProperty(t *testing.T) {
	problems := progressionProblems([]shapeRow{
		{version: "1.1.0", props: []string{"Envelope.a", "Envelope.b"}},
		{version: "2.0.0", props: []string{"Envelope.a"}},
	})
	assertNoProblems(t, problems)
}

func TestAMinorBumpMayAddAProperty(t *testing.T) {
	problems := progressionProblems([]shapeRow{
		{version: "1.1.0", props: []string{"Envelope.a"}},
		{version: "1.2.0", props: []string{"Envelope.a", "Envelope.b"}},
	})
	assertNoProblems(t, problems)
}

func TestAVersionThatDoesNotAscendIsRejected(t *testing.T) {
	problems := progressionProblems([]shapeRow{
		{version: "1.2.0", props: []string{"Envelope.a", "Envelope.b"}},
		{version: "1.1.0", props: []string{"Envelope.a"}},
	})
	assertProblem(t, problems, "does not come after")
}

func TestANewVersionWithAnUnchangedShapeIsRejected(t *testing.T) {
	problems := progressionProblems([]shapeRow{
		{version: "1.1.0", props: []string{"Envelope.a"}},
		{version: "1.2.0", props: []string{"Envelope.a"}},
	})
	assertProblem(t, problems, "same shape")
}

func TestANonSemverVersionIsRejected(t *testing.T) {
	for _, bad := range []string{"1.1", "v1.1.0", "1.1.0-rc1", "01.1.0", "1.1.x"} {
		problems := progressionProblems([]shapeRow{{version: bad, props: []string{"Envelope.a"}}})
		if len(problems) == 0 {
			t.Errorf("version %q was accepted", bad)
		}
	}
}

func TestAnUnsortedRowIsRejected(t *testing.T) {
	problems := progressionProblems([]shapeRow{
		{version: "1.1.0", props: []string{"Envelope.b", "Envelope.a"}},
	})
	assertProblem(t, problems, "not sorted")
}

func TestADuplicatedPropertyIsRejected(t *testing.T) {
	problems := progressionProblems([]shapeRow{
		{version: "1.1.0", props: []string{"Envelope.a", "Envelope.a"}},
	})
	assertProblem(t, problems, "listed twice")
}

func TestAnEmptyHistoryIsRejected(t *testing.T) {
	assertProblem(t, progressionProblems(nil), "history is empty")
}

// wireShape must reach nested structs, not just Envelope's own fields. Scope
// was added to SourceStatus and a walker that stopped at the top level would
// have let it through — the exact miss this gate exists to prevent.
func TestWireShapeReachesNestedStructs(t *testing.T) {
	got := wireShape()
	for _, want := range []string{
		"SourceStatus.scope", "TestCounts.total", "Finding.rule",
		"RepoContext.commitSha", "ToolInfo.name",
	} {
		if !containsString(got, want) {
			t.Errorf("wireShape() omits %q", want)
		}
	}
}

// time.Time serialises as one RFC 3339 string. Its unexported wall/ext/loc
// fields are not part of any consumer's view, and a walker that reflected into
// them would put three phantom properties under every timestamp.
func TestWireShapeDoesNotReachIntoStdlibStructs(t *testing.T) {
	for _, p := range wireShape() {
		if strings.HasPrefix(p, "Time.") {
			t.Errorf("wireShape() reflected into time.Time: %q", p)
		}
	}
	if !containsString(wireShape(), "Envelope.timestampUtc") {
		t.Error("wireShape() lost the timestamp property itself")
	}
}

func containsString(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func assertProblem(t *testing.T, problems []string, want string) {
	t.Helper()
	for _, p := range problems {
		if strings.Contains(p, want) {
			return
		}
	}
	t.Fatalf("no problem mentioning %q; got %v", want, problems)
}

func assertNoProblems(t *testing.T, problems []string) {
	t.Helper()
	if len(problems) > 0 {
		t.Fatalf("expected no problems, got %v", problems)
	}
}
