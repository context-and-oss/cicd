package main

// The bundle, re-indexed by the question a reader is asking.
//
// parts/ is organised by producing module because that is how the pipeline is
// built. Nobody receiving a report asks it that way. "What about SAST?" is
// answered by one row inside parts/03-security.json, next to two rows that
// answer entirely different questions, and the reader has to know that Semgrep
// lives in the same envelope as Trivy and Gitleaks to find it. That is pipeline
// trivia, and it is the last thing standing between this bundle and a report
// somebody can send to a customer.
//
// concerns/ holds POINTERS, not copies. Each row names the part file its
// evidence lives in and restates only the counts a reader scans; the findings
// themselves stay in findings.sarif and in the verbatim envelope under parts/.
// Copying them would double the bundle's largest documents to say nothing new,
// and it would create a second copy that can disagree with the first.

// concernOrder is the order a report reads, not alphabetical and not the order
// the modules happen to run in.
//
// It is fixed here so two runs of the same pipeline produce byte-identical
// indexes, which is what makes a diff between two bundles meaningful. Sorting
// by findings count or by outcome would reorder the document every time a
// scanner found something, and a reader comparing last week's report to this
// week's would see the whole file move.
var concernOrder = []Concern{
	ConcernSAST,
	ConcernSCA,
	ConcernSecrets,
	ConcernLicenses,
	ConcernSBOM,
	ConcernIaC,
	ConcernDAST,
	ConcernLint,
	ConcernTests,
	ConcernCoverage,
}

// unclassifiedFile holds the rows whose producer declared no concern.
//
// They are collected rather than dropped. A row with no concern is a producer
// that has not been converted — or a tool somebody added without saying what
// question it answers — and either way the honest report of it is "this ran and
// we cannot file it", not silence. Dropping it would shorten the run by exactly
// the rows nobody is watching.
const unclassifiedFile = "unclassified.json"

// concernRow is one tool's contribution to one concern, and where to read the
// rest of it.
//
// Part is the pointer that makes this a index rather than a duplicate. It names
// a file in parts/, so a reader who wants the SARIF, the args, the timestamps
// or anything else this row omits has one hop to make and does not have to
// guess which module produced what.
type concernRow struct {
	Part          string    `json:"part"`
	ModuleName    string    `json:"moduleName"`
	Stage         string    `json:"stage,omitempty"`
	Tool          string    `json:"tool,omitempty"`
	Scope         string    `json:"scope,omitempty"`
	Passed        bool      `json:"passed"`
	Outcome       Outcome   `json:"outcome,omitempty"`
	Examined      *Examined `json:"examined,omitempty"`
	FindingsCount int       `json:"findingsCount"`
	ErrorsCount   int       `json:"errorsCount"`
	WarningsCount int       `json:"warningsCount"`
}

// concernSummary is the whole answer to one question, and the file
// concerns/<concern>.json contains.
type concernSummary struct {
	// Concern is absent in unclassified.json, which is the one summary that
	// names no concern because its rows named none.
	Concern       Concern      `json:"concern,omitempty"`
	Passed        bool         `json:"passed"`
	Outcome       Outcome      `json:"outcome,omitempty"`
	Examined      *Examined    `json:"examined,omitempty"`
	FindingsCount int          `json:"findingsCount"`
	ErrorsCount   int          `json:"errorsCount"`
	WarningsCount int          `json:"warningsCount"`
	Tools         []concernRow `json:"tools"`
}

// concernEntry is one row of concerns/index.json: what a concern file is and
// what it said, so a reader can scan the run without opening ten documents.
//
// It embeds ConcernRollup rather than restating its fields, so the index and
// the combined envelope's concerns block cannot drift into saying different
// things about the same concern. The only thing this adds is where to read the
// rest, which is the one fact the envelope's copy cannot carry — a consumer
// holding combined-evidence.json alone has no bundle to point into.
type concernEntry struct {
	File string `json:"file"`
	ConcernRollup
}

// concernIndex is concerns/index.json.
//
// NotAnswered is the field that stops this directory from becoming the failure
// class it was built to fix. A reader handed seven concern files can see which
// seven are there; they cannot see that ten exist, so "no SAST file" reads
// identically to "no SAST problem". Listing the unanswered ones supplies the
// denominator.
//
// It is deliberately NOT a verdict, and the name says so. This module cannot
// know which concerns a given pipeline OUGHT to answer: a repository with no
// infrastructure has no IaC leg and is not missing one, and a service with no
// deployed endpoint has no DAST leg and is not missing one. Calling those
// absences defects would be inventing a denominator, which is the same sin one
// level up. So the document states the two things it actually knows — these
// questions exist, this run answered these — and leaves the judgement to the
// reader who knows the project.
type concernIndex struct {
	Concerns    []concernEntry `json:"concerns"`
	NotAnswered []Concern      `json:"notAnswered"`
}

// buildConcerns re-indexes the run by concern. names must be partFileName's
// output for envs, index for index — the same pairing buildPartsIndex takes.
//
// Rows arrive through envelopeRows, the same function the combined envelope
// uses, so a fused module contributes its per-tool rows here exactly as it does
// there. Deriving them separately is how the two documents would come to
// disagree about how many tools ran.
func buildConcerns(envs []*envelope, names []string) (map[string]concernSummary, concernIndex) {
	byConcern := concernRows(envs, names)

	files := map[string]concernSummary{}
	idx := concernIndex{Concerns: []concernEntry{}, NotAnswered: []Concern{}}
	for _, c := range concernOrder {
		rows := byConcern[c]
		if len(rows) == 0 {
			// No file. An empty concerns/sast.json would be a document
			// asserting that SAST ran and reported nothing, which is the exact
			// claim a pipeline without a SAST leg must not make. The concern is
			// named in NotAnswered instead, where it carries no verdict.
			idx.NotAnswered = append(idx.NotAnswered, c)
			continue
		}
		sum := summariseConcern(c, rows)
		file := string(c) + ".json"
		files[file] = sum
		idx.Concerns = append(idx.Concerns, entryFor(file, sum))
	}
	if rows := byConcern[""]; len(rows) > 0 {
		sum := summariseConcern("", rows)
		files[unclassifiedFile] = sum
		idx.Concerns = append(idx.Concerns, entryFor(unclassifiedFile, sum))
	}
	return files, idx
}

func entryFor(file string, sum concernSummary) concernEntry {
	return concernEntry{
		File:          concernsDirName + "/" + file,
		ConcernRollup: sum.rollup(),
	}
}

// summariseConcern folds one concern's rows into the verdict its file reports.
//
// Passed is the AND and Outcome is worstOutcome, the same two rules the
// combined envelope uses — a concern is a subset of the same rows, so any other
// fold here would let concerns/ and combined-evidence.json disagree about the
// same run.
func summariseConcern(c Concern, rows []concernRow) concernSummary {
	sum := concernSummary{Concern: c, Passed: true, Tools: rows}
	outcomes := make([]Outcome, 0, len(rows))
	for _, r := range rows {
		sum.Passed = sum.Passed && r.Passed
		sum.FindingsCount += r.FindingsCount
		sum.ErrorsCount += r.ErrorsCount
		sum.WarningsCount += r.WarningsCount
		outcomes = append(outcomes, r.Outcome)
	}
	sum.Outcome = worstOutcome(outcomes)
	sum.Examined = foldExamined(rows)
	return sum
}

// foldExamined sums a concern's denominators, and refuses to when the sum would
// not mean anything.
//
// Two conditions have to hold. Every row must count in the SAME unit —
// "coverable lines" plus "resolved packages" is a number about nothing, and it
// would be printed under a heading that implies it is a real total. And every
// row must state one: a sum over the three scanners that answered, presented as
// the concern's denominator, understates it by however much the silent fourth
// looked at, and an understated denominator makes the findings look better
// proportionally than they are. Either way the answer is to say nothing, which
// examinedCell already renders as "not stated".
//
// Total is not folded. A total is a claim about what existed in scope, and two
// tools' scopes overlap in ways this layer cannot see; summing them would
// manufacture a ceiling no tool reported.
func foldExamined(rows []concernRow) *Examined {
	if len(rows) == 0 {
		return nil
	}
	unit := ""
	n := 0
	for i, r := range rows {
		if r.Examined == nil {
			return nil
		}
		if i == 0 {
			unit = r.Examined.Unit
		} else if r.Examined.Unit != unit {
			return nil
		}
		n += r.Examined.Count
	}
	if unit == "" {
		// A count with no unit cannot be reported; see Examined's own
		// contract. Folding several of them would only multiply the problem.
		return nil
	}
	return &Examined{Unit: unit, Count: n}
}

// concernRows gathers every row in the run under the concern its producer
// declared.
//
// Rows arrive through envelopeRows, the same function the combined envelope
// uses, so a fused module contributes its per-tool rows here exactly as it
// does there. Gathering them separately is how the two documents would come to
// disagree about how many tools ran.
//
// names is partFileName's output for envs, index for index, and may be nil.
// Nil means the caller is folding for a consumer that has no bundle to point
// into — the combined envelope's concerns block — and Part is left empty
// rather than filled with a path to a file that consumer cannot open.
func concernRows(envs []*envelope, names []string) map[Concern][]concernRow {
	byConcern := map[Concern][]concernRow{}
	for i, e := range envs {
		part := ""
		if names != nil {
			part = partsDirName + "/" + names[i]
		}
		for _, s := range envelopeRows(e) {
			byConcern[s.Concern] = append(byConcern[s.Concern], concernRow{
				Part:          part,
				ModuleName:    s.ModuleName,
				Stage:         s.Stage,
				Tool:          s.Tool,
				Scope:         s.Scope,
				Passed:        s.Passed,
				Outcome:       s.Outcome,
				Examined:      s.Examined,
				FindingsCount: s.FindingsCount,
				ErrorsCount:   s.ErrorsCount,
				WarningsCount: s.WarningsCount,
			})
		}
	}
	return byConcern
}

// concernReport folds the run by concern for a consumer holding nothing but
// combined-evidence.json.
//
// It walks concernOrder and calls summariseConcern, exactly as buildConcerns
// does, because notify's table and the bundle's concerns/ directory are read
// side by side by the same person. A second fold written for the consumer
// would eventually disagree with the first, and the disagreement would be
// invisible: two documents from one run, both internally consistent, saying
// different things about SCA with nothing anywhere failing.
//
// Always non-nil for a run that was aggregated at all, including a run whose
// producers declared nothing. That case is an empty Answered beside a
// NotAnswered naming all ten, which is the honest report of it — nil would say
// "nobody folded this", which would be untrue.
func concernReport(envs []*envelope) *ConcernReport {
	byConcern := concernRows(envs, nil)
	rep := &ConcernReport{Answered: []ConcernRollup{}, NotAnswered: []Concern{}}
	for _, c := range concernOrder {
		rows := byConcern[c]
		if len(rows) == 0 {
			rep.NotAnswered = append(rep.NotAnswered, c)
			continue
		}
		rep.Answered = append(rep.Answered, summariseConcern(c, rows).rollup())
	}
	if rows := byConcern[""]; len(rows) > 0 {
		// The unclassified group is answered, not unanswered: those tools
		// ran and reported. Filing them under NotAnswered would hide a
		// converted-but-untagged producer behind a list that reads as
		// "these legs are absent".
		rep.Answered = append(rep.Answered, summariseConcern("", rows).rollup())
	}
	return rep
}

// rollup drops the rows and keeps the verdict, for the copy that travels in
// the combined envelope. See ConcernRollup for why the rows do not travel.
func (s concernSummary) rollup() ConcernRollup {
	return ConcernRollup{
		Concern:       s.Concern,
		Passed:        s.Passed,
		Outcome:       s.Outcome,
		Examined:      s.Examined,
		FindingsCount: s.FindingsCount,
		ErrorsCount:   s.ErrorsCount,
		WarningsCount: s.WarningsCount,
		Tools:         len(s.Tools),
	}
}
