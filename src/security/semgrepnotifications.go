// Semgrep's own account of what it could NOT do: the files it could not parse
// and the rules that timed out, read from the SARIF cicd already receives.
//
// Deliberately untagged (no //go:build !unit_test): this is JSON reading,
// string matching and message construction, none of which needs Dagger, so
// semgrepnotifications_test.go can drive it under `go test -tags unit_test`.
//
// Why this file exists. Semgrep OSS emits one entry in
// runs[0].invocations[0].toolExecutionNotifications for every file its parser
// rejected ("Syntax error") and for every rule that exceeded its per-file time
// budget ("Timeout"). Both are level "warning"; semgrep exits 0; the results
// array is well-formed. Nothing here read the notifications, so a repository
// whose C# the parser cannot handle — measured on a C# 12 tree of a few hundred files,
// where nearly every file drew a "Syntax error" notification and a handful
// drew a "Timeout" beside a dozen-odd findings — produced a semgrep row reading
// `FINDINGS, N, errors 0, warnings 0`. Partial
// coverage rendered as full coverage, on the one scanner whose question is
// "did anyone read this code".
//
// Measured against the pinned image (semgrep/semgrep:1.161.0), not recalled:
//
//	{"descriptor":{"id":"Syntax error"},"level":"warning",
//	 "message":{"text":"Syntax error at line Primary.cs:3:\n `(int x)` was unexpected"}}
//	{"descriptor":{"id":"Timeout"},"level":"warning",
//	 "message":{"text":"Timeout when running work.cs-string-concat on Slow.cs:\n "}}
//
// Neither carries a `locations` array. The path lives only in message.text, so
// it is read from there, and a `locations[0]` uri is accepted as the fallback
// in case a later semgrep adds one. A notification that names no file in
// either place is still counted — as an unattributed failure — because "cicd
// could not tell which file" must never decay into "no file failed".
//
// Two facts from the same measurement shape the wording. Semgrep parses
// PARTIALLY: Primary.cs, whose primary-constructor header it rejected, still
// yielded a finding from its method body, so "those files received zero
// findings" would be an overclaim — their findings are a floor. And a file
// semgrep dropped for its size limit appears NOWHERE in the SARIF, only in the
// JSON output's paths.skipped, so this file reports what the SARIF says and
// does not claim to have seen every skip.
package main

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The two descriptor ids semgrep uses for the partial-work cases this file
// classifies. Anything else is bucketed by level, never guessed at.
const (
	semgrepNoticeSyntax  = "Syntax error"
	semgrepNoticeTimeout = "Timeout"
)

// semgrepNoticeListCap is how many names a warning spells out before "and N
// more". Five: enough to recognise the pattern (one directory, one
// language), few enough that a several-hundred-file list does not become the whole PR
// comment.
const semgrepNoticeListCap = 5

var (
	// "Syntax error at line <path>:<line>:\n <detail>". Greedy path so a colon
	// inside a path cannot truncate it; the last ":<digits>:" on the first line
	// is the location.
	semgrepSyntaxRe = regexp.MustCompile(`^Syntax error at line (.+):(\d+):`)
	// "Timeout when running <rule> on <path>:\n " — note the trailing colon
	// semgrep leaves after the path.
	semgrepTimeoutRe = regexp.MustCompile(`^Timeout when running (\S+) on (.+?):?\s*$`)
)

// semgrepNotices is one SARIF document's notifications, classified.
//
// Files are DISTINCT and in first-seen order; the plain counts are
// notification counts. Three syntax errors in one file are one unparsed file
// and three notifications, and both numbers are stated because they answer
// different questions ("how much of my tree" versus "how broken is this
// file").
type semgrepNotices struct {
	// ParseFailures is the number of "Syntax error" notifications.
	ParseFailures int
	// UnparsedFiles is every distinct path a "Syntax error" named.
	UnparsedFiles []string
	// UnattributedParseFailures counts "Syntax error" notifications that named
	// no file anywhere cicd knows to look. Counted, never dropped.
	UnattributedParseFailures int
	// FirstParserMessage is the first notification's "<path>:<line> <detail>",
	// whitespace collapsed — the one sentence that tells a reader WHERE the
	// parser gave up. The source semgrep quotes in the detail is withheld
	// (semgrepredact.go): it can be the whole line, credential included.
	FirstParserMessage string

	// Timeouts is the number of "Timeout" notifications, i.e. (rule, file)
	// pairs semgrep gave up on.
	Timeouts int
	// TimedOutFiles and TimedOutRules are the distinct files and rules those
	// pairs named.
	TimedOutFiles []string
	TimedOutRules []string
	// UnattributedTimeouts counts "Timeout" notifications naming no file.
	UnattributedTimeouts int

	// ErrorLevel holds the descriptor ids of every OTHER notification semgrep
	// marked level "error" — a shape this module has not measured and so
	// names rather than interprets.
	ErrorLevel []string
	// Unclassified holds the descriptor ids ("unnamed" when there is none) of
	// every remaining notification. A notification cicd could not classify is
	// still a notification: semgrep said something did not go to plan.
	Unclassified []string
}

// any reports whether semgrep said anything at all.
func (n semgrepNotices) any() bool {
	return n.ParseFailures > 0 || n.Timeouts > 0 ||
		len(n.ErrorLevel) > 0 || len(n.Unclassified) > 0
}

// sarifNotification is the subset of a SARIF toolExecutionNotification
// (SARIF 2.1.0 §3.58) this file reads. Every field is optional in the spec
// and treated as optional here — a missing descriptor is data, not a panic.
type sarifNotification struct {
	Descriptor *struct {
		ID string `json:"id"`
	} `json:"descriptor"`
	Level   string `json:"level"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
		} `json:"physicalLocation"`
	} `json:"locations"`
}

type sarifInvocationsDoc struct {
	Runs []struct {
		Invocations []struct {
			ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications"`
		} `json:"invocations"`
	} `json:"runs"`
}

// parseSemgrepNotifications reads every toolExecutionNotification in the
// document and classifies it. A document that is not JSON, has no runs, no
// invocations or no notifications yields the zero value — which is exactly
// "semgrep reported nothing it could not do", and is the clean-tree case.
//
// It never returns an error: the SARIF has already been accepted by
// semgrepRunError as the scan's report, so an unreadable notifications array
// is a reporting gap in a scan that ran, not a reason to fail the scan.
func parseSemgrepNotifications(raw json.RawMessage) semgrepNotices {
	var n semgrepNotices
	var doc sarifInvocationsDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return n
	}
	seenFile := map[string]bool{}
	seenTimedFile := map[string]bool{}
	seenRule := map[string]bool{}
	for _, run := range doc.Runs {
		for _, inv := range run.Invocations {
			for _, note := range inv.ToolExecutionNotifications {
				id := ""
				if note.Descriptor != nil {
					id = note.Descriptor.ID
				}
				switch {
				case id == semgrepNoticeSyntax:
					n.ParseFailures++
					file, line, detail := semgrepSyntaxLocation(note)
					if file == "" {
						n.UnattributedParseFailures++
						continue
					}
					if !seenFile[file] {
						seenFile[file] = true
						n.UnparsedFiles = append(n.UnparsedFiles, file)
					}
					if n.FirstParserMessage == "" {
						where := file
						if line != "" {
							where += ":" + line
						}
						n.FirstParserMessage = strings.TrimSpace(where + " " + detail)
					}
				case id == semgrepNoticeTimeout:
					n.Timeouts++
					rule, file := semgrepTimeoutSubject(note)
					if rule != "" && !seenRule[rule] {
						seenRule[rule] = true
						n.TimedOutRules = append(n.TimedOutRules, rule)
					}
					if file == "" {
						n.UnattributedTimeouts++
						continue
					}
					if !seenTimedFile[file] {
						seenTimedFile[file] = true
						n.TimedOutFiles = append(n.TimedOutFiles, file)
					}
				case strings.EqualFold(note.Level, "error"):
					n.ErrorLevel = append(n.ErrorLevel, orUnnamed(id))
				default:
					n.Unclassified = append(n.Unclassified, orUnnamed(id))
				}
			}
		}
	}
	return n
}

func orUnnamed(id string) string {
	if id == "" {
		return "unnamed"
	}
	return id
}

// semgrepSyntaxLocation reads path, line and the parser's detail from a
// "Syntax error" notification: the message first, a SARIF location second.
// Returns "" for the path when neither says.
func semgrepSyntaxLocation(note sarifNotification) (file, line, detail string) {
	text := note.Message.Text
	first, rest, _ := strings.Cut(text, "\n")
	// The detail is withheld here as well as in redactSemgrepSARIF, which has
	// already rewritten every report this module reads: the warning is built
	// from it, and a second caller must not be the one that forgets.
	if m := semgrepSyntaxRe.FindStringSubmatch(first); m != nil {
		return strings.TrimSpace(m[1]), m[2], collapseSpace(withholdSemgrepQuotedSource(rest))
	}
	if uri := firstLocationURI(note); uri != "" {
		return uri, "", collapseSpace(withholdSemgrepQuotedSource(text))
	}
	return "", "", ""
}

// semgrepTimeoutSubject reads the rule and path a "Timeout" notification
// names. Either may come back "" when the message has a shape this module has
// not seen and no location is attached.
func semgrepTimeoutSubject(note sarifNotification) (rule, file string) {
	first, _, _ := strings.Cut(note.Message.Text, "\n")
	if m := semgrepTimeoutRe.FindStringSubmatch(strings.TrimSpace(first)); m != nil {
		return m[1], strings.TrimSpace(m[2])
	}
	return "", firstLocationURI(note)
}

func firstLocationURI(note sarifNotification) string {
	for _, loc := range note.Locations {
		if uri := strings.TrimSpace(loc.PhysicalLocation.ArtifactLocation.URI); uri != "" {
			return uri
		}
	}
	return ""
}

// collapseSpace folds every run of whitespace, newlines included, into one
// space. notify renders each warnings[] entry as one markdown list item, and an
// embedded newline breaks the item.
func collapseSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// semgrepNotificationWarnings is the envelope-facing entry point: zero
// warnings for a document in which semgrep reported nothing it could not do,
// one warning otherwise. Zero, not an empty disclosure — a "semgrep parsed
// everything" line on every clean run is noise the next real one drowns in.
func semgrepNotificationWarnings(raw json.RawMessage) []string {
	n := parseSemgrepNotifications(raw)
	if !n.any() {
		return nil
	}
	return []string{semgrepPartialScanWarning(n)}
}

// semgrepPartialScanWarning renders the classified notifications as ONE line.
//
// Every clause is load-bearing. The counts and the capped file list say how
// much of the tree this concerns; the language split says whether it is one
// parser or many; the "floor, not a verdict" sentence says what the reader
// must not conclude from the finding count; the first parser message names the
// file and line where the parser broke, because that is the only thing a
// consumer can act on (the construct itself is withheld: semgrep quotes it
// from the source, see semgrepredact.go);
// and the remedy is stated as far as cicd knows it. A warning a consumer
// cannot act on gets scrolled past, and this one is deliberately the opposite
// of an error — see the spec for why a C# 12 repository must not go
// permanently red over a parser it does not control.
func semgrepPartialScanWarning(n semgrepNotices) string {
	var parts []string

	if n.ParseFailures > 0 {
		s := strconv.Itoa(len(n.UnparsedFiles)) + " file(s) could not be fully parsed"
		if len(n.UnparsedFiles) > 0 {
			s += " (" + languageSplit(n.UnparsedFiles) + " — " +
				listCapped(n.UnparsedFiles, semgrepNoticeListCap) + ")"
		}
		if n.ParseFailures != len(n.UnparsedFiles) {
			s += " across " + strconv.Itoa(n.ParseFailures) + " syntax error(s)"
		}
		if n.UnattributedParseFailures > 0 {
			s += ", " + strconv.Itoa(n.UnattributedParseFailures) +
				" of which named no file cicd could read"
		}
		parts = append(parts, s)
	}

	if n.Timeouts > 0 {
		s := strconv.Itoa(n.Timeouts) + " rule timeout(s) hit " +
			strconv.Itoa(len(n.TimedOutFiles)) + " file(s)"
		var detail []string
		if len(n.TimedOutFiles) > 0 {
			detail = append(detail, listCapped(n.TimedOutFiles, semgrepNoticeListCap))
		}
		if len(n.TimedOutRules) > 0 {
			detail = append(detail, "rules: "+listCapped(n.TimedOutRules, semgrepNoticeListCap))
		}
		if len(detail) > 0 {
			s += " (" + strings.Join(detail, "; ") + ")"
		}
		if n.UnattributedTimeouts > 0 {
			s += ", " + strconv.Itoa(n.UnattributedTimeouts) + " naming no file"
		}
		parts = append(parts, s)
	}

	if len(n.ErrorLevel) > 0 {
		parts = append(parts, strconv.Itoa(len(n.ErrorLevel))+
			" error-level notification(s) semgrep raised (id(s): "+
			listCapped(distinct(n.ErrorLevel), semgrepNoticeListCap)+")")
	}
	if len(n.Unclassified) > 0 {
		parts = append(parts, strconv.Itoa(len(n.Unclassified))+
			" notification(s) cicd could not classify (id(s): "+
			listCapped(distinct(n.Unclassified), semgrepNoticeListCap)+")")
	}

	msg := "semgrep: PARTIAL SCAN — " + strings.Join(parts, ", and ") + "."

	if n.ParseFailures > 0 || n.Timeouts > 0 {
		msg += " Semgrep matches nothing in a region it could not parse and nothing for a rule " +
			"that timed out, so those files' findings are a floor, not a verdict, and zero " +
			"findings there is not a clean one."
	}
	if n.FirstParserMessage != "" {
		msg += " First parser message: " + n.FirstParserMessage + "."
	}
	if n.ParseFailures > 0 {
		msg += " Semgrep OSS " + semgrepVersion + " skips what its parser rejects; a newer " +
			"semgrep or the Pro engine may accept the construct at the line it names"
		if hasLanguage(n.UnparsedFiles, "C#") {
			msg += " (its C# parser rejects C# 12 primary constructors, measured)"
		}
		msg += "."
	}
	return msg
}

// languageSplit renders "C#: 240, TypeScript: 1" from the files' extensions —
// most files first, then by name, so the parser that matters leads.
func languageSplit(files []string) string {
	counts := map[string]int{}
	for _, f := range files {
		counts[languageOfPath(f)]++
	}
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if counts[names[i]] != counts[names[j]] {
			return counts[names[i]] > counts[names[j]]
		}
		return names[i] < names[j]
	})
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, name+": "+strconv.Itoa(counts[name]))
	}
	return strings.Join(out, ", ")
}

func hasLanguage(files []string, language string) bool {
	for _, f := range files {
		if languageOfPath(f) == language {
			return true
		}
	}
	return false
}

// extensionLanguages names the language a file extension implies, in the
// words a consumer uses. An extension not listed is reported as itself
// (".foo") rather than mapped to a guess: the point of the split is to say
// which PARSER failed, and a wrong name is worse than a raw extension.
var extensionLanguages = map[string]string{
	".cs": "C#", ".go": "Go", ".py": "Python",
	".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
	".ts": "TypeScript", ".tsx": "TypeScript",
	".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin", ".scala": "Scala",
	".rb": "Ruby", ".php": "PHP", ".rs": "Rust", ".swift": "Swift", ".dart": "Dart",
	".c": "C", ".h": "C", ".cpp": "C++", ".cc": "C++", ".hpp": "C++",
	".tf": "Terraform", ".yaml": "YAML", ".yml": "YAML", ".json": "JSON",
	".sh": "Shell", ".bash": "Shell", ".html": "HTML", ".vue": "Vue",
	".ex": "Elixir", ".exs": "Elixir", ".lua": "Lua", ".sol": "Solidity", ".ml": "OCaml",
}

func languageOfPath(p string) string {
	base := p
	if i := strings.LastIndexAny(base, "/\\"); i >= 0 {
		base = base[i+1:]
	}
	if strings.EqualFold(base, "Dockerfile") || strings.HasPrefix(base, "Dockerfile.") {
		return "Dockerfile"
	}
	dot := strings.LastIndex(base, ".")
	if dot < 0 || dot == len(base)-1 {
		return "no extension"
	}
	ext := strings.ToLower(base[dot:])
	if name, ok := extensionLanguages[ext]; ok {
		return name
	}
	return ext
}

// listCapped spells out the first `cap` names and counts the rest, so a
// several-hundred-file list is a recognisable sample and a number rather than the whole
// PR comment. Names are quoted by nothing here: notify fences them.
func listCapped(in []string, cap int) string {
	if len(in) <= cap {
		return strings.Join(in, ", ")
	}
	return strings.Join(in[:cap], ", ") + ", and " + strconv.Itoa(len(in)-cap) + " more"
}

func distinct(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
