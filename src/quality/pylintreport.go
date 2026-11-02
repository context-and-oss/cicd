// pylint report parsing.
//
// Deliberately untagged (no //go:build !unit_test): none of this needs Dagger,
// so `go test -tags unit_test` reaches it. It lives here rather than in lint.go
// — which is container code — for the same reason eslintreport.go and
// dotnetreport.go do: the bytes a consumer reads out of the evidence envelope
// are decided here, so they have to be assertable without a Dagger session.

package main

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// pylintReport is pylint's json2 document. json2 rather than json because it
// carries the file path of every message (json carried only the dotted module
// name, which is not a location a SARIF consumer can open) and because it is
// one object, not a bare array, so a report that stopped half-way cannot read
// as a short list.
type pylintReport struct {
	Messages *[]pylintMessage `json:"messages"`
}

type pylintMessage struct {
	Type    string `json:"type"` // fatal, error, warning, convention, refactor, info
	Symbol  string `json:"symbol"`
	Path    string `json:"path"`
	Message string `json:"message"`
	Line    int    `json:"line"`
	MsgID   string `json:"messageId"`
}

// pylintFatalLimit caps how many unreadable files an error names.
const pylintFatalLimit = 5

// parsePylintJSON reads a json2 report. A `fatal` message is pylint saying it
// could not read a file — F0010 parse-error is what `pylint .` printed for a
// flat tree with no __init__.py at its root, and it was counted as one HIGH
// finding, so a lint that read nothing failed the gate as if it had found a
// bug, and passed at --fail-on NONE as if it had run. Fatal messages are
// therefore returned as unread paths, never as findings.
func parsePylintJSON(data []byte) (json.RawMessage, map[Severity]int, []string) {
	var rep pylintReport
	if err := json.Unmarshal(data, &rep); err != nil || rep.Messages == nil {
		return nil, nil, nil
	}

	counts := map[Severity]int{}
	var findings []pylintMessage
	unread := map[string]bool{}
	for _, m := range *rep.Messages {
		switch m.Type {
		case "fatal":
			unread[m.Path] = true
			continue
		case "error":
			counts[SeverityHigh]++
		case "warning":
			counts[SeverityMedium]++
		default:
			counts[SeverityLow]++
		}
		findings = append(findings, m)
	}

	sarif := buildPylintSarif(findings)
	raw, _ := json.Marshal(sarif)
	paths := make([]string, 0, len(unread))
	for p := range unread {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return json.RawMessage(raw), counts, paths
}

func buildPylintSarif(msgs []pylintMessage) map[string]any {
	var results []map[string]any
	for _, m := range msgs {
		level := "note"
		switch m.Type {
		case "error":
			level = "error"
		case "warning":
			level = "warning"
		}
		results = append(results, map[string]any{
			"ruleId":  m.MsgID,
			"level":   level,
			"message": map[string]any{"text": m.Message},
			"locations": []map[string]any{{
				"physicalLocation": map[string]any{
					"artifactLocation": map[string]any{"uri": m.Path},
					"region":           map[string]any{"startLine": m.Line},
				},
			}},
		})
	}
	return singleRunSARIF("pylint", pylintVersion, results)
}

// emptySARIF stands in for a report pylint did not produce, so the envelope
// still carries a valid SARIF document. It is never the evidence of a clean
// run: every path that returns it also returns an error.
var emptySARIF = json.RawMessage(`{"version":"2.1.0","runs":[]}`)

// foldPylintRun turns pylint's stdout into the leg's result. pylint runs with
// --exit-zero, so a lint finding never makes the exec fail: an error here is
// pip or pylint itself failing, and the run is a non-run even when it left some
// stdout behind. A clean run prints a json2 object with an empty messages
// array, so stdout that is empty, not an object, or missing that array is a
// report that never arrived. Both used to be substituted with an empty SARIF
// and no error, which read as a clean lint.
//
// targets is how many files cicd handed pylint (pylinttargets.go). It becomes
// Examined only when every one of them was read: pylint's own modulesLinted
// is not a file count (measured on 3.1.0, an empty directory reports 2 and
// eight files report 10), so the denominator is cicd's.
func foldPylintRun(out string, err error, targets int) (json.RawMessage, map[Severity]int, *Examined, []string) {
	if err != nil {
		return emptySARIF, nil, nil, []string{"pylint: " + err.Error()}
	}
	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		return emptySARIF, nil, nil, []string{"pylint: exited 0 but wrote no report"}
	}
	if !strings.HasPrefix(trimmed, "{") {
		return emptySARIF, nil, nil, []string{"pylint: exited 0 but its report is not pylint JSON"}
	}
	sarifRaw, bySeverity, unread := parsePylintJSON([]byte(trimmed))
	if sarifRaw == nil {
		return emptySARIF, nil, nil, []string{"pylint: exited 0 but its report is not pylint JSON"}
	}
	if len(unread) > 0 {
		return sarifRaw, bySeverity, nil, []string{"pylint: could not read " + strconv.Itoa(len(unread)) +
			" of " + strconv.Itoa(targets) + " file(s) it was given (" +
			capPaths(unread, pylintFatalLimit) +
			"), so their findings are unknown and the rest do not stand for the tree"}
	}
	return sarifRaw, bySeverity, &Examined{Unit: "files", Count: targets}, nil
}
