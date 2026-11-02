package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// TestPylintTargetsPrunesWhatIsNotTheProject pins the selection: hidden
// directories, node_modules, __pycache__, site-packages and any directory
// holding a pyvenv.cfg are pruned and counted; everything else is linted,
// sorted and "./"-prefixed so no path can read as a pylint option.
func TestPylintTargetsPrunesWhatIsNotTheProject(t *testing.T) {
	files := []string{
		"sub/b.py",
		"a.py",
		"-rcfile.py",
		"pkg/__init__.py",
		"./pkg/c.py",
		".venv/lib/v.py",
		".hidden/h.py",
		"node_modules/x/n.py",
		"pkg/__pycache__/c.py",
		"lib/site-packages/s.py",
		"env/lib/python3.12/e.py",
		"envy/keep.py",
	}
	targets, pruned := pylintTargets(files, []string{"env/pyvenv.cfg"})
	want := []string{"./-rcfile.py", "./a.py", "./envy/keep.py", "./pkg/__init__.py", "./pkg/c.py", "./sub/b.py"}
	if !reflect.DeepEqual(targets, want) {
		t.Errorf("targets = %q, want %q", targets, want)
	}
	if pruned != 6 {
		t.Errorf("pruned = %d, want 6", pruned)
	}
}

// TestPylintTargetWarningsNameTheNarrowing: a pruned file is named in a
// warning, and an empty target list says why the leg is SKIPPED.
func TestPylintTargetWarningsNameTheNarrowing(t *testing.T) {
	if w := pylintTargetWarnings([]string{"./a.py"}, 0); w != nil {
		t.Errorf("nothing pruned, targets left: warnings %q, want none", w)
	}
	w := pylintTargetWarnings([]string{"./a.py"}, 2)
	if len(w) != 1 || !strings.Contains(w[0], "skipped 2 .py file(s)") || !strings.Contains(w[0], "virtualenvs") {
		t.Errorf("two pruned: warnings %q", w)
	}
	w = pylintTargetWarnings(nil, 3)
	if len(w) != 2 || !strings.Contains(w[1], "SKIPPED") {
		t.Errorf("nothing left: warnings %q, want the pruned count and SKIPPED", w)
	}
}

// TestPylintScriptReadsTheListItIsGiven pins the script: json2, exit-zero and
// the list path, which is the only way targets reach pylint.
func TestPylintScriptReadsTheListItIsGiven(t *testing.T) {
	s := pylintScript("/tmp/x")
	for _, want := range []string{`open("/tmp/x"`, "'--output-format=json2'", "'--exit-zero'", "*targets", "split('\\0')"} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q:\n%s", want, s)
		}
	}
}

// TestPylintFatalIsANonRunNotAFinding: pylint's fatal messages mean it could
// not read a file. They are named as unread, never counted as a finding, and
// the leg reports no Examined because what it examined is not the tree.
func TestPylintFatalIsANonRunNotAFinding(t *testing.T) {
	out := `{"messages":[
		{"type":"fatal","symbol":"astroid-error","path":"b.py","messageId":"F0002"},
		{"type":"fatal","symbol":"parse-error","path":"a.py","messageId":"F0010"},
		{"type":"warning","symbol":"unused-import","path":"c.py","message":"m","line":1,"messageId":"W0611"}]}`
	sarif, counts, examined, errs := foldPylintRun(out, nil, 3)
	if len(errs) != 1 || !strings.Contains(errs[0], "could not read 2 of 3 file(s) it was given (a.py, b.py)") {
		t.Fatalf("errors %q", errs)
	}
	if examined != nil {
		t.Errorf("examined %+v, want nil", *examined)
	}
	if counts[SeverityHigh] != 0 || counts[SeverityMedium] != 1 {
		t.Errorf("counts %v, want the warning only", counts)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(sarif, &doc); err != nil || len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 {
		t.Fatalf("sarif %s (%v)", sarif, err)
	}
	// The location is the file path, not pylint's dotted module name: a
	// finding's location is part of its identity.
	if uri := doc.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI; uri != "c.py" {
		t.Errorf("uri %q, want c.py", uri)
	}
}

// TestCapPathsSaysWhatItLeftOut.
func TestCapPathsSaysWhatItLeftOut(t *testing.T) {
	if got := capPaths([]string{"a", "b"}, 2); got != "a, b" {
		t.Errorf("got %q", got)
	}
	if got := capPaths([]string{"a", "b", "c"}, 2); got != "a, b and 1 more" {
		t.Errorf("got %q", got)
	}
}

// TestLintOutcomeZeroFilesIsSkipped: a clean run over zero files is SKIPPED;
// findings, a non-run and an unknown count are left as scanOutcome says.
func TestLintOutcomeZeroFilesIsSkipped(t *testing.T) {
	zero, some := &Examined{Unit: "files"}, &Examined{Unit: "files", Count: 4}
	cases := []struct {
		ran      bool
		findings int
		examined *Examined
		want     Outcome
	}{
		{true, 0, zero, OutcomeSkipped},
		{true, 0, some, OutcomeClean},
		{true, 0, nil, OutcomeClean},
		{true, 2, some, OutcomeFindings},
		{false, 0, zero, OutcomeError},
	}
	for _, c := range cases {
		if got := lintOutcome(c.ran, c.findings, c.examined); got != c.want {
			t.Errorf("lintOutcome(%v, %d, %+v) = %s, want %s", c.ran, c.findings, c.examined, got, c.want)
		}
	}
}

// TestEslintExaminedIsAllOrNothing: the per-project counts sum only when every
// project's count is known and the leg ran; otherwise the leg says nothing.
func TestEslintExaminedIsAllOrNothing(t *testing.T) {
	if n := eslintFilesLinted(" [{\"filePath\":\"a\"},{\"filePath\":\"b\"}]\n"); n != 2 {
		t.Errorf("two results: %d", n)
	}
	if n := eslintFilesLinted("[]"); n != 0 {
		t.Errorf("empty array: %d", n)
	}
	if n := eslintFilesLinted("Oops! Something went wrong"); n != -1 {
		t.Errorf("not JSON: %d", n)
	}
	if e := eslintExamined([]int{2, 3}, true); e == nil || e.Count != 5 || e.Unit != "files" {
		t.Errorf("sum: %+v", e)
	}
	for _, c := range []struct {
		counts []int
		ran    bool
	}{{[]int{2, -1}, true}, {[]int{2}, false}, {nil, true}} {
		if e := eslintExamined(c.counts, c.ran); e != nil {
			t.Errorf("eslintExamined(%v, %v) = %+v, want nil", c.counts, c.ran, *e)
		}
	}
}
