package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runGitleaksScript runs gitleaksScript under sh with a fake gitleaks first on
// PATH and returns the files it wrote. fake is the fake's body; extraBin holds
// further fakes (an awk that fails, say).
func runGitleaksScript(t *testing.T, fake string, extraBin map[string]string, args ...string) map[string]string {
	t.Helper()
	root := t.TempDir()
	out := filepath.Join(root, "out")
	bin := filepath.Join(root, "bin")
	for _, d := range []string{out, bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	tools := map[string]string{"gitleaks": fake}
	for k, v := range extraBin {
		tools[k] = v
	}
	for name, body := range tools {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	cmd := exec.Command("sh", append([]string{"-c", gitleaksScript, "sh", out}, args...)...)
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FIXTURE="+mustAbs(t, gitleaksArchivesFixture),
		"ARGS_FILE="+filepath.Join(root, "args"))
	if b, err := cmd.CombinedOutput(); err != nil {
		// The script always exits 0: gitleaksRunError, not Dagger's exec
		// failure, decides what happened.
		t.Fatalf("script exited non-zero: %v\n%s", err, b)
	}

	files := map[string]string{}
	for _, name := range []string{"gitleaks.err", "gitleaks.skipped", "gitleaks.ignored", "gitleaks.exit", "gitleaks.out", "report.sarif", "args"} {
		dir := out
		if name == "args" {
			dir = root
		}
		if b, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
			files[name] = string(b)
		}
	}
	return files
}

func mustAbs(t *testing.T, p string) string {
	t.Helper()
	a, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// A credential the fake logs the way gitleaks' DBG segment lines log decoded
// content. Built at run time so this file holds no string a secrets scanner
// would flag.
var segmentSecret = "ghp_" + strings.Repeat("Zq9X", 9)

// replayFake writes the captured stderr, then a DBG segment line carrying the
// decoded credential — one shaped to look like the kept line as well — and
// exits with $1.
func replayFake(code string) string {
	return `#!/bin/sh
printf '%s\n' "$*" > "$ARGS_FILE"
cat "$FIXTURE" >&2
echo '2:32PM DBG segment found: "Z2hw" -> "` + segmentSecret + `" decoder=base64' >&2
echo '2:32PM DBG segment found: " DBG skipping binary file mime_type=application/zip path=` + segmentSecret + `"' >&2
exit ` + code + "\n"
}

// TestGitleaksScriptKeepsOnlyTheSkippedBinaryLines is the guard on the one
// thing --log-level debug costs: DBG writes decoded file content, past
// --redact. Every DBG line but the skipped-binary shape must die in the
// filter, a decoded credential must reach no file the script leaves, and the
// non-DBG lines must reach gitleaks.err unchanged so gitleaksRunError reads
// what it always read.
func TestGitleaksScriptKeepsOnlyTheSkippedBinaryLines(t *testing.T) {
	files := runGitleaksScript(t, replayFake("0"), nil, gitleaksTreeArgs()...)

	for name, content := range files {
		if strings.Contains(content, segmentSecret) {
			t.Errorf("decoded credential written to %s:\n%s", name, content)
		}
	}
	if got := strings.TrimSpace(files["gitleaks.exit"]); got != "0" {
		t.Errorf("exit = %q, want gitleaks' own 0", got)
	}
	if strings.Contains(files["gitleaks.err"], " DBG ") {
		t.Errorf("a DBG line reached gitleaks.err:\n%s", files["gitleaks.err"])
	}

	wantStderr, wantSkipped := splitGitleaksLog(t, readGitleaksFixture(t))
	if strings.TrimSpace(files["gitleaks.err"]) != strings.TrimSpace(wantStderr) {
		t.Errorf("gitleaks.err:\n%s\nwant:\n%s", files["gitleaks.err"], wantStderr)
	}
	if strings.TrimSpace(files["gitleaks.skipped"]) != strings.TrimSpace(wantSkipped) {
		t.Errorf("gitleaks.skipped:\n%s\nwant:\n%s", files["gitleaks.skipped"], wantSkipped)
	}
	if strings.Count(files["gitleaks.skipped"], "\n") != 4 {
		t.Errorf("want the four skipped-binary lines of the capture, got:\n%s", files["gitleaks.skipped"])
	}

	// And the split feeds the parser to the same answer as the Go split.
	got := gitleaksTreeScanResult(files["gitleaks.err"], files["gitleaks.skipped"], "build output")
	if len(got.Warnings) != 2 || got.Examined == nil || got.Examined.Count != 62 {
		t.Errorf("script output parsed to %+v", got)
	}
	if msg := gitleaksRunError(files["gitleaks.exit"], files["gitleaks.err"], cleanSARIF, false); msg != "" {
		t.Errorf("a clean tree run classified as a non-run: %s", msg)
	}
}

// TestGitleaksScriptPassesTheArgumentsThrough: the tree leg opens archives and
// logs at the level that names the ones it would not; the history leg does
// neither; both keep --redact.
func TestGitleaksScriptPassesTheArgumentsThrough(t *testing.T) {
	tree := runGitleaksScript(t, replayFake("0"), nil, gitleaksTreeArgs()...)["args"]
	for _, want := range []string{"dir . --max-archive-depth 3 --log-level debug ", " --redact "} {
		if !strings.Contains(tree, want) {
			t.Errorf("tree leg args lack %q: %s", want, tree)
		}
	}
	history := runGitleaksScript(t, replayFake("0"), nil, gitleaksHistoryArgs()...)["args"]
	if !strings.HasPrefix(history, "detect --source . ") || !strings.Contains(history, " --redact ") {
		t.Errorf("history leg args: %s", history)
	}
	if strings.Contains(history, "--log-level") || strings.Contains(history, "--max-archive-depth") {
		t.Errorf("history leg carries a tree flag: %s", history)
	}
}

// TestGitleaksScriptRecordsGitleaksOwnExit: the status recorded is gitleaks',
// not the filter's — a pipeline's status is its last command's, which is the
// mistake the brace group exists to avoid.
func TestGitleaksScriptRecordsGitleaksOwnExit(t *testing.T) {
	fake := "#!/bin/sh\necho 'Error: unknown flag: --max-archive-depth' >&2\nexit 2\n"
	files := runGitleaksScript(t, fake, nil, gitleaksTreeArgs()...)
	if got := strings.TrimSpace(files["gitleaks.exit"]); got != "2" {
		t.Errorf("exit = %q, want 2", got)
	}
	msg := gitleaksRunError(files["gitleaks.exit"], files["gitleaks.err"], files["report.sarif"], false)
	if !strings.Contains(msg, "did not run (exit 2): Error: unknown flag: --max-archive-depth") {
		t.Errorf("classification lost the reason: %q", msg)
	}
}

// TestGitleaksScriptFailsClosedWhenItCannotFilter: a filter that died leaves
// the skipped list unknowable, and an unknown list must not read as "no
// archive went unopened". It becomes a non-run naming why.
func TestGitleaksScriptFailsClosedWhenItCannotFilter(t *testing.T) {
	brokenAwk := "#!/bin/sh\ncat >/dev/null\nexit 1\n"
	files := runGitleaksScript(t, replayFake("0"), map[string]string{"awk": brokenAwk}, gitleaksTreeArgs()...)
	if got := strings.TrimSpace(files["gitleaks.exit"]); got != "125" {
		t.Errorf("exit = %q, want 125", got)
	}
	msg := gitleaksRunError(files["gitleaks.exit"], files["gitleaks.err"], cleanSARIF, false)
	if !strings.Contains(msg, "could not filter gitleaks' log") {
		t.Errorf("non-run does not say why: %q", msg)
	}
	for name, content := range files {
		if strings.Contains(content, segmentSecret) {
			t.Errorf("decoded credential written to %s", name)
		}
	}
}

// TestGitleaksScriptKeepsTheIgnoredFingerprints: the one DBG line that says a
// .gitleaksignore entry removed a finding is kept, cut down to its
// fingerprint. Lines that only look like it — a segment line quoting file
// content, and a fingerprint line whose finding was not redacted — are
// dropped whole, so nothing a file contains reaches gitleaks.ignored.
func TestGitleaksScriptKeepsTheIgnoredFingerprints(t *testing.T) {
	fake := `#!/bin/sh
echo '3:02PM DBG skipping finding: global fingerprint finding=REDACTED fingerprint=a.go:aws-access-token:2' >&2
echo '3:02PM DBG skipping finding: global fingerprint finding=REDACTED fingerprint="sp ace/e.go:aws-access-token:2"' >&2
echo '3:02PM DBG segment found: " DBG skipping finding: global fingerprint finding=REDACTED fingerprint=` + segmentSecret + `" decoder=base64' >&2
echo '3:02PM DBG skipping finding: global fingerprint finding=` + segmentSecret + ` fingerprint=c.go:github-pat:1' >&2
echo '3:02PM INF no leaks found' >&2
exit 0
`
	files := runGitleaksScript(t, fake, nil, gitleaksTreeArgs()...)
	want := "a.go:aws-access-token:2\n\"sp ace/e.go:aws-access-token:2\"\n"
	if files["gitleaks.ignored"] != want {
		t.Errorf("gitleaks.ignored = %q, want %q", files["gitleaks.ignored"], want)
	}
	for name, content := range files {
		if strings.Contains(content, segmentSecret) {
			t.Errorf("decoded credential written to %s:\n%s", name, content)
		}
	}
	if got := parseGitleaksIgnored(files["gitleaks.ignored"]); len(got) != 2 ||
		got[0] != (gitleaksFingerprint{File: "a.go", Rule: "aws-access-token", Line: 2}) ||
		got[1] != (gitleaksFingerprint{File: "sp ace/e.go", Rule: "aws-access-token", Line: 2}) {
		t.Errorf("parsed to %+v", got)
	}
}

// TestGitleaksShadowArgs: the shadow pass is the tree leg with inline marks
// ignored, so its findings differ from the tree leg's only by what the marks
// and the removed config files suppressed.
func TestGitleaksShadowArgs(t *testing.T) {
	got := strings.Join(gitleaksShadowArgs(), " ")
	if got != "dir . --max-archive-depth 3 --ignore-gitleaks-allow" {
		t.Errorf("shadow args = %q", got)
	}
}

// TestGitleaksAllowMarksScript drives the marks grep against a real tree: a
// mark is listed with its line, the line's other content is not, and an
// absent mark is exit 1 rather than an unknown list.
func TestGitleaksAllowMarksScript(t *testing.T) {
	run := func(t *testing.T, files map[string]string) (marks, exit string) {
		t.Helper()
		root := t.TempDir()
		tree := filepath.Join(root, "tree")
		out := filepath.Join(root, "out")
		for _, d := range []string{tree, out} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		for name, body := range files {
			p := filepath.Join(tree, name)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.Command("sh", "-c", gitleaksAllowMarksScript, "sh", out)
		cmd.Dir = tree
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("script exited non-zero: %v\n%s", err, b)
		}
		m, _ := os.ReadFile(filepath.Join(out, "gitleaks.marks"))
		e, _ := os.ReadFile(filepath.Join(out, "gitleaks.marks.exit"))
		return string(m), strings.TrimSpace(string(e))
	}

	marks, exit := run(t, map[string]string{
		"b.go":     "package b\n\nvar k = \"" + segmentSecret + "\" // gitleaks:allow\n",
		"sub/c.py": "x = 1\n",
	})
	if exit != "0" {
		t.Errorf("exit = %q, want 0", exit)
	}
	if strings.Contains(marks, segmentSecret) {
		t.Errorf("the marked line's content reached gitleaks.marks:\n%s", marks)
	}
	got, ok := parseGitleaksAllowMarks(marks, exit)
	if !ok || len(got) != 1 || got[0] != (gitleaksMark{File: "b.go", Line: 3}) {
		t.Errorf("marks = %+v, known = %v (raw %q)", got, ok, marks)
	}

	marks, exit = run(t, map[string]string{"a.go": "package a\n"})
	got, ok = parseGitleaksAllowMarks(marks, exit)
	if exit != "1" || !ok || len(got) != 0 {
		t.Errorf("no marks: exit %q, known %v, marks %+v", exit, ok, got)
	}
}
