//go:build unit_test

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestClassifyGitScope(t *testing.T) {
	for _, tc := range []struct {
		name, status, stderr string
		pruned               bool
		warn                 string // substring; "" means no warning
	}{
		{"no .git", "none\n", "", false, ""},
		{"nothing ignored", "git 0 0 0\n", "", true, ""},
		{"ignored paths removed", "git 0 3 0\n", "", true, "3 gitignored paths present in the tree were not scanned"},
		{"one ignored path", "git 0 1 0\n", "", true, "1 gitignored path present in the tree was not scanned"},
		{"git failed", "git 128 - -\n", "fatal: not a git repository: /elsewhere/.git/worktrees/x\n", false,
			"git exited 128: fatal: not a git repository"},
		{"rm failed", "git 0 2 1\n", "rm: cannot remove 'dist': Permission denied\n", true,
			"could not remove every one of the 2 gitignored paths"},
		{"garbled status", "", "", false, "unexpected status"},
		{"garbled count", "git 0 x 0\n", "", false, "how many paths"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyGitScope(tc.status, tc.stderr)
			if got.Pruned != tc.pruned {
				t.Errorf("Pruned = %v, want %v", got.Pruned, tc.pruned)
			}
			if tc.warn == "" && got.Warning != "" {
				t.Errorf("unexpected warning %q", got.Warning)
			}
			if tc.warn != "" && !strings.Contains(got.Warning, tc.warn) {
				t.Errorf("warning %q does not contain %q", got.Warning, tc.warn)
			}
			if !tc.pruned && tc.warn != "" && !strings.Contains(got.Warning, "gitignored ones included") {
				t.Errorf("a scope git did not answer for must say the whole tree was walked: %q", got.Warning)
			}
		})
	}
}

// TestGitScopeScriptRemovesWhatGitIgnores runs the script against a real
// repository: ignored files and directories go, tracked files stay even when
// an ignore pattern matches them, untracked files git does not ignore stay,
// and a hostile file name is an argument, never shell source or an option.
func TestGitScopeScriptRemovesWhatGitIgnores(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	out := filepath.Join(dir, "out")
	// The user's own git config (a global excludesFile) must not decide
	// what this repository ignores.
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("XDG_CONFIG_HOME", dir)
	write := func(rel, body string) {
		p := filepath.Join(src, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", src, "-c", "user.name=t", "-c", "user.email=t@example.com"}, args...)...)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, b)
		}
	}
	write(".gitignore", "dist/\n*.log\nkept.gen.go\n")
	write("main.go", "package main\n")
	write("kept.gen.go", "package main\n")
	git("init", "-q")
	git("add", "-f", ".gitignore", "main.go", "kept.gen.go")
	git("commit", "-q", "-m", "init")
	write("dist/bundle.js", "x")
	write("debug.log", "x")
	write("-rf.log", "x")
	write("$(touch pwned).log", "x")
	write("notes.txt", "untracked, not ignored")

	script := strings.ReplaceAll(gitScopeScript(), gitScopeOut, out)
	script = strings.ReplaceAll(script, "cd "+gitScopeMount, "cd "+src)
	if b, err := exec.Command("sh", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("script: %v\n%s", err, b)
	}
	for _, d := range []string{src, dir} {
		if _, err := os.Stat(filepath.Join(d, "pwned")); err == nil {
			t.Fatal("a file name was executed as shell source")
		}
	}
	status, _ := os.ReadFile(filepath.Join(out, "status"))
	if got := strings.TrimSpace(string(status)); got != "git 0 4 0" {
		errOut, _ := os.ReadFile(filepath.Join(out, "err"))
		t.Fatalf("status = %q, want \"git 0 4 0\" (dist/, debug.log, -rf.log, the hostile .log); stderr: %s", got, errOut)
	}
	var left []string
	_ = filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if info.IsDir() && rel == ".git" {
			return filepath.SkipDir
		}
		if !info.IsDir() {
			left = append(left, rel)
		}
		return nil
	})
	sort.Strings(left)
	if want := ".gitignore,kept.gen.go,main.go,notes.txt"; strings.Join(left, ",") != want {
		t.Errorf("left %v, want %s", left, want)
	}
}

func TestGitScopeScriptWithoutGit(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	out := filepath.Join(dir, "out")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	script := strings.ReplaceAll(gitScopeScript(), gitScopeOut, out)
	script = strings.ReplaceAll(script, "cd "+gitScopeMount, "cd "+src)
	if b, err := exec.Command("sh", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("script: %v\n%s", err, b)
	}
	status, _ := os.ReadFile(filepath.Join(out, "status"))
	if got := classifyGitScope(string(status), ""); got.Pruned || got.Warning != "" {
		t.Errorf("a tree without .git must be scanned as handed over, silently: %+v (status %q)", got, status)
	}
}
