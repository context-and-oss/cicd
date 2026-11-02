//go:build unit_test

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestByoTestArgvRunsTheCommandAsItsOwnScript executes the real wrapper under
// sh. Each case is a command a consumer can legally write that the old
// "( %s )" splice turned into cicd's own syntax error: no exit file, a
// non-run blamed on the consumer.
func TestByoTestArgvRunsTheCommandAsItsOwnScript(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not on PATH")
	}
	cases := []struct {
		name, cmd, wantOut, wantExit string
	}{
		{"trailing comment", "echo ran # run the suite", "ran", "0"},
		{"heredoc", "cat <<END\nran\nEND", "ran", "0"},
		{"unbalanced paren in a string", "echo 'ran)'", "ran)", "0"},
		{"compound command", "echo first && echo ran", "ran", "0"},
		{"stderr is captured", "echo ran >&2", "ran", "0"},
		{"failure exit survives", "echo ran; exit 3", "ran", "3"},
		{"trailing comment after a failure", "false # still fails", "", "1"},
		{"dollar is the consumer's own", `x=ran; echo "$x"`, "ran", "0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			out, exit := filepath.Join(dir, "out"), filepath.Join(dir, "exit")
			argv := byoTestArgv(tc.cmd, out, exit)
			if err := exec.Command(argv[0], argv[1:]...).Run(); err != nil {
				t.Fatalf("wrapper itself failed: %v", err)
			}
			code, err := os.ReadFile(exit)
			if err != nil {
				t.Fatalf("no exit file: the wrapper, not the command, decided the outcome: %v", err)
			}
			if got := strings.TrimSpace(string(code)); got != tc.wantExit {
				t.Errorf("exit = %q, want %q", got, tc.wantExit)
			}
			got, _ := os.ReadFile(out)
			if !strings.Contains(string(got), tc.wantOut) {
				t.Errorf("output = %q, want it to contain %q", got, tc.wantOut)
			}
		})
	}
}

// TestByoTestArgvNamesASyntaxErrorAsTheConsumers keeps a broken command a
// failed run with the shell's own message, not a missing exit file.
func TestByoTestArgvNamesASyntaxErrorAsTheConsumers(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not on PATH")
	}
	dir := t.TempDir()
	out, exit := filepath.Join(dir, "out"), filepath.Join(dir, "exit")
	argv := byoTestArgv("if then", out, exit)
	if err := exec.Command(argv[0], argv[1:]...).Run(); err != nil {
		t.Fatalf("wrapper itself failed: %v", err)
	}
	code, err := os.ReadFile(exit)
	if err != nil {
		t.Fatalf("no exit file: %v", err)
	}
	if strings.TrimSpace(string(code)) == "0" {
		t.Errorf("a syntax error in the command read as a pass")
	}
	if got, _ := os.ReadFile(out); len(strings.TrimSpace(string(got))) == 0 {
		t.Errorf("the shell's syntax error was not captured")
	}
}
