//go:build unit_test

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestArchiveBuildArgvRunsTheCommandAsItsOwnScript executes the real wrapper
// under sh. Each case is a build command a consumer can legally write that
// the old "( %s )" splice turned into cicd's own syntax error.
func TestArchiveBuildArgvRunsTheCommandAsItsOwnScript(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not on PATH")
	}
	cases := []struct {
		name, cmd, wantOut, wantErr, wantExit string
	}{
		{"trailing comment", "echo built # npm run build", "built", "", "0"},
		{"heredoc", "cat <<END\nbuilt\nEND", "built", "", "0"},
		{"unbalanced paren in a string", "echo 'built)'", "built)", "", "0"},
		{"stderr stays separate", "echo built; echo warn >&2", "built", "warn", "0"},
		{"failure exit survives", "echo broke >&2; exit 4", "", "broke", "4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			out, errOut, exit := filepath.Join(dir, "out"), filepath.Join(dir, "err"), filepath.Join(dir, "exit")
			argv := archiveBuildArgv(tc.cmd, out, errOut, exit)
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
			if got, _ := os.ReadFile(out); !strings.Contains(string(got), tc.wantOut) {
				t.Errorf("stdout = %q, want it to contain %q", got, tc.wantOut)
			}
			gotErr, _ := os.ReadFile(errOut)
			if !strings.Contains(string(gotErr), tc.wantErr) {
				t.Errorf("stderr = %q, want it to contain %q", gotErr, tc.wantErr)
			}
			if tc.wantErr == "" && strings.Contains(string(gotErr), tc.wantOut) && tc.wantOut != "" {
				t.Errorf("stdout leaked into stderr: %q", gotErr)
			}
		})
	}
}
