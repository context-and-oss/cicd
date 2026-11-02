package main

import (
	"strings"
	"testing"
)

// TestEslintRunErrorSurfacesNonRuns is the regression guard for the silent
// false pass: the old command ended in `2>/dev/null || true`, so ESLint failing
// to run at all left an empty report that parsed as "no findings" and passed
// the gate. Anything other than a genuine 0/1 exit must now be reported.
func TestEslintRunErrorSurfacesNonRuns(t *testing.T) {
	cases := []struct {
		name     string
		exit     string
		stderr   string
		report   string
		wantErr  bool
		contains string
	}{
		{
			name:    "clean run with empty array",
			exit:    "0",
			report:  "[]",
			wantErr: false,
		},
		{
			name:    "findings reported",
			exit:    "1",
			report:  `[{"filePath":"a.js","messages":[{"severity":2}]}]`,
			wantErr: false,
		},
		{
			name:     "config error",
			exit:     "2",
			stderr:   "Oops! Something went wrong\nInvalid option '--nope'",
			wantErr:  true,
			contains: "Invalid option",
		},
		{
			// A monorepo whose package.json is not at the linted root, or a repo
			// that simply does not depend on ESLint: node_modules/.bin/eslint is
			// not there, the shell exits 127, nothing runs. A synthetic layout
			// such as apps/web/ exercises this missing-binary condition.
			name:     "the binary is not in node_modules",
			exit:     "127",
			stderr:   "sh: 4: ./node_modules/.bin/eslint: not found",
			wantErr:  true,
			contains: "exit 127",
		},
		{
			name:    "exited zero but wrote nothing",
			exit:    "0",
			report:  "   \n",
			wantErr: true,
		},
		{
			name:    "unreadable exit status",
			exit:    "not-a-number",
			wantErr: true,
		},
		{
			name:     "trailing newline on exit code is tolerated",
			exit:     "2\n",
			stderr:   "boom",
			wantErr:  true,
			contains: "exit 2",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := eslintRunError(c.exit, c.stderr, c.report, npmDefault.record("0"))
			if c.wantErr && got == "" {
				t.Fatal("expected an error string, got none — a non-run would pass the gate silently")
			}
			if !c.wantErr && got != "" {
				t.Fatalf("expected no error, got %q", got)
			}
			if c.contains != "" && !contains(got, c.contains) {
				t.Fatalf("error %q does not mention %q", got, c.contains)
			}
		})
	}
}

func TestLastNonEmptyLine(t *testing.T) {
	cases := map[string]string{
		"a\nb\nc":         "c",
		"a\nb\n\n\n":      "b",
		"  only  ":        "only",
		"":                "",
		"\n\n":            "",
		"noise\n  real  ": "real",
	}
	for in, want := range cases {
		if got := lastNonEmptyLine(in); got != want {
			t.Errorf("lastNonEmptyLine(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestParseEslintJSONNilOnlyForNonReports pins the contract runEslint relies on:
// nil means "not an ESLint report", never "no findings". A clean run emits an
// empty JSON array and must produce a non-nil SARIF document.
func TestParseEslintJSONNilOnlyForNonReports(t *testing.T) {
	sarif, counts := parseEslintJSON([]byte("[]"), "9.39.5")
	if sarif == nil {
		t.Fatal("clean run ([]) must yield a SARIF document, not nil")
	}
	if len(counts) != 0 {
		t.Fatalf("clean run should have no counts, got %v", counts)
	}

	for _, bad := range []string{"", "   ", "not json", `{"not":"an array"}`} {
		if s, _ := parseEslintJSON([]byte(bad), "9.39.5"); s != nil {
			t.Errorf("parseEslintJSON(%q) should be nil, got %s", bad, s)
		}
	}
}

func TestParseEslintJSONSeverities(t *testing.T) {
	report := `[{"filePath":"/src/a.js","messages":[
        {"severity":2,"message":"err","line":3,"ruleId":"no-undef"},
        {"severity":1,"message":"warn","line":9,"ruleId":"semi"}
      ]}]`
	sarif, counts := parseEslintJSON([]byte(report), "9.39.5")
	if counts[SeverityHigh] != 1 || counts[SeverityMedium] != 1 {
		t.Fatalf("counts = %v, want 1 HIGH and 1 MEDIUM", counts)
	}
	// The emitted SARIF must carry explicit levels so downstream severity
	// resolution never has to guess.
	if !contains(string(sarif), `"level":"error"`) || !contains(string(sarif), `"level":"warning"`) {
		t.Fatalf("SARIF is missing explicit levels: %s", sarif)
	}
}

// TestSarifReportsTheVersionThatRan is the regression guard for attribution: the
// SARIF driver version used to be a compile-time constant ("8.57.0") while the
// binary belongs to the consumer's lockfile, so evidence credited findings to a
// build that never executed.
func TestSarifReportsTheVersionThatRan(t *testing.T) {
	sarif, _ := parseEslintJSON([]byte("[]"), "9.39.5")
	if !contains(string(sarif), `"version":"9.39.5"`) {
		t.Fatalf("SARIF does not report the version that ran: %s", sarif)
	}
	if contains(string(sarif), "8.57.0") {
		t.Fatalf("SARIF still carries a cicd-chosen version: %s", sarif)
	}

	// "unknown" must survive into the document rather than being replaced by a
	// plausible default — an unknown version is a fact, not a blank to fill in.
	unknown, _ := parseEslintJSON([]byte("[]"), "unknown")
	if !contains(string(unknown), `"version":"unknown"`) {
		t.Fatalf("SARIF did not preserve an unknown version: %s", unknown)
	}
}

func TestEslintVersionLabel(t *testing.T) {
	cases := map[string]string{
		"v9.39.5\n":  "9.39.5", // what `eslint --version` actually prints
		"9.39.5":     "9.39.5",
		"  v8.57.1 ": "8.57.1",
		// Not a version: the file was missing, so the shell wrote an error or
		// nothing at all. Reporting "unknown" keeps the envelope honest.
		"":                            "unknown",
		"\n":                          "unknown",
		"sh: eslint: not found":       "unknown",
		"Debugger attached.\nv9.39.5": "unknown",
	}
	for in, want := range cases {
		if got := eslintVersionLabel(in); got != want {
			t.Errorf("eslintVersionLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestEslintStderrMessagePicksTheDiagnostic pins the reason lastNonEmptyLine is
// not used for crash output: ESLint prints a banner first and a documentation URL
// *last*, so the final line is "https://eslint.org/..." while the actual
// diagnostic sits in the middle. Every input below is a measured layout.
func TestEslintStderrMessagePicksTheDiagnostic(t *testing.T) {
	cases := []struct {
		name   string
		stderr string
		want   string
	}{
		{
			name: "eslint 9 missing flat config",
			stderr: "Oops! Something went wrong! :(\n\nESLint: 9.39.5\n\n" +
				"ESLint couldn't find an eslint.config.(js|mjs|cjs) file.\n\n" +
				"From ESLint v9.0.0, the default configuration file is now eslint.config.js.\n" +
				"If you are using a .eslintrc.* file, please follow the migration guide\n" +
				"to update your configuration file: https://eslint.org/docs/latest/use/configure/migration-guide\n\n" +
				"https://eslint.org/chat/help to chat with the team.\n",
			want: "ESLint couldn't find an eslint.config.(js|mjs|cjs) file.",
		},
		{
			name: "unresolvable rule",
			stderr: "Oops! Something went wrong! :(\n\nESLint: 9.39.5\n\n" +
				"TypeError: Key \"rules\": Key \"no-nope\": Could not find \"no-nope\" in plugin \"\".\n" +
				"    at throwRuleNotFoundError (/app/node_modules/eslint/lib/config/config.js:99:11)\n",
			want: "TypeError: Key \"rules\": Key \"no-nope\": Could not find \"no-nope\" in plugin \"\".",
		},
		{
			name:   "flag removed in eslint 9",
			stderr: "Invalid option '--eslintrc' - perhaps you meant '--no-eslintrc'?\nYou're using eslint.config.js, some command line flags are no longer available.\n",
			want:   "Invalid option '--eslintrc' - perhaps you meant '--no-eslintrc'?",
		},
		{
			name:   "shell could not find the binary",
			stderr: "sh: 4: ./node_modules/.bin/eslint: not found\n",
			want:   "sh: 4: ./node_modules/.bin/eslint: not found",
		},
		{
			// Nothing but skippable lines: fall back rather than report nothing,
			// because an empty message is how a non-run hides.
			name:   "only skippable lines",
			stderr: "Oops!\nESLint: 9.39.5\nhttps://eslint.org/chat/help\n",
			want:   "https://eslint.org/chat/help",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := eslintStderrMessage(c.stderr); got != c.want {
				t.Errorf("eslintStderrMessage() = %q, want %q", got, c.want)
			}
		})
	}
}

// TestEslintRunErrorCarriesTheRemedy: the three non-runs a consumer actually hits
// each have a different fix, and the error string is the only place they will see
// it — a container log is gone by the time anyone reads the evidence.
func TestEslintRunErrorCarriesTheRemedy(t *testing.T) {
	missingBinary := eslintRunError("127", eslintMissingStderr, "", npmDefault.record("0"))
	for _, want := range []string{"not installed", "devDependencies", "--include"} {
		if !contains(missingBinary, want) {
			t.Errorf("exit 127 remedy %q does not mention %q", missingBinary, want)
		}
	}

	for _, stderr := range []string{
		"Oops!\nESLint: 9.39.5\nESLint couldn't find an eslint.config.(js|mjs|cjs) file.\n",
		"ESLint couldn't find a configuration file. To set up a configuration file for this project, please run:\n",
		"No ESLint configuration found in /src.\n",
	} {
		got := eslintRunError("2", stderr, "", npmDefault.record("0"))
		if !contains(got, "eslint.config.js") || !contains(got, ".eslintrc") {
			t.Errorf("missing-config remedy %q does not name both config eras (stderr %q)", got, stderr)
		}
	}

	// An unrecognised failure still has to be reported — just without a remedy
	// invented for it.
	other := eslintRunError("2", "TypeError: something we have never seen\n", "", npmDefault.record("0"))
	if other == "" {
		t.Fatal("an unclassified non-run must still be an error")
	}
	if contains(other, "devDependencies") {
		t.Errorf("unrelated failure got the missing-binary remedy: %q", other)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}

// TestEslintMissingBinaryRemedyFollowsTheInstall: exit 127 used to say "add
// eslint to devDependencies" whatever the cause. When the install failed the
// project may well declare eslint, and that advice sends the reader the wrong
// way; when the install ran elsewhere, cicd cannot tell, and must say so.
func TestEslintMissingBinaryRemedyFollowsTheInstall(t *testing.T) {
	failed := eslintRunError("127", eslintMissingStderr, "", npmDefault.record("1\n"))
	if !contains(failed, "npm install exited 1") || !contains(failed, "fix the install") {
		t.Errorf("install failed: %q does not name the install as the cause", failed)
	}
	if contains(failed, "devDependencies") {
		t.Errorf("install failed: %q still sends the reader to devDependencies", failed)
	}

	for _, unknown := range []string{"", "\n", "garbage"} {
		got := eslintRunError("127", eslintMissingStderr, "", npmDefault.record(unknown))
		if !contains(got, "cannot see whether the dependency install succeeded") || !contains(got, "devDependencies") {
			t.Errorf("install unknown (%q): %q must name both causes", unknown, got)
		}
	}

	ok := eslintRunError("127", eslintMissingStderr, "", npmDefault.record("0\n"))
	if contains(ok, "install") && !contains(ok, "not installed") {
		t.Errorf("install ok: %q blames the install", ok)
	}
}

// TestEslintNonRunNamesAFailedInstall: a plugin the config names that the
// failed install never fetched fails like a broken config. The install exit is
// the only place the likelier cause shows; a clean install adds nothing.
func TestEslintNonRunNamesAFailedInstall(t *testing.T) {
	stderr := "Oops! Something went wrong! :(\nESLint: 9.39.5\nError [ERR_MODULE_NOT_FOUND]: Cannot find package 'eslint-plugin-x'\n"
	if got := eslintRunError("2", stderr, "", npmDefault.record("1")); !contains(got, "npm install exited 1") {
		t.Errorf("exit 2 after a failed install: %q does not name the install", got)
	}
	if got := eslintRunError("2", stderr, "", npmDefault.record("0")); contains(got, "npm install") {
		t.Errorf("exit 2 after a clean install: %q blames the install", got)
	}
	if got := eslintRunError("1", "", "[]", npmDefault.record("1")); got != "" {
		t.Errorf("a run is a run whatever the install did: got %q", got)
	}
}

// TestEslintScriptNeverFetchesEslint: plain npx fetches the newest ESLint when
// the project has none, and ./node_modules/.bin misses a workspace member's
// hoisted one. Every eslint invocation is `npx --no --`.
func TestEslintScriptNeverFetchesEslint(t *testing.T) {
	for _, install := range []bool{true, false} {
		s := eslintScript(npmDefault, install)
		if n := strings.Count(s, "eslint --"); n == 0 || n != strings.Count(s, "npx --no -- eslint --") {
			t.Errorf("install=%v: %d eslint invocations, not all through `npx --no --`:\n%s", install, n, s)
		}
		if strings.Contains(s, "node_modules/.bin") {
			t.Errorf("install=%v: script still names node_modules/.bin:\n%s", install, s)
		}
	}
}

// TestEslintScriptRecordsTheInstall: the install runs only when asked, and its
// exit is written, never swallowed by `|| true`.
func TestEslintScriptRecordsTheInstall(t *testing.T) {
	with := eslintScript(npmDefault, true)
	install := strings.Index(with, "npm install")
	rec := strings.Index(with, "echo $? > "+nodeInstallExitPath)
	if install < 0 || rec < install {
		t.Fatalf("install's exit is not recorded after it:\n%s", with)
	}
	if strings.Contains(with[install:rec], "||") {
		t.Errorf("install exit is swallowed before it is recorded:\n%s", with)
	}
	without := eslintScript(npmDefault, false)
	if strings.Contains(without, "npm install") || strings.Contains(without, nodeInstallExitPath) {
		t.Errorf("prepared path must not install or write an install exit:\n%s", without)
	}
}

// TestEslintScriptRunsNothingWithoutEslint: no version means no eslint
// resolved, so the lint must not run and the recorded exit must be the 127
// eslintRemedy keys on — never 1, which is "found problems".
func TestEslintScriptRunsNothingWithoutEslint(t *testing.T) {
	s := eslintScript(npmDefault, true)
	ver := strings.Index(s, "eslint --version")
	guard := strings.Index(s, "if [ -s "+eslintVersionPath+" ]")
	lint := strings.Index(s, "eslint --format json")
	if ver < 0 || guard < ver || lint < guard {
		t.Fatalf("lint is not guarded by the version read:\n%s", s)
	}
	elseArm := s[strings.Index(s, "else\n"):]
	for _, want := range []string{"echo 127 > " + eslintExitPath, ": > " + eslintReportPath, eslintMissingStderr} {
		if !strings.Contains(elseArm, want) {
			t.Errorf("missing-eslint arm lacks %q:\n%s", want, elseArm)
		}
	}
}
