package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Unset is unset: a blank value parses to the zero policy, which is what
// keeps the archive scan byte-for-byte what it was before either flag existed.
func TestParseGitleaksPolicyUnset(t *testing.T) {
	for _, v := range []string{"", "  ", "\n\t"} {
		p, err := parseGitleaksPolicy("archive-gitleaks-config", v, "archive-gitleaks-ignore", v)
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		if p.set() || p != (gitleaksPolicy{}) {
			t.Errorf("%q parsed to %+v, want the zero policy", v, p)
		}
		if args := gitleaksPolicyArgs(p); len(args) != 0 {
			t.Errorf("%q: unset policy adds args %q", v, args)
		}
	}
}

func TestGitleaksPolicyPath(t *testing.T) {
	ok := map[string]string{
		".gitleaks.archive.toml":      ".gitleaks.archive.toml",
		"./.gitleaks.archive.toml":    ".gitleaks.archive.toml",
		" ci/gitleaks/archive.toml ":  "ci/gitleaks/archive.toml",
		"web/.gitleaksignore.archive": "web/.gitleaksignore.archive",
		"a..b/name..toml":             "a..b/name..toml",
	}
	for in, want := range ok {
		got, err := gitleaksPolicyPath("archive-gitleaks-config", in)
		if err != nil || got != want {
			t.Errorf("%q = %q, %v; want %q", in, got, err, want)
		}
	}
	refused := map[string]string{
		"/etc/gitleaks.toml":       "an absolute path",
		"../.gitleaks.toml":        "a .. segment",
		"ci/../../.gitleaks.toml":  "a .. segment",
		"ci/..":                    "a .. segment",
		`ci\gitleaks.toml`:         "a backslash",
		"C:/gitleaks.toml":         "a drive letter",
		".":                        "an empty or . segment",
		"ci//gitleaks.toml":        "an empty or . segment",
		"ci/":                      "an empty or . segment",
		"ci/./gitleaks.toml":       "an empty or . segment",
		"ci/gitleaks\x00.toml":     "a control character",
		"ci/gitleaks.toml\nx.toml": "a control character",
	}
	for in, why := range refused {
		_, err := gitleaksPolicyPath("archive-gitleaks-config", in)
		if err == nil {
			t.Errorf("%q accepted, want refused (%s)", in, why)
			continue
		}
		if !strings.HasPrefix(err.Error(), "--archive-gitleaks-config ") || !strings.Contains(err.Error(), why) {
			t.Errorf("%q: error %q does not name the flag and %q", in, err, why)
		}
	}
	// The ignore flag is checked by the same rule, and named in its own error.
	if _, err := parseGitleaksPolicy("archive-gitleaks-config", "", "archive-gitleaks-ignore", "/x"); err == nil ||
		!strings.HasPrefix(err.Error(), "--archive-gitleaks-ignore ") {
		t.Errorf("ignore path: %v", err)
	}
}

// runResolveScript runs gitleaksPolicyResolveScript under sh against root and
// returns the status word and the copied content.
func runResolveScript(t *testing.T, root, rel string) (status, content string) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "out")
	cmd := exec.Command("sh", "-c", gitleaksPolicyResolveScript, "sh", out, root, rel, "config.toml")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("script exited non-zero: %v\n%s", err, b)
	}
	s, err := os.ReadFile(filepath.Join(out, "config.toml.status"))
	if err != nil {
		t.Fatalf("no status: %v", err)
	}
	c, _ := os.ReadFile(filepath.Join(out, "config.toml"))
	return strings.TrimSpace(string(s)), string(c)
}

// The resolve script is the check the path's spelling cannot make: the file
// must exist, be a regular file, and not reach outside the tree through a
// symlink, however the link is spelt. Real symlinks, real directories.
func TestGitleaksPolicyResolveScript(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "src")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{filepath.Join(root, "ci", "nested"), outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, body string) {
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, name string) {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, ".gitleaks.archive.toml"), "[extend]\nuseDefault = true\n")
	write(filepath.Join(root, "ci", "nested", "real.toml"), "inside\n")
	write(filepath.Join(outside, "evil.toml"), "outside\n")
	link(filepath.Join(outside, "evil.toml"), "abs-escape.toml")
	link("../outside/evil.toml", "rel-escape.toml")
	link(outside, "outdir")
	link("ci/nested/real.toml", "inside-link.toml")
	link("ci/nested/gone.toml", "dangling.toml")
	link(filepath.Join(outside, "gone.toml"), "dangling-out.toml")
	// The shape a Dagger upload produces: the link travels, its out-of-tree
	// target does not.
	link("../not-uploaded/evil.toml", "uploaded-escape.toml")

	cases := []struct {
		rel, status, content string
	}{
		{".gitleaks.archive.toml", "ok", "[extend]\nuseDefault = true\n"},
		{"ci/nested/real.toml", "ok", "inside\n"},
		{"inside-link.toml", "ok", "inside\n"},
		{"absent.toml", "missing", ""},
		{"ci/absent/x.toml", "missing", ""},
		{"ci", "notfile", ""},
		{"abs-escape.toml", "escape", ""},
		{"rel-escape.toml", "escape", ""},
		{"outdir/evil.toml", "escape", ""},
		{"dangling.toml", "dangling", ""},
		{"dangling-out.toml", "dangling", ""},
		{"uploaded-escape.toml", "dangling", ""},
	}
	for _, tc := range cases {
		status, content := runResolveScript(t, root, tc.rel)
		if status != tc.status || content != tc.content {
			t.Errorf("%s: status %q content %q; want %q %q", tc.rel, status, content, tc.status, tc.content)
		}
	}
}

func TestGitleaksPolicyStatusError(t *testing.T) {
	if err := gitleaksPolicyStatusError("config", ".gitleaks.archive.toml", "ok\n"); err != nil {
		t.Fatalf("ok: %v", err)
	}
	for status, want := range map[string]string{
		"missing":    "gitleaks: the config .gitleaks.archive.toml does not exist in the source tree",
		"escape":     "resolves, through a symlink, to a file outside the source tree",
		"dangling":   "is a symbolic link whose target is not in the source tree",
		"notfile":    "is not a regular file in the source tree",
		"unreadable": "could not be read from the source tree",
		"":           `could not be checked (resolve status "")`,
		"weird":      `could not be checked (resolve status "weird")`,
	} {
		err := gitleaksPolicyStatusError("config", ".gitleaks.archive.toml", status)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want it to contain %q", status, err, want)
		}
		if err != nil && !strings.Contains(err.Error(), "not scanned") {
			t.Errorf("%q: %q does not say the output was not scanned", status, err)
		}
	}
}

// Supplied files beside the output's own root files are refused; unset, the
// output's root files are honoured as they always were.
func TestGitleaksPolicyCollision(t *testing.T) {
	supplied := gitleaksPolicy{Config: ".gitleaks.archive.toml"}
	if err := gitleaksPolicyCollision([]string{".gitleaks.toml", ".gitleaksignore", "index.html"}, gitleaksPolicy{}, "build output"); err != nil {
		t.Errorf("unset policy refused the output's own files: %v", err)
	}
	if err := gitleaksPolicyCollision([]string{"index.html", ".gitleaks.toml/"}, supplied, "build output"); err != nil {
		t.Errorf("a directory named .gitleaks.toml is not the file: %v", err)
	}
	err := gitleaksPolicyCollision([]string{".gitleaksignore", "index.html"}, gitleaksPolicy{Ignore: "x.ignore"}, "build output")
	want := "gitleaks: the build output's root carries .gitleaksignore, and a gitleaks config or ignore file was also supplied from the source tree; " +
		"two sources of acceptance cannot be reported as one, so the build output was not scanned. " +
		"Remove the scanner file from the build output (it ships with the deployable), or stop supplying one from the source tree"
	if err == nil || err.Error() != want {
		t.Errorf("got %v\nwant %s", err, want)
	}
	err = gitleaksPolicyCollision([]string{".gitleaks.toml", ".gitleaksignore"}, supplied, "build output")
	if err == nil || !strings.Contains(err.Error(), "carries .gitleaks.toml and .gitleaksignore,") {
		t.Errorf("both root files: %v", err)
	}
}

func TestGitleaksConfigExtendsPath(t *testing.T) {
	yes := []string{
		"[extend]\npath = \"base.toml\"\n",
		"[extend]\nuseDefault = true\n  path='x.toml' # trailing\n",
		"[ extend ]\n\"path\" = \"x\"\n",
		"title = \"x\"\nextend.path = \"base.toml\"\n",
		"extend = { path = \"base.toml\" }\n",
	}
	no := []string{
		"",
		"[extend]\nuseDefault = true\n",
		"[extend]\n# path = \"base.toml\"\nuseDefault = true\n",
		"[[allowlists]]\npaths = ['''^wwwroot/assets/[^/]+\\.js$''']\n",
		"[[rules]]\nid = \"x\"\npath = '''\\.env$'''\n",
		"[extend]\nuseDefault = true\n[[rules]]\npath = \"x\"\n",
	}
	for _, c := range yes {
		if !gitleaksConfigExtendsPath(c) {
			t.Errorf("not detected:\n%s", c)
		}
	}
	for _, c := range no {
		if gitleaksConfigExtendsPath(c) {
			t.Errorf("false positive:\n%s", c)
		}
	}
}

// The supplied files are passed on the primary leg, from outside /src.
func TestGitleaksPolicyArgs(t *testing.T) {
	got := gitleaksPolicyArgs(gitleaksPolicy{Config: "a.toml", Ignore: "b.ignore"})
	want := []string{"--config", "/cicd-gitleaks/config.toml", "--gitleaks-ignore-path", "/cicd-gitleaks/gitleaksignore"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	for _, a := range got {
		if strings.HasPrefix(a, "/src") {
			t.Errorf("%q is inside the scanned tree", a)
		}
	}
	if got := gitleaksPolicyArgs(gitleaksPolicy{Ignore: "b.ignore"}); !reflect.DeepEqual(got, want[2:]) {
		t.Errorf("ignore only: %q", got)
	}
}

// The evidence records which files were used, and which version of them.
func TestGitleaksPolicyRecord(t *testing.T) {
	d := gitleaksPolicyDigest("[extend]\nuseDefault = true\n")
	if !strings.HasPrefix(d, "sha256:") || len(d) != len("sha256:")+16 {
		t.Fatalf("digest %q", d)
	}
	if d == gitleaksPolicyDigest("[extend]\nuseDefault = false\n") {
		t.Fatal("digest does not follow the content")
	}
	got := gitleaksPolicyRecord(gitleaksPolicy{Config: ".gitleaks.archive.toml"}, d, "", "build output")
	want := "gitleaks: SUPPLIED POLICY — the build output was scanned with the config .gitleaks.archive.toml (" + d +
		"), read from the source tree and not from the build output; what it removed is listed as SUPPRESSED, " +
		"and a default rule it does not load as NARROWED RULES"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	got = gitleaksPolicyRecord(gitleaksPolicy{Ignore: "ci/archive.ignore"}, "", "sha256:00", "build output")
	if !strings.Contains(got, "scanned with gitleaks' default rules and the ignore file ci/archive.ignore (sha256:00),") {
		t.Errorf("ignore only: %s", got)
	}
}

// The concrete case: gitleaks' generic-api-key matches a minified UI
// library's prop read in a hashed bundle, and a narrow allowlist in the
// supplied config removes it. The finding stays in the evidence, suppressed
// and named under the supplied file, and the default rules all loaded.
func TestGitleaksDisclosesSuppliedConfig(t *testing.T) {
	const bundle = "wwwroot/assets/index-Cx9aB2kQ.js"
	rules := append([]string{"generic-api-key"}, glDefaults...)
	primary := glSARIF(rules)
	shadow := glSARIF(rules, glResult{"generic-api-key", bundle, 1, 0})
	origin := gitleaksSuppliedOrigin(gitleaksPolicy{Config: ".gitleaks.archive.toml"})

	out, warnings := gitleaksDiscloseSuppressions(primary, shadow, nil, nil, true, origin, "build output")
	want := []string{"gitleaks: SUPPRESSED — 1 finding in the build output was removed by the source tree's " +
		".gitleaks.archive.toml, the config supplied for this scan (an [allowlist] entry, or a default rule it disables, " +
		"narrows or does not load) and is not counted: \"" + bundle + ":1 generic-api-key\""}
	if !reflect.DeepEqual(warnings, want) {
		t.Errorf("warnings\n got %q\nwant %q", warnings, want)
	}
	got := suppressedBy(t, out)["generic-api-key:"+bundle]
	if !strings.HasPrefix(got, "external removed by the source tree's .gitleaks.archive.toml, the config supplied for this scan") {
		t.Errorf("suppression %q", got)
	}
	if n := len(gitleaksFindings(out)); n != 0 {
		t.Errorf("the suppressed finding is counted: %d findings", n)
	}
}

// A supplied config that does not extend the defaults loads only its own
// rules, and the default rules it leaves out are named under its name.
func TestGitleaksNarrowedRulesNamesSuppliedConfig(t *testing.T) {
	primary := glSARIF([]string{"custom-token"})
	shadow := glSARIF(glDefaults)
	origin := gitleaksSuppliedOrigin(gitleaksPolicy{Config: "ci/archive.toml"})
	_, warnings := gitleaksDiscloseSuppressions(primary, shadow, nil, nil, true, origin, "build output")
	want := []string{"gitleaks: NARROWED RULES — the config supplied for the build output, the source tree's ci/archive.toml, " +
		"loads 1 rule and leaves out 3 of gitleaks' 3 default rules, which searched for nothing: " +
		"\"aws-access-token\", \"github-pat\", \"private-key\""}
	if !reflect.DeepEqual(warnings, want) {
		t.Errorf("warnings\n got %q\nwant %q", warnings, want)
	}
}

// An ignore file supplied without a config: the removal is pinned on the
// supplied file by its fingerprint, and nothing is pinned on a config.
func TestGitleaksDisclosesSuppliedIgnore(t *testing.T) {
	primary := glSARIF(glDefaults)
	shadow := glSARIF(glDefaults,
		glResult{"github-pat", "app/main.js", 4, 0},
		glResult{"aws-access-token", "app/other.js", 9, 0})
	ignored := parseGitleaksIgnored("app/main.js:github-pat:4\n")
	origin := gitleaksSuppliedOrigin(gitleaksPolicy{Ignore: "ci/archive.gitleaksignore"})
	_, warnings := gitleaksDiscloseSuppressions(primary, shadow, ignored, nil, true, origin, "build output")
	want := []string{
		"gitleaks: SUPPRESSED — 1 finding in the build output was removed by a fingerprint in the source tree's " +
			"ci/archive.gitleaksignore, the ignore file supplied for this scan and is not counted: \"app/main.js:4 github-pat\"",
		"gitleaks: SUPPRESSED — 1 finding in the build output was removed by a suppression cicd could not identify " +
			"(a gitleaks:allow inside an archive, or in a tree whose marks could not be listed) and is not counted: " +
			"\"app/other.js:9 aws-access-token\"",
	}
	if !reflect.DeepEqual(warnings, want) {
		t.Errorf("warnings\n got %q\nwant %q", warnings, want)
	}
}

// The default origin names the scanned tree's own files exactly as before.
func TestGitleaksTreeOriginIsUnchanged(t *testing.T) {
	o := gitleaksTreeOrigin(true)
	if got := o.ignoreName(); got != ".gitleaksignore" {
		t.Errorf("ignore %q", got)
	}
	if got := o.configName(); got != "the scanned tree's .gitleaks.toml" {
		t.Errorf("config %q", got)
	}
	if got := o.narrowedSubject("source tree"); got != "the source tree's .gitleaks.toml" {
		t.Errorf("narrowed %q", got)
	}
}
