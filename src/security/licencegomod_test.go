//go:build unit_test

package main

import (
	"os"
	"strings"
	"testing"
)

// editSection is one go.mod's section of the go mod edit stream, as
// goModEditScript writes it.
func editSection(i, rc, body string) string {
	return goEditMarker + i + " " + rc + "\n" + body + "\n"
}

// probeGoMod is go mod edit -json's output for a go.mod measured with the
// pinned golang image: a public module, a private one, a wildcard replace to
// another public module, and a replace to a local directory.
const probeGoMod = `{
	"Module": {"Path": "example.com/probe"},
	"Go": "1.99",
	"Toolchain": "go1.99.1",
	"Require": [
		{"Path": "github.com/sirupsen/logrus", "Version": "v1.9.3"},
		{"Path": "git.example.invalid/team/lib", "Version": "v1.2.0"},
		{"Path": "github.com/old/thing", "Version": "v1.0.0"},
		{"Path": "git.example.invalid/team/local", "Version": "v0.1.0", "Indirect": true}
	],
	"Replace": [
		{"Old": {"Path": "github.com/old/thing"}, "New": {"Path": "github.com/pkg/errors", "Version": "v0.9.1"}},
		{"Old": {"Path": "git.example.invalid/team/local"}, "New": {"Path": "../local"}}
	]
}`

const secondGoMod = `{"Require": [{"Path": "github.com/sirupsen/logrus", "Version": "v1.9.3"}]}`

func refStrings(refs []goModRef) []string {
	var out []string
	for _, r := range refs {
		out = append(out, r.String())
	}
	return out
}

func TestGoDownloadPlanAppliesReplacesAndDeduplicates(t *testing.T) {
	gomods := []string{"go.mod", "tools/go.mod"}
	stream := editSection("0", "0", probeGoMod) + editSection("1", "0", secondGoMod)
	plan := planGoDownload(gomods, stream)

	if len(plan.Errors) != 0 {
		t.Fatalf("a clean stream raised errors: %v", plan.Errors)
	}
	want := []string{
		"git.example.invalid/team/lib@v1.2.0",
		"github.com/pkg/errors@v0.9.1",
		"github.com/sirupsen/logrus@v1.9.3",
	}
	if got := refStrings(plan.Refs); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("refs = %v, want %v (sorted, deduplicated, replace applied)", got, want)
	}
	// The replaced module is downloaded under its replacement, never the original.
	for _, r := range plan.Refs {
		if r.Path == "github.com/old/thing" {
			t.Errorf("the replaced module itself was planned: %v", r)
		}
	}
	logrus := goModRef{Path: "github.com/sirupsen/logrus", Version: "v1.9.3"}
	if by := plan.RequiredBy[logrus]; len(by) != 2 || by[0] != "go.mod" || by[1] != "tools/go.mod" {
		t.Errorf("RequiredBy[logrus] = %v, want both go.mod files in order", by)
	}
	if len(plan.Local) != 1 || !strings.Contains(plan.Local[0], "git.example.invalid/team/local@v0.1.0 => ../local (go.mod)") {
		t.Errorf("Local = %v, want the directory replace named with its go.mod", plan.Local)
	}
}

// The go command applies a replace naming the required version over one naming
// no version, whatever order go.mod lists them in.
func TestGoReplaceVersionedBeatsWildcard(t *testing.T) {
	for _, order := range []string{"wildcard-first", "versioned-first"} {
		wild := `{"Old": {"Path": "example.com/a"}, "New": {"Path": "example.com/wild", "Version": "v1.0.0"}}`
		pinned := `{"Old": {"Path": "example.com/a", "Version": "v1.2.0"}, "New": {"Path": "example.com/pinned", "Version": "v2.0.0"}}`
		reps := wild + "," + pinned
		if order == "versioned-first" {
			reps = pinned + "," + wild
		}
		doc := `{"Require": [{"Path": "example.com/a", "Version": "v1.2.0"}, {"Path": "example.com/a", "Version": "v1.3.0"}], "Replace": [` + reps + `]}`
		plan := planGoDownload([]string{"go.mod"}, editSection("0", "0", doc))
		got := strings.Join(refStrings(plan.Refs), ",")
		if got != "example.com/pinned@v2.0.0,example.com/wild@v1.0.0" {
			t.Errorf("%s: refs = %s, want the versioned replace for v1.2.0 and the wildcard for v1.3.0", order, got)
		}
	}
}

// Every go.mod go mod edit could not read is an error naming it: Trivy may list
// nothing for a go.mod it cannot parse, so the coverage line cannot show the gap.
func TestGoModEditFailuresAreNamed(t *testing.T) {
	gomods := []string{"a/go.mod", "b/go.mod", "c/go.mod", "d/go.mod"}
	stream := editSection("0", "1", goEditErrMarker+"go: a/go.mod:3: unknown directive: requir") +
		editSection("1", "0", "{not json") +
		editSection("3", "0", secondGoMod)
	plan := planGoDownload(gomods, stream)

	if len(plan.Errors) != 3 {
		t.Fatalf("errors = %d (%v), want one each for a, b and c", len(plan.Errors), plan.Errors)
	}
	for i, want := range []string{
		"go mod edit could not read a/go.mod (exit 1): go: a/go.mod:3: unknown directive: requir",
		"could not parse go mod edit's output for b/go.mod",
		"go mod edit left no result for c/go.mod",
	} {
		if !strings.Contains(plan.Errors[i], want) {
			t.Errorf("error %d = %q, want it to contain %q", i, plan.Errors[i], want)
		}
	}
	if !strings.Contains(plan.Errors[0], "--license-exclude") {
		t.Errorf("the unreadable go.mod error states no remedy: %q", plan.Errors[0])
	}
	if got := refStrings(plan.Refs); len(got) != 1 || got[0] != "github.com/sirupsen/logrus@v1.9.3" {
		t.Errorf("the readable go.mod's modules were not planned: %v", got)
	}
}

// A section marker inside another section's stderr cannot forge a result: the
// stderr lines carry their own prefix.
func TestGoModEditStderrCannotForgeASection(t *testing.T) {
	stream := editSection("0", "1", goEditErrMarker+goEditMarker+"1 0")
	plan := planGoDownload([]string{"a/go.mod", "b/go.mod"}, stream)
	if len(plan.Errors) != 2 || !strings.Contains(plan.Errors[1], "left no result for b/go.mod") {
		t.Errorf("errors = %v, want b/go.mod reported as having no result", plan.Errors)
	}
}

func TestGoModRefValidation(t *testing.T) {
	accept := []goModRef{
		{"github.com/sirupsen/logrus", "v1.9.3"},
		{"golang.org/x/sys", "v0.0.0-20220715151400-c0bba94af5f8"},
		{"github.com/dgrijalva/jwt-go", "v3.2.0+incompatible"},
		{"gopkg.in/yaml.v3", "v3.0.1"},
		{"github.com/BurntSushi/toml", "v1.3.2"},
	}
	for _, r := range accept {
		if why := goModRefRejected(r); why != "" {
			t.Errorf("%s rejected (%s), want accepted", r, why)
		}
	}
	reject := []goModRef{
		{"-x/y", "v1.0.0"},
		{"example.com/has space", "v1.0.0"},
		{"example.com/a;b", "v1.0.0"},
		{"example.com/a'b", "v1.0.0"},
		{"/abs.example/x", "v1.0.0"},
		{"example.com/", "v1.0.0"},
		{"example.com//x", "v1.0.0"},
		{"example.com/../x", "v1.0.0"},
		{"example.com/./x", "v1.0.0"},
		{"nodot/x", "v1.0.0"},
		{"", "v1.0.0"},
		{"example.com/x", "latest"},
		{"example.com/x", "v1.2"},
		{"example.com/x", "-v1.0.0"},
		{"example.com/x", "v1.0.0 extra"},
	}
	for _, r := range reject {
		if why := goModRefRejected(r); why == "" {
			t.Errorf("%q accepted, want rejected", r.String())
		}
	}
	doc := `{"Require": [{"Path": "nodot/x", "Version": "v1.0.0"}]}`
	plan := planGoDownload([]string{"go.mod"}, editSection("0", "0", doc))
	if len(plan.Refs) != 0 || len(plan.Rejected) != 1 || !strings.Contains(plan.Rejected[0], `"nodot/x@v1.0.0" (go.mod: `) {
		t.Errorf("plan = %+v, want the bad ref rejected and named", plan)
	}
}

// Measured: the module cache writes github.com/BurntSushi/toml under
// github.com/!burnt!sushi/toml@v1.3.2.
func TestGoCacheRelEscapesCase(t *testing.T) {
	got := goCacheRel(goModRef{"github.com/BurntSushi/toml", "v1.3.2"})
	if got != "github.com/!burnt!sushi/toml@v1.3.2" {
		t.Errorf("goCacheRel = %q", got)
	}
	if got := goCacheRel(goModRef{"example.com/x", "v1.0.0-RC1"}); got != "example.com/x@v1.0.0-!r!c1" {
		t.Errorf("goCacheRel escaped the path but not the version: %q", got)
	}
}

func goPlanOf(t *testing.T, gm string, refs ...goModRef) goDownloadPlan {
	t.Helper()
	plan := goDownloadPlan{GoMods: []string{gm}, RequiredBy: map[goModRef][]string{}}
	for _, r := range refs {
		plan.Refs = append(plan.Refs, r)
		plan.RequiredBy[r] = []string{gm}
	}
	return plan
}

func goOK(r goModRef) string {
	return `{"Path":"` + r.Path + `","Version":"` + r.Version + `","Dir":"` + goModCachePath + "/" + goCacheRel(r) + `"}` + "\n"
}

func goFail(r goModRef, msg string) string {
	return `{"Path":"` + r.Path + `","Version":"` + r.Version + `","Error":"` + msg + `"}` + "\n"
}

var (
	logrusRef  = goModRef{"github.com/sirupsen/logrus", "v1.9.3"}
	tomlRef    = goModRef{"github.com/BurntSushi/toml", "v1.3.2"}
	privateRef = goModRef{"git.example.invalid/team/lib", "v1.2.0"}
	goneRef    = goModRef{"example.com/gone", "v1.0.0"}
	brokenRef  = goModRef{"example.com/broken", "v1.0.0"}
)

func TestClassifyGoDownloadSortsEveryModule(t *testing.T) {
	plan := goPlanOf(t, "go.mod", logrusRef, tomlRef, privateRef, goneRef, brokenRef)
	run := goDownloadRun{
		Exit: "123\n",
		JSON: goOK(logrusRef) + goOK(tomlRef) +
			goFail(privateRef, `git.example.invalid/team/lib@v1.2.0: reading https://proxy.golang.org/git.example.invalid/team/lib/@v/v1.2.0.info: 404 Not Found\n\tserver response: not found`) +
			goFail(goneRef, `example.com/gone@v1.0.0: reading https://proxy.golang.org/example.com/gone/@v/v1.0.0.info: 410 Gone`) +
			goFail(brokenRef, `example.com/broken@v1.0.0: verifying module: checksum mismatch`),
		Copied: goCacheRel(logrusRef) + "\n" + goCacheRel(tomlRef) + "\n",
	}
	out := classifyGoDownload(plan, run)
	if len(out.Errors) != 0 {
		t.Fatalf("a download that failed only per module raised errors: %v", out.Errors)
	}
	if out.Downloaded != 2 {
		t.Errorf("Downloaded = %d, want 2", out.Downloaded)
	}
	if len(out.NotServed) != 2 || !strings.Contains(out.NotServed[0], "git.example.invalid/team/lib@v1.2.0 (go.mod)") {
		t.Errorf("NotServed = %v, want the 404 and the 410", out.NotServed)
	}
	if len(out.Failed) != 1 || !strings.Contains(out.Failed[0], "verifying module: checksum mismatch") {
		t.Errorf("Failed = %v, want the checksum failure with the go command's line", out.Failed)
	}
}

// A 404 from anywhere but the proxy is not "not served": cicd only asks the
// proxy, so such a line is something else going wrong.
func TestGoNotServedNeedsTheProxy(t *testing.T) {
	if goNotServed("reading https://other.example/x/@v/v1.0.0.info: 404 Not Found") {
		t.Error("a 404 from another host was read as the proxy refusing the module")
	}
	if goNotServed("reading https://proxy.golang.org/x/@v/v1.0.0.info: 500 Internal Server Error") {
		t.Error("a proxy 500 was read as the module not being served")
	}
}

// What makes the download's own result unknown is an error; each of these was
// a way for a module to vanish from the count without being named.
func TestClassifyGoDownloadUnknownOutcomesAreErrors(t *testing.T) {
	plan := goPlanOf(t, "go.mod", logrusRef, tomlRef)
	both := goCacheRel(logrusRef) + "\n" + goCacheRel(tomlRef) + "\n"
	cases := []struct {
		name string
		run  goDownloadRun
		want string
	}{
		{"xargs did not run", goDownloadRun{Exit: "127", Stderr: "sh: xargs: not found"}, "did not run (xargs exited 127), so no Go module licence was read: sh: xargs: not found"},
		{"no exit status", goDownloadRun{}, "recorded no exit status"},
		{"unparseable output", goDownloadRun{Exit: "0", JSON: goOK(logrusRef) + "{oops", Copied: both}, "could not parse"},
		{"no result for a module", goDownloadRun{Exit: "0", JSON: goOK(logrusRef), Copied: both}, "returned no result for 1 module(s) (github.com/BurntSushi/toml@v1.3.2 (go.mod))"},
		{"a result somewhere else", goDownloadRun{Exit: "0", JSON: goOK(logrusRef) +
			`{"Path":"` + tomlRef.Path + `","Version":"` + tomlRef.Version + `","Dir":"/root/go/pkg/mod/x"}`, Copied: both}, "where cicd did not look"},
		{"copy failed", goDownloadRun{Exit: "0", JSON: goOK(logrusRef) + goOK(tomlRef), Copied: goCacheRel(logrusRef), CopyFailed: goCacheRel(tomlRef)}, "could not be copied for Trivy (github.com/BurntSushi/toml@v1.3.2 (go.mod))"},
		{"never copied", goDownloadRun{Exit: "0", JSON: goOK(logrusRef) + goOK(tomlRef), Copied: goCacheRel(logrusRef)}, "(not in the module cache)"},
	}
	for _, c := range cases {
		out := classifyGoDownload(plan, c.run)
		if len(out.Errors) == 0 || !strings.Contains(strings.Join(out.Errors, " | "), c.want) {
			t.Errorf("%s: errors = %v, want one containing %q", c.name, out.Errors, c.want)
		}
		if out.Downloaded == 2 {
			t.Errorf("%s: counted every module as downloaded", c.name)
		}
	}
}

func goCov(targets ...string) *licenceCoverage {
	return &licenceCoverage{Ecosystems: []licenceEcosystemCoverage{{Type: "gomod", Targets: targets}}}
}

func TestGoLicenceDownloadWarningComplete(t *testing.T) {
	plan := goPlanOf(t, "go.mod", logrusRef, tomlRef)
	out := goDownloadOutcome{Plan: plan, Downloaded: 2}
	msg := goLicenceDownloadWarning(out, goCov("go.mod"))
	for _, want := range []string{
		"cicd downloaded 2 of 2 module(s) required by 1 go.mod file(s) from https://proxy.golang.org",
		"never a module's own host",
		"Trivy listed the modules of every go.mod file.",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("warning lacks %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "Not downloaded") || strings.Contains(msg, "credential") {
		t.Errorf("a complete download named a gap:\n%s", msg)
	}
}

func TestGoLicenceDownloadWarningNamesEveryGap(t *testing.T) {
	plan := goPlanOf(t, "go.mod", logrusRef, privateRef, brokenRef)
	plan.GoMods = append(plan.GoMods, "tools/go.mod")
	plan.Local = []string{"example.com/l@v0.1.0 => ../l (go.mod)"}
	plan.Rejected = []string{`"nodot/x@v1.0.0" (go.mod: no dot)`}
	out := goDownloadOutcome{
		Plan:       plan,
		Downloaded: 1,
		NotServed:  []string{"git.example.invalid/team/lib@v1.2.0 (go.mod)"},
		Failed:     []string{"example.com/broken@v1.0.0 (go.mod): checksum mismatch"},
	}
	msg := goLicenceDownloadWarning(out, goCov("go.mod"))
	for _, want := range []string{
		"downloaded 1 of 3 module(s) required by 2 go.mod file(s)",
		"1 not served by the Go module proxy, which is what a private module looks like (git.example.invalid/team/lib@v1.2.0 (go.mod))",
		"1 failed to download (example.com/broken@v1.0.0 (go.mod): checksum mismatch)",
		"1 replaced by a local directory (example.com/l@v0.1.0 => ../l (go.mod))",
		`1 not passed to the go command ("nodot/x@v1.0.0"`,
		"cicd has no Go credential input",
		"Trivy listed the modules of 1 of the go.mod files; it listed none for 1 (tools/go.mod)",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("warning lacks %q:\n%s", want, msg)
		}
	}
}

// A scan that did not complete claims nothing about what it read.
func TestGoLicenceDownloadWarningWithoutAScan(t *testing.T) {
	out := goDownloadOutcome{Plan: goPlanOf(t, "go.mod", logrusRef), Downloaded: 1}
	msg := goLicenceDownloadWarning(out, nil)
	if !strings.Contains(msg, "The scan did not complete") || strings.Contains(msg, "Trivy listed") {
		t.Errorf("warning over an incomplete scan:\n%s", msg)
	}
}

func TestGoLicenceDownloadWarningSilentWhenNothingWasAsked(t *testing.T) {
	out := goDownloadOutcome{Plan: goDownloadPlan{GoMods: []string{"go.mod"}}}
	if msg := goLicenceDownloadWarning(out, goCov("go.mod")); msg != "" {
		t.Errorf("a go.mod with no requirement produced a warning: %q", msg)
	}
}

func TestGoLicenceDownloadNeededFindsEveryGoMod(t *testing.T) {
	files := []string{"/src/go.mod", "/src/go.sum", "/src/tools/go.mod", "/src/vendor/modules.txt", "/src/x/notgo.mod", ""}
	got := goLicenceDownloadNeeded(trivyConfigDir, files)
	if strings.Join(got, ",") != "go.mod,tools/go.mod" {
		t.Errorf("goLicenceDownloadNeeded = %v", got)
	}
}

// The go.mod paths reach the container as argv, never as script text, and the
// module list as a data file: a path or module name is never shell source.
func TestGoScriptsCarryNoConsumerValue(t *testing.T) {
	edit := goModEditScript()
	if !strings.Contains(edit, `for f in "$@"; do`) || !strings.Contains(edit, `go mod edit -json "$f"`) {
		t.Errorf("go mod edit does not read its paths from argv:\n%s", edit)
	}
	dl := goDownloadScript()
	if !strings.Contains(dl, "go mod download -json < "+goDownloadArgsPath) {
		t.Errorf("go mod download does not read its modules from the data file:\n%s", dl)
	}
	if !strings.Contains(dl, `[ -f "$f" ] || continue`) {
		t.Errorf("the snapshot copies more than each module's top-level files:\n%s", dl)
	}
}

// The proxy is the only source. A `direct` entry would let a go.mod point this
// container at any host its module path names; the wiring is Dagger code the
// unit suite cannot execute, so the guard reads the source.
func TestGoDownloadUsesTheProxyOnlyAndAPrivateCache(t *testing.T) {
	if goModuleProxy != "https://proxy.golang.org" {
		t.Errorf("goModuleProxy = %q, want the Go module proxy alone", goModuleProxy)
	}
	raw, err := os.ReadFile("goexec.go")
	if err != nil {
		t.Fatalf("cannot read goexec.go, so the guard did not run: %v", err)
	}
	src := string(raw)
	for _, want := range []string{
		`WithEnvVariable("GOPROXY", goModuleProxy)`,
		`WithEnvVariable("GOTOOLCHAIN", "local")`,
		`WithEnvVariable("GOFLAGS", "")`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("goexec.go lacks %s", want)
		}
	}
	for _, banned := range []string{"direct", "GONOSUMDB", "GOSUMDB", "GOPRIVATE", "GOINSECURE", "GONOPROXY"} {
		if strings.Contains(src, banned) {
			t.Errorf("goexec.go mentions %s, which widens where a module is fetched from or skips its checksum", banned)
		}
	}
	mounts := 0
	for _, line := range strings.Split(src, "\n") {
		if !strings.Contains(line, "WithMountedCache(goModCachePath") {
			continue
		}
		mounts++
		if !strings.Contains(line, "Sharing: dagger.CacheSharingModePrivate") {
			t.Errorf("Go module cache mounted without CacheSharingModePrivate:\n%s", strings.TrimSpace(line))
		}
	}
	if mounts == 0 {
		t.Fatal("no Go module cache mount found in goexec.go; the guard matched nothing")
	}
}
