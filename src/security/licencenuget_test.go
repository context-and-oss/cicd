//go:build unit_test

package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestNuspecSnapshotIsInsideTheRestoreExec is the cache-prune race closed in
// code: the snapshot must be written by the restore script itself, before it
// exits, so it is cached with the lockfiles that exec wrote.
func TestNuspecSnapshotIsInsideTheRestoreExec(t *testing.T) {
	script := dotnetRestoreScript(restoreMount, "/root/.nuget/packages")
	snap := strings.Index(script, nuspecSnapshotPath)
	exit := strings.LastIndex(script, "exit 0")
	if snap < 0 || exit < 0 || snap > exit {
		t.Fatalf("the .nuspec snapshot must run inside the restore script, before exit 0:\n%s", script)
	}
	if !strings.Contains(script, dotnetRestoreNuspecPath) {
		t.Error("the snapshot must record its exit status, or a failed copy reads as no licences")
	}
}

// TestNuspecSnapshotScriptParses: the script is a string glued into sh -c, so
// the only proof it is shell is a shell.
func TestNuspecSnapshotScriptParses(t *testing.T) {
	for name, script := range map[string]string{
		"snapshot": nuspecSnapshotScript("/root/.nuget/packages"),
		"restore":  dotnetRestoreScript(restoreMount, "/root/.nuget/packages"),
	} {
		cmd := exec.Command("sh", "-n")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s script does not parse: %v\n%s\n%s", name, err, out, script)
		}
	}
}

// TestNuspecSnapshotGuardsTheUnmatchedGlob: an empty packages folder leaves the
// literal */*/*.nuspec in $f, and copying that would fail the snapshot of a tree
// that simply has no packages.
func TestNuspecSnapshotGuardsTheUnmatchedGlob(t *testing.T) {
	s := nuspecSnapshotScript("/root/.nuget/packages")
	if !strings.Contains(s, `[ -f "$f" ] || continue`) {
		t.Errorf("unmatched glob is not guarded:\n%s", s)
	}
	if !strings.Contains(s, "|| rc=1") {
		t.Errorf("a failed copy must be recorded, not skipped:\n%s", s)
	}
}

// TestDotnetLicenceRestoreNeededIgnoresTheLockfile is the measurement turned
// into a rule: a committed lockfile gave 0 licences on MediatR, so it must not
// stand the licence restore down the way it stands the dependency restore down.
func TestDotnetLicenceRestoreNeededIgnoresTheLockfile(t *testing.T) {
	files := []string{"/src/Api/Api.csproj", "/src/Api/packages.lock.json"}
	if got := dotnetRestoreNeeded(restoreMount, files); len(got) != 0 {
		t.Fatalf("precondition: the dependency restore stands down on a lockfile, got %v", got)
	}
	if got := dotnetLicenceRestoreNeeded(restoreMount, files); len(got) == 0 {
		t.Error("a .NET tree with a committed lockfile still needs the restore to read any licence")
	}
	if got := dotnetLicenceRestoreNeeded(restoreMount, []string{"/src/package-lock.json"}); len(got) != 0 {
		t.Errorf("a tree without .NET must not restore, got %v", got)
	}
}

func TestDotnetLicenceRestoreErrors(t *testing.T) {
	ok := dotnetRestoreOutcome{
		Band: dotnetSDK80Band, FindExit: "0\n", NuspecExit: "0\n",
		Projects: []string{"Api/Api.csproj", "Legacy/Legacy.csproj"},
	}
	if msg := dotnetLicenceRestoreError(ok); msg != "" {
		t.Fatalf("a clean restore and snapshot is not an error: %s", msg)
	}

	cases := map[string]struct {
		mutate func(*dotnetRestoreOutcome)
		want   []string
	}{
		"find failed": {func(o *dotnetRestoreOutcome) { o.FindExit = "1" }, []string{"find exited 1"}},
		"find silent": {func(o *dotnetRestoreOutcome) { o.FindExit = "" }, []string{"no exit status"}},
		"no projects": {func(o *dotnetRestoreOutcome) { o.Projects = nil }, []string{"found no project file"}},
		"partial": {func(o *dotnetRestoreOutcome) {
			o.Failed = []string{"Legacy/Legacy.csproj"}
			o.Stderr = "error NU1101: Unable to find package Contoso.Internal.\n"
		}, []string{"1 of 2", "Legacy/Legacy.csproj", "does not clear this", "--nuget-feed-url", "NU1101", "restores under no SDK"}},
		"snapshot failed": {func(o *dotnetRestoreOutcome) { o.NuspecExit = "1" }, []string{"could not copy the package metadata"}},
		"snapshot silent": {func(o *dotnetRestoreOutcome) { o.NuspecExit = "" }, []string{"no exit status recorded"}},
	}
	for name, c := range cases {
		o := ok
		o.Projects = append([]string(nil), ok.Projects...)
		c.mutate(&o)
		msg := dotnetLicenceRestoreError(o)
		if !strings.HasPrefix(msg, "security license scan: ") {
			t.Errorf("%s: must be an error naming the licence scan, got %q", name, msg)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(msg, w) {
				t.Errorf("%s: message missing %q:\n%s", name, w, msg)
			}
		}
		if strings.Contains(msg, "vulnerabilit") {
			t.Errorf("%s: the licence error must not speak about vulnerabilities:\n%s", name, msg)
		}
	}
}

// TestLicenceZeroReadIsNeverAnError: SKIPPED passes, so it must never be able
// to stand in for a scan that did not complete.
func TestLicenceZeroReadIsNeverAnError(t *testing.T) {
	if !licenceZeroRead(true, 0, 0) {
		t.Error("a completed scan that read nothing is a zero read")
	}
	if licenceZeroRead(false, 0, 0) {
		t.Error("a scan that did not complete is an error, never SKIPPED")
	}
	if licenceZeroRead(true, 3, 0) {
		t.Error("a scan that read declarations judged something")
	}
	if licenceZeroRead(true, 0, 5) {
		t.Error("declarations the consumer excluded were read; the exclusion warning says so")
	}
}

func TestLicenceZeroReadWarningNamesWhatWasThere(t *testing.T) {
	inputs := []string{"package-lock.json", "a/go.sum", "b/poetry.lock", "c/Cargo.lock"}
	msg := licenceZeroReadWarning(licenceScanTree, inputs)
	for _, w := range []string{"NOT READ", "4 dependency input(s)", "package-lock.json", "b/poetry.lock", ", …", "SKIPPED rather than CLEAN"} {
		if !strings.Contains(msg, w) {
			t.Errorf("missing %q:\n%s", w, msg)
		}
	}
	if strings.Contains(msg, "c/Cargo.lock") {
		t.Error("only the first three inputs are named")
	}
	for mode, want := range map[licenceScanMode]string{
		licenceScanTree:       "NOTHING IN SCOPE — no dependency manifest",
		licenceScanSourceOnly: "NOTHING IN SCOPE — the tree's own files",
		licenceScanSBOM:       "NOT READ — the supplied SBOM",
	} {
		if msg := licenceZeroReadWarning(mode, nil); !strings.Contains(msg, want) || !strings.Contains(msg, "SKIPPED") {
			t.Errorf("mode %d: want %q and SKIPPED, got %q", mode, want, msg)
		}
	}
}

// TestLicenceZeroReadRowIsSkippedAndPasses is the row the envelope ships: a
// zero read reads SKIPPED, still passes, and an error beside it wins.
func TestLicenceZeroReadRowIsSkippedAndPasses(t *testing.T) {
	rows := perToolSources(scopeLicense, SeverityHigh, toolResult{
		Name: "trivy-license", Skipped: licenceZeroRead(true, 0, 0), Concern: ConcernLicenses,
		Examined: &Examined{Unit: "licence declarations", Count: 0},
	})
	if rows[0].Outcome != OutcomeSkipped || !rows[0].Passed {
		t.Fatalf("zero read: outcome %s passed %v, want SKIPPED and passing", rows[0].Outcome, rows[0].Passed)
	}
	if got := sourcesOutcome(rows); got != OutcomeSkipped {
		t.Errorf("envelope outcome %s, want SKIPPED", got)
	}

	rows = perToolSources(scopeLicense, SeverityNone, toolResult{
		Name: "trivy-license", Skipped: licenceZeroRead(false, 0, 0), Concern: ConcernLicenses,
		Err: errString("security license scan: the .NET restore …"),
	})
	if rows[0].Outcome != OutcomeError || rows[0].Passed {
		t.Errorf("a failed restore at NONE: outcome %s passed %v, want ERROR and failing", rows[0].Outcome, rows[0].Passed)
	}
}

type errString string

func (e errString) Error() string { return string(e) }
