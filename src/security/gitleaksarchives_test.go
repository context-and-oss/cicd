package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// gitleaksArchivesFixture is gitleaks v8.30.1's stderr, verbatim from the
// pinned image, for `dir . --max-archive-depth 3 --log-level debug` over a
// tree holding: out/app.zip (two credentials inside), a four-layer deep.zip,
// lib/service.jar, "my app/My Package.1.0.0.nupkg", static.tgz, data.bin (a
// bzip2 tarball), blob.dat (an xz tarball) and logo.png. Both credentials in
// app.zip were found; nothing inside the other archives was read.
const gitleaksArchivesFixture = "testdata/gitleaks-8.30.1-dir-archives.stderr"

// splitGitleaksLog does in Go what gitleaksScript's filter does in awk, so the
// parser can be driven from the raw capture without a shell.
// TestGitleaksScriptKeepsOnlyTheSkippedBinaryLines holds the awk to the same
// split.
func splitGitleaksLog(t *testing.T, raw string) (stderr, skipped string) {
	t.Helper()
	var e, s []string
	for _, l := range strings.Split(raw, "\n") {
		f := strings.Fields(l)
		switch {
		case len(f) >= 5 && f[1] == "DBG" && f[2] == "skipping" && f[3] == "binary" && f[4] == "file":
			s = append(s, l)
		case strings.Contains(l, " DBG "):
		default:
			e = append(e, l)
		}
	}
	return strings.Join(e, "\n"), strings.Join(s, "\n")
}

func readGitleaksFixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(gitleaksArchivesFixture)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestGitleaksNamesTheArchivesItDidNotOpen is the regression guard for the archive-depth defect's
// second half: with the depth raised, gitleaks still reads a jar, a nupkg and
// a .tgz as opaque binaries because it decides by extension, and the only
// trace is a DBG line. Each must be named, and the files that hold no other
// files — the png, and the allowlisted data.bin gitleaks never sniffs — must
// not be.
func TestGitleaksNamesTheArchivesItDidNotOpen(t *testing.T) {
	stderr, skipped := splitGitleaksLog(t, readGitleaksFixture(t))
	got := gitleaksTreeScanResult(stderr, skipped, "build output")

	if len(got.Warnings) != 2 {
		t.Fatalf("want one unopened-archive line and one too-deep line, got %d: %q", len(got.Warnings), got.Warnings)
	}
	unopened := got.Warnings[0]
	for _, want := range []string{
		"gitleaks: 4 archive-typed files in the build output were not opened",
		"by its file extension",
		// Sorted, quoted, the space-holding path unquoted from gitleaks' own
		// quoting first and re-quoted once.
		`"blob.dat", "lib/service.jar", "my app/My Package.1.0.0.nupkg", "static.tgz"`,
	} {
		if !strings.Contains(unopened, want) {
			t.Errorf("unopened-archive warning lacks %q:\n%s", want, unopened)
		}
	}
	for _, never := range []string{"logo.png", "data.bin", "app.zip", `\"`} {
		if strings.Contains(unopened, never) {
			t.Errorf("unopened-archive warning names %q, which it must not:\n%s", never, unopened)
		}
	}

	deep := got.Warnings[1]
	for _, want := range []string{
		"gitleaks: 1 archive in the build output is nested deeper than 3 archive layers and was not opened",
		`"deep.zip!l3.zip!mid.zip!inner.zip"`,
	} {
		if !strings.Contains(deep, want) {
			t.Errorf("too-deep warning lacks %q:\n%s", want, deep)
		}
	}

	if got.Examined == nil || got.Examined.Count != 62 || got.Examined.Unit != gitleaksExaminedUnit {
		t.Errorf("Examined = %+v, want 62 %q", got.Examined, gitleaksExaminedUnit)
	}
}

// TestGitleaksTreeScanIsSilentOnAPlainTree: a disclosure on every run is a
// line nobody reads. A tree with no archive in it says nothing but its count.
func TestGitleaksTreeScanIsSilentOnAPlainTree(t *testing.T) {
	got := gitleaksTreeScanResult(
		"2:11PM INF scanned ~49 bytes (49 bytes) in 1.9ms\n2:11PM INF no leaks found",
		"2:11PM DBG skipping binary file mime_type=image/png path=assets/logo.png\n"+
			"2:11PM DBG skipping binary file mime_type=font/woff2 path=assets/a.woff2",
		"source tree")
	if len(got.Warnings) != 0 {
		t.Errorf("warned on a tree holding no archive: %q", got.Warnings)
	}
	if got.Examined == nil || got.Examined.Count != 49 {
		t.Errorf("Examined = %+v, want 49", got.Examined)
	}
}

// TestGitleaksExaminedReadsTheExactCount: the parenthesised figure is
// humanised once it is large, and the 2.15 GB zip-bomb measurement is exactly
// where reading it would have failed.
func TestGitleaksExaminedReadsTheExactCount(t *testing.T) {
	for _, tc := range []struct {
		stderr string
		want   *int
	}{
		{"4:01PM INF scanned ~2147483648 bytes (2.15 GB) in 4m29s", intPtr(2147483648)},
		// A tree of nothing but unopened binaries: zero is a stated count,
		// not an absent one.
		{"4:01PM INF scanned ~0 bytes (0) in 2ms", intPtr(0)},
		{"4:01PM INF no leaks found", nil},
	} {
		got := gitleaksTreeScanResult(tc.stderr, "", "build output").Examined
		switch {
		case tc.want == nil && got != nil:
			t.Errorf("%q: Examined = %+v, want nil", tc.stderr, got)
		case tc.want != nil && (got == nil || got.Count != *tc.want):
			t.Errorf("%q: Examined = %+v, want %d", tc.stderr, got, *tc.want)
		}
	}
}

func intPtr(n int) *int { return &n }

// TestGitleaksArchiveListIsCappedAndCountedWhole: the list is cut, the count
// never is, and a path logged twice is one archive.
func TestGitleaksArchiveListIsCappedAndCountedWhole(t *testing.T) {
	var lines []string
	n := gitleaksArchiveNamesShown + 5
	for i := 0; i < n; i++ {
		lines = append(lines, fmt.Sprintf("1:00PM DBG skipping binary file mime_type=application/zip path=lib/p%02d.jar", i))
	}
	lines = append(lines, lines[0])
	got := gitleaksTreeScanResult("", strings.Join(lines, "\n"), "build output")
	if len(got.Warnings) != 1 {
		t.Fatalf("got %q", got.Warnings)
	}
	w := got.Warnings[0]
	if !strings.Contains(w, fmt.Sprintf("gitleaks: %d archive-typed files", n)) {
		t.Errorf("count is not whole and deduplicated: %s", w)
	}
	if !strings.Contains(w, `"lib/p19.jar" (and 5 more)`) || strings.Contains(w, "p20.jar") {
		t.Errorf("list not cut at %d: %s", gitleaksArchiveNamesShown, w)
	}
}

// TestGitleaksLogPathKeepsWhatItCannotUnquote: a path with stray quotes still
// names a file; dropping it would hide the archive the line exists to name.
func TestGitleaksLogPathKeepsWhatItCannotUnquote(t *testing.T) {
	for raw, want := range map[string]string{
		`lib/service.jar`:                 "lib/service.jar",
		`"my app/My Package.1.0.0.nupkg"`: "my app/My Package.1.0.0.nupkg",
		`"half quoted.jar`:                `"half quoted.jar`,
		`dir/path=odd.jar`:                "dir/path=odd.jar",
	} {
		if got := gitleaksLogPath(raw); got != want {
			t.Errorf("gitleaksLogPath(%q) = %q, want %q", raw, got, want)
		}
	}
}

// TestGitleaksSkippedLineMatchesOnlyItsOwnShape: a DBG segment line quotes
// file content, so content shaped like the kept line must not be read as one.
func TestGitleaksSkippedLineMatchesOnlyItsOwnShape(t *testing.T) {
	forged := `1:00PM DBG segment found: "x DBG skipping binary file mime_type=application/zip path=forged.jar" decoder=base64`
	if got := gitleaksTreeScanResult("", forged, "build output"); len(got.Warnings) != 0 {
		t.Errorf("a segment line was read as a skipped archive: %q", got.Warnings)
	}
}
