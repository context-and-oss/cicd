package main

// Unit tests for the coverage-report sniffer and the new cobertura parser
// behind Quality.Test. Run with:
//
//	go test -tags unit_test -run TestParseCobertura ./...
//
// The unit_test tag excludes the Dagger-importing files (main.go, test.go,
// lint.go, byotest.go) so the pure helpers compile without a Dagger session
// (gating_test.go pattern).

import (
	"testing"
	"unicode"
)

const coberturaHappy = `<?xml version="1.0" encoding="utf-8"?>
<coverage line-rate="0.8765" branch-rate="0.7" lines-covered="142" lines-valid="162" version="1.9" timestamp="1700000000">
  <packages>
    <package name="app" line-rate="0.8765" />
  </packages>
</coverage>`

func TestParseCobertura_happy(t *testing.T) {
	pct, lines, ok := parseCobertura(coberturaHappy)
	if !ok {
		t.Fatalf("expected ok for well-formed cobertura report")
	}
	// line-rate 0.8765 → 87.65%
	if pct < 87.64 || pct > 87.66 {
		t.Errorf("pct = %v, want 87.65 (line-rate × 100)", pct)
	}
	if lines != 162 {
		t.Errorf("lines = %d, want 162 (lines-valid)", lines)
	}
}

func TestParseCobertura_malformed(t *testing.T) {
	cases := map[string]string{
		"truncated XML":        `<coverage line-rate="0.5" lines-valid="10"`,
		"wrong root element":   `<report line-rate="0.5" lines-valid="10"></report>`,
		"non-numeric lineRate": `<coverage line-rate="half" lines-valid="10"></coverage>`,
		"empty input":          ``,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, ok := parseCobertura(raw); ok {
				t.Errorf("expected ok=false for %s", name)
			}
		})
	}
}

func TestParseCobertura_missingAttributes(t *testing.T) {
	// Missing line-rate → the report carries no usable percentage.
	if _, _, ok := parseCobertura(`<coverage lines-valid="10"></coverage>`); ok {
		t.Errorf("expected ok=false when line-rate is missing")
	}
	// Missing lines-valid used to degrade to 0 lines while keeping the
	// percentage. That was a documented decision and a measured wrong number: a
	// test project that runs tests but instruments nothing can write a valid
	// report with line-rate="1", <packages /> and no lines-valid, so
	// degrading returned (100.0, 0, ok=true). mergeDotnetCoverage drops
	// zero-line readings from its weighted sum, so a repository whose reports
	// are *all* empty fell through to the unweighted mean and reported 100% with
	// a nil line count. A report with no coverable lines carries no coverage
	// information — the same rule parseGoCoverprofile applies at zero
	// statements.
	for name, raw := range map[string]string{
		"lines-valid absent": `<coverage line-rate="0.5"></coverage>`,
		"lines-valid zero":   `<coverage line-rate="1" lines-valid="0"></coverage>`,
		"the empty report MTP writes": `<?xml version="1.0" encoding="utf-8"?>` +
			`<coverage line-rate="1" branch-rate="1" complexity="1" version="1.9" ` +
			`timestamp="0"><packages /></coverage>`,
	} {
		t.Run(name, func(t *testing.T) {
			pct, lines, ok := parseCobertura(raw)
			if ok {
				t.Fatalf("a report with no coverable lines is not a measurement: "+
					"got (%v, %d, true)", pct, lines)
			}
			if pct != 0 || lines != 0 {
				t.Errorf("an unusable report must report nothing, got (%v, %d)", pct, lines)
			}
		})
	}
}

// Regression rows: all four formats routed through the sniffer.
func TestSniffCoverageReport_formats(t *testing.T) {
	cases := []struct {
		name       string
		raw        string
		wantFormat string
		wantPct    float64
		wantLines  int
	}{
		{
			name: "v8 json-summary",
			raw: `{"total":{"lines":{"total":120,"covered":102,"skipped":0,"pct":85.0},
				"statements":{"total":130,"covered":110,"pct":84.6}}}`,
			wantFormat: covFormatV8Summary,
			wantPct:    85.0,
			wantLines:  120,
		},
		{
			name: "go coverprofile",
			raw: "mode: set\n" +
				"example.com/app/main.go:10.2,12.3 3 1\n" +
				"example.com/app/main.go:14.2,16.3 1 0\n",
			wantFormat: covFormatGoCover,
			wantPct:    75.0, // 3 of 4 statements covered
			wantLines:  4,
		},
		{
			name:       "pytest-cov JSON",
			raw:        `{"meta":{"version":"7.4"},"totals":{"percent_covered":91.5,"num_statements":200,"covered_lines":183}}`,
			wantFormat: covFormatPytestCov,
			wantPct:    91.5,
			wantLines:  200,
		},
		{
			name:       "cobertura XML",
			raw:        coberturaHappy,
			wantFormat: covFormatCobertura,
			wantPct:    87.65,
			wantLines:  162,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep, ok := sniffCoverageReport(tc.raw)
			if !ok {
				t.Fatalf("sniffer rejected a valid %s report", tc.name)
			}
			if rep.Format != tc.wantFormat {
				t.Errorf("format = %q, want %q", rep.Format, tc.wantFormat)
			}
			if rep.Pct < tc.wantPct-0.01 || rep.Pct > tc.wantPct+0.01 {
				t.Errorf("pct = %v, want %v", rep.Pct, tc.wantPct)
			}
			if rep.Lines != tc.wantLines {
				t.Errorf("lines = %d, want %d", rep.Lines, tc.wantLines)
			}
		})
	}
}

func TestSniffCoverageReport_rejectsUnrecognized(t *testing.T) {
	cases := map[string]string{
		"empty":                      ``,
		"whitespace only":            "  \n\t",
		"unrelated JSON":             `{"hello":"world"}`,
		"invalid JSON":               `{"total":`,
		"plain text":                 `all tests passed`,
		"go profile with no stmts":   "mode: set\n",
		"v8 shape without total":     `{"src/index.js":{"lines":{"pct":85.0}}}`,
		"xml that is not a coverage": `<testsuite tests="3"></testsuite>`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if rep, ok := sniffCoverageReport(raw); ok {
				t.Errorf("sniffer accepted %s as %q", name, rep.Format)
			}
		})
	}
}

// TestSniffCoverageReportStripsTheBOM uses independently generated coverage
// documents to exercise the UTF-8 BOM shape emitted by Microsoft.Testing.Platform.
// strings.TrimSpace does not remove a BOM.
//
// U+FEFF was dropped from the White_Space property in Unicode 4.0.1, so
// unicode.IsSpace reports false for it and a BOM'd document still begins U+FEFF
// rather than "<". No arm of the format switch fired, and a document that parses
// perfectly well was reported as being in no recognized coverage format — which
// on a BYO leg means no reading, no coverage, and a ratchet silently skipped
// behind a green envelope. The fixture below isolates that format-dispatch
// failure without retaining run-specific counts.
func TestSniffCoverageReportStripsTheBOM(t *testing.T) {
	const bom = "\uFEFF"

	// The reason TrimSpace cannot be relied on here. Asserted rather than
	// commented, because the whole defect follows from it.
	if unicode.IsSpace('\uFEFF') {
		t.Fatal("U+FEFF is not White_Space (Unicode 4.0.1); this test's premise is gone")
	}

	cobertura := `<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<coverage line-rate="0.25" lines-covered="360" lines-valid="1440">
  <sources><source>/src</source></sources>
  <packages></packages>
</coverage>`
	// The JSON arm has exactly the same exposure the moment any tool writes a
	// BOM'd json-summary, which is why the strip happens before the switch and
	// not inside its XML arm.
	v8 := `{"total":{"lines":{"pct":81.5,"total":200}}}`

	for _, tc := range []struct {
		name       string
		raw        string
		wantFormat string
		wantPct    float64
	}{
		{"cobertura as MTP writes it", bom + cobertura, covFormatCobertura, 25.0},
		{"cobertura without a BOM", cobertura, covFormatCobertura, 25.0},
		{"json-summary with a BOM", bom + v8, covFormatV8Summary, 81.5},
		{"json-summary without a BOM", v8, covFormatV8Summary, 81.5},
	} {
		rep, ok := sniffCoverageReport(tc.raw)
		if !ok {
			t.Errorf("%s: sniff returned ok=false for a parseable document", tc.name)
			continue
		}
		if rep.Format != tc.wantFormat {
			t.Errorf("%s: format=%q, want %q", tc.name, rep.Format, tc.wantFormat)
		}
		if rep.Pct != tc.wantPct {
			t.Errorf("%s: pct=%v, want %v", tc.name, rep.Pct, tc.wantPct)
		}
	}

	// A BOM must not turn something unreadable into something readable, and it
	// must not make an empty document look like a measurement.
	if _, ok := sniffCoverageReport(bom); ok {
		t.Error("a document holding nothing but a BOM is not a measurement")
	}
	if _, ok := sniffCoverageReport(bom + "not a coverage report at all"); ok {
		t.Error("stripping the BOM must not widen what counts as a coverage format")
	}
}

// TestStripBOMRemovesExactlyOne holds the strip to one BOM. A document carrying
// two is malformed, and laundering it into a measurement is the direction this
// package refuses.
func TestStripBOMRemovesExactlyOne(t *testing.T) {
	const bom = "\uFEFF"
	if got := stripBOM(bom + "<coverage/>"); got != "<coverage/>" {
		t.Errorf("one BOM must be stripped, got %q", got)
	}
	if got := stripBOM("  " + bom + "  <coverage/>  "); got != "<coverage/>" {
		t.Errorf("whitespace either side of the BOM must be tolerated, got %q", got)
	}
	if got := stripBOM(bom + bom + "<coverage/>"); got != bom+"<coverage/>" {
		t.Errorf("a second BOM must survive, so a malformed document stays malformed, got %q", got)
	}
	if got := stripBOM("<coverage/>"); got != "<coverage/>" {
		t.Errorf("a document with no BOM must pass through unchanged, got %q", got)
	}
}
