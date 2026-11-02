//go:build unit_test

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// cleanSARIF is what a completed golangci-lint v2 run writes for a clean tree.
// It is byte-for-byte the document measured from the real binary, because the
// whole point of these tests is that this document is indistinguishable from the
// one a *failed* run writes.
const cleanSARIF = `{"version":"2.1.0","$schema":"https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.6.json","runs":[{"tool":{"driver":{"name":"golangci-lint"}},"results":[]}]}`

func TestGolangciRunError_RanCleanly(t *testing.T) {
	if msg := golangciRunError("0", "", cleanSARIF); msg != "" {
		t.Fatalf("exit 0 with a real SARIF document must be a run, got %q", msg)
	}
	// Trailing newline is how the exit sentinel actually arrives from `echo $?`.
	if msg := golangciRunError("0\n", "", cleanSARIF); msg != "" {
		t.Fatalf("exit sentinel must tolerate a trailing newline, got %q", msg)
	}
}

// The regression this whole change exists for. golangci-lint v2.12.2 pointed at a
// directory outside its workspace prints "0 issues.", writes exactly cleanSARIF,
// and exits 7. If the exit status is not authoritative, that reads as a clean
// tree — which is what shipped.
func TestGolangciRunError_ValidEmptySARIFWithNonZeroExitIsANonRun(t *testing.T) {
	const stderr = `level=error msg="[linters_context] typechecking error: pattern ./...: directory prefix . does not contain modules listed in go.work or their selected dependencies"`

	msg := golangciRunError("7", stderr+"\n0 issues.\n", cleanSARIF)
	if msg == "" {
		t.Fatal("exit 7 must be a non-run even though the report is valid and empty")
	}
	if !strings.Contains(msg, "did not run") {
		t.Fatalf("message must say it did not run, got %q", msg)
	}
	if !strings.Contains(msg, "go.work") {
		t.Fatalf("message must carry the go.work remedy, got %q", msg)
	}
}

// The original defect, kept as a test so it cannot come back by another route:
// v1 has no sarif format, so the flag itself was rejected.
func TestGolangciRunError_UnsupportedOutputFormat(t *testing.T) {
	const stderr = `Error: unsupported output format "sarif"
Failed executing command with error: unsupported output format "sarif"`

	msg := golangciRunError("3", stderr, "")
	if msg == "" {
		t.Fatal("exit 3 must be a non-run")
	}
	if !strings.Contains(msg, "--output.sarif.path") {
		t.Fatalf("remedy must name the v2 flag, got %q", msg)
	}
}

func TestGolangciRunError_V1ConfigSchema(t *testing.T) {
	const stderr = `Error: can't load config: unsupported version of the configuration: "" See https://golangci-lint.run/docs/product/migration-guide for migration instructions`

	msg := golangciRunError("3", stderr, "")
	if !strings.Contains(msg, `version: "2"`) {
		t.Fatalf("remedy must tell the consumer to add version: \"2\", got %q", msg)
	}
}

func TestGolangciRunError_ExportDataTooOld(t *testing.T) {
	const stderr = `level=error msg="[runner] Can't run linter goanalysis_metalinter: buildir: failed to load package goarch: could not load export data: internal error in importing \"internal/goarch\" (unsupported version: 2)"`

	msg := golangciRunError("3", stderr, "")
	if !strings.Contains(msg, "newer toolchain") {
		t.Fatalf("remedy must point at the toolchain mismatch, got %q", msg)
	}
}

func TestGolangciRunError_EmptyAndBogusReports(t *testing.T) {
	if msg := golangciRunError("0", "", ""); !strings.Contains(msg, "empty report") {
		t.Fatalf("exit 0 with no report must be a non-run, got %q", msg)
	}
	if msg := golangciRunError("0", "", "not json at all"); msg == "" {
		t.Fatal("exit 0 with non-JSON output must be a non-run")
	}
	// `{}` parses as JSON and would otherwise sail through as zero findings.
	if msg := golangciRunError("0", "", `{}`); !strings.Contains(msg, "not a SARIF document") {
		t.Fatalf("bare {} must not pass for a clean result, got %q", msg)
	}
	// A SARIF document with no runs carries no tool that could have reported.
	if msg := golangciRunError("0", "", `{"version":"2.1.0","runs":[]}`); msg == "" {
		t.Fatal("a SARIF document with zero runs must be a non-run")
	}
}

func TestGolangciRunError_UnreadableExit(t *testing.T) {
	msg := golangciRunError("", "", cleanSARIF)
	if !strings.Contains(msg, "unreadable exit status") {
		t.Fatalf("an absent sentinel must be a non-run, got %q", msg)
	}
	if msg := golangciRunError("wat", "", cleanSARIF); !strings.Contains(msg, "unreadable exit status") {
		t.Fatalf("a garbage sentinel must be a non-run, got %q", msg)
	}
}

func TestGolangciStderrMessage(t *testing.T) {
	if got := golangciStderrMessage(`level=error msg="the real problem"`); got != "the real problem" {
		t.Fatalf("logrus msg= extraction = %q", got)
	}
	if got := golangciStderrMessage("Error: bare form\n"); got != "bare form" {
		t.Fatalf("bare Error: extraction = %q", got)
	}
	// Neither shape present: return something rather than nothing, or the reader
	// gets an exit code and no context.
	if got := golangciStderrMessage("something odd happened"); got != "something odd happened" {
		t.Fatalf("fallback = %q", got)
	}
	if got := golangciStderrMessage("   \n\n"); got != "" {
		t.Fatalf("blank stderr = %q, want empty", got)
	}
}

func TestStampSARIFDriverVersion(t *testing.T) {
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"driver"`
			} `json:"tool"`
			Results []any `json:"results"`
		} `json:"runs"`
	}

	out := stampSARIFDriverVersion([]byte(cleanSARIF), "2.12.2")
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("stamped document must still parse: %v", err)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("run count changed: %d", len(doc.Runs))
	}
	if got := doc.Runs[0].Tool.Driver.Version; got != "2.12.2" {
		t.Fatalf("driver version = %q, want 2.12.2", got)
	}
	if got := doc.Runs[0].Tool.Driver.Name; got != "golangci-lint" {
		t.Fatalf("driver name must survive, got %q", got)
	}

	// "unknown" is stamped as-is. An absent field would read as "nobody looked";
	// the pin must never be substituted for an unread version.
	out = stampSARIFDriverVersion([]byte(cleanSARIF), "unknown")
	doc.Runs = nil
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := doc.Runs[0].Tool.Driver.Version; got != "unknown" {
		t.Fatalf("driver version = %q, want unknown", got)
	}

	// Findings must survive the round trip — the stamp touches metadata only.
	const withResult = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"golangci-lint"}},` +
		`"results":[{"ruleId":"errcheck","level":"error","message":{"text":"boom"}}]}]}`
	doc.Runs = nil
	if err := json.Unmarshal(stampSARIFDriverVersion([]byte(withResult), "2.12.2"), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Runs[0].Results) != 1 {
		t.Fatalf("results must survive stamping, got %d", len(doc.Runs[0].Results))
	}

	// Anything unparseable or shaped unexpectedly comes back byte-identical: a
	// metadata field is never worth losing a report over.
	for _, in := range []string{"not json", `{}`, `{"runs":"nope"}`, `{"runs":[{"tool":42}]}`} {
		if got := string(stampSARIFDriverVersion([]byte(in), "2.12.2")); got != in {
			t.Fatalf("stampSARIFDriverVersion(%q) = %q, want it returned untouched", in, got)
		}
	}
}

func TestGolangciVersionLabel(t *testing.T) {
	const real = "golangci-lint has version 2.12.2 built with go1.26.2 from c0d3ddc9 on 2026-05-06T11:07:58Z"
	if got := golangciVersionLabel(real); got != "2.12.2" {
		t.Fatalf("golangciVersionLabel = %q, want 2.12.2", got)
	}
	if got := golangciVersionLabel("golangci-lint has version v1.57.2 built with go1.22.1"); got != "1.57.2" {
		t.Fatalf("a v prefix must be stripped, got %q", got)
	}
	// Never fall back to the pin: reporting a configured version as an observed
	// one is how the .NET leg came to describe an SDK that never started.
	if got := golangciVersionLabel(""); got != "unknown" {
		t.Fatalf("empty probe = %q, want unknown", got)
	}
	if got := golangciVersionLabel("command not found"); got != "unknown" {
		t.Fatalf("failed probe = %q, want unknown", got)
	}
}
