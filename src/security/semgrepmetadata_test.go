package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSemgrepMetadataAdapter(t *testing.T) {
	cmd := exec.Command("python3", "-B", "-m", "unittest", "semgrep_metadata_test", "-v")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("metadata adapter tests: %v\n%s", err, output)
	}
}

func TestSemgrepMetadataSurvivesRedactionWithoutChangingGate(t *testing.T) {
	fixture := filepath.Join("..", "..", "testdata", "semgrep-finding-metadata")
	original, err := os.ReadFile(filepath.Join(fixture, "native.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "report.sarif")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("python3", "-B", "semgrep_metadata.py", "--json", filepath.Join(fixture, "native.json"), "--sarif", path).CombinedOutput(); err != nil {
		t.Fatalf("enrich: %v\n%s", err, output)
	}
	enriched, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	redacted, err := redactSemgrepSARIF(enriched)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(redacted), "securitySink(input)") || strings.Contains(string(redacted), `"snippet"`) {
		t.Fatal("matched source survived redaction")
	}
	if !strings.Contains(string(redacted), `"confidence":"LOW"`) || !strings.Contains(string(redacted), `"category":"style"`) {
		t.Fatal("classification lost during redaction")
	}
	before, after := parseSarifSeverities(original), parseSarifSeverities(redacted)
	if !reflect.DeepEqual(before, after) || after[SeverityHigh] != 3 {
		t.Fatalf("severity changed: %v -> %v", before, after)
	}
	for _, threshold := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityNone} {
		if shouldFail(before, threshold) != shouldFail(after, threshold) {
			t.Fatalf("metadata changed gate at %s", threshold)
		}
	}
	// The same count reducer is used by ScanSource; enrichment is not a second scan.
	var doc map[string]any
	if err := json.Unmarshal(redacted, &doc); err != nil {
		t.Fatal(err)
	}
}

func TestMetadataAdapterIsMountedOnEverySemgrepInvocation(t *testing.T) {
	source, err := os.ReadFile("sast.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), "WithNewFile(semgrepMetadataPath, semgrepMetadataScript)") ||
		!strings.Contains(semgrepScript, "python3 "+semgrepMetadataPath+" --json /tmp/report.json --sarif /tmp/report.sarif") {
		t.Fatal("ordinary/custom/compatibility scan lost metadata adapter wiring")
	}
}
