package main

import (
	"strings"
	"testing"
)

func TestConftestFailureMessage_namesTheGroupAndDisclaimsAVerdict(t *testing.T) {
	msg := conftestFailureMessage("dockerfile", "risk.docker", "exit code: 1",
		`exec: "conftest": executable file not found in $PATH`)

	for _, want := range []string{
		"dockerfile",
		"risk.docker",
		// The line replaces a synthetic violation, so it has to say outright that
		// no policy produced it — otherwise a reader who has seen the old evidence
		// reads this as a policy failure too.
		"not a policy verdict",
		"exit code: 1",
		"executable file not found",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message must contain %q, got %q", want, msg)
		}
	}
}

func TestConftestFailureMessage_omitsAbsentParts(t *testing.T) {
	msg := conftestFailureMessage("yaml", "risk.pipeline", "", "")
	if strings.Contains(msg, "stderr:") {
		t.Errorf("no stderr must mean no stderr clause, got %q", msg)
	}
	if strings.HasSuffix(strings.TrimSpace(msg), ":") {
		t.Errorf("message must not trail a dangling colon, got %q", msg)
	}
	if !strings.Contains(msg, "risk.pipeline") {
		t.Errorf("the group must survive even with nothing else, got %q", msg)
	}
}

func TestBoundedStderr(t *testing.T) {
	if got := boundedStderr("   \n\t\n  "); got != "" {
		t.Errorf("blank stderr = %q, want empty", got)
	}

	// Newlines must not survive: the envelope is rendered into markdown lists,
	// where a raw newline ends the item and silently drops the rest.
	got := boundedStderr("first line\n\nsecond line\n")
	if strings.Contains(got, "\n") {
		t.Errorf("newlines must be collapsed, got %q", got)
	}
	if got != "first line | second line" {
		t.Errorf("boundedStderr = %q", got)
	}

	long := boundedStderr(strings.Repeat("x", conftestStderrBudget*3))
	if len(long) > conftestStderrBudget+len("…") {
		t.Errorf("stderr must be bounded, got %d bytes", len(long))
	}
	if !strings.HasSuffix(long, "…") {
		t.Errorf("truncation must be visible, got %q", long[len(long)-10:])
	}

	// Truncating mid-rune must not leave invalid UTF-8, or the envelope's JSON
	// marshalling replaces it and the message becomes unreadable.
	multi := boundedStderr(strings.Repeat("é", conftestStderrBudget))
	for _, r := range multi {
		if r == '�' {
			t.Fatalf("truncation produced invalid UTF-8: %q", multi)
		}
	}
}
