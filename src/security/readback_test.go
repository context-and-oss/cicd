package main

import (
	"errors"
	"strings"
	"testing"
)

func TestReadbackError_namesToolPathAndCause(t *testing.T) {
	got := readbackError("go test", "/tmp/gotest.out", errors.New("no such file"))
	for _, want := range []string{"go test:", "/tmp/gotest.out", "no such file", "could not read"} {
		if !strings.Contains(got, want) {
			t.Errorf("readbackError = %q, missing %q", got, want)
		}
	}
}

func TestReadbackCount(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		readErr error
		want    int
		wantMsg string // substring; empty means no message
	}{
		{"plain", "3\n", nil, 3, ""},
		{"padded", "  12  \n", nil, 12, ""},
		{"zero is a count", "0", nil, 0, ""},
		{"read error is never zero", "", errors.New("boom"), 0, "could not read /tmp/x back"},
		{"empty file is not a count", "", nil, 0, `holds "", which is not a count`},
		{"prose is not a count", "lots", nil, 0, `holds "lots", which is not a count`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n, msg := readbackCount("tool", "/tmp/x", c.raw, c.readErr)
			if n != c.want {
				t.Errorf("count = %d, want %d", n, c.want)
			}
			if c.wantMsg == "" && msg != "" {
				t.Errorf("unexpected message %q", msg)
			}
			if c.wantMsg != "" && !strings.Contains(msg, c.wantMsg) {
				t.Errorf("message = %q, want substring %q", msg, c.wantMsg)
			}
			if msg != "" && !strings.HasPrefix(msg, "tool: ") {
				t.Errorf("message %q does not name the tool first", msg)
			}
		})
	}
}
