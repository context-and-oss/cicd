//go:build unit_test

package main

import (
	"strings"
	"testing"
)

func TestValidateTestInputsRefusalsInEntryOrder(t *testing.T) {
	cases := []struct {
		name                                          string
		testCmd, testLegs, coveragePath, coverageGate string
		tolerance                                     float64
		parallelism                                   int
		npmFeed, npmRouting                           string
		npmToken                                      bool
		want                                          string
		wantLegs                                      int
	}{
		{name: "single command", parallelism: 1, testCmd: "go test ./...", coverageGate: "gate", tolerance: 1},
		{name: "declared legs", parallelism: 1, testLegs: `[{"label":"go","language":"go","cmd":"go test ./..."}]`, coverageGate: "warn", wantLegs: 1},
		{name: "malformed legs document", parallelism: 1, testLegs: `{not json`, coverageGate: "gate", want: "test-legs"},
		{name: "both shapes", parallelism: 1, testCmd: "go test", testLegs: `[{"label":"go","language":"go","cmd":"x"}]`, coverageGate: "gate", want: "test-cmd"},
		{name: "legs plus coverage-path", parallelism: 1, testLegs: `[{"label":"go","language":"go","cmd":"x"}]`, coveragePath: "cov.out", coverageGate: "gate", want: "coverage-path"},
		{name: "unknown gate mode", parallelism: 1, testCmd: "x", coverageGate: "soft", want: `coverage-gate must be "gate" or "warn", got "soft"`},
		{name: "negative tolerance", parallelism: 1, testCmd: "x", coverageGate: "gate", tolerance: -0.5, want: "tolerance must be >= 0, got -0.5"},
		{name: "http feed with token", parallelism: 1, testCmd: "x", coverageGate: "gate", npmFeed: "http://feed.example", npmToken: true, want: "npm-feed-url"},
		{name: "npmrc routing", parallelism: 1, testCmd: "x", coverageGate: "gate", npmFeed: "https://feed.example", npmRouting: "npmrc", npmToken: true},
		{name: "npmrc routing without a feed", parallelism: 1, testCmd: "x", coverageGate: "gate", npmRouting: "npmrc", want: "needs npm-feed-url"},
		{name: "unknown routing", parallelism: 1, testCmd: "x", coverageGate: "gate", npmFeed: "https://feed.example", npmRouting: "Registry", want: `got "Registry"`},
		{name: "parallelism zero", parallelism: 0, testCmd: "x", coverageGate: "gate", want: "parallelism must be an integer from 1 to 4, got 0"},
		{name: "parallelism over the cap", parallelism: 5, testCmd: "x", coverageGate: "gate", want: "parallelism must be an integer from 1 to 4, got 5"},
		{name: "four legs at once", parallelism: 4, testLegs: `[{"label":"a","language":"go","cmd":"x"},{"label":"b","language":"go","cmd":"y"}]`, coverageGate: "gate", wantLegs: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			legs, err := validateTestInputs(tc.testCmd, tc.testLegs, tc.coveragePath, tc.coverageGate, tc.tolerance, tc.parallelism, tc.npmFeed, tc.npmRouting, tc.npmToken, "", false)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(legs) != tc.wantLegs {
					t.Fatalf("legs = %d, want %d", len(legs), tc.wantLegs)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestValidateTestInputsLegDocumentIsRefusedBeforeTheGateMode(t *testing.T) {
	// Both are wrong; the leg document is the first refusal the entry ever
	// stated, so a consumer fixing errors one at a time sees the same order.
	_, err := validateTestInputs("", `{not json`, "", "soft", 0, 1, "", "", false, "", false)
	if err == nil || strings.Contains(err.Error(), "coverage-gate") {
		t.Fatalf("error = %v, want the leg document refused first", err)
	}
}

func TestApplyPreparedLegWithoutAContainer(t *testing.T) {
	legs := []testLeg{legacyTestLeg("go test ./...", "", "", []string{"go"})}
	out, label, err := applyPreparedLeg(legs, 0, false, "", "", "")
	if err != nil || label != "" || len(out) != 1 || out[0].ToolchainImage != "" {
		t.Fatalf("got (%+v, %q, %v)", out, label, err)
	}
	for _, md := range [][3]string{{"test-cmd", "", ""}, {"", "golang:1.26", ""}, {"", "", "go"}} {
		_, _, err := applyPreparedLeg(legs, 0, false, md[0], md[1], md[2])
		if err == nil || err.Error() != "prepared test metadata requires a prepared container" {
			t.Fatalf("metadata %v without a container: err = %v", md, err)
		}
	}
}

func TestApplyPreparedLegBindsTheLegacyLeg(t *testing.T) {
	// No declared legs, no label: the single test-cmd leg is the prepared one,
	// takes the prepared language and the prepared image.
	legs := []testLeg{legacyTestLeg("npm test", "cov/summary.json", "", []string{"go", "node"})}
	out, label, err := applyPreparedLeg(legs, 0, true, "", "node:22@sha256:abc", "node")
	if err != nil {
		t.Fatal(err)
	}
	if label != legacyLegLabel {
		t.Fatalf("label = %q, want %q", label, legacyLegLabel)
	}
	if out[0].Language != "node" || out[0].ToolchainImage != "node:22@sha256:abc" {
		t.Fatalf("leg = %+v", out[0])
	}
	if legs[0].ToolchainImage != "" || legs[0].Language != "go" {
		t.Fatalf("input mutated: %+v", legs[0])
	}
}

func TestApplyPreparedLegRefusals(t *testing.T) {
	declared := []testLeg{
		{Label: "api", Language: "dotnet", Cmd: "dotnet test"},
		{Label: "web", Language: "node", Cmd: "npm test", ToolchainImage: "node:22"},
	}
	cases := []struct {
		name               string
		label, image, lang string
		want               string
	}{
		{name: "label names no leg", label: "worker", image: "img", want: `prepared-test-label "worker" does not name a test leg`},
		{name: "empty label with declared legs", label: "", image: "img", want: `prepared-test-label "test-cmd" does not name a test leg`},
		{name: "no prepared image", label: "api", image: "", want: "prepared test leg must use the preparation toolchain image"},
		{name: "language disagrees", label: "api", image: "img", lang: "node", want: "prepared test leg must use the preparation toolchain image"},
		{name: "leg image disagrees", label: "web", image: "node:20", want: "prepared test leg must use the preparation toolchain image"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := applyPreparedLeg(declared, len(declared), true, tc.label, tc.image, tc.lang)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}

	// A leg whose own image agrees with the preparation is bound; its sibling
	// is left alone.
	out, label, err := applyPreparedLeg(declared, len(declared), true, "web", "node:22", "node")
	if err != nil || label != "web" {
		t.Fatalf("got (%q, %v)", label, err)
	}
	if out[1].ToolchainImage != "node:22" || out[0].ToolchainImage != "" {
		t.Fatalf("legs = %+v", out)
	}
}

func TestSingleContainerWarningFiresOnlyForThePolyglotSingleCommand(t *testing.T) {
	w := singleContainerWarning(0, "", []string{"go", "node"}, "golang:1.26")
	for _, want := range []string{"golang:1.26", "first detected language (go)", "of go, node", "Use test-legs"} {
		if !strings.Contains(w, want) {
			t.Fatalf("warning %q lacks %q", w, want)
		}
	}
	if singleContainerWarning(1, "", []string{"go", "node"}, "x") != "" {
		t.Fatal("declared legs must not warn")
	}
	if singleContainerWarning(0, "golang:1.26", []string{"go", "node"}, "x") != "" {
		t.Fatal("an explicit image is a deliberate choice")
	}
	if singleContainerWarning(0, "", []string{"go"}, "x") != "" {
		t.Fatal("one candidate is no choice at all")
	}
	if singleContainerWarning(0, "", nil, "x") != "" {
		t.Fatal("nothing detected is no choice at all")
	}
}

func TestTestPlanWarningsOrder(t *testing.T) {
	legs := []testLeg{
		{Label: "api", Language: "go", Cmd: "go test"},
		{Label: "web", Language: "node", Cmd: "npm test"},
	}
	res := []ToolchainResolution{
		{Image: "golang:1.26", From: ToolchainFromDefault},
		{Image: "node:22", From: ToolchainFromNvmrc, Note: ".nvmrc said v99 and no image matches it; node:22 used instead"},
	}
	got := testPlanWarnings(legs, res, []string{"golang:1.26", "node:22"}, len(legs), "node:22", "web", []string{"go", "node"})
	if len(got) != 2 {
		t.Fatalf("warnings = %q, want the note then the image scope", got)
	}
	if !strings.Contains(got[0], ".nvmrc") {
		t.Fatalf("first warning %q should be the version-file note", got[0])
	}
	if !strings.Contains(got[1], "node:22") || !strings.Contains(got[1], "web") {
		t.Fatalf("second warning %q should scope the toolchain image to the prepared leg", got[1])
	}

	// Single command on a polyglot tree: just the disclosure.
	single := []testLeg{legacyTestLeg("make test", "", "", []string{"go", "node"})}
	got = testPlanWarnings(single, res[:1], []string{"golang:1.26"}, 0, "", "", []string{"go", "node"})
	if len(got) != 1 || !strings.Contains(got[0], "test-cmd runs in exactly one container") {
		t.Fatalf("warnings = %q", got)
	}
}
