package main

import (
	"strings"
	"testing"
)

func TestValidateWebInputs(t *testing.T) {
	cases := []struct {
		name                       string
		mode                       string
		hasAPISpec, hasAPISpecPath bool
		want                       string // substring of the error; "" means accepted
	}{
		{"baseline with no document", webModeBaseline, false, false, ""},
		{"full with no document", webModeFull, false, false, ""},
		{"api from a file", webModeAPI, true, false, ""},
		{"api from a served path", webModeAPI, false, true, ""},
		{"unknown mode is refused first", "passive", true, true, "zap: unknown --mode \"passive\""},
		{"both documents", webModeAPI, true, true, "--api-spec and --api-spec-path were both given"},
		{"api without a document", webModeAPI, false, false, "--mode api needs an API document"},
		{"a file handed to baseline", webModeBaseline, true, false, "an API document was supplied but --mode is \"baseline\""},
		{"a path handed to full", webModeFull, false, true, "an API document was supplied but --mode is \"full\""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateWebInputs(tc.mode, tc.hasAPISpec, tc.hasAPISpecPath)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("accepted; want a refusal")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not say %q", err.Error(), tc.want)
			}
		})
	}
}

// The refusal order is part of the contract: a caller who gets the
// both-documents refusal must not be told about the mode on the next try
// and the document the try after.
func TestValidateWebInputsRefusesTheModeBeforeTheDocuments(t *testing.T) {
	err := validateWebInputs("", true, true)
	if err == nil || !strings.HasPrefix(err.Error(), "zap: unknown --mode") {
		t.Fatalf("got %v; want the mode refusal first", err)
	}
}
