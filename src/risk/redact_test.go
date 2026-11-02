package main

import (
	"strings"
	"testing"
)

func TestRedactSnippet(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		mustGo   []string // substrings that must NOT survive
		mustStay []string // substrings that MUST survive (file context for triage)
	}{
		{
			name:     "env file — uppercase client secret",
			in:       "APP_CLIENT_SECRET=AbCdEf~1234567890ZyXwVuTsRqPoNmLkJiHg",
			mustGo:   []string{"AbCdEf~1234567890ZyXwVuTsRqPoNmLkJiHg"},
			mustStay: []string{"APP_CLIENT_SECRET", "<redacted>"},
		},
		{
			name:     "env file — quoted value",
			in:       `API_TOKEN="ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`,
			mustGo:   []string{"ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			mustStay: []string{"API_TOKEN", "<redacted>"},
		},
		{
			name:     "env file — non-secret key untouched",
			in:       "LOG_LEVEL=debug",
			mustGo:   nil,
			mustStay: []string{"LOG_LEVEL=debug"},
		},
		{
			name:     "JSON credential",
			in:       `{"clientSecret": "verySecretValue123"}`,
			mustGo:   []string{"verySecretValue123"},
			mustStay: []string{`"clientSecret"`, "<redacted>"},
		},
		{
			name:     "JSON non-secret untouched",
			in:       `{"timeout": "30s"}`,
			mustGo:   nil,
			mustStay: []string{`"timeout": "30s"`},
		},
		{
			name:     "YAML password",
			in:       "database:\n  password: hunter2pls",
			mustGo:   []string{"hunter2pls"},
			mustStay: []string{"password:", "<redacted>"},
		},
		{
			name:     "YAML double-quoted secret",
			in:       "database:\n  password: \"hunter2quoted\"",
			mustGo:   []string{"hunter2quoted"},
			mustStay: []string{"password:", `"<redacted>"`},
		},
		{
			name:     "YAML single-quoted secret",
			in:       "api_token: 'ghp_singlequoted1234567890'",
			mustGo:   []string{"ghp_singlequoted1234567890"},
			mustStay: []string{"api_token:", `'<redacted>'`},
		},
		{
			name:     "YAML non-secret untouched",
			in:       "service:\n  port: 8080",
			mustGo:   nil,
			mustStay: []string{"port: 8080"},
		},
		{
			name:     "PEM private key body wiped",
			in:       "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAxxxxxxxxx\n-----END RSA PRIVATE KEY-----",
			mustGo:   []string{"MIIEowIBAAKCAQEAxxxxxxxxx"},
			mustStay: []string{"-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----", "<redacted>"},
		},
		{
			name:     "empty snippet",
			in:       "",
			mustGo:   nil,
			mustStay: nil,
		},
		{
			name:     "TOML quoted",
			in:       `api_key = "sk-xxxxxxxxxxxxxxxxxxxx"`,
			mustGo:   []string{"sk-xxxxxxxxxxxxxxxxxxxx"},
			mustStay: []string{"api_key", "<redacted>"},
		},
		{
			name: "comment-only line referencing 'password' word stays",
			// description-style prose where 'password' appears as a word, not
			// next to a value assignment — must not be touched.
			in:       "# this is the password rotation runbook",
			mustGo:   nil,
			mustStay: []string{"# this is the password rotation runbook"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactSnippet(tc.in)
			for _, leak := range tc.mustGo {
				if strings.Contains(got, leak) {
					t.Errorf("expected %q to be redacted, got %q", leak, got)
				}
			}
			for _, keep := range tc.mustStay {
				if !strings.Contains(got, keep) {
					t.Errorf("expected %q to remain, got %q", keep, got)
				}
			}
		})
	}
}

func TestRedactFindingsModifiesOnlySnippet(t *testing.T) {
	in := []Finding{{
		ID:          "abc12345",
		Category:    "compliance",
		Severity:    "critical",
		Confidence:  0.95,
		Title:       "Live service-principal client secret committed",
		Description: "A real client secret is present.",
		Evidence: Evidence{
			File:      ".env.local",
			StartLine: 17,
			EndLine:   17,
			Snippet:   "APP_CLIENT_SECRET=AbCdEf1234567890",
		},
	}}

	out := redactFindings(in)

	if got, want := out[0].Title, "Live service-principal client secret committed"; got != want {
		t.Errorf("Title got %q, want %q", got, want)
	}
	if got, want := out[0].Description, "A real client secret is present."; got != want {
		t.Errorf("Description got %q, want %q", got, want)
	}
	if strings.Contains(out[0].Evidence.Snippet, "AbCdEf1234567890") {
		t.Errorf("snippet still contains the secret: %q", out[0].Evidence.Snippet)
	}
	if !strings.Contains(out[0].Evidence.Snippet, "<redacted>") {
		t.Errorf("snippet missing redaction marker: %q", out[0].Evidence.Snippet)
	}
	if out[0].Evidence.File != ".env.local" || out[0].Evidence.StartLine != 17 {
		t.Errorf("triage anchor (file + line) lost: %+v", out[0].Evidence)
	}
}
