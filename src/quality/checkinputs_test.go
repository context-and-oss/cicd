//go:build unit_test

package main

import (
	"strings"
	"testing"
)

func TestValidateCheckInputs(t *testing.T) {
	cases := []struct {
		name                  string
		hasPrepared, lintOnly bool
		preparedLanguage      string
		limit                 int
		npmURL                string
		npmRouting            string
		npmToken              bool
		nugetURL              string
		nugetToken            bool
		want                  string
	}{
		{name: "defaults pass", limit: 4},
		{name: "prepared node lint-only passes", hasPrepared: true, lintOnly: true, preparedLanguage: "node", limit: 4},
		{name: "prepared dotnet lint-only passes", hasPrepared: true, lintOnly: true, preparedLanguage: "dotnet", limit: 4},
		{name: "prepared without lint-only is refused", hasPrepared: true, preparedLanguage: "node", limit: 4,
			want: "prepared quality checks require lint-only and prepared-language node or dotnet"},
		{name: "prepared for a language with no prepared linter is refused", hasPrepared: true, lintOnly: true, preparedLanguage: "go", limit: 4,
			want: "prepared quality checks require lint-only and prepared-language node or dotnet"},
		{name: "zero node projects is refused", limit: 0, want: "node-project-limit must be positive"},
		{name: "npm token over http is refused", limit: 4, npmURL: "http://feed.example/npm", npmToken: true, want: "npm-feed-url"},
		{name: "nuget token over http is refused", limit: 4, nugetURL: "http://feed.example/nuget", nugetToken: true, want: "nuget-feed-url"},
		{name: "cleartext url without a token is fine", limit: 4, npmURL: "http://feed.example/npm"},
		{name: "npmrc routing with a feed passes", limit: 4, npmURL: "https://feed.example/npm", npmRouting: "npmrc", npmToken: true},
		{name: "registry routing passes", limit: 4, npmURL: "https://feed.example/npm", npmRouting: "registry", npmToken: true},
		{name: "npmrc routing without a feed is refused", limit: 4, npmRouting: "npmrc", want: `npm-feed-routing "npmrc" needs npm-feed-url`},
		{name: "unknown routing is refused", limit: 4, npmURL: "https://feed.example/npm", npmRouting: "scoped",
			want: `npm-feed-routing must be "registry" or "npmrc", got "scoped"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCheckInputs(tc.hasPrepared, tc.lintOnly, tc.preparedLanguage, tc.limit,
				tc.npmURL, tc.npmRouting, tc.npmToken, tc.nugetURL, tc.nugetToken)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("unexpected refusal: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want refusal containing %q, got %v", tc.want, err)
			}
		})
	}
}

// The prepared-container rule is checked first, the project cap second, the
// npm feed routing third, the feed transport last: a consumer with all of
// them wrong hears about them in that order, and a message a run log greps
// for does not move.
func TestValidateCheckInputsOrder(t *testing.T) {
	err := validateCheckInputs(true, false, "go", 0, "http://feed.example/npm", "scoped", true, "", false)
	if err == nil || !strings.Contains(err.Error(), "prepared quality checks") {
		t.Fatalf("prepared rule must win, got %v", err)
	}
	err = validateCheckInputs(false, false, "", 0, "http://feed.example/npm", "scoped", true, "", false)
	if err == nil || !strings.Contains(err.Error(), "node-project-limit") {
		t.Fatalf("project cap must come before the feed routing, got %v", err)
	}
	err = validateCheckInputs(false, false, "", 4, "http://feed.example/npm", "scoped", true, "", false)
	if err == nil || !strings.Contains(err.Error(), "npm-feed-routing") {
		t.Fatalf("feed routing must come before the feed transport, got %v", err)
	}
}
