//go:build unit_test

package main

import (
	"strings"
	"testing"
)

// Synthetic credentials, shaped like the real thing so the patterns are proven
// against the widths they claim. None of these is or was a live secret.
const (
	fakePAT       = "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop" // 52 chars
	fakeGHP       = "ghp_SYNTHETIC0token0must0never0appear0in0evidence"
	fakeGHPAT     = "github_pat_SYNTHETIC0token0must0never0appear0in0evidence"
	fakeNuGetKey  = "oy2" + "abcdefghijklmnopqrstuvwxyz0123456789abcdefg" // 3 + 43
	fakePassword  = "hunter2-SYNTHETIC"
	fakeBearer    = "SYNTHETIC.bearer.value.0123456789"
	fakeAuthToken = "npm_SYNTHETIC0authtoken0value"
)

func TestScrubCredentialsRemovesEveryShapeItClaims(t *testing.T) {
	for _, tc := range []struct {
		name   string
		in     string
		secret string
		keep   string // a non-secret part of the line that must survive
	}{
		{
			name:   "feed URL userinfo in a NuGet restore error",
			in:     "error NU1301: Unable to load the service index for source https://build:" + fakePAT + "@pkgs.dev.azure.com/org/_packaging/feed/nuget/v3/index.json.",
			secret: fakePAT,
			keep:   "pkgs.dev.azure.com/org/_packaging/feed",
		},
		{
			name:   "username is redacted too, because a PAT can sit in either slot",
			in:     "source https://" + fakePAT + ":x@pkgs.dev.azure.com/",
			secret: fakePAT,
			keep:   "pkgs.dev.azure.com",
		},
		{
			name:   "bearer header echoed by a transport diagnostic",
			in:     "  Authorization: Bearer " + fakeBearer,
			secret: fakeBearer,
			keep:   "Authorization: Bearer",
		},
		{
			name:   "NuGet.Config ClearTextPassword attribute",
			in:     `<add key="ClearTextPassword" value="` + fakePassword + `" />`,
			secret: fakePassword,
			keep:   `key="ClearTextPassword"`,
		},
		{
			name:   "npm _authToken assignment",
			in:     "//pkgs.dev.azure.com/org/_packaging/feed/npm/registry/:_authToken=" + fakeAuthToken,
			secret: fakeAuthToken,
			keep:   "_authToken=",
		},
		{
			name:   "password key=value",
			in:     "password=" + fakePassword + " rejected",
			secret: fakePassword,
			keep:   "rejected",
		},
		{
			name:   "GitHub classic token",
			in:     "using token " + fakeGHP + " for github.com",
			secret: fakeGHP,
			keep:   "for github.com",
		},
		{
			name:   "GitHub fine-grained token",
			in:     "using " + fakeGHPAT + " for github.com",
			secret: fakeGHPAT,
			keep:   "for github.com",
		},
		{
			name:   "NuGet.org API key",
			in:     "pushing with key " + fakeNuGetKey,
			secret: fakeNuGetKey,
			keep:   "pushing with key",
		},
		{
			name:   "bare classic Azure DevOps PAT",
			in:     "PAT " + fakePAT + " expired",
			secret: fakePAT,
			keep:   "expired",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := scrubCredentials(tc.in)
			if !changed {
				t.Fatalf("reported no change on %q", tc.in)
			}
			if strings.Contains(got, tc.secret) {
				t.Fatalf("secret survived: %q", got)
			}
			if !strings.Contains(got, credentialPlaceholder) {
				t.Errorf("no placeholder marks the edit: %q", got)
			}
			if !strings.Contains(got, tc.keep) {
				t.Errorf("over-redacted: %q lost %q", got, tc.keep)
			}
		})
	}
}

// The other direction, because a scrubber that eats diagnostics is a scrubber
// people switch off. Each of these is a line `dotnet` prints on an ordinary
// day and none of them carries a credential.
func TestScrubCredentialsLeavesOrdinaryOutputAlone(t *testing.T) {
	for _, line := range []string{
		"Unhandled exception: The process cannot access the file '/root/.nuget/packages/example.devtool/1.0.0/example.devtool.1.0.0.nupkg' because it is being used by another process.",
		"/src/tests/T.csproj(13,48): error MSB4025: The project file could not be loaded.",
		"Passed!  - Failed:     0, Passed:   100, Skipped:     0, Total:   100, Duration: 4 s",
		"Restored /src/App/App.csproj (in 1.2 sec).",
		"https://api.nuget.org/v3/index.json",
		"https://localhost:8080/path/with/port",
		"Operation cancelled via CancellationToken.",
		"commit 0123456789abcdef0123456789abcdef01234567",                         // 40-char SHA
		"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", // 64-char digest
		"The passwordless flow is not supported.",
		"Data collector 'XPlat Code Coverage' message: [coverlet]Not instrumenting App.dll.",
	} {
		got, changed := scrubCredentials(line)
		if changed || got != line {
			t.Errorf("ordinary line was edited:\n in: %s\nout: %s", line, got)
		}
	}
}

func TestScrubCredentialsReportsNoChangeOnEmpty(t *testing.T) {
	if got, changed := scrubCredentials(""); got != "" || changed {
		t.Errorf("empty input = (%q, %v)", got, changed)
	}
}
