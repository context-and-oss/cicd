package main

import (
	"strings"
	"testing"
)

// TestResolveWebTargetRefusesAnythingButExactlyOneSource.
//
// Zero sources and two sources are both hard errors rather than a default,
// following resolveIncludeNames: no envelope is produced at all, because an
// envelope is a thing a consumer reads as a verdict and a scan with no
// resolvable target must not produce one.
func TestResolveWebTargetRefusesAnythingButExactlyOneSource(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		target                   string
		hasService, hasContainer bool
		wantErr                  string
	}{
		{name: "nothing", wantErr: "no target"},
		{name: "url and service", target: "http://x:8080", hasService: true, wantErr: "exactly one source"},
		{name: "url and container", target: "http://x:8080", hasContainer: true, wantErr: "exactly one source"},
		{name: "service and container", hasService: true, hasContainer: true, wantErr: "exactly one source"},
		{name: "all three", target: "http://x:8080", hasService: true, hasContainer: true, wantErr: "exactly one source"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolveWebTarget(tc.target, tc.hasService, tc.hasContainer, "http", 8080, "/", "")
			if err == nil {
				t.Fatalf("resolveWebTarget accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestResolveWebTargetNamesItsSource. The source is not decoration: it is what
// webDisclosureWarnings reads to decide whether the evidence may claim the
// running code was built from this commit.
func TestResolveWebTargetNamesItsSource(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		target                   string
		hasService, hasContainer bool
		wantSource               string
	}{
		{name: "url", target: "http://staging.example.com/app", wantSource: webSourceURL},
		{name: "service", hasService: true, wantSource: webSourceService},
		{name: "container", hasContainer: true, wantSource: webSourceContainer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveWebTarget(tc.target, tc.hasService, tc.hasContainer, "http", 8080, "/", "")
			if err != nil {
				t.Fatalf("resolveWebTarget: %v", err)
			}
			if got.Source != tc.wantSource {
				t.Errorf("source = %q, want %q", got.Source, tc.wantSource)
			}
		})
	}
}

// TestResolveBoundTargetComposesTheURLItself. A bound service's host is fixed
// by cicd, so the URL handed to ZAP never contains a host string a consumer
// typed.
func TestResolveBoundTargetComposesTheURLItself(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		scheme               string
		port                 int
		basePath, healthPath string
		wantBase, wantHealth string
		wantAlias            string
		wantPort             int
	}{
		{
			name: "defaults", scheme: "http", port: 8080, basePath: "/",
			wantBase: "http://app-under-test:8080/", wantHealth: "http://app-under-test:8080/",
			wantAlias: webServiceAlias, wantPort: 8080,
		},
		{
			name: "base path and health path", scheme: "https", port: 5001, basePath: "app/", healthPath: "healthz",
			wantBase: "https://app-under-test:5001/app", wantHealth: "https://app-under-test:5001/healthz",
			wantAlias: webServiceAlias, wantPort: 5001,
		},
		{
			name: "health defaults to the base path", scheme: "http", port: 3000, basePath: "/api",
			wantBase: "http://app-under-test:3000/api", wantHealth: "http://app-under-test:3000/api",
			wantAlias: webServiceAlias, wantPort: 3000,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveBoundTarget(webSourceContainer, tc.scheme, tc.port, tc.basePath, tc.healthPath)
			if err != nil {
				t.Fatalf("resolveBoundTarget: %v", err)
			}
			if got.BaseURL != tc.wantBase {
				t.Errorf("BaseURL = %q, want %q", got.BaseURL, tc.wantBase)
			}
			if got.HealthURL != tc.wantHealth {
				t.Errorf("HealthURL = %q, want %q", got.HealthURL, tc.wantHealth)
			}
			if got.Alias != tc.wantAlias {
				t.Errorf("Alias = %q, want %q", got.Alias, tc.wantAlias)
			}
			if got.Port != tc.wantPort {
				t.Errorf("Port = %d, want %d", got.Port, tc.wantPort)
			}
		})
	}
}

func TestResolveBoundTargetRefusesAnUnusableBinding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		scheme string
		port   int
	}{
		{"empty scheme", "", 8080},
		{"a scheme ZAP does not speak", "tcp", 8080},
		{"port zero", "http", 0},
		{"port out of range", "http", 70000},
		{"negative port", "http", -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := resolveBoundTarget(webSourceService, tc.scheme, tc.port, "/", ""); err == nil {
				t.Errorf("resolveBoundTarget = %+v, want an error", got)
			}
		})
	}
}

// TestResolveURLTargetChecksTheOneAddressCicdDidNotCompose.
func TestResolveURLTargetChecksTheOneAddressCicdDidNotCompose(t *testing.T) {
	for _, tc := range []struct{ name, target string }{
		{"no scheme", "staging.example.com"},
		{"a scheme ZAP does not speak", "ftp://staging.example.com"},
		{"file url", "file:///etc/passwd"},
		{"scheme with no host", "http://"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := resolveURLTarget(tc.target, ""); err == nil {
				t.Errorf("resolveURLTarget(%q) = %+v, want an error", tc.target, got)
			}
		})
	}

	got, err := resolveURLTarget("https://staging.example.com/app?x=1", "/healthz")
	if err != nil {
		t.Fatalf("resolveURLTarget: %v", err)
	}
	// The scan target keeps the URL as given — cicd does not edit a consumer's
	// address — while the probe is composed against its origin.
	if got.BaseURL != "https://staging.example.com/app?x=1" {
		t.Errorf("BaseURL = %q, want the URL as supplied", got.BaseURL)
	}
	if got.HealthURL != "https://staging.example.com/healthz" {
		t.Errorf("HealthURL = %q, want the health path on the same origin with no query", got.HealthURL)
	}
	// url is the source with nothing to bind, so it must carry no alias — a
	// binding under an alias nothing was bound to would make withTarget silently
	// point the scan at a host that does not resolve.
	if got.Alias != "" || got.Port != 0 {
		t.Errorf("url target carries a binding: alias=%q port=%d", got.Alias, got.Port)
	}
}

func TestResolveURLTargetProbesTheTargetItselfByDefault(t *testing.T) {
	got, err := resolveURLTarget("http://staging.example.com/app", "")
	if err != nil {
		t.Fatalf("resolveURLTarget: %v", err)
	}
	if got.HealthURL != got.BaseURL {
		t.Errorf("HealthURL = %q, want it to equal BaseURL %q", got.HealthURL, got.BaseURL)
	}
}

func TestAPISpecURLResolvesAgainstTheTargetOrigin(t *testing.T) {
	tgt, err := resolveBoundTarget(webSourceContainer, "http", 8080, "/app", "")
	if err != nil {
		t.Fatalf("resolveBoundTarget: %v", err)
	}
	got, err := apiSpecURL(tgt, "swagger/v1/swagger.json")
	if err != nil {
		t.Fatalf("apiSpecURL: %v", err)
	}
	if got != "http://app-under-test:8080/swagger/v1/swagger.json" {
		t.Errorf("apiSpecURL = %q", got)
	}

	if _, err := apiSpecURL(tgt, "   "); err == nil {
		t.Error("apiSpecURL accepted an empty path; -t would then be the empty string and ZAP would scan nothing")
	}
}

func TestNormalisePathComposesTheSameURLFromEitherSpelling(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", "/"},
		{"   ", "/"},
		{"/", "/"},
		{"//", "/"},
		{"api", "/api"},
		{"/api", "/api"},
		{"/api/", "/api"},
		{"api/v1/", "/api/v1"},
		{" /health ", "/health"},
	} {
		if got := normalisePath(tc.in); got != tc.want {
			t.Errorf("normalisePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
