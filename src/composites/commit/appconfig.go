package main

import (
	"encoding/json"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
)

var appIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// Commands own setup and execution in one container. Paths name outputs from
// that execution, not files imported from another workflow or an earlier run.
type appLeg struct {
	Label          string `json:"label"`
	Language       string `json:"language"`
	Cmd            string `json:"cmd"`
	ToolchainImage string `json:"toolchainImage,omitempty"`
	ReportPath     string `json:"reportPath,omitempty"`
	CoveragePath   string `json:"coveragePath,omitempty"`
	Format         string `json:"format,omitempty"`
	// Services are dependency containers a test leg's command can reach. The
	// field is carried, validated and re-marshalled here rather than left to
	// quality.Test alone, because app mode marshals []appLeg straight into
	// quality.Test's --test-legs: a key this struct does not model is dropped
	// silently on the way, and the leg would run against nothing while the
	// consumer's configuration says otherwise.
	//
	// The shape is quality's serviceSpec. Two parsers for one document that
	// disagree about its keys is one of them being wrong, so the tests assert
	// the two accept the same documents rather than each asserting its own.
	Services []appLegService `json:"services,omitempty"`
}

// appLegService mirrors quality's serviceSpec field for field. It cannot be
// imported — Dagger modules are isolated and share Go types only by file copy
// — so appconfig_test.go asserts the agreement instead of assuming it.
type appLegService struct {
	Alias        string            `json:"alias"`
	Image        string            `json:"image"`
	Port         int               `json:"port"`
	Env          map[string]string `json:"env,omitempty"`
	ReadyCmd     string            `json:"readyCmd,omitempty"`
	ReadyTimeout int               `json:"readyTimeout,omitempty"`
}

// appLegServiceKeys is the case-exact key set for a service object, checked
// the same way the leg's own keys are.
var appLegServiceKeys = map[string]bool{
	"alias": true, "image": true, "port": true,
	"env": true, "readyCmd": true, "readyTimeout": true,
}

type appConfig struct {
	ID          string
	Paths       []string
	Lint, Tests []appLeg
}

func appRelativePath(p string) bool {
	return p != "" && p != "." && path.Clean(p) == p && !path.IsAbs(p) && p != ".." &&
		!strings.HasPrefix(p, "../") && !strings.ContainsAny(p, "\\\x00\r\n*?[]") &&
		p != ".git" && !strings.HasPrefix(p, ".git/")
}

func parseAppLegs(raw, kind string) ([]appLeg, error) {
	if kind != "lint" && kind != "test" {
		return nil, fmt.Errorf("unsupported application leg kind %q", kind)
	}
	var legs []appLeg
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&legs); err != nil {
		return nil, fmt.Errorf("%s-legs: %w", kind, err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("%s-legs: expected one JSON array", kind)
	}
	if len(legs) == 0 || len(legs) > 8 {
		return nil, fmt.Errorf("%s-legs: expected 1–8 declared executions", kind)
	}
	// encoding/json accepts case-insensitive matches even with
	// DisallowUnknownFields. Keep the public input contract exact.
	var records []map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &records); err != nil {
		return nil, err
	}
	keys := map[string]bool{"label": true, "language": true, "cmd": true, "toolchainImage": true, "reportPath": true, "coveragePath": true, "format": true, "services": true}
	for _, record := range records {
		for key := range record {
			if !keys[key] {
				return nil, fmt.Errorf("%s-legs: unknown field %q", kind, key)
			}
		}
		// The same check one level down. DisallowUnknownFields already rejects
		// a key no struct field matches; this is the case-exact half, and it
		// has to reach the nested object too or "readycmd" is accepted here
		// and means nothing to the module that ends up reading it.
		if raw, ok := record["services"]; ok {
			var svcRecords []map[string]json.RawMessage
			if err := json.Unmarshal(raw, &svcRecords); err != nil {
				return nil, fmt.Errorf("%s-legs: services: %w", kind, err)
			}
			for _, svc := range svcRecords {
				for key := range svc {
					if !appLegServiceKeys[key] {
						return nil, fmt.Errorf("%s-legs: services: unknown field %q", kind, key)
					}
				}
			}
		}
	}
	seen := map[string]bool{}
	for _, leg := range legs {
		if !appIDPattern.MatchString(leg.Label) || seen[leg.Label] {
			return nil, fmt.Errorf("%s-legs: invalid or duplicate label %q", kind, leg.Label)
		}
		seen[leg.Label] = true
		if leg.Language != "node" && leg.Language != "dotnet" {
			return nil, fmt.Errorf("%s/%s: supported languages are node and dotnet", kind, leg.Label)
		}
		if strings.TrimSpace(leg.Cmd) == "" {
			return nil, fmt.Errorf("%s/%s: cmd is required", kind, leg.Label)
		}
		if kind == "lint" && len(leg.Services) > 0 {
			// A linter reads files. Binding a database beside it would be a
			// container pull and a healthcheck wait bought with nothing, and
			// accepting the key here would make it look supported everywhere.
			return nil, fmt.Errorf("lint/%s: services are for test legs — a lint command reads the source and reaches nothing", leg.Label)
		}
		if err := validateAppLegServices(kind, leg.Label, leg.Services); err != nil {
			return nil, err
		}
		if kind == "test" {
			if leg.ReportPath != "" || leg.Format != "" {
				return nil, fmt.Errorf("test/%s: use coveragePath, not reportPath or format", leg.Label)
			}
			if leg.CoveragePath != "" && !appRelativePath(leg.CoveragePath) {
				return nil, fmt.Errorf("test/%s: coveragePath must be a literal relative file path", leg.Label)
			}
		} else {
			if !appRelativePath(leg.ReportPath) || leg.CoveragePath != "" {
				return nil, fmt.Errorf("%s/%s: reportPath must be a literal relative file path", kind, leg.Label)
			}
			want := "eslint"
			if leg.Language == "dotnet" {
				want = "dotnet-format"
			}
			if leg.Format != want {
				return nil, fmt.Errorf("%s/%s: format must be %q", kind, leg.Label, want)
			}
		}
	}
	return legs, nil
}

func parseAppConfig(id string, paths []string, lint, tests string) (appConfig, error) {
	c := appConfig{ID: id}
	if !appIDPattern.MatchString(id) {
		return c, fmt.Errorf("app-id must match %s", appIDPattern)
	}
	seen := map[string]bool{}
	for _, p := range paths {
		if !appRelativePath(p) {
			return c, fmt.Errorf("source-paths: invalid literal path %q", p)
		}
		if !seen[p] {
			c.Paths = append(c.Paths, p)
			seen[p] = true
		}
	}
	if len(c.Paths) == 0 {
		return c, fmt.Errorf("source-paths must not be empty")
	}
	var err error
	if c.Lint, err = parseAppLegs(lint, "lint"); err != nil {
		return c, err
	}
	if c.Tests, err = parseAppLegs(tests, "test"); err != nil {
		return c, err
	}
	// Each declared ecosystem needs lint and tests. Dependency assessment is
	// explicitly deferred in application mode, not supplied through custom legs.
	langs := map[string]int{}
	for i, group := range [][]appLeg{c.Lint, c.Tests} {
		for _, l := range group {
			langs[l.Language] |= 1 << i
		}
	}
	for lang, mask := range langs {
		if mask != 3 {
			return c, fmt.Errorf("%s requires lint and test legs", lang)
		}
	}
	return c, nil
}

// validateAppLegServices refuses here what quality.Test would refuse later.
//
// Deliberately not a re-implementation of quality's validateServices: this
// checks the shape app mode can see going wrong on its own side, and the
// module that binds the containers keeps the authoritative rules. What it must
// not do is *accept* something quality rejects and let the failure surface as
// an opaque module error three stages downstream, which is why the alias
// charset and the limit are stated on both sides and pinned by a test.
func validateAppLegServices(kind, label string, svcs []appLegService) error {
	if len(svcs) == 0 {
		return nil
	}
	if len(svcs) > appLegServiceLimit {
		return fmt.Errorf("%s/%s: %d services exceeds the limit of %d", kind, label, len(svcs), appLegServiceLimit)
	}
	seen := map[string]bool{}
	for i, svc := range svcs {
		alias := strings.TrimSpace(svc.Alias)
		if !appServiceAliasPattern.MatchString(alias) {
			return fmt.Errorf("%s/%s: services[%d]: alias %q must be lowercase letters, digits and dashes, starting with a letter — it is bound as a hostname", kind, label, i, svc.Alias)
		}
		if seen[alias] {
			return fmt.Errorf("%s/%s: services[%d]: alias %q is declared twice", kind, label, i, alias)
		}
		seen[alias] = true
		if strings.TrimSpace(svc.Image) == "" {
			return fmt.Errorf("%s/%s: services[%d] (%s): image is required", kind, label, i, alias)
		}
		if svc.Port < 1 || svc.Port > 65535 {
			return fmt.Errorf("%s/%s: services[%d] (%s): port must be declared, between 1 and 65535 — cicd does not guess one", kind, label, i, alias)
		}
		if svc.ReadyCmd == "" && svc.ReadyTimeout != 0 {
			return fmt.Errorf("%s/%s: services[%d] (%s): readyTimeout is the budget for readyCmd and none is declared", kind, label, i, alias)
		}
	}
	return nil
}

// appLegServiceLimit and appServiceAliasPattern restate quality's serviceLimit
// and validServiceAlias. See validateAppLegServices for why they are restated
// rather than imported, and appconfig_test.go for what keeps them in step.
const appLegServiceLimit = 4

var appServiceAliasPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,61}[a-z0-9]$|^[a-z]$`)
