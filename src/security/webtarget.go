// Target resolution for the DAST leg: which of the three sources supplied the
// application, and what URL the scan and the readiness probe are pointed at.
//
// Deliberately untagged (no //go:build !unit_test): none of this needs Dagger.
package main

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// The three ways an application reaches the scanner.
//
//	url       the consumer started it somewhere the engine can route to
//	service   the consumer started it on the runner; the Dagger CLI tunnels it
//	container cicd builds and starts it, so the image's provenance is known
//
// url and service are the "you start it, we scan it" shape and attest nothing
// about what is behind the address. container is the "we start it, we scan it"
// shape and is the only one whose evidence can name the commit the running code
// was built from.
const (
	webSourceURL       = "url"
	webSourceService   = "service"
	webSourceContainer = "container"
)

// webServiceAlias is the hostname a bound service answers on inside the scan
// container. It is fixed by cicd rather than taken from the consumer, so the
// URL handed to ZAP never contains a host string a consumer typed.
const webServiceAlias = "app-under-test"

type webTarget struct {
	// Source is one of the three constants above.
	Source string
	// BaseURL is what the scan is pointed at.
	BaseURL string
	// HealthURL is what the readiness probe requests.
	HealthURL string
	// Alias is the service-binding hostname, empty for the url source.
	Alias string
	// Port is the port the binding exposes, zero for the url source.
	Port int
}

// resolveWebTarget picks the single supplied source and composes the URLs.
//
// Zero sources and two sources are both hard errors, returned before any
// container starts and therefore before any envelope exists. That is stronger
// than passed=false on purpose, and it is the rule resolveIncludeNames already
// follows: an envelope is a thing that can be read as a verdict, so a scan with
// no resolvable target must not produce one at all.
func resolveWebTarget(target string, hasService, hasContainer bool,
	scheme string, port int, basePath, healthPath string) (webTarget, error) {

	var supplied []string
	if strings.TrimSpace(target) != "" {
		supplied = append(supplied, "--target")
	}
	if hasService {
		supplied = append(supplied, "--service")
	}
	if hasContainer {
		supplied = append(supplied, "--container")
	}
	switch len(supplied) {
	case 1:
	case 0:
		return webTarget{}, errors.New("dast: no target: pass exactly one of " +
			"--target (a URL the engine can reach), --service (tcp://host:port, an app running on the runner) " +
			"or --container (an image cicd starts itself)")
	default:
		return webTarget{}, errors.New("dast: " + strings.Join(supplied, " and ") +
			" were both given; exactly one source may be supplied, because cicd cannot know which one the evidence would be about")
	}

	if strings.TrimSpace(target) != "" {
		return resolveURLTarget(target, healthPath)
	}

	source := webSourceService
	if hasContainer {
		source = webSourceContainer
	}
	return resolveBoundTarget(source, scheme, port, basePath, healthPath)
}

// resolveURLTarget validates a consumer-supplied URL. It is the one source
// whose address cicd did not compose, so it is the one that has to be checked.
func resolveURLTarget(target, healthPath string) (webTarget, error) {
	raw := strings.TrimSpace(target)
	u, err := url.Parse(raw)
	if err != nil {
		return webTarget{}, fmt.Errorf("dast: --target %s is not a URL: %w", strconv.Quote(raw), err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return webTarget{}, fmt.Errorf("dast: --target %s must be an http:// or https:// URL", strconv.Quote(raw))
	}
	if u.Host == "" {
		return webTarget{}, fmt.Errorf("dast: --target %s names no host", strconv.Quote(raw))
	}

	t := webTarget{Source: webSourceURL, BaseURL: raw, HealthURL: raw}
	if p := strings.TrimSpace(healthPath); p != "" {
		probe := *u
		probe.Path = normalisePath(p)
		probe.RawQuery = ""
		probe.Fragment = ""
		t.HealthURL = probe.String()
	}
	return t, nil
}

// resolveBoundTarget composes the URL for a service cicd binds itself. The host
// is always webServiceAlias, so only the scheme, port and paths are open.
func resolveBoundTarget(source, scheme string, port int, basePath, healthPath string) (webTarget, error) {
	s := strings.TrimSpace(scheme)
	if s != "http" && s != "https" {
		return webTarget{}, fmt.Errorf("dast: --scheme %s must be http or https", strconv.Quote(scheme))
	}
	if port < 1 || port > 65535 {
		return webTarget{}, fmt.Errorf("dast: --port %d is out of range 1-65535", port)
	}
	base := normalisePath(basePath)
	health := base
	if p := strings.TrimSpace(healthPath); p != "" {
		health = normalisePath(p)
	}

	origin := fmt.Sprintf("%s://%s:%d", s, webServiceAlias, port)
	return webTarget{
		Source:    source,
		BaseURL:   origin + base,
		HealthURL: origin + health,
		Alias:     webServiceAlias,
		Port:      port,
	}, nil
}

// apiSpecURL turns a path the target serves its API document on into a URL, so
// --api-spec-path can be used against an application that generates its own
// spec at runtime rather than committing one.
func apiSpecURL(t webTarget, specPath string) (string, error) {
	p := strings.TrimSpace(specPath)
	if p == "" {
		return "", errors.New("dast: empty --api-spec-path")
	}
	u, err := url.Parse(t.BaseURL)
	if err != nil {
		return "", fmt.Errorf("dast: cannot resolve --api-spec-path against %s: %w", strconv.Quote(t.BaseURL), err)
	}
	u.Path = normalisePath(p)
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

// normalisePath guarantees a leading slash and strips a trailing one, so
// "/api/" and "api" compose the same URL. The root stays "/".
func normalisePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
	}
	if p == "" {
		return "/"
	}
	return p
}
