// Private-feed credential plumbing, kept untagged so every byte cicd hands to
// npm and NuGet is unit-tested. The container wiring that consumes these lives
// in lint.go, test.go, byotest.go and dotnetexec.go.
//
// The NuGet half — the transport check, the feed-URL comparison and the
// NuGet.Config rendering — lives in nugetfeed.go, which the security module
// carries a byte-identical copy of because it restores against the same feeds.
// What is left here is npm-specific, plus validateFeedCredentials, which is the
// one entry point that has to speak about both tools at once.
//
// Both halves of this file exist because a credential that cannot be applied is
// indistinguishable from no credential at all: npm and NuGet both respond to a
// malformed auth config by fetching anonymously, so the feed answers 401, the
// install fails, and the leg reports a missing linter or a failed test suite —
// never "your token was ignored". That is the "a tool that could not run must
// never read as clean" doctrine one layer down, at the credential.
package main

import (
	"fmt"
	"strings"
	"unicode"
)

// npm-feed-routing values. The empty string is the registry mode, so a caller
// that never heard of the input keeps the behaviour it was built against.
const (
	npmRoutingRegistry = "registry"
	npmRoutingNpmrc    = "npmrc"
)

// validateNpmFeedRouting refuses a routing value cicd does not know and an
// npmrc routing with no feed to credential.
//
// The second refusal exists because npmrc routing only changes what cicd does
// with a feed: without npm-feed-url it would do nothing at all, and a knob
// that silently does nothing reads to its author as a knob that worked.
func validateNpmFeedRouting(routing, npmFeedURL string) error {
	switch routing {
	case "", npmRoutingRegistry:
		return nil
	case npmRoutingNpmrc:
		if strings.TrimSpace(npmFeedURL) == "" {
			return fmt.Errorf("npm-feed-routing %q needs npm-feed-url: it says which host the token belongs to", routing)
		}
		return nil
	default:
		return fmt.Errorf("npm-feed-routing must be %q or %q, got %q", npmRoutingRegistry, npmRoutingNpmrc, routing)
	}
}

// validateFeedCredentials refuses, before any container is built, to hand a
// feed token to an endpoint that would carry it in cleartext.
//
// This is the same doctrine as the rest of this file read from the other end. A
// credential that cannot be applied must not read as no credential — and a
// credential that *is* applied must not be applied to the wrong transport. npm
// sends `Authorization: Bearer <token>` on the first request and NuGet answers
// a `401 WWW-Authenticate: Basic` challenge with `Basic base64(user:token)`;
// over plain HTTP either is a readable secret on the wire, and neither tool
// refuses on the consumer's behalf. Since cicd is handed the token by a
// pipeline identity that can usually read every private feed in the
// organisation, silently downgrading its transport is not a consumer's
// footgun to keep.
//
// Failing here rather than dropping the credential is deliberate: a dropped
// credential is exactly the silent 401 this whole change exists to remove.
//
// Loopback is exempt so the request/response seam can be proven against a local
// server the way `notify` proves its own — the wire tests
// behind this file did precisely that.
func validateFeedCredentials(npmFeedURL string, hasNpmToken bool, nugetFeedURL string, hasNugetToken bool) error {
	if hasNpmToken {
		// The URL becomes a line of cicd's npmrc (nodeFeedConfig), and a
		// scheme-less one is never parsed by feedTransportOK: a line break in it
		// would write a second configuration line beside the credential.
		if strings.ContainsFunc(strings.TrimSpace(npmFeedURL), func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
			return fmt.Errorf("--npm-feed-url (%q) contains whitespace or a control character; pass the feed URL alone", npmFeedURL)
		}
		if err := feedTransportOK("npm-feed-url", npmFeedURL, schemeOptional); err != nil {
			return err
		}
	}
	if hasNugetToken {
		if err := feedTransportOK("nuget-feed-url", nugetFeedURL, schemeRequired); err != nil {
			return err
		}
	}
	return nil
}

// npmRegistryURL normalises a feed URL for NPM_CONFIG_REGISTRY, which requires
// a scheme. Consumers hand cicd whatever their .npmrc holds, and an
// Azure Artifacts index copied out of the portal sometimes arrives scheme-less;
// npm rejects that outright rather than assuming https.
func npmRegistryURL(feedURL string) string {
	u := strings.TrimSpace(feedURL)
	if u == "" {
		return ""
	}
	if strings.Contains(u, "://") {
		return u
	}
	return "https://" + strings.TrimPrefix(u, "//")
}

// npmNerfDart is npm's "nerf dart" for a feed: `//` + host+path with **no
// scheme** + `/`. It is the key prefix npm (and pnpm) match a credential to a
// request by, so `npmNerfDart(u) + ":_authToken"` is the npmrc key that carries
// the feed token.
//
// The dart is the opposite shape from the one NPM_CONFIG_REGISTRY needs — and
// cicd used to build both from the same string by concatenation:
//
//	WithSecretVariable("NPM_CONFIG_//"+feedUrl+"/:_authToken", feedToken)
//
// With the scheme-bearing URL that NPM_CONFIG_REGISTRY demands, that yields
// `//https://host/path//:_authToken`. npm deliberately does not normalise
// config keys that begin with `//` (@npmcli/config: "don't normalize
// nerf-darted keys"), so the key is stored verbatim, never matches the dart npm
// computes for the request, and the token is silently dropped. Measured against
// npm 11.16.0 with a local registry logging headers: the concatenated spelling
// sent no Authorization header at all, the dart below sent
// `Authorization: Bearer <token>`.
//
// The same `//` guard is why the path must be passed through untouched: a
// feed path containing `_packaging` (every Azure Artifacts feed does) would be
// rewritten to `-packaging` by npm's normal key handling.
func npmNerfDart(feedURL string) string {
	dart := strings.TrimSpace(feedURL)
	if i := strings.Index(dart, "://"); i >= 0 {
		dart = dart[i+3:]
	}
	dart = strings.TrimPrefix(dart, "//")
	dart = strings.TrimRight(dart, "/")
	return "//" + dart + "/"
}
