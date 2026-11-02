// Feed helpers shared verbatim by the quality and security modules.
//
// SYNCED FILE — src/quality/nugetfeed.go and src/security/nugetfeed.go are
// byte-identical, and scripts/check-repo-surface.py fails when they are not
// (synced_files in scripts/repo-inventory.json). Edit one, copy it to the other.
// There is no canonical copy under src/internal/ because none of this is
// reachable from there: a Dagger module cannot import across the workspace, so
// the repo shares by file copy (schema.go precedent, CLAUDE.md).
//
// Why the copy is checked rather than merely commented. `markers.go` is the same
// pattern left unchecked and `.slnx` went missing from two of its three copies
// "for exactly as long as nothing tested the pair together". The failure mode
// here is worse than a missed marker file: this is the code that decides whether
// a feed token may be put on the wire at all, and whether the credential NuGet
// is handed matches the source it was meant for. A copy that drifts on
// feedTransportOK sends a token in cleartext from one module and refuses it from
// the other, and nothing about the passing module's evidence would say so.
//
// Both modules restore NuGet packages against a consumer's private feed —
// quality for the .NET lint and test legs, security for the lockfile-free
// dependency-graph fallback (src/security/dotnetrestore.go) — so both need every
// function here. Nothing npm-specific lives in this file: npm is quality's alone
// and stays in src/quality/feeds.go.
//
// Deliberately untagged (no //go:build !unit_test): every byte cicd hands to
// NuGet is rendered here and none of it needs Dagger, so both modules' unit
// suites drive it directly.
package main

import (
	"encoding/xml"
	"fmt"
	"net"
	"net/url"
	"strings"
	"unicode/utf16"
)

// Whether a scheme-less feed URL is acceptable is not a matter of strictness —
// the two tools read one without a scheme differently:
//
//   - npm rejects a registry that carries no scheme, so cicd upgrades it to
//     https (npmRegistryURL) and nothing is lost.
//   - NuGet reads a source value without a scheme as a **local directory path**,
//     which is a legitimate offline-feed shape. Upgrading it to https would be
//     cicd guessing at the consumer's intent; leaving it alone attaches the
//     token to a filesystem source, where it means nothing and the restore
//     reports missing packages rather than a bad feed URL. A credential handed
//     to a directory is incoherent either way, so it is refused.
type feedScheme int

const (
	schemeOptional feedScheme = iota
	schemeRequired
)

// feedTransportOK reports whether feedURL is a transport a token may be sent
// over: an explicit non-https scheme is refused unless the host is loopback,
// and a missing scheme is refused for the tools that will not infer one.
func feedTransportOK(flag, feedURL string, scheme feedScheme) error {
	raw := strings.TrimSpace(feedURL)
	if raw == "" {
		return nil
	}
	if !strings.Contains(raw, "://") {
		if scheme == schemeRequired {
			return fmt.Errorf("--%s (%q) has no scheme: NuGet reads a source without one as a local directory path, so the feed token would be attached to a filesystem source with no packages and the restore would report missing packages rather than a bad feed URL — pass the full https:// index URL", flag, raw)
		}
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("--%s is not a valid URL: %v", flag, err)
	}
	if strings.EqualFold(u.Scheme, "https") {
		return nil
	}
	if strings.EqualFold(u.Scheme, "http") && isLoopbackHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("--%s uses %s://, which would send the feed token in cleartext; use https:// (only http:// to a loopback host is allowed, for local protocol tests)", flag, strings.ToLower(u.Scheme))
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// sameFeedURL compares two feed URLs for the purpose of matching a configured
// package source against the one cicd was handed. Scheme and host are
// case-insensitive per RFC 3986 §6.2.2.1 and a trailing slash on an Azure
// Artifacts index is cosmetic, so `https://PKGS.dev.azure.com/o/_packaging/f/nuget/v3/index.json`
// and the lower-cased form name the same feed. The path is left case-sensitive:
// a feed name is part of the path and NuGet treats it as significant.
func sameFeedURL(a, b string) bool {
	na, oka := normaliseFeedURL(a)
	nb, okb := normaliseFeedURL(b)
	if !oka || !okb {
		// One of them is not a URL we can decompose; fall back to the literal
		// comparison rather than guessing a match.
		return strings.TrimSpace(a) == strings.TrimSpace(b)
	}
	return na == nb
}

func normaliseFeedURL(s string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Host == "" {
		return "", false
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + strings.TrimRight(u.Path, "/"), true
}

// nugetCredentialedConfig renders the NuGet.Config that attaches the feed token
// to a package source.
//
// The credentials block is not optional decoration: NuGet reads no
// NUGET_AUTH_TOKEN environment variable of its own — that name is a convention
// of setup-dotnet and of this config, nothing more. A config that declares the
// source without <packageSourceCredentials> therefore restores anonymously,
// which on a private feed is a 401 that surfaces as "restore operation failed"
// with no mention of authentication. `%NUGET_AUTH_TOKEN%` is expanded by NuGet
// itself, so the token stays a Dagger secret and never enters a shell word, an
// image layer as plaintext, or the evidence envelope.
//
// sourceName is the consumer's own source key (discovered from their
// NuGet.config by nugetSourceNameForFeed) so packageSourceMapping keeps routing
// private packages to the source that now has credentials.
func nugetCredentialedConfig(sourceName, feedURL string) string {
	return `<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="` + xmlAttr(sourceName) + `" value="` + xmlAttr(feedURL) + `" />
  </packageSources>
  <packageSourceCredentials>
    <` + nugetCredentialsElement(sourceName) + `>
      <add key="Username" value="cicd" />
      <add key="ClearTextPassword" value="%NUGET_AUTH_TOKEN%" />
    </` + nugetCredentialsElement(sourceName) + `>
  </packageSourceCredentials>
</configuration>`
}

// nugetCredentialsElement encodes a source name for use as an XML *element*
// name inside <packageSourceCredentials>, which is where NuGet keys credentials
// by source.
//
// A source name is an attribute value everywhere else, so it may legally
// contain characters no element name can hold — "Company Feed" with a space
// is ordinary. Emitted verbatim that produces `<Company Feed>`: not invalid
// NuGet config but invalid XML, so NuGet fails to parse the file it was handed
// and the restore error names a syntax problem in a file the consumer never
// wrote. NuGet's own answer is `_xHHHH_` escaping (`_x0020_` for a space), which
// is what this emits, so a credentialed source with a space in its name still
// matches.
//
// The encoding has to be reversible, because NuGet decodes the element name
// back to a source name (XmlConvert.DecodeName) before matching it. Two cases
// would otherwise decode to something other than what was encoded, and a
// credentials element that decodes to the wrong name is not a parse error: the
// credential is simply not applied to the source it was meant for, so the
// restore fails with a 401 — or succeeds anonymously where the feed permits it,
// which is the worse outcome and the exact silence this file exists to remove:
//
//   - A literal underscore that begins what looks like an escape marker. A
//     source genuinely named `feed_x0020_v2` emitted verbatim decodes back to
//     `feed v2`. The underscore itself is escaped as `_x005f_`, which is what
//     XmlConvert.EncodeLocalName does.
//   - A character outside the BMP. NuGet decodes each marker into one UTF-16
//     code unit, so a code point above U+FFFF has to be emitted as its two
//     surrogate halves; a single `_x1f600_` is neither the 4- nor the 8-hex
//     digit form DecodeName accepts and would survive into the element name.
func nugetCredentialsElement(name string) string {
	var b strings.Builder
	units := utf16.Encode([]rune(name))
	for i, u := range units {
		switch {
		case u == '_' && startsEscapeMarker(units[i:]):
			b.WriteString("_x005f_")
		case u >= 'a' && u <= 'z', u >= 'A' && u <= 'Z', u == '_':
			b.WriteRune(rune(u))
		case i > 0 && (u >= '0' && u <= '9' || u == '.' || u == '-'):
			b.WriteRune(rune(u))
		default:
			// Leading digits and every other code unit, including a leading
			// '.'/'-' and each half of a surrogate pair, go through the escape —
			// an element name may not start with them.
			fmt.Fprintf(&b, "_x%04x_", u)
		}
	}
	if b.Len() == 0 {
		return "internal"
	}
	return b.String()
}

// startsEscapeMarker reports whether units begins with `_x<hex>_` in one of the
// two widths XmlConvert.DecodeName recognises (4 or 8 hex digits) — i.e.
// whether leaving this underscore verbatim would make the decoder consume it.
func startsEscapeMarker(units []uint16) bool {
	if len(units) < 2 || units[0] != '_' || (units[1] != 'x' && units[1] != 'X') {
		return false
	}
	for _, width := range []int{4, 8} {
		if len(units) < width+3 || units[width+2] != '_' {
			continue
		}
		allHex := true
		for _, u := range units[2 : width+2] {
			if !isHexUnit(u) {
				allHex = false
				break
			}
		}
		if allHex {
			return true
		}
	}
	return false
}

func isHexUnit(u uint16) bool {
	return u >= '0' && u <= '9' || u >= 'a' && u <= 'f' || u >= 'A' && u <= 'F'
}

// xmlAttr escapes a string for safe use inside an XML attribute value.
func xmlAttr(s string) string {
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		return s
	}
	return b.String()
}

// nugetSourceNameFromConfig finds the consumer's own key for a package source
// pointing at feedURL, in the contents of one NuGet.config.
//
// The name matters because <packageSourceCredentials> is keyed by source name:
// credentialing a source cicd invented ("internal") while the consumer's
// packageSourceMapping routes private packages to *their* name leaves the
// mapped source uncredentialed, and the restore 401s on exactly the packages
// the token was supplied for.
//
// ok is false for an absent, unparseable or non-matching config — never an
// error. The caller has a fallback name and a working restore is preferable to
// a refusal over a file the consumer may not even have.
func nugetSourceNameFromConfig(contents, feedURL string) (string, bool) {
	var cfg struct {
		PackageSources struct {
			Add []struct {
				Key   string `xml:"key,attr"`
				Value string `xml:"value,attr"`
			} `xml:"add"`
		} `xml:"packageSources"`
	}
	if xml.Unmarshal([]byte(contents), &cfg) != nil {
		return "", false
	}
	for _, a := range cfg.PackageSources.Add {
		if a.Key != "" && sameFeedURL(a.Value, feedURL) {
			return a.Key, true
		}
	}
	return "", false
}

// nugetConfigNames are the spellings of a NuGet config file cicd looks for.
// NuGet itself is case-insensitive about this on Windows and case-sensitive on
// Linux, where the restore actually runs, so the list is explicit.
var nugetConfigNames = []string{"NuGet.config", "NuGet.Config", "nuget.config", "nuget.Config"}

// nugetDefaultSourceName is the source key cicd falls back to when the consumer
// declares no source for the feed it was handed.
const nugetDefaultSourceName = "internal"
