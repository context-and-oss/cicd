//go:build unit_test

package main

import (
	"encoding/xml"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"
)

// The spelling asserted here is not a style choice — it is the difference
// between npm sending `Authorization: Bearer <token>` and sending no
// Authorization header at all, measured against npm 11.16.0 with a local
// registry that logged its request headers.
func TestNpmNerfDart(t *testing.T) {
	const want = "//pkgs.dev.azure.com/org/_packaging/feed/npm/registry/"

	cases := []struct {
		name string
		url  string
		want string
	}{{
		name: "https with trailing slash — the shape NPM_CONFIG_REGISTRY needs",
		url:  "https://pkgs.dev.azure.com/org/_packaging/feed/npm/registry/",
		want: want,
	}, {
		name: "https without trailing slash",
		url:  "https://pkgs.dev.azure.com/org/_packaging/feed/npm/registry",
		want: want,
	}, {
		name: "scheme-less",
		url:  "pkgs.dev.azure.com/org/_packaging/feed/npm/registry/",
		want: want,
	}, {
		name: "already a nerf dart",
		url:  "//pkgs.dev.azure.com/org/_packaging/feed/npm/registry/",
		want: want,
	}, {
		name: "http scheme",
		url:  "http://pkgs.dev.azure.com/org/_packaging/feed/npm/registry/",
		want: want,
	}, {
		name: "surrounding whitespace and repeated trailing slashes",
		url:  "  https://pkgs.dev.azure.com/org/_packaging/feed/npm/registry//  ",
		want: want,
	}, {
		name: "plain public registry",
		url:  "https://registry.npmjs.org/",
		want: "//registry.npmjs.org/",
	}, {
		name: "port is part of the dart",
		url:  "http://registry.example:8081/repository/npm-fixture/",
		want: "//registry.example:8081/repository/npm-fixture/",
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := npmNerfDart(c.url)
			if got != c.want {
				t.Fatalf("npmNerfDart(%q)\n got %q\nwant %q", c.url, got, c.want)
			}
			// npm only skips key normalisation — the step that would turn
			// `_packaging` into `-packaging` — for keys starting with `//`.
			if !strings.HasPrefix(got, "//") {
				t.Fatalf("key %q is not nerf-darted: npm would normalise it", got)
			}
			if strings.Contains(got, "://") {
				t.Fatalf("key %q still carries a scheme", got)
			}
		})
	}
}

// The regression itself: one URL has to serve the registry variable and the
// credential key, and the two want different shapes. Assert them together so a future edit cannot fix one by
// breaking the other.
func TestNpmFeedEnvPairFromOneURL(t *testing.T) {
	for _, url := range []string{
		"https://pkgs.dev.azure.com/org/_packaging/feed/npm/registry/",
		"pkgs.dev.azure.com/org/_packaging/feed/npm/registry",
	} {
		if got, want := npmRegistryURL(url), "https://pkgs.dev.azure.com/org/_packaging/feed/npm/registry"; !strings.HasPrefix(got, want) {
			t.Errorf("npmRegistryURL(%q) = %q, want a scheme-bearing feed URL", url, got)
		}
		if got, want := npmNerfDart(url), "//pkgs.dev.azure.com/org/_packaging/feed/npm/registry/"; got != want {
			t.Errorf("npmNerfDart(%q) = %q, want %q", url, got, want)
		}
	}
}

func TestNpmRegistryURL(t *testing.T) {
	cases := map[string]string{
		"":                          "",
		"https://feed.example/npm/": "https://feed.example/npm/",
		"http://feed.example/npm/":  "http://feed.example/npm/",
		"feed.example/npm/":         "https://feed.example/npm/",
		"//feed.example/npm/":       "https://feed.example/npm/",
		"  feed.example/npm/  ":     "https://feed.example/npm/",
	}
	for in, want := range cases {
		if got := npmRegistryURL(in); got != want {
			t.Errorf("npmRegistryURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// A config NuGet cannot parse is worse than no config: the restore error names a
// syntax problem in a file the consumer never wrote. Every source name that can
// reach this must still produce parseable XML.
func TestNugetCredentialedConfigParses(t *testing.T) {
	cases := []struct{ name, source, feed string }{
		{"plain", "company.nuget", "https://pkgs.dev.azure.com/org/_packaging/feed/nuget/v3/index.json"},
		{"space in source name", "Company Feed", "https://feed.example/v3/index.json"},
		{"ampersand in feed url", "internal", "https://feed.example/v3/index.json?api-version=2.0&mode=all"},
		{"leading digit", "365feed", "https://feed.example/v3/index.json"},
		{"quote and angle bracket", `ev"il<source>`, `https://feed.example/"><x`},
		{"fallback name", "internal", "https://feed.example/v3/index.json"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := nugetCredentialedConfig(c.source, c.feed)

			var cfg struct {
				PackageSources struct {
					Add []struct {
						Key   string `xml:"key,attr"`
						Value string `xml:"value,attr"`
					} `xml:"add"`
				} `xml:"packageSources"`
				Credentials struct {
					Sources []struct {
						XMLName xml.Name
						Add     []struct {
							Key   string `xml:"key,attr"`
							Value string `xml:"value,attr"`
						} `xml:"add"`
					} `xml:",any"`
				} `xml:"packageSourceCredentials"`
			}
			if err := xml.Unmarshal([]byte(out), &cfg); err != nil {
				t.Fatalf("NuGet.Config does not parse as XML: %v\n%s", err, out)
			}

			if n := len(cfg.PackageSources.Add); n != 1 {
				t.Fatalf("want 1 package source, got %d", n)
			}
			if got := cfg.PackageSources.Add[0].Key; got != c.source {
				t.Errorf("source key = %q, want the consumer's own name %q", got, c.source)
			}
			if got := cfg.PackageSources.Add[0].Value; got != c.feed {
				t.Errorf("source value = %q, want %q", got, c.feed)
			}

			if n := len(cfg.Credentials.Sources); n != 1 {
				t.Fatalf("want credentials for exactly 1 source, got %d", n)
			}
			creds := map[string]string{}
			for _, a := range cfg.Credentials.Sources[0].Add {
				creds[a.Key] = a.Value
			}
			// NuGet expands %NUGET_AUTH_TOKEN% itself; a token interpolated
			// here would land in an image layer in plaintext.
			if creds["ClearTextPassword"] != "%NUGET_AUTH_TOKEN%" {
				t.Errorf("ClearTextPassword = %q, want the %%NUGET_AUTH_TOKEN%% placeholder", creds["ClearTextPassword"])
			}
			if creds["Username"] == "" {
				t.Error("no Username: Azure Artifacts rejects a credential with no user")
			}
			if got, want := cfg.Credentials.Sources[0].XMLName.Local, nugetCredentialsElement(c.source); got != want {
				t.Errorf("credentials element = %q, want %q", got, want)
			}
		})
	}
}

func TestNugetCredentialsElement(t *testing.T) {
	cases := map[string]string{
		"company.nuget": "company.nuget",
		"internal":      "internal",
		"my-feed_2":     "my-feed_2",
		"Company Feed":  "Company_x0020_Feed",
		"365feed":       "_x0033_65feed",
		".hidden":       "_x002e_hidden",
		"a<b>c":         "a_x003c_b_x003e_c",
		"":              "internal",
		// An underscore that begins what NuGet's decoder would read as an escape
		// marker has to be escaped itself, in both widths DecodeName accepts.
		"feed_x0020_v2":     "feed_x005f_x0020_v2",
		"feed_x0001f600_v2": "feed_x005f_x0001f600_v2",
		"_x005f_":           "_x005f_x005f_",
		// ...but an underscore that begins nothing stays verbatim.
		"feed_x00_v2": "feed_x00_v2",
		"trailing_":   "trailing_",
		// Outside the BMP: two UTF-16 code units, because that is what NuGet
		// decodes each marker into.
		"feed \U0001F600": "feed_x0020__xd83d__xde00_",
	}
	for in, want := range cases {
		if got := nugetCredentialsElement(in); got != want {
			t.Errorf("nugetCredentialsElement(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestNugetCredentialsElementRoundTrips is the property that actually matters:
// NuGet decodes the element name back to a source name before matching it, so
// an encoding that is merely valid XML is not enough. A name that decodes to
// anything other than itself attaches the credential to a source the consumer
// does not have — which is not a parse error but an anonymous restore, the
// silent 401 this file exists to remove.
func TestNugetCredentialsElementRoundTrips(t *testing.T) {
	names := []string{
		"company.nuget",
		"internal",
		"Company Feed",
		"365feed",
		".hidden",
		"a<b>c",
		"feed_x0020_v2",
		"feed_x0001f600_v2",
		"_x005f_",
		"feed_x00_v2",
		"trailing_",
		"feed \U0001F600",
		"Ünïcödé feed",
		"tab\tseparated",
		"quote\"and'apostrophe",
	}
	for _, name := range names {
		encoded := nugetCredentialsElement(name)
		if got := decodeNuGetName(encoded); got != name {
			t.Errorf("round trip of %q: encoded %q decoded to %q", name, encoded, got)
		}
		if err := xml.Unmarshal([]byte("<"+encoded+"/>"), new(struct{})); err != nil {
			t.Errorf("encoded name %q (from %q) is not a valid XML element name: %v", encoded, name, err)
		}
	}
}

// decodeNuGetName mirrors XmlConvert.DecodeName: each `_xHHHH_` (or
// `_xHHHHHHHH_`) becomes the UTF-16 code unit(s) it names, everything else is
// literal. It exists so the encoder is tested against the decoder that will
// actually read its output, not against a table of expected strings.
func decodeNuGetName(s string) string {
	var units []uint16
	src := utf16.Encode([]rune(s))
	for i := 0; i < len(src); {
		if consumed, decoded, ok := decodeMarker(src[i:]); ok {
			units = append(units, decoded...)
			i += consumed
			continue
		}
		units = append(units, src[i])
		i++
	}
	return string(utf16.Decode(units))
}

func decodeMarker(src []uint16) (int, []uint16, bool) {
	if len(src) < 2 || src[0] != '_' || (src[1] != 'x' && src[1] != 'X') {
		return 0, nil, false
	}
	for _, width := range []int{4, 8} {
		if len(src) < width+3 || src[width+2] != '_' {
			continue
		}
		v, err := strconv.ParseUint(string(utf16.Decode(src[2:width+2])), 16, 32)
		if err != nil {
			continue
		}
		if width == 4 {
			return width + 3, []uint16{uint16(v)}, true
		}
		return width + 3, utf16.Encode([]rune{rune(v)}), true
	}
	return 0, nil, false
}

// TestValidateFeedCredentials pins the transport rule: a token may not be handed
// to a feed that would carry it in cleartext. npm sends its token unprompted on
// the first request and NuGet answers a Basic challenge with it, so neither tool
// protects the consumer here.
func TestValidateFeedCredentials(t *testing.T) {
	const https = "https://pkgs.dev.azure.com/org/_packaging/feed/npm/registry/"
	const insecure = "http://pkgs.dev.azure.com/org/_packaging/feed/npm/registry/"

	cases := []struct {
		name                 string
		npmURL, nugetURL     string
		npmToken, nugetToken bool
		wantErr              bool
		wantMentions         string
	}{
		{name: "https with both tokens", npmURL: https, nugetURL: https, npmToken: true, nugetToken: true},
		{name: "scheme-less is upgraded by npmRegistryURL", npmURL: "pkgs.dev.azure.com/org/_packaging/feed/npm/registry/", npmToken: true},
		// NuGet does not infer a scheme — it reads a bare value as a local
		// directory, so the token would be attached to a filesystem source.
		{name: "scheme-less nuget is a local path, not a feed", nugetURL: "pkgs.dev.azure.com/org/_packaging/feed/nuget/v3/index.json", nugetToken: true, wantErr: true, wantMentions: "nuget-feed-url"},
		{name: "an actual local path with a token is incoherent", nugetURL: "/mnt/offline-packages", nugetToken: true, wantErr: true, wantMentions: "no scheme"},
		{name: "file:// nuget source with a token", nugetURL: "file:///mnt/offline-packages", nugetToken: true, wantErr: true, wantMentions: "nuget-feed-url"},
		// A feed URL with no token is nobody's business here — nothing is sent,
		// and a local offline folder feed is a legitimate NuGet shape.
		{name: "scheme-less nuget without a token", nugetURL: "/mnt/offline-packages"},
		{name: "no feed configured", npmToken: true, nugetToken: true},
		// A URL with no token is not cicd's business — nothing is being sent.
		{name: "http without a token", npmURL: insecure},
		{name: "http with a token", npmURL: insecure, npmToken: true, wantErr: true, wantMentions: "npm-feed-url"},
		{name: "http nuget with a token", nugetURL: insecure, nugetToken: true, wantErr: true, wantMentions: "nuget-feed-url"},
		{name: "uppercase scheme is still http", npmURL: "HTTP://pkgs.dev.azure.com/f/", npmToken: true, wantErr: true, wantMentions: "npm-feed-url"},
		{name: "a non-web scheme is not a feed", npmURL: "file:///tmp/feed", npmToken: true, wantErr: true, wantMentions: "npm-feed-url"},
		// Loopback stays open so the seam can be proven against a local server,
		// which is how both halves of this file were measured.
		{name: "loopback http", npmURL: "http://127.0.0.1:5001/registry/", npmToken: true},
		{name: "loopback by name", npmURL: "http://localhost:5001/registry/", npmToken: true},
		{name: "loopback v6", npmURL: "http://[::1]:5001/registry/", npmToken: true},
		// A public host is not made safe by looking loopback-ish.
		// The URL becomes a line of cicd's npmrc; a line break would add another.
		{name: "line break in a scheme-less npm url", npmURL: "npm.feed.example/\nregistry=https://elsewhere.example/", npmToken: true, wantErr: true, wantMentions: "npm-feed-url"},
		{name: "space in an npm url", npmURL: "https://npm.feed.example/a b/", npmToken: true, wantErr: true, wantMentions: "npm-feed-url"},
		{name: "surrounding whitespace is trimmed, not refused", npmURL: "  https://npm.feed.example/\n", npmToken: true},
		{name: "not actually loopback", npmURL: "http://localhost.example.com/registry/", npmToken: true, wantErr: true, wantMentions: "npm-feed-url"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateFeedCredentials(c.npmURL, c.npmToken, c.nugetURL, c.nugetToken)
			if c.wantErr && err == nil {
				t.Fatalf("validateFeedCredentials(%q, %v, %q, %v) = nil, want an error", c.npmURL, c.npmToken, c.nugetURL, c.nugetToken)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("validateFeedCredentials(%q, %v, %q, %v) = %v, want nil", c.npmURL, c.npmToken, c.nugetURL, c.nugetToken, err)
			}
			if c.wantErr && !strings.Contains(err.Error(), c.wantMentions) {
				t.Errorf("error %q does not name the offending flag %q", err, c.wantMentions)
			}
		})
	}
}

// TestSameFeedURL covers the matching that decides whether injected credentials
// attach to the consumer's own source name or to the "internal" fallback that
// shadows it.
func TestSameFeedURL(t *testing.T) {
	const canonical = "https://pkgs.dev.azure.com/org/_packaging/feed/nuget/v3/index.json"

	same := []string{
		canonical,
		canonical + "/",
		"https://PKGS.DEV.AZURE.COM/org/_packaging/feed/nuget/v3/index.json",
		"HTTPS://pkgs.dev.azure.com/org/_packaging/feed/nuget/v3/index.json",
		"  " + canonical + "  ",
	}
	for _, s := range same {
		if !sameFeedURL(s, canonical) {
			t.Errorf("sameFeedURL(%q, canonical) = false, want true", s)
		}
	}

	// The feed name lives in the path, and NuGet treats a path as significant —
	// matching case-insensitively there could attach a credential to a different
	// feed on the same host.
	different := []string{
		"https://pkgs.dev.azure.com/org/_packaging/OTHER/nuget/v3/index.json",
		"https://pkgs.dev.azure.com/ORG/_packaging/feed/nuget/v3/index.json",
		"https://pkgs.dev.azure.com/org/_packaging/feed/npm/registry/",
		"http://pkgs.dev.azure.com/org/_packaging/feed/nuget/v3/index.json",
		"",
	}
	for _, s := range different {
		if sameFeedURL(s, canonical) {
			t.Errorf("sameFeedURL(%q, canonical) = true, want false", s)
		}
	}
}
