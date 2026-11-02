//go:build unit_test

package main

import (
	"strings"
	"testing"
)

// The case this file exists for. A consumer declaring net10.0 and no global.json
// used to resolve to the pinned 8.0 default, and every project then failed to
// restore with NETSDK1045 — a leg that could not run, under an envelope that
// named neither the SDK it chose nor why.
func TestATargetFrameworkChoosesTheSDKWhenNoGlobalJSONDoes(t *testing.T) {
	res := dotnetTestToolchain(
		dotnetBandRequest{Band: dotnetSDK100Band, Source: dotnetBandSourceTFM},
		versionFileRead{},
	)
	if want := dotnetSDKLabelFor(dotnetSDK100Band); res.Image != want {
		t.Fatalf("image = %q, want %q", res.Image, want)
	}
	if res.From != ToolchainFromTargetFramework {
		t.Errorf("from = %q, want %q", res.From, ToolchainFromTargetFramework)
	}
	if res.Note != "" {
		t.Errorf("a band cicd served exactly must carry no note, got %q", res.Note)
	}
}

// A global.json that names a band cicd pins keeps deciding, and keeps saying so.
func TestGlobalJSONStillDecidesAndIsNamedAsTheSource(t *testing.T) {
	res := dotnetTestToolchain(
		dotnetBandRequest{Band: dotnetSDK100Band, Source: dotnetBandSourceGlobalJSON},
		versionFileRead{Present: true, Value: dotnetSDK100Band},
	)
	if want := dotnetSDKLabelFor(dotnetSDK100Band); res.Image != want {
		t.Fatalf("image = %q, want %q", res.Image, want)
	}
	if res.From != ToolchainFromGlobalJSON {
		t.Errorf("from = %q, want %q", res.From, ToolchainFromGlobalJSON)
	}
	if res.Note != "" {
		t.Errorf("note = %q, want none", res.Note)
	}
}

// Silence has to keep meaning something. A repository that pins no version at
// all gets the oldest pinned band and no line about it.
func TestARepositoryThatPinsNothingIsSilent(t *testing.T) {
	res := dotnetTestToolchain(dotnetBandRequest{}, versionFileRead{})
	if want := dotnetSDKLabelFor(dotnetSDK80Band); res.Image != want {
		t.Fatalf("image = %q, want %q", res.Image, want)
	}
	if res.From != ToolchainFromDefault {
		t.Errorf("from = %q, want %q", res.From, ToolchainFromDefault)
	}
	if res.Note != "" {
		t.Errorf("an absent version file must carry no note, got %q", res.Note)
	}
}

// The measured MTP case, preserved from ResolveToolchainDetail: a global.json
// holding only a runner opt-in declares no sdk.version, and the 8.0 band that
// predates the opt-in cannot honour it. Present and not decisive still speaks.
func TestARunnerOnlyGlobalJSONWithNoTargetFrameworkStillSaysSo(t *testing.T) {
	res := dotnetTestToolchain(
		dotnetBandRequest{},
		versionFileRead{Present: true, Why: "declares no sdk.version"},
	)
	if want := dotnetSDKLabelFor(dotnetSDK80Band); res.Image != want {
		t.Fatalf("image = %q, want %q", res.Image, want)
	}
	for _, want := range []string{"global.json", "declares no sdk.version", res.Image} {
		if !strings.Contains(res.Note, want) {
			t.Errorf("note %q does not name %q", res.Note, want)
		}
	}
}

// And a TargetFramework rescues that same repository: the file is still not
// decisive, but something else decided, so there is nothing anomalous to report.
func TestATargetFrameworkRescuesARunnerOnlyGlobalJSON(t *testing.T) {
	res := dotnetTestToolchain(
		dotnetBandRequest{Band: dotnetSDK100Band, Source: dotnetBandSourceTFM},
		versionFileRead{Present: true, Why: "declares no sdk.version"},
	)
	if want := dotnetSDKLabelFor(dotnetSDK100Band); res.Image != want {
		t.Fatalf("image = %q, want %q", res.Image, want)
	}
	if res.Note != "" {
		t.Errorf("note = %q, want none — the band was decided", res.Note)
	}
}

// A band cicd pins no image of runs on a pinned one, and says which and why.
// Never a refusal: the request is read from files cicd cannot fully evaluate.
func TestABandCicdDoesNotPinRunsOnAPinnedOneAndSaysSo(t *testing.T) {
	for _, tc := range []struct{ name, band string }{
		{"between pinned bands", "9.0"},
		{"above every pinned band", "99.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := dotnetTestToolchain(
				dotnetBandRequest{Band: tc.band, Source: dotnetBandSourceTFM},
				versionFileRead{},
			)
			if res.Note == "" {
				t.Fatalf("a band cicd could not serve exactly must carry a note")
			}
			if !strings.Contains(res.Note, tc.band) {
				t.Errorf("note %q does not name the requested band %q", res.Note, tc.band)
			}
			if res.Image == dotnetSDKLabelFor(tc.band) {
				t.Errorf("image %q is the unpinned band itself", res.Image)
			}
		})
	}
}

// The BYO leg and the Check legs must agree about which band a request resolves
// to. They are two callers of dotnetResolveBand and the bug this file fixes was
// a second, disagreeing resolver — so the agreement is asserted, not assumed.
func TestTheBYOLegResolvesTheSameBandAsTheCheckLegs(t *testing.T) {
	for _, req := range []dotnetBandRequest{
		{},
		{Band: dotnetSDK80Band, Source: dotnetBandSourceGlobalJSON},
		{Band: dotnetSDK100Band, Source: dotnetBandSourceTFM},
		{Band: "9.0", Source: dotnetBandSourceTFM},
		{Band: "99.0", Source: dotnetBandSourceGlobalJSON},
	} {
		band, _ := dotnetResolveBand(req)
		got := dotnetTestToolchain(req, versionFileRead{})
		if want := dotnetSDKLabelFor(band); got.Image != want {
			t.Errorf("request %+v: BYO image %q, Check band image %q", req, got.Image, want)
		}
	}
}

// Every band cicd pins must be reachable as a BYO image, or a pin exists that
// no consumer command can ever run in.
func TestEveryPinnedBandIsReachable(t *testing.T) {
	if len(dotnetSDKBands) == 0 {
		t.Fatal("no pinned bands — this test would pass vacuously")
	}
	for _, band := range dotnetSDKBands {
		res := dotnetTestToolchain(
			dotnetBandRequest{Band: band, Source: dotnetBandSourceTFM},
			versionFileRead{},
		)
		if want := dotnetSDKLabelFor(band); res.Image != want {
			t.Errorf("pinned band %s resolves to %q, want %q", band, res.Image, want)
		}
		if res.Note != "" {
			t.Errorf("pinned band %s carries note %q, want none", band, res.Note)
		}
	}
}

// The source names are spelled in dotnetreport.go and switched on here. A pair
// that can drift is how the accepted-language set drifted from its shell case.
func TestEveryBandSourceIsMappedToAResolutionLevel(t *testing.T) {
	for source, want := range map[string]string{
		dotnetBandSourceGlobalJSON: ToolchainFromGlobalJSON,
		dotnetBandSourceTFM:        ToolchainFromTargetFramework,
		"":                         ToolchainFromDefault,
	} {
		band := dotnetSDK100Band
		if source == "" {
			band = ""
		}
		res := dotnetTestToolchain(dotnetBandRequest{Band: band, Source: source}, versionFileRead{})
		if res.From != want {
			t.Errorf("source %q -> from %q, want %q", source, res.From, want)
		}
	}
}
