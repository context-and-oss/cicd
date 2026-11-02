//go:build unit_test

package main

import (
	"strings"
	"testing"
)

// TestDotnetResolveBandFallsBackToTheOldestPin. Nothing readable said anything —
// no global.json, no literal TargetFramework — which is the common case, not an
// error. The oldest pinned band is the choice that restores the widest range of
// targets, since a newer SDK restores an older target but never the reverse.
func TestDotnetResolveBandFallsBackToTheOldestPin(t *testing.T) {
	for _, req := range []dotnetBandRequest{
		{},
		{Band: "", Source: ""},
		{Band: "netstandard2.0", Source: "TargetFramework"},
		{Band: "not-a-band", Source: "global.json"},
	} {
		band, note := dotnetResolveBand(req)
		if band != dotnetSDKBands[0] {
			t.Errorf("%+v resolved to %s, expected the oldest pinned band %s",
				req, band, dotnetSDKBands[0])
		}
		if !strings.Contains(note, dotnetSDKBands[0]) {
			t.Errorf("note must name the band it chose, got %q", note)
		}
	}
}

// TestDotnetResolveBandHonoursAnExactRequest.
func TestDotnetResolveBandHonoursAnExactRequest(t *testing.T) {
	for _, want := range dotnetSDKBands {
		band, note := dotnetResolveBand(dotnetBandRequest{Band: want, Source: "global.json"})
		if band != want {
			t.Errorf("requested %s, got %s", want, band)
		}
		if !strings.Contains(note, "global.json") {
			t.Errorf("note must say where the request came from, got %q", note)
		}
	}
}

// TestDotnetResolveBandRoundsUpToTheNearestPin. A net9.0 tree restores fine in a
// 10.0 SDK; there is no image to pin for every band Microsoft ships, and picking
// the nearest one above is the only choice that can build the tree.
func TestDotnetResolveBandRoundsUpToTheNearestPin(t *testing.T) {
	band, note := dotnetResolveBand(dotnetBandRequest{Band: "9.0", Source: "TargetFramework"})
	if band != dotnetSDK100Band {
		t.Fatalf("net9.0 should restore in %s, got %s", dotnetSDK100Band, band)
	}
	if !strings.Contains(note, "9.0") || !strings.Contains(note, "nearest") {
		t.Errorf("note must explain the substitution, got %q", note)
	}
}

// TestDotnetResolveBandRunsAboveThePinRatherThanRefusing. The request is read
// from files cicd cannot fully evaluate — a net11.0 inside a conditioned
// TargetFrameworks element may never be built at all — so refusing would fail a
// tree that restores perfectly well. Running keeps the verdict with the SDK: if
// the band genuinely cannot restore, the restore fails as a non-run, which no
// --fail-on threshold forgives.
func TestDotnetResolveBandRunsAboveThePinRatherThanRefusing(t *testing.T) {
	highest := dotnetSDKBands[len(dotnetSDKBands)-1]
	band, note := dotnetResolveBand(dotnetBandRequest{Band: "99.0", Source: "TargetFramework"})
	if band != highest {
		t.Fatalf("expected the newest pinned band %s, got %s", highest, band)
	}
	for _, want := range []string{"99.0", "above every band", dotnetBandsLabel(), "never as a clean pass"} {
		if !strings.Contains(note, want) {
			t.Errorf("note missing %q: %s", want, note)
		}
	}
}

// TestDotnetResolveBandNeverInventsAnUnpinnedBand. Every answer must be a band
// dotnetSDKBase has a literal, digest-pinned From() for; anything else is a
// verdict attributed to an SDK nobody pinned.
func TestDotnetResolveBandNeverInventsAnUnpinnedBand(t *testing.T) {
	pinned := map[string]bool{}
	for _, b := range dotnetSDKBands {
		pinned[b] = true
	}
	for _, req := range []string{"", "6.0", "8.0", "9.0", "10.0", "12.5", "garbage"} {
		band, _ := dotnetResolveBand(dotnetBandRequest{Band: req, Source: "TargetFramework"})
		if !pinned[band] {
			t.Errorf("request %q resolved to unpinned band %q", req, band)
		}
	}
}

// TestGlobalJSONWinsOverTargetFramework. global.json is the consumer's explicit
// statement about which SDK to use, and honouring it is what keeps NETSDK1045 off
// the table when a TargetFramework cicd can read disagrees with it.
func TestGlobalJSONWinsOverTargetFramework(t *testing.T) {
	raw := dotnetProbeGlobalJSON + "\n" +
		`{"sdk":{"version":"10.0.100","rollForward":"latestFeature"}}` + "\n" +
		dotnetProbeTFM + "\n" +
		"<Project><TargetFramework>net8.0</TargetFramework></Project>\n"

	req := parseDotnetBandRequest(raw)
	if req.Band != "10.0" || req.Source != "global.json" {
		t.Fatalf("expected 10.0 from global.json, got %+v", req)
	}
}

// TestTargetFrameworkAnswersWhenGlobalJSONDoesNot, including the multi-targeting
// case: a project built for net8.0 and net10.0 needs the SDK that can do both.
func TestTargetFrameworkAnswersWhenGlobalJSONDoesNot(t *testing.T) {
	raw := dotnetProbeGlobalJSON + "\n\n" + dotnetProbeTFM + "\n" +
		"<Project><TargetFrameworks>net8.0;net10.0</TargetFrameworks></Project>\n" +
		"<Project><TargetFramework>net6.0</TargetFramework></Project>\n"

	req := parseDotnetBandRequest(raw)
	if req.Band != "10.0" || req.Source != "TargetFramework" {
		t.Fatalf("expected the highest literal target framework, got %+v", req)
	}
}

// TestTargetFrameworkIsReadOnlyFromItsOwnElement. Scanning the whole project
// file for anything version-shaped would pick a version out of a PackageReference
// and restore in an SDK band chosen by a dependency's version number.
func TestTargetFrameworkIsReadOnlyFromItsOwnElement(t *testing.T) {
	raw := dotnetProbeGlobalJSON + "\n\n" + dotnetProbeTFM + "\n" +
		`<Project><TargetFramework>net8.0</TargetFramework>` +
		`<PackageReference Include="Foo" Version="net99.0" /></Project>`

	if req := parseDotnetBandRequest(raw); req.Band != "8.0" {
		t.Fatalf("a PackageReference must not set the SDK band, got %+v", req)
	}
}

// TestUnreadableProbeOutputIsNoRequest, not a guess. An answer invented from
// output the probe did not produce is worse than no answer: the fallback to the
// oldest pinned band is at least stated in the note.
func TestUnreadableProbeOutputIsNoRequest(t *testing.T) {
	for name, raw := range map[string]string{
		"empty":         "",
		"no delimiters": "{}",
		"truncated":     dotnetProbeGlobalJSON + "\n{\"sdk\":",
	} {
		if req := parseDotnetBandRequest(raw); req.Band != "" {
			t.Errorf("%s: expected no request, got %+v", name, req)
		}
	}
}

// TestDotnetBandFromGlobalJSONNeedsTwoComponents. "10" is not a band, and
// treating it as 10.0 would be cicd deciding what the consumer meant.
func TestDotnetBandFromGlobalJSONNeedsTwoComponents(t *testing.T) {
	for _, raw := range []string{`{"sdk":{"version":"10"}}`, `{"sdk":{}}`, `{`, "  "} {
		if band, ok := dotnetBandFromGlobalJSON(raw); ok {
			t.Errorf("%q must not yield a band, got %q", raw, band)
		}
	}
	if band, ok := dotnetBandFromGlobalJSON(`{"sdk":{"version":"8.0.404"}}`); !ok || band != "8.0" {
		t.Errorf("expected 8.0, got %q ok=%v", band, ok)
	}
}

// TestDotnetBandCompareRefusesRatherThanReportingEquality. A comparison against
// something that is not a band must not come back as "equal" — that is how an
// unparseable request would silently match the first pinned band.
func TestDotnetBandCompareRefusesRatherThanReportingEquality(t *testing.T) {
	if _, ok := dotnetBandCompare("8.0", "netstandard2.0"); ok {
		t.Error("a non-band comparison must report ok=false")
	}
	if cmp, ok := dotnetBandCompare("10.0", "8.0"); !ok || cmp <= 0 {
		t.Errorf("10.0 must order above 8.0, got %d ok=%v", cmp, ok)
	}
	if cmp, ok := dotnetBandCompare("8.10", "8.9"); !ok || cmp <= 0 {
		t.Errorf("minor versions must compare numerically, not as text: %d ok=%v", cmp, ok)
	}
}
