package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// cdxTestRepo and cdxTestTime keep the merge tests focused on merging: the
// header they now produce is pinned in cdxmetadata_test.go instead.
var cdxTestRepo = repoContext{RepoURL: "https://example.com/acme/widget", CommitSHA: "abc123"}

var cdxTestTime = time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)

func cdxEnv(t *testing.T, cdxJSON string) *envelope {
	t.Helper()
	return &envelope{
		ModuleName:      "test",
		CycloneDXReport: json.RawMessage(cdxJSON),
	}
}

func mustMergeCDX(t *testing.T, envs []*envelope) cdxDocument {
	t.Helper()
	doc, err := mergeCycloneDX(envs, cdxTestRepo, cdxTestTime)
	if err != nil {
		t.Fatalf("mergeCycloneDX() unexpected error: %v", err)
	}
	return doc
}

func decodeObjects(t *testing.T, raws []json.RawMessage) []map[string]any {
	t.Helper()
	out := make([]map[string]any, 0, len(raws))
	for _, r := range raws {
		var m map[string]any
		if err := json.Unmarshal(r, &m); err != nil {
			t.Fatalf("decode %s: %v", r, err)
		}
		out = append(out, m)
	}
	return out
}

// TestMergeCycloneDX covers the identity-preserving aggregation contract:
// exact duplicates collapse, complementary data merges losslessly, conflicting
// non-empty scalars error explicitly, purl/tuple fallback identity resolves
// for components lacking a bom-ref, and identity-less vulnerabilities are
// preserved distinctly unless semantically identical. A naive
// append-only aggregator (the pre-existing behavior) fails every duplicate
// assertion here.
func TestMergeCycloneDX(t *testing.T) {
	t.Run("exact duplicate bom-ref collapses to one component", func(t *testing.T) {
		a := cdxEnv(t, `{"components":[{"bom-ref":"pkg:npm/left-pad@1.3.0","type":"library","name":"left-pad","version":"1.3.0"}]}`)
		b := cdxEnv(t, `{"components":[{"bom-ref":"pkg:npm/left-pad@1.3.0","type":"library","name":"left-pad","version":"1.3.0"}]}`)

		doc := mustMergeCDX(t, []*envelope{a, b})
		if len(doc.Components) != 1 {
			t.Fatalf("got %d components, want 1 (duplicate must collapse): %s", len(doc.Components), doc.Components)
		}
	})

	t.Run("exact duplicate vulnerability bom-ref collapses to one", func(t *testing.T) {
		a := cdxEnv(t, `{"vulnerabilities":[{"bom-ref":"vuln-1","id":"CVE-2024-0001"}]}`)
		b := cdxEnv(t, `{"vulnerabilities":[{"bom-ref":"vuln-1","id":"CVE-2024-0001"}]}`)

		doc := mustMergeCDX(t, []*envelope{a, b})
		if len(doc.Vulnerabilities) != 1 {
			t.Fatalf("got %d vulnerabilities, want 1: %s", len(doc.Vulnerabilities), doc.Vulnerabilities)
		}
	})

	t.Run("complementary data merges losslessly without duplicate identity", func(t *testing.T) {
		// One scan supplies licenses, the other supplies hashes — both are
		// non-conflicting, complementary facts about the same component.
		a := cdxEnv(t, `{"components":[{"bom-ref":"pkg:npm/left-pad@1.3.0","type":"library","name":"left-pad","version":"1.3.0","licenses":[{"license":{"id":"MIT"}}]}]}`)
		b := cdxEnv(t, `{"components":[{"bom-ref":"pkg:npm/left-pad@1.3.0","type":"library","name":"left-pad","hashes":[{"alg":"SHA-256","content":"deadbeef"}]}]}`)

		doc := mustMergeCDX(t, []*envelope{a, b})
		if len(doc.Components) != 1 {
			t.Fatalf("got %d components, want 1 merged record: %s", len(doc.Components), doc.Components)
		}
		merged := decodeObjects(t, doc.Components)[0]
		if merged["version"] != "1.3.0" {
			t.Errorf("version = %v, want 1.3.0 (complementary field must survive)", merged["version"])
		}
		licenses, ok := merged["licenses"].([]any)
		if !ok || len(licenses) != 1 {
			t.Errorf("licenses = %v, want the one entry from the first record", merged["licenses"])
		}
		hashes, ok := merged["hashes"].([]any)
		if !ok || len(hashes) != 1 {
			t.Errorf("hashes = %v, want the one entry from the second record", merged["hashes"])
		}
	})

	t.Run("union of equivalent arrays dedups shared elements", func(t *testing.T) {
		a := cdxEnv(t, `{"components":[{"bom-ref":"pkg:npm/left-pad@1.3.0","name":"left-pad","licenses":[{"license":{"id":"MIT"}}]}]}`)
		b := cdxEnv(t, `{"components":[{"bom-ref":"pkg:npm/left-pad@1.3.0","name":"left-pad","licenses":[{"license":{"id":"MIT"}},{"license":{"id":"Apache-2.0"}}]}]}`)

		doc := mustMergeCDX(t, []*envelope{a, b})
		merged := decodeObjects(t, doc.Components)[0]
		licenses, _ := merged["licenses"].([]any)
		if len(licenses) != 2 {
			t.Fatalf("licenses = %v, want 2 deduped entries (MIT ∪ {MIT, Apache-2.0})", licenses)
		}
	})

	t.Run("conflicting non-empty scalar identity data errors explicitly", func(t *testing.T) {
		a := cdxEnv(t, `{"components":[{"bom-ref":"pkg:npm/left-pad@1.3.0","name":"left-pad","version":"1.3.0"}]}`)
		b := cdxEnv(t, `{"components":[{"bom-ref":"pkg:npm/left-pad@1.3.0","name":"left-pad","version":"1.3.1"}]}`)

		_, err := mergeCycloneDX([]*envelope{a, b}, cdxTestRepo, cdxTestTime)
		if err == nil {
			t.Fatal("mergeCycloneDX() error = nil, want an explicit conflict error (1.3.0 vs 1.3.1)")
		}
		if !strings.Contains(err.Error(), "version") {
			t.Errorf("error = %q, want it to name the conflicting field", err.Error())
		}
	})

	t.Run("conflicting nested vulnerability source errors instead of picking one", func(t *testing.T) {
		a := cdxEnv(t, `{"vulnerabilities":[{"id":"CVE-2024-0001","source":{"name":"OSV"}}]}`)
		b := cdxEnv(t, `{"vulnerabilities":[{"id":"CVE-2024-0001","source":{"name":"GHSA"}}]}`)

		_, err := mergeCycloneDX([]*envelope{a, b}, cdxTestRepo, cdxTestTime)
		if err == nil {
			t.Fatal("mergeCycloneDX() error = nil, want a conflict on source.name (OSV vs GHSA)")
		}
	})

	t.Run("array fields union rather than conflict across sources", func(t *testing.T) {
		// Two ratings from different scanners describing the same
		// vulnerability are complementary, additive facts — not a conflict —
		// so both must survive in the merged array.
		a := cdxEnv(t, `{"vulnerabilities":[{"id":"CVE-2024-0001","ratings":[{"source":{"name":"OSV"},"severity":"critical"}]}]}`)
		b := cdxEnv(t, `{"vulnerabilities":[{"id":"CVE-2024-0001","ratings":[{"source":{"name":"GHSA"},"severity":"low"}]}]}`)

		doc := mustMergeCDX(t, []*envelope{a, b})
		if len(doc.Vulnerabilities) != 1 {
			t.Fatalf("got %d vulnerabilities, want 1 merged record: %s", len(doc.Vulnerabilities), doc.Vulnerabilities)
		}
		merged := decodeObjects(t, doc.Vulnerabilities)[0]
		ratings, _ := merged["ratings"].([]any)
		if len(ratings) != 2 {
			t.Fatalf("ratings = %v, want both scanners' ratings retained", merged["ratings"])
		}
	})

	t.Run("purl fallback identity used when bom-ref absent", func(t *testing.T) {
		a := cdxEnv(t, `{"components":[{"purl":"pkg:npm/left-pad@1.3.0","name":"left-pad","version":"1.3.0"}]}`)
		b := cdxEnv(t, `{"components":[{"purl":"pkg:npm/left-pad@1.3.0","name":"left-pad","version":"1.3.0","description":"string padding"}]}`)

		doc := mustMergeCDX(t, []*envelope{a, b})
		if len(doc.Components) != 1 {
			t.Fatalf("got %d components, want 1 (purl fallback identity must collapse them): %s", len(doc.Components), doc.Components)
		}
		merged := decodeObjects(t, doc.Components)[0]
		if merged["description"] != "string padding" {
			t.Errorf("description = %v, want the complementary field to survive the purl-keyed merge", merged["description"])
		}
	})

	t.Run("deterministic package tuple fallback used when bom-ref and purl absent", func(t *testing.T) {
		a := cdxEnv(t, `{"components":[{"type":"library","name":"left-pad","version":"1.3.0"}]}`)
		b := cdxEnv(t, `{"components":[{"type":"library","name":"left-pad","version":"1.3.0"}]}`)
		// A distinct version must NOT collapse into the same tuple identity.
		c := cdxEnv(t, `{"components":[{"type":"library","name":"left-pad","version":"1.3.1"}]}`)

		doc := mustMergeCDX(t, []*envelope{a, b, c})
		if len(doc.Components) != 2 {
			t.Fatalf("got %d components, want 2 (1.3.0 collapsed, 1.3.1 distinct): %s", len(doc.Components), doc.Components)
		}
	})

	t.Run("identity-less vulnerabilities are preserved distinctly unless identical", func(t *testing.T) {
		// No bom-ref, no id on either — no safe identity is derivable.
		a := cdxEnv(t, `{"vulnerabilities":[{"description":"unscored finding A"}]}`)
		b := cdxEnv(t, `{"vulnerabilities":[{"description":"unscored finding B"}]}`)
		dup := cdxEnv(t, `{"vulnerabilities":[{"description":"unscored finding A"}]}`)

		doc := mustMergeCDX(t, []*envelope{a, b, dup})
		if len(doc.Vulnerabilities) != 2 {
			t.Fatalf("got %d vulnerabilities, want 2 (A/dup collapse as identical, B stays distinct): %s", len(doc.Vulnerabilities), doc.Vulnerabilities)
		}
	})

	t.Run("materially distinct records with the same identity are not lost", func(t *testing.T) {
		// Two components sharing a bom-ref but with genuinely additive detail
		// (no conflict) must retain all complementary data, not just the
		// first-seen record (which an append-only or first-wins merge would do).
		a := cdxEnv(t, `{"components":[{"bom-ref":"c1","name":"left-pad","scope":"required"}]}`)
		b := cdxEnv(t, `{"components":[{"bom-ref":"c1","name":"left-pad","group":"npm"}]}`)

		doc := mustMergeCDX(t, []*envelope{a, b})
		if len(doc.Components) != 1 {
			t.Fatalf("got %d components, want 1: %s", len(doc.Components), doc.Components)
		}
		merged := decodeObjects(t, doc.Components)[0]
		if merged["scope"] != "required" || merged["group"] != "npm" {
			t.Errorf("merged = %v, want both scope and group preserved", merged)
		}
	})
}

// TestOnePackageIsOneComponentHoweverManyProjectsReferenceIt replays the shape
// that made the merge a no-op: Trivy stamps a fresh random bom-ref on every
// occurrence, so reading bom-ref before purl gave one package as many
// identities as there were referencing projects.
func TestOnePackageIsOneComponentHoweverManyProjectsReferenceIt(t *testing.T) {
	// Three records of one package, the shape a consumer's run produced twenty-odd
	// of (synthetic bom-refs: Trivy stamps a fresh random one on each).
	env := cdxEnv(t, `{"components":[
		{"bom-ref":"00000000-0000-4000-8000-000000000001","type":"library","name":"Newtonsoft.Json","version":"13.0.4","purl":"pkg:nuget/Newtonsoft.Json@13.0.4"},
		{"bom-ref":"00000000-0000-4000-8000-000000000002","type":"library","name":"Newtonsoft.Json","version":"13.0.4","purl":"pkg:nuget/Newtonsoft.Json@13.0.4"},
		{"bom-ref":"00000000-0000-4000-8000-000000000003","type":"library","name":"Newtonsoft.Json","version":"13.0.4","purl":"pkg:nuget/Newtonsoft.Json@13.0.4"}
	]}`)

	doc := mustMergeCDX(t, []*envelope{env})
	if len(doc.Components) != 1 {
		t.Fatalf("got %d components, want 1 — the same package at the same version is one component", len(doc.Components))
	}
	got := decodeObjects(t, doc.Components)[0]
	if got["purl"] != "pkg:nuget/Newtonsoft.Json@13.0.4" {
		t.Errorf("purl = %v, want the package coordinate preserved", got["purl"])
	}
	// One ref, deterministically the first seen: a merged record with an
	// arbitrary-but-stable ref beats one with none, and beats a merge that
	// fails on "conflicting values".
	if got["bom-ref"] != "00000000-0000-4000-8000-000000000001" {
		t.Errorf("bom-ref = %v, want the first-seen ref", got["bom-ref"])
	}
}

// Different versions are different components. Collapsing by purl must not
// collapse by name.
func TestTwoVersionsOfOnePackageStayTwoComponents(t *testing.T) {
	env := cdxEnv(t, `{"components":[
		{"bom-ref":"a","type":"library","name":"Newtonsoft.Json","version":"13.0.4","purl":"pkg:nuget/Newtonsoft.Json@13.0.4"},
		{"bom-ref":"b","type":"library","name":"Newtonsoft.Json","version":"12.0.3","purl":"pkg:nuget/Newtonsoft.Json@12.0.3"}
	]}`)
	if doc := mustMergeCDX(t, []*envelope{env}); len(doc.Components) != 2 {
		t.Fatalf("got %d components, want 2", len(doc.Components))
	}
}

// A component with no purl still has to be identifiable. The bom-ref fallback
// is the previous behaviour and stays.
func TestAComponentWithNoPurlFallsBackToItsRef(t *testing.T) {
	env := cdxEnv(t, `{"components":[
		{"bom-ref":"app-1","type":"application","name":"Widget.Api","licenses":[{"license":{"id":"MIT"}}]},
		{"bom-ref":"app-1","type":"application","name":"Widget.Api","version":"1.0.0"},
		{"bom-ref":"app-2","type":"application","name":"Widget.Worker"}
	]}`)
	doc := mustMergeCDX(t, []*envelope{env})
	if len(doc.Components) != 2 {
		t.Fatalf("got %d components, want 2 (app-1 folded, app-2 distinct)", len(doc.Components))
	}
	first := decodeObjects(t, doc.Components)[0]
	if first["version"] != "1.0.0" || first["licenses"] == nil {
		t.Errorf("complementary fields did not merge across one ref: %v", first)
	}
}

// The purl-first order is for components only. A vulnerability has no purl and
// its bom-ref is the identity its producer meant.
func TestVulnerabilityIdentityIsUnchanged(t *testing.T) {
	env := cdxEnv(t, `{"vulnerabilities":[
		{"bom-ref":"v1","id":"CVE-2024-0001"},
		{"bom-ref":"v1","id":"CVE-2024-0001","source":{"name":"OSV"}},
		{"id":"CVE-2024-0002"}
	]}`)
	if doc := mustMergeCDX(t, []*envelope{env}); len(doc.Vulnerabilities) != 2 {
		t.Fatalf("got %d vulnerabilities, want 2", len(doc.Vulnerabilities))
	}
}

// Two records proven to be one package may still disagree on a real field, and
// that is still a conflict. Making bom-ref local must not make everything local.
func TestAGenuineConflictBetweenTwoRecordsOfOnePurlStillFails(t *testing.T) {
	env := cdxEnv(t, `{"components":[
		{"bom-ref":"a","name":"pkg","version":"1.0.0","purl":"pkg:npm/pkg@1.0.0","scope":"required"},
		{"bom-ref":"b","name":"pkg","version":"1.0.0","purl":"pkg:npm/pkg@1.0.0","scope":"optional"}
	]}`)
	if _, err := mergeCycloneDX([]*envelope{env}, cdxTestRepo, cdxTestTime); err == nil {
		t.Fatal("merged two records claiming different scope for one purl; want an explicit conflict")
	}
}
