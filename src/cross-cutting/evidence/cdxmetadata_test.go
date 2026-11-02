package main

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestTheSBOMSaysWhatItIsAnSBOMOf pins the header that was absent: without
// metadata.component the document is a list of packages with no subject.
func TestTheSBOMSaysWhatItIsAnSBOMOf(t *testing.T) {
	// Revision and clock are synthetic metadata controls, not run provenance.
	repo := repoContext{
		RepoURL:   "https://dev.azure.com/acme/Widget",
		CommitSHA: "0123456789abcdef0123456789abcdef01234567",
		Branch:    "main",
	}
	md := buildCDXMetadata(repo, time.Date(2000, 1, 2, 3, 4, 5, 0, time.UTC))

	if md.Timestamp != "2000-01-02T03:04:05Z" {
		t.Errorf("timestamp = %q, want RFC3339 UTC", md.Timestamp)
	}
	if md.Component == nil {
		t.Fatal("metadata.component is nil — the BOM still does not say what it describes")
	}
	if got, want := md.Component.Name, "Widget"; got != want {
		t.Errorf("component.name = %q, want %q (verbatim: a repository with a space in its name has one)", got, want)
	}
	if got, want := md.Component.Group, "acme"; got != want {
		t.Errorf("component.group = %q, want %q", got, want)
	}
	if got, want := md.Component.Version, repo.CommitSHA; got != want {
		t.Errorf("component.version = %q, want the commit %q", got, want)
	}
	if md.Component.Type != "application" {
		t.Errorf("component.type = %q, want application", md.Component.Type)
	}
	if md.Tools == nil || len(md.Tools.Components) != 1 || md.Tools.Components[0].Name != "cicd" {
		t.Errorf("tools = %+v, want the one component that produced this document", md.Tools)
	}
}

// TestTheSubjectIsIdentifiedByATreeAndNotByAName: a tag moves and a branch
// advances, so neither identifies the tree the components were read from.
func TestTheSubjectIsIdentifiedByATreeAndNotByAName(t *testing.T) {
	for _, tc := range []struct {
		name string
		repo repoContext
		want string
	}{
		{"commit wins over both", repoContext{CommitSHA: "sha", Tag: "v1.0.0", Branch: "main"}, "sha"},
		{"tag when there is no commit", repoContext{Tag: "v1.0.0", Branch: "main"}, "v1.0.0"},
		{"branch is the last resort", repoContext{Branch: "main"}, "main"},
		{"nothing at all", repoContext{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cdxSubjectVersion(tc.repo); got != tc.want {
				t.Errorf("cdxSubjectVersion() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTheSubjectNameSurvivesTheURLShapesInUse(t *testing.T) {
	for _, tc := range []struct{ url, name, group string }{
		{"https://github.com/context-and-oss/cicd", "cicd", "context-and-oss"},
		{"https://github.com/context-and-oss/cicd.git", "cicd", "context-and-oss"},
		{"https://github.com/context-and-oss/cicd/", "cicd", "context-and-oss"},
		{"git@github.com:context-and-oss/cicd.git", "cicd", "context-and-oss"},
		{"https://dev.azure.com/acme/Consumer App", "Consumer App", "acme"},
		{"widget", "widget", ""},
		{"", "", ""},
		{"   ", "", ""},
	} {
		name, group := cdxSubjectName(tc.url)
		if name != tc.name || group != tc.group {
			t.Errorf("cdxSubjectName(%q) = (%q, %q), want (%q, %q)", tc.url, name, group, tc.name, tc.group)
		}
	}
}

// A missing repo URL must not remove the subject: the commit is still the part
// a reader can act on.
func TestAnUnknownRepositoryStillGetsASubject(t *testing.T) {
	md := buildCDXMetadata(repoContext{CommitSHA: "abc"}, time.Now())
	if md.Component == nil || md.Component.Name != "unknown" || md.Component.Version != "abc" {
		t.Errorf("component = %+v, want a named-unknown subject carrying the commit", md.Component)
	}
}

var urnUUID = regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestTheSerialNumberIsTheSubjectAndNotTheRun(t *testing.T) {
	a := repoContext{RepoURL: "https://example.com/acme/widget", CommitSHA: "abc"}
	b := repoContext{RepoURL: "https://example.com/acme/widget", CommitSHA: "def"}

	first := cdxSerialNumber(a)
	if !urnUUID.MatchString(first) {
		t.Fatalf("serial %q is not a v5-shaped urn:uuid", first)
	}
	if second := cdxSerialNumber(a); second != first {
		t.Errorf("same subject produced two serials (%q, %q); re-running one commit is not a second BOM", first, second)
	}
	if other := cdxSerialNumber(b); other == first {
		t.Errorf("two commits share serial %q; the serial must follow the tree it describes", other)
	}
}

// The header must reach the marshalled document, not just the struct.
func TestTheHeaderReachesTheFileAConsumerReads(t *testing.T) {
	doc, err := mergeCycloneDX(nil, repoContext{
		RepoURL: "https://example.com/acme/widget", CommitSHA: "abc",
	}, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil {
		t.Fatalf("mergeCycloneDX() error = %v", err)
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{
		`"bomFormat":"CycloneDX"`,
		`"serialNumber":"urn:uuid:`,
		`"metadata":{"timestamp":"2026-01-02T03:04:05Z"`,
		`"name":"widget"`,
		`"name":"cicd"`,
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("marshalled BOM is missing %s\ngot: %s", want, b)
		}
	}
}
