package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// The SBOM's own header: what this document describes, who produced it, and
// when. Untagged and free of Dagger, so cdxmetadata_test.go can pin it.
//
// It was missing entirely. sbom.cdx.json carried bomFormat, specVersion,
// version and an array of components, and nothing that said what the components
// were components OF. A CycloneDX document without metadata.component is a list
// of packages with no subject — a reader cannot tell one repository's SBOM from
// another's, and NTIA's minimum elements (author, timestamp, and the primary
// component) are three fields none of which were present.
//
// This is the same failure this repository keeps finding in its own output, in
// its cheapest form: a document that answers a question nobody asked it, and is
// silent on the one that matters.

// cdxMetadata is CycloneDX 1.5 `metadata`.
type cdxMetadata struct {
	Timestamp string        `json:"timestamp"`
	Tools     *cdxTools     `json:"tools,omitempty"`
	Component *cdxComponent `json:"component,omitempty"`
}

// cdxTools is the 1.5 object form (`{components: []}`), not the array form the
// spec deprecated in 1.5. Trivy already emits the object form, so a consumer
// reading both cicd's BOM and a raw Trivy BOM meets one shape.
type cdxTools struct {
	Components []cdxComponent `json:"components,omitempty"`
}

// cdxComponent is the subset of a CycloneDX component this module writes for
// itself and for the subject. Components harvested from producers stay
// json.RawMessage and are never coerced through this struct — a lossy round
// trip through a partial Go type is how fields go missing.
type cdxComponent struct {
	Type    string `json:"type"`
	BOMRef  string `json:"bom-ref,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Group   string `json:"group,omitempty"`
}

// buildCDXMetadata describes the scanned repository and the tool that scanned
// it. now is a parameter so a test can pin the timestamp.
func buildCDXMetadata(repo repoContext, now time.Time) *cdxMetadata {
	md := &cdxMetadata{
		Timestamp: now.UTC().Format(time.RFC3339),
		Tools: &cdxTools{Components: []cdxComponent{{
			Type:  "application",
			Group: "context-and-oss",
			Name:  "cicd",
		}}},
	}
	name, group := cdxSubjectName(repo.RepoURL)
	if repo.AppID != "" {
		group = strings.Trim(group+"/"+name, "/")
		name = repo.AppID
	}
	if name == "" {
		// No repo URL is not a reason to omit the subject: a BOM whose subject
		// is "unknown at commit abc123" still says more than a BOM with no
		// subject at all, and the commit is the part a reader can act on.
		name = "unknown"
	}
	md.Component = &cdxComponent{
		Type:    "application",
		BOMRef:  "cicd-subject",
		Name:    name,
		Group:   group,
		Version: cdxSubjectVersion(repo),
	}
	return md
}

// cdxSubjectName derives a component name and group from a repository URL:
// the last path segment is the name and the one before it the group. Both are
// taken verbatim apart from a trailing ".git" — a repository whose name
// contains spaces has a name with spaces in it, and inventing a slug here
// would mean the BOM names something that does not exist.
func cdxSubjectName(repoURL string) (name, group string) {
	s := strings.TrimSpace(repoURL)
	if s == "" {
		return "", ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	} else if i := strings.Index(s, ":"); i >= 0 && !strings.Contains(s[:i], "/") {
		// scp-style remote (git@host:group/name). Without this the host lands in
		// the group and the BOM attributes the component to "git@github.com:acme".
		s = s[i+1:]
	}
	s = strings.Trim(s, "/")
	parts := strings.Split(s, "/")
	last := strings.TrimSpace(strings.TrimSuffix(parts[len(parts)-1], ".git"))
	if len(parts) >= 2 {
		return last, strings.TrimSpace(parts[len(parts)-2])
	}
	return last, ""
}

// cdxSubjectVersion is the commit, falling back to the tag and then the branch.
//
// The commit first because it is the only one of the three that identifies a
// tree exactly: a tag can be moved and a branch names a different tree every
// time it advances, so an SBOM versioned "main" describes whichever main the
// reader happens to assume.
func cdxSubjectVersion(repo repoContext) string {
	switch {
	case repo.CommitSHA != "":
		return repo.CommitSHA
	case repo.Tag != "":
		return repo.Tag
	default:
		return repo.Branch
	}
}

// cdxSerialNumber is a deterministic urn:uuid derived from the subject: the
// same repository at the same commit always produces the same serial.
//
// Deterministic rather than random because the identity of a BOM is the
// identity of what it describes. Two runs over one commit produce the same
// component set and are the same bill of materials; giving them different
// serials would invite a consumer to store both. What distinguishes the two
// runs is metadata.timestamp, which is where run identity belongs.
//
// Shaped as a v5 UUID (SHA-1 is what RFC 4122 names; the bits below are set the
// same way over SHA-256, which is a stronger digest in the same layout). It is
// an identifier, never a security claim — nothing verifies a BOM by its serial.
func cdxSerialNumber(repo repoContext) string {
	identity := repo.RepoURL + "\x00" + cdxSubjectVersion(repo)
	if repo.AppID != "" {
		identity += "\x00" + repo.AppID
	}
	sum := sha256.Sum256([]byte(identity))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50 // version 5
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	h := hex.EncodeToString(b)
	return fmt.Sprintf("urn:uuid:%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}
