package main

import (
	"strings"
	"testing"
)

func TestManifestBindsEvidenceAndRetainsFailure(t *testing.T) {
	hash := strings.Repeat("a", 64)
	for _, passed := range []string{"true", "false"} {
		raw := []byte(`{"repo":{"repoUrl":"repo","commitSha":"abc","branch":"main"},"passed":` + passed + `}`)
		m, err := makeArtifactManifest(raw, "archive", "application.tar.gz", hash, hash, "abc", "main", "repo", "run", "", "node:22", "")
		if err != nil || m.Passed != (passed == "true") {
			t.Fatalf("%v %v", m, err)
		}
		if _, err := makeArtifactManifest(raw, "archive", "application.tar.gz", hash, hash, "other", "main", "repo", "run", "", "", ""); err == nil {
			t.Fatal("accepted wrong source")
		}
		if _, err := makeArtifactManifest(raw, "archive", "../payload", hash, hash, "abc", "main", "repo", "run", "", "", ""); err == nil {
			t.Fatal("accepted unsafe path")
		}
	}
	if _, err := makeArtifactManifest([]byte(`{}`), "container", "image.tar", hash, hash, "abc", "main", "repo", "", "", "", ""); err == nil {
		t.Fatal("accepted missing verdict")
	}
}
