package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type artifactDescriptor struct {
	Kind           string `json:"kind"`
	Path           string `json:"path"`
	SHA256         string `json:"sha256"`
	ToolchainImage string `json:"toolchainImage,omitempty"`
	Platform       string `json:"platform,omitempty"`
}

type artifactManifest struct {
	SchemaVersion  string               `json:"schemaVersion"`
	Repo           repoContext          `json:"repo"`
	RunURL         string               `json:"runUrl,omitempty"`
	Passed         bool                 `json:"passed"`
	EvidenceSHA256 string               `json:"evidenceSha256"`
	Artifacts      []artifactDescriptor `json:"artifacts"`
}

func makeArtifactManifest(raw []byte, kind, name, payloadHash, evidenceHash, sha, branch, repo, run, app, image, platform string) (*artifactManifest, error) {
	if (kind != "archive" || name != "application.tar.gz") && (kind != "container" || name != "image.tar") {
		return nil, fmt.Errorf("invalid artifact kind or transport path")
	}
	for _, hash := range []string{payloadHash, evidenceHash} {
		b, err := hex.DecodeString(hash)
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("invalid SHA-256 checksum")
		}
	}
	var e struct {
		Repo   repoContext `json:"repo"`
		Passed *bool       `json:"passed"`
	}
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, fmt.Errorf("invalid combined evidence: %w", err)
	}
	if e.Passed == nil || sha == "" || repo == "" || e.Repo.CommitSHA != sha || e.Repo.RepoURL != repo || e.Repo.Branch != branch || e.Repo.AppID != app {
		return nil, fmt.Errorf("artifact provenance does not match combined evidence")
	}
	return &artifactManifest{SchemaVersion: "1.0", Repo: e.Repo, RunURL: run, Passed: *e.Passed,
		EvidenceSHA256: evidenceHash, Artifacts: []artifactDescriptor{{Kind: kind, Path: name, SHA256: payloadHash, ToolchainImage: image, Platform: platform}}}, nil
}
