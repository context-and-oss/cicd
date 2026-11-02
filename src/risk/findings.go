// The findings.json and decisions.json types the AI scan commits to a
// repository and Validate reads back. src/security/findings.go shares the
// name and nothing else: it reads scanner output into the evidence envelope,
// while these are source artifacts reviewed by humans.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Finding is one AI-identified risk in the scanned tree, as findings.json
// records it: a stable ID hashed from category, file and start line, the
// model's severity and confidence, and the evidence that anchors it.
type Finding struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Confidence  float64  `json:"confidence"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Evidence    Evidence `json:"evidence"`
}

// Evidence anchors a Finding to the source: the file, the line span and the
// snippet the model was shown. It is the risk module's own type and not the
// evidence envelope of schema.go.
type Evidence struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Snippet   string `json:"snippet"`
}

// Decision is a reviewer's recorded verdict on one finding in decisions.json:
// accepted, mitigated or rejected, with who decided, when, and until when.
type Decision struct {
	Title         string `json:"title,omitempty"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
	ReviewedBy    string `json:"reviewed_by"`
	ReviewedAt    string `json:"reviewed_at"`
	ExpiresAt     string `json:"expires_at,omitempty"`
}

// FindingsFile is the committed findings.json: the schema version, when the
// scan ran and every Finding it produced.
type FindingsFile struct {
	SchemaVersion string    `json:"schema_version"`
	ScannedAt     string    `json:"scanned_at"`
	Findings      []Finding `json:"findings"`
}

// ScanManifest records what was sent to the LLM during a scan run.
// Committed alongside findings.json + decisions.json so operators can audit
// exactly which files left the local machine — paths only, no content.
type ScanManifest struct {
	SchemaVersion string `json:"schema_version"`
	ScannedAt     string `json:"scanned_at"`
	LLMMode       string `json:"llm_mode"`
	// IgnoreRules names which ignore rules decided the file list: "git" (the
	// repository's own) or "tree-gitignore" (only the .gitignore files inside a
	// tree that carried no .git). See collect.go.
	IgnoreRules        string             `json:"ignore_rules"`
	BudgetBytes        int                `json:"budget_bytes"`
	PerFileBudgetBytes int                `json:"per_file_budget_bytes"`
	TotalBytes         int                `json:"total_bytes"`
	Files              []ScanManifestFile `json:"files"`
}

// ScanManifestFile is one entry of ScanManifest: a path that was sent and how
// many bytes of it.
type ScanManifestFile struct {
	Path  string `json:"path"`
	Bytes int    `json:"bytes"`
}

func hashFinding(category, file string, startLine int) string {
	key := fmt.Sprintf("%s:%s:%d", category, file, startLine)
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:4])
}

func scaffoldDecisions(findings []Finding) map[string]Decision {
	d := make(map[string]Decision, len(findings))
	for _, f := range findings {
		d[f.ID] = Decision{Title: f.Title, Status: "needs_review"}
	}
	return d
}
