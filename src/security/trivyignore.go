package main

import "fmt"

// A suppression cicd cannot read is one it cannot disclose.
//
// Trivy auto-loads `.trivyignore` from its working directory, and both scans run
// with WithWorkdir("/src"), so a file committed at the root of the scanned tree
// drops the identifiers it names **before Trivy writes the report**. Nothing
// downstream can tell that apart from a tree where those vulnerabilities were
// never there: the count is lower, findings[] is shorter, the CycloneDX document
// carries no trace, and the envelope says nothing at all.
//
// This repository proved the shape on itself. Its own `.trivyignore` accepted
// CVE-2026-39882 with thirty lines of reasoning, a named exposure argument and a
// removal condition — every one of which lived in a file no consumer of the
// evidence ever saw. The evidence said the scan was clean.
//
// The file is still honoured, and that is deliberate: it is checked into the
// consumer's repository and reviewable in their pull request, and neutralising it
// would turn every consumer who has one red on an upgrade with no warning first.
// What changes is that cicd now says the scan was narrowed and by which file, so
// a reader of the envelope knows to go and read it — and names --vuln-accept,
// which does the same job with the reason in the envelope.
//
// Scope: root only, because that is the only place Trivy looks. `.trivyignore.yaml`
// (the richer form with `statement`/`expired_at`) is deliberately absent from
// this check: measured against trivy 0.70.0 it is not auto-loaded at all, so a
// consumer who commits one suppresses nothing. That is a misreading in the safe
// direction — every finding still reports — and a warning about it would fire on
// a file with no effect on the scan.
const trivyIgnoreFile = ".trivyignore"

// trivyIgnoreWarning returns the disclosure for a root-level .trivyignore, or ""
// when the scanned tree ships none. entries is the scanned directory's root
// listing; Dagger appends a trailing separator to directory names, so an exact
// match cannot be satisfied by a directory of the same name.
func trivyIgnoreWarning(entries []string) string {
	for _, e := range entries {
		if e != trivyIgnoreFile {
			continue
		}
		return fmt.Sprintf("security: SCAN NARROWED BY %s — the scanned tree commits a %s, "+
			"which Trivy auto-loads from the scan's working directory and applies before it "+
			"writes the report. Every identifier that file names is absent from the "+
			"vulnerability counts, from findings[] and from the CycloneDX document attached "+
			"to this envelope, and cicd cannot say which identifiers or why: the rows are "+
			"gone before cicd sees them. Read %s in the scanned repository to learn what "+
			"this scan did not report. To accept a vulnerability and keep it legible, pass "+
			"--vuln-accept \"<id>=<reason>\" instead — the row still leaves the counts and "+
			"the gate, but the identifier and the reason are disclosed here.",
			trivyIgnoreFile, trivyIgnoreFile, trivyIgnoreFile)
	}
	return ""
}
