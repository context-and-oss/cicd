//go:build !unit_test

package main

import (
	"context"
	"dagger/security/internal/dagger"
	"encoding/json"
	"errors"
)

// gitleaksScript, the tree leg's flags and the filter that keeps its debug
// log safe live in gitleaksscript.go, untagged, so they can be tested.

// runGitleaks scans src for secrets and returns SARIF JSON plus the findings it
// lists. A non-nil error means gitleaks itself could not scan — never that it
// found nothing.
//
// It always scans the working tree, and additionally scans git history when src
// carries a .git directory. Neither mode subsumes the other; measured against
// gitleaks v8.30.1:
//
//	fixture                              dir .   detect --source .
//	secret only in history (removed)         0                   1
//	secret uncommitted in working tree       1                   0
//	no .git at all                           1                   0
//
// `detect` (git-log mode) was the only leg here, which left two holes. A secret
// staged or written but not yet committed was reported by nothing, and a source
// tree with no .git — every testdata fixture, so every module-test and
// composite-smoke cell that claims to prove this module works — produced
// "0 commits scanned" and a clean report. The tree scan is now the baseline
// because it is the leg that examines what actually ships, and it is
// independent of clone depth; history is additive coverage for a credential
// that was committed and then deleted, which stays exposed to anyone who can
// clone the repository.
//
// The tree scan's own account of what it read and which archives it did not
// open (gitleaksarchives.go) is returned beside the findings; the history leg
// has nothing to add to it. Neither has the history leg's suppressions: only
// the tree leg is checked for what a suppression removed (gitleakssuppress.go).
func runGitleaks(ctx context.Context, src *dagger.Directory) (json.RawMessage, []finding, gitleaksTreeScan, error) {
	entries, err := src.Entries(ctx)
	if err != nil {
		return nil, nil, gitleaksTreeScan{}, err
	}
	tree, scan, treeErr := runGitleaksTree(ctx, src, entries, "source tree")
	if tree == nil {
		return nil, nil, gitleaksTreeScan{}, treeErr
	}
	if !historyAvailable(entries) {
		return tree, gitleaksFindings(tree), scan, treeErr
	}

	history, _, _, err := runGitleaksLeg(ctx, src, true, "")
	if err != nil {
		// Unlike runSemgrep and runTrivyFS, this returns a report *and* an
		// error. The tree scan already succeeded, and discarding its result
		// would trade a located, actionable secret for a message about a
		// different leg. main.go appends the error to errors[] (which fails the
		// gate) and carries the report independently, so the team gets both the
		// leak and the reason history could not be read.
		return tree, gitleaksFindings(tree), scan, joinGitleaksErrors(treeErr, err)
	}

	merged := mergeGitleaksSARIF(tree, history)
	return merged, gitleaksFindings(merged), scan, treeErr
}

// runGitleaksDir scans a directory's files only, with no history leg. Built
// archive outputs carry no git history at all, so asking for one could only
// produce the "0 commits scanned" failure rather than any extra coverage.
func runGitleaksDir(ctx context.Context, dir *dagger.Directory) (json.RawMessage, []finding, gitleaksTreeScan, error) {
	entries, err := dir.Entries(ctx)
	if err != nil {
		return nil, nil, gitleaksTreeScan{}, err
	}
	sarif, scan, err := runGitleaksTree(ctx, dir, entries, "build output")
	if sarif == nil {
		return nil, nil, gitleaksTreeScan{}, err
	}
	return sarif, gitleaksFindings(sarif), scan, err
}

// runGitleaksTree runs the tree leg and, beside it, the shadow that measures
// what the tree's suppressions removed (gitleakssuppress.go), and returns the
// tree leg's report with those findings put back as suppressed results.
//
// A shadow that fails returns the tree leg's report with an error, the shape a
// failed history leg has: the findings the real scan reported are real, but a
// pass resting on an acceptance cicd could not read is not one it can stand
// behind. A nil report means the tree leg itself did not scan.
func runGitleaksTree(ctx context.Context, src *dagger.Directory, entries []string, scope string) (json.RawMessage, gitleaksTreeScan, error) {
	hasConfig, hasIgnore := gitleaksSuppressionFiles(entries)

	shadowDone := make(chan gitleaksShadow, 1)
	go func() { shadowDone <- runGitleaksShadow(ctx, src, hasConfig, hasIgnore) }()

	report, scan, ignored, err := runGitleaksLeg(ctx, src, false, scope)
	shadow := <-shadowDone
	if err != nil {
		return nil, gitleaksTreeScan{}, err
	}
	if shadow.err != nil {
		return report, scan, errors.New("gitleaks: could not measure which findings the " + scope +
			"'s suppressions removed, so a pass may rest on an acceptance nobody can read: " + shadow.err.Error())
	}
	if shadow.report == nil {
		return report, scan, nil
	}
	disclosed, warnings := gitleaksDiscloseSuppressions(report, shadow.report,
		parseGitleaksIgnored(ignored), shadow.marks, shadow.marksKnown, hasConfig, scope)
	scan.Warnings = append(scan.Warnings, warnings...)
	return disclosed, scan, nil
}

// gitleaksShadow is what runGitleaksShadow measured. A nil report with no
// error means no suppression could have applied, so there was nothing to run.
type gitleaksShadow struct {
	report     json.RawMessage
	marks      []gitleaksMark
	marksKnown bool
	err        error
}

// runGitleaksShadow lists the tree's `gitleaks:allow` marks and, when any
// suppression could apply, scans a copy of the tree with every suppression
// turned off. Both run in one container over the tree with .gitleaks.toml and
// .gitleaksignore removed, so the mark list is of the tree the shadow scans.
func runGitleaksShadow(ctx context.Context, src *dagger.Directory, hasConfig, hasIgnore bool) gitleaksShadow {
	bare := src
	if hasConfig {
		bare = bare.WithoutFile(gitleaksConfigFile)
	}
	if hasIgnore {
		bare = bare.WithoutFile(gitleaksIgnoreFile)
	}

	listed := dag.Container().
		From(gitleaksImage).
		WithoutEntrypoint().
		WithMountedDirectory("/src", bare).
		WithWorkdir("/src").
		WithExec([]string{"sh", "-c", gitleaksAllowMarksScript, "sh", "/tmp"})
	exit, err := listed.File("/tmp/gitleaks.marks.exit").Contents(ctx)
	if err != nil {
		return gitleaksShadow{err: errors.New(readbackError("gitleaks", "/tmp/gitleaks.marks.exit", err))}
	}
	raw, err := listed.File("/tmp/gitleaks.marks").Contents(ctx)
	if err != nil {
		return gitleaksShadow{err: errors.New(readbackError("gitleaks", "/tmp/gitleaks.marks", err))}
	}
	marks, known := parseGitleaksAllowMarks(raw, exit)
	if !gitleaksShadowNeeded(hasConfig, hasIgnore, marks, known) {
		return gitleaksShadow{marksKnown: true}
	}

	ran := listed.WithExec(append([]string{"sh", "-c", gitleaksScript, "sh", "/tmp"}, gitleaksShadowArgs()...))
	report, err := gitleaksReadRun(ctx, ran, false)
	if err != nil {
		return gitleaksShadow{err: err}
	}
	return gitleaksShadow{report: report, marks: marks, marksKnown: known}
}

// joinGitleaksErrors keeps both legs' reasons when both failed.
func joinGitleaksErrors(a, b error) error {
	if a == nil {
		return b
	}
	return errors.New(a.Error() + "; " + b.Error())
}

// runGitleaksLeg runs one gitleaks scan over src: git history when history is
// set, otherwise the files on disk, with archives opened. scope names the tree
// leg's input in the warnings it reads out of the log; the history leg returns
// an empty scan. The tree leg also returns the fingerprints .gitleaksignore
// removed, one per line (see gitleaksScript).
func runGitleaksLeg(ctx context.Context, src *dagger.Directory, history bool, scope string) (json.RawMessage, gitleaksTreeScan, string, error) {
	args := gitleaksTreeArgs()
	if history {
		args = gitleaksHistoryArgs()
	}

	ran := dag.Container().
		From(gitleaksImage).
		// Bypass the image's entrypoint so sh runs the script.
		WithoutEntrypoint().
		WithMountedDirectory("/src", src).
		WithWorkdir("/src").
		WithExec(append([]string{"sh", "-c", gitleaksScript, "sh", "/tmp"}, args...))

	report, err := gitleaksReadRun(ctx, ran, history)
	if err != nil {
		return nil, gitleaksTreeScan{}, "", err
	}
	if history {
		return report, gitleaksTreeScan{}, "", nil
	}
	// The script always creates these files, so an unreadable one is a Dagger
	// failure and not an empty list — and an empty list is exactly what
	// would let an unread jar pass for no jar at all, or a fingerprint in
	// .gitleaksignore pass for a suppression nobody can name.
	stderr, err := ran.File("/tmp/gitleaks.err").Contents(ctx)
	if err != nil {
		return nil, gitleaksTreeScan{}, "", errors.New(readbackError("gitleaks", "/tmp/gitleaks.err", err))
	}
	skipped, err := ran.File("/tmp/gitleaks.skipped").Contents(ctx)
	if err != nil {
		return nil, gitleaksTreeScan{}, "", err
	}
	ignored, err := ran.File("/tmp/gitleaks.ignored").Contents(ctx)
	if err != nil {
		return nil, gitleaksTreeScan{}, "", errors.New(readbackError("gitleaks", "/tmp/gitleaks.ignored", err))
	}
	return report, gitleaksTreeScanResult(stderr, skipped, scope), ignored, nil
}

// gitleaksReadRun reads back one gitleaksScript run and classifies it,
// returning its report only when gitleaksRunError found it trustworthy.
func gitleaksReadRun(ctx context.Context, ran *dagger.Container, history bool) (json.RawMessage, error) {
	code, err := ran.File("/tmp/gitleaks.exit").Contents(ctx)
	if err != nil {
		return nil, err
	}
	// The script creates the file before gitleaks runs (see gitleaksScript),
	// so a read that fails is cicd's, and gitleaksRunError must not classify
	// the exit against an empty log it would read as "the tool said nothing".
	stderr, err := ran.File("/tmp/gitleaks.err").Contents(ctx)
	if err != nil {
		return nil, errors.New(readbackError("gitleaks", "/tmp/gitleaks.err", err))
	}
	report, err := ran.File("/tmp/report.sarif").Contents(ctx)
	if err != nil {
		return nil, err
	}
	if msg := gitleaksRunError(code, stderr, report, history); msg != "" {
		return nil, errors.New(msg)
	}
	// Every leg, not only history: the tree and shadow legs write the same
	// keys empty (measured, v8.30.1), and one rule for every leg leaves no leg
	// for a later gitleaks to start filling unnoticed.
	return withholdGitleaksCommitIdentity(json.RawMessage(report))
}

// historyAvailable reports, from the root's Entries(), whether src carries a
// git object store gitleaks can actually read, which is what decides that
// asking for a history scan is meaningful.
//
// It is checked on the uploaded directory rather than assumed from the pipeline,
// because the two disagree routinely: the reusable workflows check out with
// fetch-depth: 0, but a module-test cell passes a plain fixture directory and
// the archive path passes build output, and neither has a .git at all.
//
// A *directory* named .git is required, not merely an entry named .git. In a git
// worktree or a submodule, .git is a regular file holding an absolute
// "gitdir: /path/to/main/.git/worktrees/x" pointer. That path does not exist
// inside the container, so git fails, gitleaks reports 0 commits, and demanding
// a history scan would fail the gate on a checkout that is perfectly valid.
// Dagger's Entries() distinguishes the two: a directory is reported with a
// trailing separator (".git/"), a file without one (".git").
func historyAvailable(entries []string) bool {
	for _, e := range entries {
		if e == ".git/" {
			return true
		}
	}
	return false
}
