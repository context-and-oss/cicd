// What gitleaks' tree leg read, and which archives it did not open.
//
// Deliberately untagged (no //go:build !unit_test): the rules are pure string
// work over the log gitleaksScript keeps, so gitleaksarchives_test.go drives
// them against a log captured from the pinned image.
//
// Two blind spots, both measured on v8.30.1 and both reported as "no leaks
// found" before this file existed:
//
//   - gitleaks recognises an archive by its file EXTENSION. It opens .zip, .tar
//     and .tar.gz, and reads a .jar, .war, .nupkg, .whl, .vsix, .apk, a .tgz or
//     an extensionless zip as an opaque binary at every depth — a Spring Boot
//     jar with application.properties inside it is exactly the bundled-.env
//     class of leak the archive stage exists to catch. The only trace is a DBG
//     line naming the file and the content type it sniffed.
//   - an archive nested deeper than --max-archive-depth is skipped with a WRN
//     line naming its path.
//
// Both become one warnings[] line each, naming the files. A warning and not an
// error, on the precedent of semgrepnotifications.go: the scan did run over
// everything else, the remedy for a jar is upstream's, and a permanent red is
// how secrets scanning gets switched off along with its findings.
package main

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// gitleaksArchiveMIME is the set of sniffed content types that mean "this
// file holds other files". The strings are the ones gitleaks prints after
// `mime_type=`. Measured on the pinned image: application/zip (.jar, .war,
// .nupkg, .whl, .vsix, .apk, extensionless), application/gzip (.tgz),
// application/x-xz, application/x-tar (a bzip2 tarball also sniffs as this),
// application/x-compress and application/x-unix-archive (ar). The rest are the
// same library's names for formats this repository has not seen in an output
// yet, listed so the first one to appear is disclosed rather than dropped.
//
// A content type is not on this list merely because it is binary: an image, a
// font or a DLL holds no files, and naming every one would bury the line that
// matters under a dist folder's assets.
var gitleaksArchiveMIME = map[string]bool{
	// measured
	"application/zip":            true,
	"application/gzip":           true,
	"application/x-xz":           true,
	"application/x-tar":          true,
	"application/x-compress":     true,
	"application/x-unix-archive": true,
	// not yet measured
	"application/x-bzip2":                   true,
	"application/x-7z-compressed":           true,
	"application/vnd.rar":                   true,
	"application/x-rar-compressed":          true,
	"application/zstd":                      true,
	"application/x-lzip":                    true,
	"application/java-archive":              true,
	"application/vnd.ms-cab-compressed":     true,
	"application/x-rpm":                     true,
	"application/vnd.debian.binary-package": true,
}

// gitleaksArchiveNamesShown caps how many paths one warning names. The count
// is always exact; only the list is cut. Twenty fits a typical Java or .NET
// output's handful of packages whole, and keeps a node_modules-sized output
// from turning one warning into a page — the full list is one `find` away for
// whoever reads the count.
const gitleaksArchiveNamesShown = 20

var (
	// Anchored on the timestamp field and on the field order gitleaks
	// writes, path last, so a filename holding "path=" stays whole.
	gitleaksSkippedBinaryRE = regexp.MustCompile(`^\S+ DBG skipping binary file mime_type=(\S+) path=(.+)$`)
	gitleaksTooDeepRE       = regexp.MustCompile(`^\S+ WRN skipping archive: exceeds max archive depth max_archive_depth=[0-9]+ path=(.+)$`)
	// The leading `~` is gitleaks' own; the parenthesised figure beside it is
	// humanised ("2.15 GB") and so is not read.
	gitleaksScannedBytesRE = regexp.MustCompile(`(?:^|\s)INF scanned ~([0-9]+) bytes`)
)

// gitleaksExaminedUnit says the count is the tree leg's alone. On ScanSource
// the history leg reads git blobs as well and reports no byte count of its own,
// so a bare "bytes" would read as the whole scan's denominator and understate
// it by every committed blob.
const gitleaksExaminedUnit = "bytes read from the tree"

// gitleaksTreeScan is what the tree leg's log says about the scan, beyond its
// findings.
type gitleaksTreeScan struct {
	// Examined is the bytes gitleaks read, nil when it did not say. A tree of
	// nothing but unopened binaries reads 0 — stated, so it can no longer pass
	// for a scan of a tree that had text in it.
	Examined *Examined
	Warnings []string
}

// gitleaksTreeScanResult reads the tree leg's kept log: stderr is every
// non-DBG line, skipped the DBG `skipping binary file` lines (see
// gitleaksScript). scope names the tree in the reader's words — "build output",
// "source tree".
func gitleaksTreeScanResult(stderr, skipped, scope string) gitleaksTreeScan {
	var out gitleaksTreeScan
	if m := gitleaksScannedBytesRE.FindStringSubmatch(stderr); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			out.Examined = &Examined{Unit: gitleaksExaminedUnit, Count: n}
		}
	}

	var unopened, tooDeep []string
	for _, line := range strings.Split(skipped, "\n") {
		m := gitleaksSkippedBinaryRE.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m != nil && gitleaksArchiveMIME[m[1]] {
			unopened = append(unopened, gitleaksLogPath(m[2]))
		}
	}
	for _, line := range strings.Split(stderr, "\n") {
		if m := gitleaksTooDeepRE.FindStringSubmatch(strings.TrimRight(line, "\r")); m != nil {
			tooDeep = append(tooDeep, gitleaksLogPath(m[1]))
		}
	}

	if names, n := gitleaksNameList(unopened); n > 0 {
		out.Warnings = append(out.Warnings, fmt.Sprintf(
			"gitleaks: %s in the %s %s not opened, so nothing inside %s was searched for secrets — "+
				"gitleaks opens an archive only by its file extension and read %s as an opaque binary: %s",
			plural(n, "archive-typed file", "archive-typed files"), scope, oneOrMany(n, "was", "were"),
			oneOrMany(n, "it", "them"), oneOrMany(n, "this one", "these"), names))
	}
	if names, n := gitleaksNameList(tooDeep); n > 0 {
		out.Warnings = append(out.Warnings, fmt.Sprintf(
			"gitleaks: %s in the %s %s nested deeper than %d archive layers and %s not opened, "+
				"so nothing inside %s was searched for secrets: %s",
			plural(n, "archive", "archives"), scope, oneOrMany(n, "is", "are"), gitleaksMaxArchiveDepth,
			oneOrMany(n, "was", "were"), oneOrMany(n, "it", "them"), names))
	}
	return out
}

// gitleaksLogPath returns the path a log line names. gitleaks quotes a value
// that holds a space (`path="my app/My Package.1.0.0.nupkg"`) and leaves any
// other bare; a quoted value that does not unquote is kept as printed, because
// a path with stray quotes still names the file and dropping it would not.
func gitleaksLogPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, `"`) {
		if p, err := strconv.Unquote(raw); err == nil {
			return p
		}
	}
	return raw
}

// gitleaksNameList returns the distinct paths, sorted and quoted, cut at
// gitleaksArchiveNamesShown, and how many distinct paths there were. Sorted
// because gitleaks walks the tree concurrently, so its log order differs
// between two runs over the same tree, and a warning should not.
func gitleaksNameList(paths []string) (string, int) {
	seen := map[string]bool{}
	var distinct []string
	for _, p := range paths {
		if p != "" && !seen[p] {
			seen[p] = true
			distinct = append(distinct, p)
		}
	}
	sort.Strings(distinct)
	shown := distinct
	if len(shown) > gitleaksArchiveNamesShown {
		shown = shown[:gitleaksArchiveNamesShown]
	}
	quoted := make([]string, len(shown))
	for i, p := range shown {
		quoted[i] = strconv.Quote(p)
	}
	list := strings.Join(quoted, ", ")
	if rest := len(distinct) - len(shown); rest > 0 {
		list += fmt.Sprintf(" (and %d more)", rest)
	}
	return list, len(distinct)
}

// oneOrMany is plural without the count, for the verbs and pronouns that
// agree with it.
func oneOrMany(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
