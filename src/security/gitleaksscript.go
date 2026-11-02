// The shell gitleaks runs under, and the argument list of its tree leg.
//
// Deliberately untagged (no //go:build !unit_test), for the reason
// zapRunScript moved out of web.go: the script decides which of gitleaks'
// log lines are kept and which are thrown away, and a filter that is wrong in
// either direction is invisible from the envelope. Living beside the
// !unit_test runner, it could not be driven by any test. gitleaksscript_test.go
// runs it under sh with a fake gitleaks on PATH.
package main

import "strconv"

// gitleaksScript runs gitleaks, records its exit status, and always exits 0 so
// gitleaksRunError — not Dagger's exec failure — decides what happened.
//
// The first positional argument is the directory the script writes into; the
// rest is the subcommand, referenced as "$@", so nothing is spliced into the
// script text. stdout and stderr are captured rather than discarded: gitleaks
// can exit 0 having scanned nothing, and its own log lines are the only
// evidence of that.
//
// stderr passes through a filter, and the filter is the reason this is not a
// plain redirect. The tree leg runs at --log-level debug, because the one line
// that names an archive gitleaks declined to open ("skipping binary file
// mime_type=application/zip path=lib/service.jar") is logged at DBG and at no
// other level. But DBG also logs every decoded segment with its text —
// measured on v8.30.1 over this repository, `segment found: … "%44" -> "D"
// decoder=percent` — so a base64-encoded credential would be written out
// decoded, past --redact, which only governs the report. The filter therefore
// keeps exactly one DBG shape, in its own file, and drops every other DBG line
// before it reaches the disk. The kept shape is matched on whole fields, not
// as a substring: a segment line quotes file content, so a file containing the
// words "DBG skipping binary file" would otherwise route its own decoded text
// into the kept file. The drop is the wider test — a line is discarded if any
// part of it reads as DBG, because a line wrongly dropped costs one archive's
// name and a line wrongly kept can cost a credential. Every non-DBG line goes to gitleaks.err as
// before, so gitleaksRunError reads the same stream it always did.
//
// A second DBG shape is kept, in gitleaks.ignored: the line gitleaks writes
// when a .gitleaksignore fingerprint drops a finding ("skipping finding:
// global fingerprint finding=REDACTED fingerprint=a.go:aws-access-token:2"),
// which is the only record of which ignore entry removed what. Only the part
// after "fingerprint=" is written — a path, a rule id and a line number — and
// the line must carry finding=REDACTED as a whole field: a gitleaks whose
// --redact stopped governing this line would write the secret there, and the
// filter then drops the line rather than keep it. What that costs is the
// attribution, which gitleaksDiscloseSuppressions reports as unknown; it never
// costs the finding.
//
// The filter cannot fail open. awk writes gitleaks.filtered only on reaching
// END; without it the skipped list is unknowable, so the exit status is
// replaced with 125 and the reason is written where withGitleaksReason will
// quote it. pipefail would say the same thing more briefly and is not POSIX —
// dash, which is /bin/sh on the CI runner that runs this file's test, has
// none.
//
// --redact is not optional. Without it gitleaks writes the credential it found
// into region.snippet.text, and that SARIF is passed through into the evidence
// envelope verbatim — so a secrets scan would copy the secret into a build
// artifact that is downloadable by everyone with repository read access, and
// hand it to any consumer of the cross-cutting/report extractor. Redaction
// keeps ruleId, file, line and columns, which is everything triage needs; the
// literal value is in the developer's own file at that line. Measured on
// gitleaks v8.30.1: with --redact the raw secret appears zero times in both the
// SARIF and JSON reports, findings inside archives included.
const gitleaksScript = `set -u
out=$1
shift
: > "$out/gitleaks.err"
: > "$out/gitleaks.skipped"
: > "$out/gitleaks.ignored"
rm -f "$out/gitleaks.filtered"
{ gitleaks "$@" --report-format sarif --report-path "$out/report.sarif" \
    --exit-code 0 --redact --no-banner --no-color >"$out/gitleaks.out"
  echo $? > "$out/gitleaks.exit"; } 2>&1 |
  awk -v err="$out/gitleaks.err" -v skipped="$out/gitleaks.skipped" -v ignored="$out/gitleaks.ignored" -v done="$out/gitleaks.filtered" '
    $2 == "DBG" && $3 == "skipping" && $4 == "binary" && $5 == "file" { print > skipped; next }
    $2 == "DBG" && $3 == "skipping" && $4 == "finding:" && $5 == "global" && $6 == "fingerprint" && $7 == "finding=REDACTED" && $8 ~ /^fingerprint=/ {
      i = index($0, " finding=REDACTED fingerprint=")
      print substr($0, i + 30) > ignored; next }
    $2 == "DBG" || $0 ~ / DBG / { next }
    { print > err }
    END { print "ok" > done }'
if [ ! -f "$out/gitleaks.filtered" ]; then
  echo "Error: cicd could not filter gitleaks' log, so which files it declined to open is unknown" >> "$out/gitleaks.err"
  echo 125 > "$out/gitleaks.exit"
fi
[ -f "$out/report.sarif" ] || : > "$out/report.sarif"
exit 0`

// gitleaksMaxArchiveDepth is how many archive layers the tree leg opens:
// `app.zip!.env` is one, `outer.zip!mid.zip!inner.zip!.env` is three.
//
// gitleaks' own default is 0, which opens nothing — measured on v8.30.1, a
// directory holding only app.zip, with two live credentials inside it,
// reported `scanned ~0 bytes` and `no leaks found`. That was the archive
// stage's secrets scan for every consumer who zips their deployable.
//
// Why 3 and not unbounded: the flag is the only thing standing between a
// recursive archive and a scan that never ends — 42.zip opens 16 archives per
// layer, so the fourth layer alone is 65,536 of them. Why 3 and not 1: a zip
// holding a tar.gz is already two, and the price of a layer is the bytes in it,
// not the layer — a single-layer 2 MB zip of zeros expands to 2.15 GB and took
// 4m29s at bounded memory (gitleaks streams), the same as a 2 GB file on disk
// would. An archive nested deeper than this is not silently dropped: gitleaks
// logs it at WRN and gitleaksTreeScanResult names it in warnings[].
const gitleaksMaxArchiveDepth = 3

// gitleaksTreeArgs is the tree leg's command line: the files on disk, with
// archives opened, logged at the level that names the archives it would not.
//
// Only the tree leg gets these. The history leg reads git blobs, where the
// depth flag does not apply, and running it at debug would push every
// commit's DBG lines through the filter for nothing.
func gitleaksTreeArgs() []string {
	return []string{"dir", ".",
		"--max-archive-depth", strconv.Itoa(gitleaksMaxArchiveDepth),
		"--log-level", "debug"}
}

// gitleaksHistoryArgs is the history leg's command line, at gitleaks' default
// log level — see gitleaksTreeArgs for why it carries neither tree flag.
func gitleaksHistoryArgs() []string {
	return []string{"detect", "--source", "."}
}

// gitleaksShadowArgs is the tree leg again with gitleaks' inline
// `gitleaks:allow` honoured nowhere. The scan runs on a copy of the tree with
// .gitleaks.toml and .gitleaksignore removed, so it applies gitleaks' default
// rules with no allowlist and no ignore list: every finding it reports that
// the real tree leg did not is one a suppression removed. See
// gitleakssuppress.go.
//
// No --log-level debug: nothing is read from this run's log but its errors,
// and the filter has nothing to keep.
func gitleaksShadowArgs() []string {
	return []string{"dir", ".",
		"--max-archive-depth", strconv.Itoa(gitleaksMaxArchiveDepth),
		"--ignore-gitleaks-allow"}
}

// gitleaksAllowMarksScript lists every `gitleaks:allow` mark in the tree as
// "path:line:gitleaks:allow" in gitleaks.marks, and records grep's exit in
// gitleaks.marks.exit: 0 found some, 1 found none, anything else means the
// list is unknown — an unreadable file, or a grep that could not run — and
// gitleakssuppress.go then refuses to name a suppression mechanism it cannot
// tell apart from the others.
//
// The grep is the image's BusyBox one, which has no -I, so binary files are
// searched too. That is harmless: gitleaks honours the mark only on the line
// it reports, and a mark inside a file it did not report is never matched
// against anything. A mark inside an archive cannot be seen here at all; that
// finding is reported as removed by a suppression cicd could not identify.
//
// -o keeps the output to the mark, so no line of file content leaves the
// container: a mark on a line that also holds a credential would otherwise
// copy the credential into this file.
const gitleaksAllowMarksScript = `set -u
out=$1
grep -rnoF -e 'gitleaks:allow' . > "$out/gitleaks.marks" 2> "$out/gitleaks.marks.err"
echo $? > "$out/gitleaks.marks.exit"
exit 0`
