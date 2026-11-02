// The paths inside the scan container, and the script that fills them.
//
// Untagged (no //go:build !unit_test) on purpose. zapRunScript is not container
// plumbing — it is the only place several facts are spelled in shell that Go
// reads back, starting with the status it writes when ZAP's log is missing, and
// a pair spelled in two languages with nothing holding them together is how the
// accepted-language set drifted from its shell case statement. web.go is
// //go:build !unit_test, so a constant living there is invisible to
// `make test-module-units` and any assertion about it would never run.
package main

const (
	// zapReportPath is where the packaged scan writes its JSON report.
	//
	// It is deliberately outside /zap/wrk. ZAP checks that /zap/wrk exists
	// before accepting -J at all, so that directory is mounted as a tmpfs to
	// satisfy the check — but it is not writable by the image's non-root user,
	// so the report itself goes to the regular overlay filesystem.
	zapReportPath = "/tmp/report.json"
	// zapSpecPath is where a consumer-supplied API document is mounted.
	zapSpecPath = "/tmp/api-spec"
	// zapRuleConfigPath is where a consumer-supplied ZAP rule config is mounted.
	zapRuleConfigPath = "/tmp/zap-rules.conf"

	// zapAddOnStagePath is where the pinned pscanrulesBeta add-on is mounted,
	// before it is verified. It is staged in /tmp and copied into the plugin
	// directory rather than mounted straight into it, because a mount cannot be
	// removed from inside the container, and the one thing that must not happen
	// to an artifact whose digest did not match is for it to still be there when
	// ZAP scans the plugin directory.
	zapAddOnStagePath = "/tmp/" + zapPscanRulesBetaFile
	// zapAddOnInstallPath is where ZAP finds an add-on it did not download
	// itself. Measured on the pinned image: a read-only file placed here loads,
	// and it survives ZAP recreating its home directory.
	zapAddOnInstallPath = "/zap/plugin/" + zapPscanRulesBetaFile
	// zapAddOnStatusPath is where zapRunScript records which of the four
	// answers in zapaddons.go applied.
	zapAddOnStatusPath = "/tmp/zap-addon.status"

	// zapContainerUser is who the pinned image runs everything as, and so
	// who must own anything cicd mounts for the scan to read.
	//
	// Measured in the pinned image: `id` answers uid=1000(zap) gid=1000(zap).
	// Spelled numerically rather than as "zap" because it is passed to
	// Dagger, which resolves a name through the image's /etc/passwd — a
	// lookup that can fail, and whose failure mode here is a file the scan
	// cannot read, which is the bug this constant exists to close.
	zapContainerUser = "1000:1000"
)

// zapYAMLCodePointLimit is the parser input cap cicd asks swagger-parser for,
// in code points, replacing its 3,145,728 default.
//
// The default is a denial-of-service guard on an untrusted document, and it is
// the right guard for a scanner someone points at the internet. It is the wrong
// guard here: the document is the consumer's own API description, fetched from
// the consumer's own application, in a container that exists for one scan.
//
// It was not a hypothetical. Measured against the pinned image on a consumer
// API document of ~800 KB, the import failed and the scan went on to report
// every rule as PASS. The limit is not on the original document's size: ZAP
// converts Swagger 2.0 to OpenAPI 3 and re-parses the expanded result, so even
// smaller slices could fail. With this limit the same document imports
// successfully; the original API's shape and slice thresholds are omitted.
//
// 32 MiB is ten times the default and is stated rather than removed. An
// unbounded parser turns a pathological document into a hang bounded only by
// -T; a bounded one turns it into an out-of-memory exit, which zapRunError
// already classifies as a non-run.
const zapYAMLCodePointLimit = 33554432

// zapAddOnStageScript verifies the pinned add-on and puts it where ZAP looks.
//
// Split out of zapRunScript so it can be driven directly: it is five branches
// with a status file as their only output, the status decides whether an
// envelope discloses a reduced rule set, and a wrong branch is invisible from
// the outside — an add-on that failed its digest check and got copied anyway
// produces exactly the evidence of one that passed. TestAddOnStaging runs this
// text under sh against a fake sha256sum, the same way the dagger-develop
// wrapper is driven by a fake dagger on PATH, and for the same reason: a shell
// conditional that is only read is a shell conditional that is only hoped for.
//
// It must never exit non-zero and never `exit`: it is prepended to the script
// that runs the scan, and a scan that could not gain six passive rules is still
// a scan.
const zapAddOnStageScript = `# The pinned passive-rule add-on, verified before ZAP can see it.
#
# Staged read-only in /tmp and copied in only once its digest matches, so that
# "the bytes were wrong" and "the add-on loaded" can never be the same run. A
# copy that fails for any other reason leaves the status at missing, which is a
# reduction in rules this envelope discloses rather than absorbs. Nothing here
# may exit non-zero: a scan that could not gain six passive rules is still a
# scan, and the status file is what says so. See zapaddons.go.
#
# The digest is compared by hand rather than through "sha256sum -c", because -c
# answers exit 1 both for a file whose digest differs and a file it could not
# open, and the first run of this code hit the second and reported the first.
# Taking the digest as a value separates the two: sha256sum failing at all is
# unreadable, and only a successful read can accuse the bytes.
ADDON_STATUS=` + zapAddOnStatusMissing + `
if [ -f ` + zapAddOnStagePath + ` ]; then
  if ADDON_SUM=$(sha256sum ` + zapAddOnStagePath + ` 2>/dev/null); then
    case "$ADDON_SUM" in
      "` + zapPscanRulesBetaSHA256 + `  ` + zapAddOnStagePath + `")
        cp ` + zapAddOnStagePath + ` ` + zapAddOnInstallPath + ` && ADDON_STATUS=` + zapAddOnStatusOK + `
        ;;
      *)
        ADDON_STATUS=` + zapAddOnStatusMismatch + `
        ;;
    esac
  else
    ADDON_STATUS=` + zapAddOnStatusUnreadable + `
  fi
fi
echo "$ADDON_STATUS" > ` + zapAddOnStatusPath + `
`

// zapScript runs the packaged scan, records its exit status, and always exits 0
// so that zapRunError — not Dagger's exec failure — decides what happened.
//
// The script it replaces ended in `|| true`, which is the pattern CLAUDE.md
// forbids: it collapsed ZAP's exit 3 ("any other failure") into 0. Capturing
// the status instead is the difference between a scan that found nothing and a
// scan that died before it looked.
//
// Every scan argument arrives as a positional argument and is referenced as
// "$@", so a consumer-supplied target, spec path or rule id is never part of
// the script text and cannot be re-parsed as shell syntax.
//
// The site-tree dump is touched for the same reason the report is: reading a
// path that does not exist is a Dagger error, and an error is the one answer
// that cannot be told apart from the others. Touched, the file is always
// readable, and an empty one means exactly "the hook wrote nothing" — which
// parseZAPURLDump says in those words.
const zapRunScript = `set -u
` + zapAddOnStageScript + `: > /tmp/zap.err
"$@" >/tmp/zap.out 2>/tmp/zap.err
echo $? > /tmp/zap.exit
[ -f ` + zapReportPath + ` ] || : > ` + zapReportPath + `
[ -f ` + zapURLDumpPath + ` ] || : > ` + zapURLDumpPath + `
: > ` + zapImportRejectPath + `
: > ` + zapDaemonLevelsPath + `
if [ -f ` + zapDaemonLogPath + ` ]; then
  grep -E -A 30 '(WARN|ERROR).*` + zapImportAPIPathPattern + `' ` + zapDaemonLogPath + ` \
    > ` + zapImportRejectPath + `
  echo $? > ` + zapImportRejectStatusPath + `
  grep -E '(WARN|ERROR)' ` + zapDaemonLogPath + ` > ` + zapDaemonLevelsPath + `
else
  echo ` + zapImportRejectStatusNoLogText + ` > ` + zapImportRejectStatusPath + `
fi
exit 0`
