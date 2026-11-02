// The list of URLs ZAP actually requested, taken from ZAP itself rather than
// inferred from what it found.
//
// ZAP's JSON report enumerates only URLs that produced an alert, so a scan
// that requested four hundred URLs and a scan that requested one are the same
// report when both are clean. The packaged scans print two counts (see
// zapscope.go), and a count answers "how much" but never "which" — and "which"
// is the question a reviewer has, because a scan that reached the swagger
// surface and none of the API is a scan whose clean result means nothing.
//
// ZAP knows the answer and will hand it over: zap.core.urls() is the whole
// sites tree, and the packaged scans expose trigger points where a custom
// Python module can read it. So cicd mounts one and reads the tree out.
//
// Deliberately untagged (no //go:build !unit_test): the hook source, the dump
// parser and the reconciliation are all testable without Dagger, and the one
// thing that is not — mounting the file and reading it back — is the one thing
// that stays in web.go.
package main

import (
	"encoding/json"
	"errors"
	"strings"
)

const (
	// zapHookPath is where the custom hook module is mounted. The packaged
	// scans expand ~ and fall back to wrk/, and neither applies to an absolute
	// path outside /zap/wrk — which is where this has to live, because
	// /zap/wrk is a tmpfs the image's non-root user cannot write to.
	zapHookPath = "/tmp/zap-hook.py"
	// zapURLDumpPath is where the hook writes the sites tree.
	zapURLDumpPath = "/tmp/zap-urls.json"
)

// zapURLDumpHook is the Python module the packaged scan loads with --hook.
//
// It writes the sites tree to zapURLDumpPath and does nothing else. Every
// design choice in it is about not becoming the reason a scan fails:
//
//   - Every trigger body is wrapped, so an exception inside the hook cannot
//     propagate into the packaged scan. zap-api-scan.py calls trigger_hook
//     inside its own try/except, so an escaping exception would be caught as
//     "Unexpected error", exit 3, and a scan turned into a non-run by the
//     instrument measuring it.
//
//   - It hooks zap_tuned, not zap_started. Both hand over the ZAP handle, but
//     trigger_hook feeds a hook's return value back to the caller whenever it
//     was passed more than one argument, and zap_started is the two-argument
//     one (zap, target). zap_tuned takes one, so trigger_hook discards
//     whatever this returns (zap_common.py: "elif arg_length == 1: return
//     args") and the hook cannot rewrite the scan's target by accident.
//
//   - It writes at zap_pre_shutdown and again at pre_exit. The first is the
//     normal path and is the last moment the daemon is alive — zap.core.
//     shutdown() is the next statement. But it sits inside the packaged
//     scan's try block, so any failure during the scan skips it; pre_exit is
//     outside and always runs, which is why the handle is stashed at
//     zap_tuned. pre_exit is a second chance and not a replacement: by then
//     the daemon is usually gone, and an error recorded there is the honest
//     answer.
//
//   - A failure is written into the same file as an "error" key rather than a
//     separate one, so the caller reads one path and there is no state where
//     both files are absent and the caller has to guess which silence it is.
//     A dump holding urls wins over any later attempt; a dump holding only an
//     error does not, so a pre_exit success replaces a pre_shutdown failure.
//
//   - The write is to a temporary name and renamed into place, so a dump that
//     was interrupted mid-write is never read as a short URL list. A short
//     list is the failure mode that matters here: it would name endpoints as
//     unreached that ZAP did reach.
const zapURLDumpHook = `import json
import os

OUT = "` + zapURLDumpPath + `"

_zap = None
_have_urls = False


def zap_tuned(zap):
    global _zap
    try:
        _zap = zap
    except Exception:
        pass


def zap_pre_shutdown(zap):
    _dump(zap, "zap_pre_shutdown")


def pre_exit(fail_count, warn_count, pass_count):
    _dump(_zap, "pre_exit")


def _dump(zap, trigger):
    global _have_urls
    if _have_urls:
        return
    out = {"trigger": trigger}
    try:
        out["urls"] = sorted(set(zap.core.urls()))
        _have_urls = True
    except Exception as exc:
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
    try:
        tmp = OUT + ".part"
        with open(tmp, "w") as handle:
            json.dump(out, handle)
        os.replace(tmp, OUT)
    except Exception:
        pass
`

// zapURLDump is what the hook left behind: the sites tree, or why it could not
// be read.
type zapURLDump struct {
	// Trigger names the hook trigger the dump was written from, so a reader
	// can tell a normal end-of-scan dump from the salvage attempt after a
	// failure.
	Trigger string `json:"trigger"`
	// URLs is the sites tree, sorted and deduplicated by the hook.
	URLs []string `json:"urls"`
	// Error is the hook's own failure, in the hook's words.
	Error string `json:"error"`
}

// parseZAPURLDump reads the file the hook wrote.
//
// An empty file is not an error in the JSON sense and must not be reported as
// one: the run script creates the path unconditionally so that reading it is
// never a Dagger failure, so "empty" is precisely "the hook never wrote", which
// is the plain fact the caller needs to disclose. A file that holds something
// other than the expected object is a different fact and says so.
func parseZAPURLDump(raw string) (zapURLDump, error) {
	if strings.TrimSpace(raw) == "" {
		return zapURLDump{}, errors.New("the hook wrote nothing")
	}
	var out zapURLDump
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return zapURLDump{}, errors.New("the hook's output is not readable: " + err.Error())
	}
	if strings.TrimSpace(out.Error) != "" {
		return out, errors.New("the hook could not read ZAP's site tree: " + strings.TrimSpace(out.Error))
	}
	if out.URLs == nil {
		return out, errors.New("the hook reported neither URLs nor a reason")
	}
	return out, nil
}
