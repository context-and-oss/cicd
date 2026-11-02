package main

import (
	"strings"
	"testing"
)

func TestADumpTheHookNeverWroteIsNamedAsSuchAndNotAsZeroURLs(t *testing.T) {
	got, err := parseZAPURLDump("")
	if err == nil {
		t.Fatal("an unwritten dump must be an error, not an empty site tree")
	}
	if !strings.Contains(err.Error(), "wrote nothing") {
		t.Errorf("the reason must say the hook never wrote, got %q", err)
	}
	if got.URLs != nil {
		t.Errorf("a dump that was never written states no URLs, got %v", got.URLs)
	}
}

func TestAnEmptyURLListIsARealClaimAndNotAnError(t *testing.T) {
	// ZAP requesting nothing is the diagnosis this whole change exists to
	// surface. If it parsed as an error the caller would warn that the
	// reconciliation could not run, and the loudest possible result would
	// become the quietest.
	got, err := parseZAPURLDump(`{"trigger":"zap_pre_shutdown","urls":[]}`)
	if err != nil {
		t.Fatalf("an empty site tree is a measurement: %v", err)
	}
	if got.URLs == nil || len(got.URLs) != 0 {
		t.Errorf("want an empty, non-nil list, got %#v", got.URLs)
	}
}

func TestAHookThatFailedReportsItsOwnReasonRatherThanAnEmptyList(t *testing.T) {
	_, err := parseZAPURLDump(`{"trigger":"pre_exit","error":"ConnectionError: [Errno 111] refused"}`)
	if err == nil {
		t.Fatal("a hook that recorded a failure must not read as a scan that requested nothing")
	}
	if !strings.Contains(err.Error(), "ConnectionError") {
		t.Errorf("the hook's own words must survive, got %q", err)
	}
}

func TestAGoodDumpCarriesItsTriggerSoASalvagedListIsRecognisable(t *testing.T) {
	got, err := parseZAPURLDump(`{"trigger":"pre_exit","urls":["http://app/a","http://app/b"]}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Trigger != "pre_exit" {
		t.Errorf("want the trigger recorded, got %q", got.Trigger)
	}
	if len(got.URLs) != 2 {
		t.Errorf("want both URLs, got %v", got.URLs)
	}
}

func TestADumpWithNeitherURLsNorAReasonIsAnError(t *testing.T) {
	if _, err := parseZAPURLDump(`{"trigger":"zap_pre_shutdown"}`); err == nil {
		t.Fatal("a dump that says nothing must not be read as a site tree of size zero")
	}
}

func TestGarbageIsReportedUnreadableAndNotAsAnEmptyScan(t *testing.T) {
	_, err := parseZAPURLDump("Traceback (most recent call last):")
	if err == nil {
		t.Fatal("unparseable output must be an error")
	}
	if !strings.Contains(err.Error(), "not readable") {
		t.Errorf("want the reason to name unreadability, got %q", err)
	}
}

func TestTheHookWritesToThePathTheCallerReads(t *testing.T) {
	// Two constants and one file between them. They have drifted apart in
	// every other module where the same shape exists, and the failure is
	// silent: the hook writes, the caller reads elsewhere, and every scan
	// reports its endpoint reconciliation as unavailable.
	if !strings.Contains(zapURLDumpHook, zapURLDumpPath) {
		t.Errorf("the hook source must name %q", zapURLDumpPath)
	}
}

func TestTheHookHooksNoTriggerWhoseReturnValueTheScanWouldUse(t *testing.T) {
	// zap_common.trigger_hook feeds a hook's return value back into the
	// packaged scan whenever it passed more than one argument. Of the triggers
	// that hand over the ZAP handle, zap_started is the two-argument one
	// (zap, target) — defining it would let a hook that returns the wrong
	// shape rewrite the scan's target. zap_tuned takes one and is the safe
	// place to stash the handle.
	for _, trigger := range []string{"zap_started", "cli_opts", "importing_openapi"} {
		if strings.Contains(zapURLDumpHook, "def "+trigger) {
			t.Errorf("the hook must not define %s: its return value reaches the scan", trigger)
		}
	}
	for _, trigger := range []string{"zap_tuned", "zap_pre_shutdown", "pre_exit"} {
		if !strings.Contains(zapURLDumpHook, "def "+trigger) {
			t.Errorf("the hook must define %s", trigger)
		}
	}
}

func TestTheHookCannotThrowIntoTheScanItMeasures(t *testing.T) {
	// Every trigger body reaches ZAP through _dump, and _dump's one call into
	// ZAP is wrapped. An exception escaping here is caught by the packaged
	// scan as "Unexpected error", exits 3, and turns a finished scan into a
	// non-run — the instrument failing the thing it measures.
	body := zapURLDumpHook[strings.Index(zapURLDumpHook, "def _dump"):]
	if !strings.Contains(body, "except Exception") {
		t.Error("_dump must catch its own failures")
	}
	if strings.Count(zapURLDumpHook, "except Exception") < 3 {
		t.Error("every path that touches ZAP or the filesystem must be wrapped")
	}
}
