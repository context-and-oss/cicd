package main

import (
	"strconv"
	"strings"
	"testing"
)

// TestZapScriptRefusesAModeItDoesNotKnow is the regression guard for the switch
// that had no default arm. `full bool` could only express two of the three
// modes, and the switch that replaced it must not paper over a third value by
// falling through to the weakest scan.
func TestZapScriptRefusesAModeItDoesNotKnow(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want string
	}{
		{webModeBaseline, "zap-baseline.py"},
		{webModeAPI, "zap-api-scan.py"},
		{webModeFull, "zap-full-scan.py"},
		{" full ", "zap-full-scan.py"},
	} {
		got, err := zapScript(tc.mode)
		if err != nil {
			t.Errorf("zapScript(%q): %v", tc.mode, err)
			continue
		}
		if got != tc.want {
			t.Errorf("zapScript(%q) = %q, want %q", tc.mode, got, tc.want)
		}
	}

	for _, mode := range []string{"", "BASELINE", "passive", "quick", "true"} {
		got, err := zapScript(mode)
		if err == nil {
			t.Errorf("zapScript(%q) = %q, want an error: a mode cicd does not recognise must not silently run the weakest scan", mode, got)
		}
	}
}

func TestZapArgsBaselinePointsAtTheApplication(t *testing.T) {
	args, err := zapArgs(zapOptions{
		Mode:       webModeBaseline,
		TargetURL:  "http://app-under-test:8080/",
		ReportPath: "/tmp/report.json",
	})
	if err != nil {
		t.Fatalf("zapArgs: %v", err)
	}
	want := []string{
		"-t", "http://app-under-test:8080/",
		"-J", "/tmp/report.json",
		// -P is here and not appended by the test because the port is part
		// of the command, not a detail of it. It is not, however, what
		// stopped the BindException this leg actually hit — see zapProxyPort
		// for the correction, and zapSilentOption for the flag that did.
		"-P", strconv.Itoa(zapProxyPort),
		"-I", "--autooff",
		// Spelled out rather than appended by a helper. -z "-silent" is the
		// difference between a scan that runs the pinned image's rules and
		// one that downloads seventy-three add-ons over them, so it belongs
		// in the expected command where a reader deleting it has to look at
		// it first.
		"-z", zapSilentOption,
	}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Errorf("zapArgs = %v, want %v", args, want)
	}
}

// TestZapArgsAPIModePointsAtTheDocumentAndTheApp pins the one place ZAP's
// packaged scans change the meaning of their own primary argument: -t is the
// API document and -O is the application. Getting these the wrong way round
// produces a scan that exits 0 and tested nothing.
func TestZapArgsAPIModePointsAtTheDocumentAndTheApp(t *testing.T) {
	args, err := zapArgs(zapOptions{
		Mode:       webModeAPI,
		TargetURL:  "http://app-under-test:8080/",
		APITarget:  "/tmp/api-spec",
		APIFormat:  "openapi",
		ReportPath: "/tmp/report.json",
	})
	if err != nil {
		t.Fatalf("zapArgs: %v", err)
	}
	if got := flagValue(args, "-t"); got != "/tmp/api-spec" {
		t.Errorf("-t = %q, want the API document", got)
	}
	if got := flagValue(args, "-O"); got != "http://app-under-test:8080/" {
		t.Errorf("-O = %q, want the application URL", got)
	}
	if got := flagValue(args, "-f"); got != "openapi" {
		t.Errorf("-f = %q, want openapi", got)
	}
}

// TestZapArgsNamesNoFormatOutsideAPIMode: -f, -O and the document belong to
// zap-api-scan.py alone; the other two packaged scans reject them.
func TestZapArgsNamesNoFormatOutsideAPIMode(t *testing.T) {
	for _, mode := range []string{webModeBaseline, webModeFull} {
		args, err := zapArgs(zapOptions{
			Mode:       mode,
			TargetURL:  "http://app-under-test:8080/",
			APIFormat:  "openapi",
			ReportPath: "/tmp/report.json",
		})
		if err != nil {
			t.Fatalf("zapArgs(%s): %v", mode, err)
		}
		for _, flag := range []string{"-f", "-O"} {
			if flagValue(args, flag) != "" {
				t.Errorf("mode %s passed %s, which only zap-api-scan.py accepts", mode, flag)
			}
		}
	}
}

func TestZapArgsAlwaysDefersTheVerdictToCicd(t *testing.T) {
	for _, mode := range []string{webModeBaseline, webModeAPI, webModeFull} {
		args, err := zapArgs(zapOptions{
			Mode:       mode,
			TargetURL:  "http://x:8080/",
			APITarget:  "/tmp/api-spec",
			APIFormat:  "openapi",
			ReportPath: "/tmp/report.json",
		})
		if err != nil {
			t.Fatalf("zapArgs(%s): %v", mode, err)
		}
		joined := strings.Join(args, " ")
		// -I keeps ZAP's own WARN verdict from pre-empting --fail-on, which is
		// cicd's gate and applies to severity counts through gatedPassed. All
		// three packaged scans declare it.
		if !strings.Contains(joined, " -I") {
			t.Errorf("mode %s: -I missing, so ZAP's pass/fail opinion overrides --fail-on: %v", mode, args)
		}
	}
}

// TestZapArgsNamesAutooffInBaselineAlone is a two-sided assertion because the
// flag is wrong in both directions and each direction fails differently.
//
// Missing in baseline, ZAP starts the automation framework, tries to write
// zap.yaml into the /zap/wrk tmpfs it cannot write, and dies with a
// PermissionError before scanning anything. Present anywhere else, the option
// does not exist at all: zap-api-scan.py exits 3 with "Invalid option autooff"
// before it opens a socket, which is how this shipped — the guardrail smoke
// starts no container and passed, and neither of the two scans that do start
// one had been run.
//
// Both failures are non-runs that zapRunError reports and gatedPassed fails at
// every threshold, so neither could ever have read as a clean scan. What they
// cost is the scan.
func TestZapArgsNamesAutooffInBaselineAlone(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want bool
	}{
		{webModeBaseline, true},
		{webModeAPI, false},
		{webModeFull, false},
	} {
		args, err := zapArgs(zapOptions{
			Mode:       tc.mode,
			TargetURL:  "http://x:8080/",
			APITarget:  "/tmp/api-spec",
			APIFormat:  "openapi",
			ReportPath: "/tmp/report.json",
		})
		if err != nil {
			t.Fatalf("zapArgs(%s): %v", tc.mode, err)
		}
		got := false
		for _, a := range args {
			if a == "--autooff" {
				got = true
			}
		}
		if got != tc.want {
			if tc.want {
				t.Errorf("mode %s: --autooff missing, so the automation framework writes into the read-only /zap/wrk tmpfs and ZAP dies before scanning: %v", tc.mode, args)
			} else {
				t.Errorf("mode %s: --autooff passed to a script that does not declare it — ZAP exits 3 before opening a socket: %v", tc.mode, args)
			}
		}
	}
}

func TestZapArgsPassesOptionalCapsOnlyWhenAsked(t *testing.T) {
	none, err := zapArgs(zapOptions{Mode: webModeFull, TargetURL: "http://x:8080/", ReportPath: "/tmp/report.json"})
	if err != nil {
		t.Fatalf("zapArgs: %v", err)
	}
	if flagValue(none, "-T") != "" || flagValue(none, "-c") != "" {
		t.Errorf("an unset cap or rule config must add no flag: %v", none)
	}

	set, err := zapArgs(zapOptions{
		Mode:               webModeFull,
		TargetURL:          "http://x:8080/",
		ReportPath:         "/tmp/report.json",
		RuleConfigPath:     "/tmp/zap-rules.conf",
		MaxDurationMinutes: 45,
	})
	if err != nil {
		t.Fatalf("zapArgs: %v", err)
	}
	if got := flagValue(set, "-T"); got != "45" {
		t.Errorf("-T = %q, want 45", got)
	}
	if got := flagValue(set, "-c"); got != "/tmp/zap-rules.conf" {
		t.Errorf("-c = %q, want the mounted rule config", got)
	}
}

// TestZapArgsRefusesAnIncompleteInvocation: each of these would otherwise reach
// ZAP as a command line missing its subject, which exits non-zero and arrives
// as a non-run with no explanation of the typo behind it.
func TestZapArgsRefusesAnIncompleteInvocation(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts zapOptions
	}{
		{"no report path", zapOptions{Mode: webModeBaseline, TargetURL: "http://x:8080/"}},
		{"no target", zapOptions{Mode: webModeBaseline, ReportPath: "/tmp/report.json"}},
		{"api with no document", zapOptions{Mode: webModeAPI, TargetURL: "http://x:8080/", APIFormat: "openapi", ReportPath: "/tmp/report.json"}},
		{"api with an unknown format", zapOptions{Mode: webModeAPI, TargetURL: "http://x:8080/", APITarget: "/tmp/spec", APIFormat: "swagger2", ReportPath: "/tmp/report.json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := zapArgs(tc.opts); err == nil {
				t.Errorf("zapArgs = %v, want an error", got)
			}
		})
	}
}

func TestValidateAPIFormatAcceptsWhatZapAcceptsAndNothingElse(t *testing.T) {
	for _, f := range webAPIFormats {
		if err := validateAPIFormat(f); err != nil {
			t.Errorf("validateAPIFormat(%q): %v", f, err)
		}
	}
	for _, f := range []string{"", "OpenAPI", "swagger", "wsdl", "rest"} {
		if err := validateAPIFormat(f); err == nil {
			t.Errorf("validateAPIFormat(%q) accepted a format zap-api-scan.py rejects", f)
		}
	}
}

// countOpenAPIOperations is the only scope number in this leg that is a real
// denominator rather than a floor, so an over-count is a claim of coverage the
// scan does not have.
func TestCountOpenAPIOperationsCountsOperationsNotPaths(t *testing.T) {
	const doc = `{
  "openapi": "3.0.3",
  "paths": {
    "/api/items": {
      "get": {"responses": {}},
      "post": {"responses": {}},
      "parameters": [],
      "summary": "not an operation"
    },
    "/health": {"get": {"responses": {}}},
    "/greet": {"GET": {"responses": {}}}
  }
}`
	n, err := countOpenAPIOperations([]byte(doc))
	if err != nil {
		t.Fatalf("countOpenAPIOperations: %v", err)
	}
	// Two on /api/items, one on /health, one on /greet. `parameters` and
	// `summary` are path-item keys and not operations; an upper-case method is
	// still a method.
	if n != 4 {
		t.Errorf("countOpenAPIOperations = %d, want 4", n)
	}

	paths := openAPIPaths([]byte(doc))
	want := []string{"/api/items", "/greet", "/health"}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Errorf("openAPIPaths = %v, want %v", paths, want)
	}
}

func TestCountOpenAPIOperationsRefusesADocumentItCannotRead(t *testing.T) {
	for _, tc := range []struct{ name, doc string }{
		{"not json", "openapi: 3.0.3"},
		{"no paths object", `{"openapi":"3.0.3"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if n, err := countOpenAPIOperations([]byte(tc.doc)); err == nil {
				t.Errorf("countOpenAPIOperations = %d, want an error: a count of 0 would read as a document declaring nothing", n)
			}
			if got := openAPIPaths([]byte(tc.doc)); got != nil {
				t.Errorf("openAPIPaths = %v, want nil", got)
			}
		})
	}
}

// TestZapStartAndPassiveBudgetReportsWhatZAPWillActuallyUse.
//
// Omitting -T is the case that matters. It reads as "no limit" and is not:
// zap_common.wait_for_zap_start substitutes 600 seconds, which is what cicd's
// own dast smoke — which passes no --max-duration-minutes — spent waiting for a
// daemon that had already logged its own termination.
func TestZapStartAndPassiveBudgetReportsWhatZAPWillActuallyUse(t *testing.T) {
	if got := zapStartAndPassiveBudgetSeconds(0); got != 600 {
		t.Errorf("an unset budget reported %d seconds, not ZAP's own 600", got)
	}
	if got := zapStartAndPassiveBudgetSeconds(15); got != 900 {
		t.Errorf("15 minutes reported %d seconds", got)
	}
	// A negative value reaches the same fallback ZAP applies, rather than a
	// negative clock nobody can read.
	if got := zapStartAndPassiveBudgetSeconds(-3); got != 600 {
		t.Errorf("a negative budget reported %d seconds", got)
	}
}

// TestEveryScanPinsItsProxyPort: -P is not optional and not mode-specific.
//
// Without it zap_common.py draws the proxy port at random from 32768-61000,
// which is the kernel's ephemeral range, probes it with connect_ex, binds
// nothing, and then lets ZAP spend thirty seconds downloading add-ons before
// the proxy actually tries to bind. Losing that race is not a slow scan, it is
// "Terminating ZAP, unable to start the main proxy" followed by a ten-minute
// wait for a daemon that is already dead.
func TestEveryScanPinsItsProxyPort(t *testing.T) {
	for _, mode := range []string{webModeBaseline, webModeAPI, webModeFull} {
		args, err := zapArgs(zapOptions{
			Mode:       mode,
			TargetURL:  "http://app-under-test:8080/",
			APITarget:  "/tmp/api-spec",
			APIFormat:  "openapi",
			ReportPath: "/tmp/report.json",
		})
		if err != nil {
			t.Fatalf("zapArgs(%s): %v", mode, err)
		}
		if got := flagValue(args, "-P"); got != strconv.Itoa(zapProxyPort) {
			t.Errorf("mode %s: -P = %q, want %d — an unpinned port is drawn from the ephemeral range and lost to ZAP's own add-on downloads",
				mode, got, zapProxyPort)
		}
	}
}

// TestTheProxyPortCannotBeDrawnFromTheEphemeralRange is the assertion that
// gives the fix its value. Pinning a port inside 32768-60999 would still
// compile, still pass TestEveryScanPinsItsProxyPort, and still lose the race —
// the kernel would simply hand the same number to one of ZAP's own outbound
// connections or to the OAST callback service.
//
// The bound is the Linux default ip_local_port_range in the pinned ZAP image,
// read from /proc/sys/net/ipv4/ip_local_port_range, widened at the top to
// zap_common.py's own 61000 so that a port in the sliver between the two is
// refused too.
func TestTheProxyPortCannotBeDrawnFromTheEphemeralRange(t *testing.T) {
	const (
		ephemeralLow  = 32768
		ephemeralHigh = 61000
	)
	if zapProxyPort >= ephemeralLow && zapProxyPort <= ephemeralHigh {
		t.Fatalf("zapProxyPort = %d, which get_free_port() can draw (%d-%d): pinning a port in that range restores the race it was pinned to end",
			zapProxyPort, ephemeralLow, ephemeralHigh)
	}
	if zapProxyPort < 1024 {
		t.Errorf("zapProxyPort = %d is privileged; the ZAP image runs as a non-root user and cannot bind it", zapProxyPort)
	}
}
