//go:build !unit_test

package main

import (
	"context"
	"dagger/security/internal/dagger"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// readinessScript polls the target until it answers or the budget runs out, and
// records the outcome in three files.
//
// It runs in the pinned alpine image and not in ZAP's, for the reason
// images.go gives for the dependency-input probe: the answer to "could the
// target be reached" must not come from inside the tool whose silence is the
// thing under suspicion. busybox wget is enough — this is a reachability
// question, not a scan.
//
// --no-check-certificate is deliberate and is not a weakening: a dev-mode app
// behind a self-signed certificate is the normal case for this leg, ZAP itself
// scans it regardless, and refusing to probe what the scanner will happily scan
// would turn a TLS detail into an unexplained non-run. Certificate validity is
// a property of the deployed ingress, which the profile disclosure already
// states this scan does not test.
const readinessScript = `set -u
url="$1"
deadline="$2"
attempts=0
started=$(date +%s)
status=0
while :; do
  attempts=$((attempts + 1))
  code=$(wget --no-check-certificate -S -O /dev/null "$url" 2>&1 | awk '/HTTP\//{print $2; exit}')
  if [ -n "$code" ]; then
    status="$code"
    case "$code" in
      2*|3*) break ;;
    esac
  fi
  now=$(date +%s)
  if [ $((now - started)) -ge "$deadline" ]; then break; fi
  sleep 2
done
now=$(date +%s)
echo "$status" > /tmp/probe.status
echo "$attempts" > /tmp/probe.attempts
echo $((now - started)) > /tmp/probe.waited
exit 0`

// dastRun is everything one scan needs, resolved before any container starts.
type dastRun struct {
	Target      webTarget
	Service     *dagger.Service
	Mode        string
	APISpec     *dagger.File
	APISpecPath string
	APIFormat   string
	RuleConfig  *dagger.File
	MaxDuration int
	ReadyBudget int
}

// withTarget binds the application under test, when there is one to bind.
//
// The url source has nothing to bind: the address is routable from the engine
// already, which is exactly what makes it the source with no provenance. The
// other two arrive as a *dagger.Service and answer on webServiceAlias.
func (r dastRun) withTarget(c *dagger.Container) *dagger.Container {
	if r.Service == nil {
		return c
	}
	return c.WithServiceBinding(r.Target.Alias, r.Service)
}

// probeReadiness asks whether the target answers, before anything scans it.
//
// The result is returned whether or not it succeeded, because it is recorded
// either way. A probe that never got an answer makes the caller record a
// non-run: passed=false at every threshold, NONE included, because a target
// that was never reached is not a target that was found clean.
func probeReadiness(ctx context.Context, r dastRun) readinessResult {
	res := readinessResult{URL: r.Target.HealthURL}

	ran := r.withTarget(dag.Container().From(alpineImage)).
		WithExec([]string{"sh", "-c", readinessScript, "sh", r.Target.HealthURL, strconv.Itoa(r.ReadyBudget)})

	status, err := ran.File("/tmp/probe.status").Contents(ctx)
	if err != nil {
		res.Error = "readiness probe could not run: " + err.Error()
		return res
	}
	// The script writes all three files on every exit, so a counter that
	// cannot be read back, or holds no number, is cicd failing to collect the
	// probe's answer. It is reported as such, never as status 0 — which is the
	// value the script writes when the target never answered, and the sentence
	// below would then blame the target for cicd's own fault.
	for _, counter := range []struct {
		path string
		raw  string
		err  error
		dst  *int
	}{
		{"/tmp/probe.status", status, nil, &res.Status},
		{"/tmp/probe.attempts", "", nil, &res.Attempts},
		{"/tmp/probe.waited", "", nil, &res.WaitedSeconds},
	} {
		raw, rerr := counter.raw, counter.err
		if counter.dst != &res.Status {
			raw, rerr = ran.File(counter.path).Contents(ctx)
		}
		n, msg := readbackCount("readiness probe", counter.path, raw, rerr)
		if msg != "" {
			res.Error = msg
			return res
		}
		*counter.dst = n
	}
	res.OK = res.Status >= 200 && res.Status < 400

	if !res.OK {
		if res.Status == 0 {
			res.Error = fmt.Sprintf("readiness probe: %s never answered in %ds (%d attempts)",
				res.URL, res.WaitedSeconds, res.Attempts)
		} else {
			res.Error = fmt.Sprintf("readiness probe: %s answered %d, which is not a served response",
				res.URL, res.Status)
		}
	}
	return res
}

// runZAP executes the packaged scan the mode selects and returns its report.
//
// A non-nil error means ZAP could not scan — never that it found nothing.
func runZAP(ctx context.Context, r dastRun) (zapResult, error) {
	start := time.Now()

	script, err := zapScript(r.Mode)
	if err != nil {
		return zapResult{}, err
	}

	opts := zapOptions{
		Mode:               r.Mode,
		TargetURL:          r.Target.BaseURL,
		APIFormat:          r.APIFormat,
		MaxDurationMinutes: r.MaxDuration,
		ReportPath:         zapReportPath,
	}

	c := r.withTarget(dag.Container().From(zapImage)).
		WithMountedTemp("/zap/wrk").
		// Raising swagger-parser's input cap, for the reason
		// zapYAMLCodePointLimit gives. JAVA_TOOL_OPTIONS and not
		// .ZAP_JVM.properties: zap.sh reads that file's first line into
		// JMEM verbatim, which switches off its own
		// -Xmx = memory/4 sizing, and a scanner that silently lost its
		// heap budget is the same failure one door over. The JVM also
		// echoes "Picked up JAVA_TOOL_OPTIONS: ..." on stderr, so the
		// setting evidences itself in the stream cicd already keeps.
		WithEnvVariable("JAVA_TOOL_OPTIONS", "-DmaxYamlCodePoints="+strconv.Itoa(zapYAMLCodePointLimit)).
		// The pinned passive-rule add-on, staged where zapRunScript can
		// check its digest before anything loads it.
		//
		// Fetched rather than vendored, and the fetch is allowed to fail
		// the run. That reads backwards until the alternative is spelled
		// out: today the scan fetches this add-on and seventy-two others
		// itself, from the same marketplace, pinned to nothing, and a
		// failure there does not fail the scan — it produces a smaller
		// rule set that renders identically to a complete one. A named
		// non-run is the better half of that trade. The digest is what
		// makes the fetch reproducible; the URL only says where to look.
		//
		// Owner is not decoration. Dagger mounts an HTTP file 0600
		// root:root and the pinned image runs as uid 1000(zap), so
		// without it the staged file is present and unreadable — which
		// is how the first smoke run of this code reported a digest
		// substitution that had not happened. The scan user must be able
		// to read what cicd asked it to verify.
		WithMountedFile(zapAddOnStagePath, dag.HTTP(zapPscanRulesBetaURL),
			dagger.ContainerWithMountedFileOpts{Owner: zapContainerUser}).
		// The hook module is cicd's own file, written into the container
		// rather than mounted from the host, because it is source held in
		// zapurls.go and there is no copy on disk for a consumer to shadow.
		WithNewFile(zapHookPath, zapURLDumpHook)
	opts.HookPath = zapHookPath

	if r.APISpec != nil {
		c = c.WithMountedFile(zapSpecPath, r.APISpec)
		opts.APITarget = zapSpecPath
	} else if strings.TrimSpace(r.APISpecPath) != "" {
		u, err := apiSpecURL(r.Target, r.APISpecPath)
		if err != nil {
			return zapResult{}, err
		}
		opts.APITarget = u
	}
	if r.RuleConfig != nil {
		c = c.WithMountedFile(zapRuleConfigPath, r.RuleConfig)
		opts.RuleConfigPath = zapRuleConfigPath
	}

	args, err := zapArgs(opts)
	if err != nil {
		return zapResult{}, err
	}

	ran := c.WithExec(append([]string{"sh", "-c", zapRunScript, "sh", script}, args...))

	code, err := ran.File("/tmp/zap.exit").Contents(ctx)
	if err != nil {
		return zapResult{}, fmt.Errorf("zap: exit status unreadable: %w", err)
	}
	// Both streams, because the packaged scan reports its own failures on
	// stdout while stderr carries the Java daemon's INFO log — see
	// zapFailureDetail. /tmp/zap.out was written and never read. The run
	// script creates both before ZAP starts, so a stream that cannot be read
	// back is cicd's failure, and zapRunError must not be asked to classify an
	// exit against an empty log it would read as "ZAP said nothing".
	stdout, err := ran.File("/tmp/zap.out").Contents(ctx)
	if err != nil {
		return zapResult{}, errors.New(readbackError("zap", "/tmp/zap.out", err))
	}
	stderr, err := ran.File("/tmp/zap.err").Contents(ctx)
	if err != nil {
		return zapResult{}, errors.New(readbackError("zap", "/tmp/zap.err", err))
	}
	// Which of zapaddons.go's three answers applied. Read with the rest of
	// the run's facts and not asserted on here: "the pinned rules did not
	// load" is a disclosure this file has no business turning into a verdict.
	// The *read* is asserted on: the script always writes the file, and an
	// empty string would be labelled "status missing" by zapAddOnStatus, which
	// is a claim about the add-ons and not about cicd's read.
	addOnStatus, err := ran.File(zapAddOnStatusPath).Contents(ctx)
	if err != nil {
		return zapResult{}, errors.New(readbackError("zap", zapAddOnStatusPath, err))
	}
	report, err := ran.File(zapReportPath).Contents(ctx)
	if err != nil {
		return zapResult{}, fmt.Errorf("zap: report unreadable: %w", err)
	}
	// Discarded error, deliberately and unlike the report's: the run script
	// touches this path, so a read failure here is a container that did not
	// produce files at all — which the report read above has already turned
	// into a non-run. An empty string is what the caller reads as "no dump",
	// and it discloses that rather than failing the scan over cicd's own
	// instrument.
	urlDump, _ := ran.File(zapURLDumpPath).Contents(ctx)

	// The status is read with its error folded into the status itself, not
	// discarded: an unreadable status file is cicd failing to ask, which is
	// what zapImportProbeFailed exists to say out loud. The two payload
	// files are best-effort — with no rejection to report, neither is read.
	rejectStatus, err := ran.File(zapImportRejectStatusPath).Contents(ctx)
	importProbe := zapImportProbe{Status: 2}
	if err == nil {
		importProbe.Status, err = strconv.Atoi(strings.TrimSpace(rejectStatus))
		if err != nil {
			importProbe.Status = 2
		}
	}
	if zapImportRejected(importProbe) {
		importProbe.Block, _ = ran.File(zapImportRejectPath).Contents(ctx)
		importProbe.Levels, _ = ran.File(zapDaemonLevelsPath).Contents(ctx)
	}

	// The exit sentinel is `echo $?`, so a value that is not a number is a
	// script that did not run to that line — reported, never read as exit 0.
	exit, msg := readbackCount("zap", "/tmp/zap.exit", code, nil)
	if msg != "" {
		return zapResult{}, errors.New(msg)
	}
	res := zapResult{
		Raw:                            json.RawMessage(report),
		ExitCode:                       exit,
		Args:                           append([]string{script}, args...),
		Duration:                       time.Since(start),
		Stdout:                         stdout,
		Stderr:                         stderr,
		Import:                         importProbe,
		StartAndPassiveBudgetSeconds:   zapStartAndPassiveBudgetSeconds(opts.MaxDurationMinutes),
		StartAndPassiveBudgetDefaulted: opts.MaxDurationMinutes <= 0,
		URLDump:                        urlDump,
		AddOnStatus:                    zapAddOnStatus(addOnStatus),
	}
	if msg := zapRunError(code, stdout, stderr, report); msg != "" {
		return res, errors.New(msg)
	}
	return res, nil
}

// readAPISpecContents returns the API document's bytes so cicd can count the
// operations it declares, for the --api-spec source: a file the caller handed
// in. The served source is fetchAPISpecContents' job.
func readAPISpecContents(ctx context.Context, spec *dagger.File) ([]byte, error) {
	if spec == nil {
		return nil, nil
	}
	s, err := spec.Contents(ctx)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

// specFetchScript retrieves the API document the target serves. Failure is
// reported through the file rather than the exit status, because the caller
// warns on a failed fetch and must be able to say why.
const specFetchScript = `set -u
url="$1"
if wget --no-check-certificate -q -O /tmp/spec.json "$url" 2>/tmp/spec.err; then
  echo ok > /tmp/spec.status
else
  echo "failed" > /tmp/spec.status
  : > /tmp/spec.json
fi
exit 0`

// fetchAPISpecContents returns the bytes of the document the target serves at
// --api-spec-path, so an api-mode scan driven that way can state its own
// denominator.
//
// This is deliberately a second request for a document ZAP also fetches, and
// the duplication is the point: ZAP's JSON report does not say how many
// operations it was given, so without this the evidence for the shape a
// consumer is most likely to use — the app serves its own OpenAPI document,
// nobody commits a copy — carries "dast: API SCAN" with no number in it, and a
// three-operation scan is indistinguishable from a three-hundred-operation one.
//
// It runs only after readiness passed, against the same bound service, so it
// cannot be the thing that discovers the target is down; that verdict has one
// owner. A failed fetch is the caller's warning and never an error: ZAP may
// well have read the document cicd could not, and calling that scan a non-run
// would be a false red over cicd's own accounting.
func fetchAPISpecContents(ctx context.Context, r dastRun) ([]byte, error) {
	u, err := apiSpecURL(r.Target, r.APISpecPath)
	if err != nil {
		return nil, err
	}
	ran := r.withTarget(dag.Container().From(alpineImage)).
		WithExec([]string{"sh", "-c", specFetchScript, "sh", u})

	status, err := ran.File("/tmp/spec.status").Contents(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", u, err)
	}
	if strings.TrimSpace(status) != "ok" {
		detail, derr := ran.File("/tmp/spec.err").Contents(ctx)
		detail = strings.TrimSpace(detail)
		switch {
		case derr != nil:
			detail = "(stderr unreadable: " + derr.Error() + ")"
		case detail == "":
			detail = "no output"
		}
		return nil, fmt.Errorf("fetch %s: %s", u, detail)
	}
	body, err := ran.File("/tmp/spec.json").Contents(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", u, err)
	}
	return []byte(body), nil
}

// readRuleConfig returns the ZAP rule config's parsed settings.
func readRuleConfig(ctx context.Context, cfg *dagger.File) ([]zapRuleSetting, error) {
	if cfg == nil {
		return nil, nil
	}
	s, err := cfg.Contents(ctx)
	if err != nil {
		return nil, fmt.Errorf("zap rule config unreadable: %w", err)
	}
	return parseZAPRuleConfig(s)
}
