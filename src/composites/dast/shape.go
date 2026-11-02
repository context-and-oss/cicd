package main

import (
	"fmt"
	"strconv"
	"strings"
)

// The three shapes a DAST run can take, selected explicitly with --app and
// never auto-detected (ADR-005, the same rule commit.Run's --artifact follows).
//
//   - url and service are W1: the consumer starts the application, cicd scans
//     what it is pointed at, and the evidence attests nothing about what is
//     behind the address.
//   - container is W2: cicd builds the image from this commit's Dockerfile,
//     starts it inside the engine and scans that, so the run can say the code
//     it scanned is the code this commit produced.
const (
	appURL       = "url"
	appService   = "service"
	appContainer = "container"
)

// appInputs is what the caller actually supplied, reduced to the presences
// --app has to agree with. It is a struct rather than three arguments so a
// future fourth shape cannot be added by widening a parameter list nobody
// re-reads.
type appInputs struct {
	// Target is --target, as given (blank means unset).
	Target string
	// HasService is whether --service was bound.
	HasService bool
	// HasSrc is whether --src was supplied.
	HasSrc bool
	// Port is --port. Meaningful for the two bound shapes only.
	Port int
	// Mode is --mode, as given.
	Mode string
}

// validateApp refuses every combination that would otherwise reach ScanWeb as
// a scan of something other than what was asked for.
//
// Two classes of refusal, and the second is the one that is easy to miss.
//
// A selector that disagrees with its inputs (--app url with --service bound,
// --app container with no --src) is caught here rather than downstream so the
// message names --app. ScanWeb's own "exactly one source" error would fire for
// most of these, but it would describe three parameters the consumer did not
// think they were choosing between.
//
// And a value that is the zero value of its Go type never reaches ScanWeb at
// all: Dagger's generated client drops any optional argument holding one
// (`if !querybuilder.IsZeroValue(...)`), which is the same mechanic that forces
// intent's flag to be negative and DAST's mode to be a string. So --mode ""
// and --port 0 are not passed through and rejected there — they are silently
// replaced by ScanWeb's own defaults, baseline and 8080. A caller whose
// workflow variable came out empty would get the weakest scan, or a scan of a
// port they never named, and nothing in the evidence would say so. They are
// refused here because here is the only place they are still visible.
func validateApp(app string, in appInputs) error {
	switch app {
	case appURL:
		if strings.TrimSpace(in.Target) == "" {
			return fmt.Errorf("--app url needs --target: the URL of a running application the engine can reach")
		}
		if in.HasService {
			return fmt.Errorf("--app url was given a --service; pass --app service to scan it, or drop it")
		}
		if in.HasSrc {
			return fmt.Errorf("--app url was given a --src, and nothing is built for this shape; " +
				"pass --app container to build and scan it, or drop it — a source tree that is silently ignored " +
				"makes the run look like it scanned the code in this commit")
		}
	case appService:
		if !in.HasService {
			return fmt.Errorf("--app service needs --service, e.g. --service=tcp://localhost:5000 for an " +
				"application the workflow already started on the runner")
		}
		if strings.TrimSpace(in.Target) != "" {
			return fmt.Errorf("--app service was given a --target as well; a bound service is addressed by cicd, " +
				"never by a URL the consumer typed")
		}
		if in.HasSrc {
			return fmt.Errorf("--app service was given a --src, and nothing is built for this shape; " +
				"pass --app container to build and scan it, or drop it")
		}
	case appContainer:
		if !in.HasSrc {
			return fmt.Errorf("--app container needs --src: the source tree holding the Dockerfile cicd builds " +
				"and then scans")
		}
		if strings.TrimSpace(in.Target) != "" {
			return fmt.Errorf("--app container was given a --target as well; cicd starts the image it built and " +
				"addresses it itself")
		}
		if in.HasService {
			return fmt.Errorf("--app container was given a --service as well; exactly one of the three shapes " +
				"can be scanned in a run")
		}
	default:
		// No default arm that picks a shape. An --app value cicd does not
		// recognise must not resolve to the one that needs the least from the
		// caller, which is exactly what a fall-through to url would do.
		return fmt.Errorf("invalid --app %s: want url|service|container", strconv.Quote(app))
	}

	if strings.TrimSpace(in.Mode) == "" {
		return fmt.Errorf("--mode is empty; pass baseline, api or full — an empty mode is dropped before it " +
			"reaches the scanner and silently becomes the weakest scan")
	}

	// The URL shape carries its own port inside --target, so a port is neither
	// read nor checked there. For the two bound shapes it is the port cicd
	// composes the address from, and a zero would be dropped and replaced by
	// 8080 rather than refused.
	if app != appURL && (in.Port < 1 || in.Port > 65535) {
		return fmt.Errorf("--port %d is not a port; pass the port the application answers on (1-65535)", in.Port)
	}

	return nil
}
