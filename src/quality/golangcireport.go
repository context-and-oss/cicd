// golangci-lint run-error classification and version reporting.
//
// Deliberately untagged (no //go:build !unit_test): classifying an exit status
// and a stderr blob is pure string work, so golangcireport_test.go can drive the
// real thing with `go test -tags unit_test ./...` rather than a copy.
package main

import (
	"encoding/json"
	"strconv"
	"strings"
)

// stampSARIFDriverVersion records the golangci-lint that actually produced a
// report on that report's own tool driver, and is the reason mergeGolangciVersions
// is not dead weight.
//
// golangci-lint writes no version into its SARIF, and the sub-envelope's
// toolInfo.Version does not survive aggregation — Check folds every language leg
// into one envelope whose Tool is a bare `{"name":"quality"}` (main.go). The SARIF
// runs are the only per-leg structure that reaches the consumer, so the version
// goes there or nowhere, and "nowhere" would leave evidence that cannot say which
// linter produced the verdict. This is the same place the Node leg keeps its
// per-project ESLint version (buildEslintSarif), so both legs are read the same
// way.
//
// version is golangciVersionLabel's output, so it is an observed version or the
// literal "unknown" — never the compile-time pin. Two deliberate trade-offs:
//
//   - The document is re-serialized, so it is no longer byte-identical to what the
//     binary wrote (key order changes; content does not). Acceptable because
//     mergeSARIFReports already rebuilds the wrapper for a multi-module tree.
//   - Any parse or marshal failure returns the original bytes untouched. A
//     cosmetic metadata field must never cost a single finding.
func stampSARIFDriverVersion(raw json.RawMessage, version string) json.RawMessage {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return raw
	}
	runs, ok := doc["runs"].([]any)
	if !ok {
		return raw
	}
	for _, r := range runs {
		run, ok := r.(map[string]any)
		if !ok {
			continue
		}
		tool, ok := run["tool"].(map[string]any)
		if !ok {
			continue
		}
		driver, ok := tool["driver"].(map[string]any)
		if !ok {
			continue
		}
		driver["version"] = version
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return raw
	}
	return out
}

// golangciRunError reports why golangci-lint did not run, or "" when it did.
//
// The exit status is the only trustworthy signal, and that is the whole point of
// this function. Measured on v2.12.2: pointed at a directory outside its
// workspace, golangci-lint prints "0 issues.", writes a **valid, schema-correct
// SARIF document with an empty results array**, and exits 7. A caller that reads
// the report and finds well-formed JSON with no findings therefore learns
// nothing — the identical bytes mean "clean tree" and "never analysed a single
// package". Only the exit status separates them.
//
// The leg runs with --issues-exit-code 0, so findings do not move the status:
// exit 0 means the analysis completed, anything else means it did not. That is a
// stricter rule than ESLint's (where 1 is a legitimate "problems reported") and
// it is stricter on purpose, because golangci-lint has no exit code that means
// "partially analysed".
func golangciRunError(exitCode, stderr, report string) string {
	code := strings.TrimSpace(exitCode)
	n, err := strconv.Atoi(code)
	switch {
	case err != nil:
		return "golangci-lint: unreadable exit status " + strconv.Quote(code)
	case n == 0:
		// Ran. A completed run always writes a SARIF document, so an empty or
		// unparseable file after exit 0 means the output never arrived — a
		// changed flag name, a path the binary could not write. Treat it as a
		// non-run rather than as zero findings.
		if strings.TrimSpace(report) == "" {
			return "golangci-lint: exited 0 but wrote an empty report"
		}
		if !isSARIFDocument(report) {
			return "golangci-lint: exited 0 but wrote something that is not a SARIF document"
		}
		return ""
	default:
		msg := "golangci-lint: did not run (exit " + code + ")"
		if s := golangciStderrMessage(stderr); s != "" {
			msg += ": " + s
		}
		return msg + golangciRemedy(stderr)
	}
}

// isSARIFDocument reports whether report parses as a SARIF document carrying at
// least one run. A bare `{}` is valid JSON and would otherwise pass for a clean
// result.
func isSARIFDocument(report string) bool {
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool json.RawMessage `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(report), &doc); err != nil {
		return false
	}
	return doc.Version != "" && len(doc.Runs) > 0
}

// golangciStderrMessage extracts the most useful single line from golangci-lint's
// stderr. It logs in logrus key=value form (`level=error msg="..."`) and also
// prints bare `Error: ...` lines, so both shapes are handled; the message text is
// preferred because the level prefix carries no information the exit status does
// not already give.
func golangciStderrMessage(stderr string) string {
	var fallback string
	for _, raw := range strings.Split(stderr, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if i := strings.Index(line, `msg="`); i >= 0 {
			rest := line[i+len(`msg="`):]
			if j := strings.LastIndex(rest, `"`); j > 0 {
				return strings.TrimSpace(rest[:j])
			}
			return strings.TrimSpace(rest)
		}
		if after, ok := strings.CutPrefix(line, "Error: "); ok {
			return strings.TrimSpace(after)
		}
		if fallback == "" {
			fallback = line
		}
	}
	return fallback
}

// golangciRemedy appends the fix for the failures that are configuration rather
// than code, because each has a specific answer and a bare exit code sends the
// reader to the wrong place.
//
// Every string matched here was observed in a real run against this repository's
// own trees, not copied from documentation.
func golangciRemedy(stderr string) string {
	switch {
	case strings.Contains(stderr, "unsupported version of the configuration"):
		return ". The .golangci.yml is in the v1 schema and cicd runs golangci-lint v2," +
			" which refuses it outright — add `version: \"2\"` and migrate the file" +
			" (https://golangci-lint.run/docs/product/migration-guide)"
	case strings.Contains(stderr, "does not contain modules listed in go.work"):
		return ". The directory is not one of the go.work `use` modules, so no packages" +
			" resolve there — add it to go.work, or remove go.work if every module" +
			" should be discovered independently"
	case strings.Contains(stderr, "unsupported output format"):
		return ". This golangci-lint cannot emit SARIF; cicd requires v2.x, whose flag is" +
			" --output.sarif.path"
	case strings.Contains(stderr, "typechecking error"), strings.Contains(stderr, "could not load export data"):
		return ". The packages did not type-check, so nothing was analysed — dependencies" +
			" may be unresolvable from the container, generated code may be missing," +
			" or the module may need a newer toolchain than this linter carries"
	default:
		return ""
	}
}

// golangciVersionLabel extracts the version from `golangci-lint --version`
// output, or "unknown".
//
// The envelope must report the linter that ran, not the pin it was configured
// with. Reporting the constant is how quality's .NET leg came to describe an SDK
// that had never started (see CLAUDE.md), so the version is read out of the
// container that did the work.
//
// Observed shape: `golangci-lint has version 2.12.2 built with go1.26.2 from
// c0d3ddc9 on 2026-05-06T11:07:58Z`.
func golangciVersionLabel(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f != "version" || i+1 >= len(fields) {
				continue
			}
			v := strings.TrimPrefix(strings.TrimSpace(fields[i+1]), "v")
			if v != "" && v[0] >= '0' && v[0] <= '9' {
				return v
			}
		}
	}
	return "unknown"
}
