package main

// gatedPassed applies `fail-on: NONE` to the severity verdict only.
//
// NONE means "do not fail me over findings". It never meant "do not tell me
// the tool was skipped", but that is what it did in every module that had the
// rule: the threshold was checked first and returned true unconditionally, so
// a tool that could not execute reported passed=true with the reason sitting
// unread in errors[]. That made "clean tree" and "tool did not run" the same
// verdict — the failure class each module's non-run classification exists to
// prevent, reintroduced one layer above it.
//
// So the two signals are separate. ran=false fails at every threshold, NONE
// included. severityOK carries the findings verdict and is the only thing NONE
// suppresses.
//
// This file is byte-identical in src/quality, src/security and src/risk, held
// equal by a synced_files group in scripts/repo-inventory.json (`make
// check-surface` fails the moment a copy diverges). Dagger modules are
// isolated (own go.mod, no shared package), so the rule is a copy rather than
// an import; it is one sentence long, and a copy a gate holds equal is the
// lesser evil. Nothing module-specific belongs beside it — quality's leg folds
// live in legfold.go and risk's outcome helpers in validatereport.go — because
// an addition to one copy breaks the equality for all three.
func gatedPassed(ran, severityOK bool, threshold Severity) bool {
	if !ran {
		return false
	}
	if threshold == SeverityNone {
		return true
	}
	return severityOK
}
