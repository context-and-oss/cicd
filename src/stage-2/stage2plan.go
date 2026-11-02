// What Run decides before it calls a domain module: whether the consumer owns
// test execution, which inputs are refused, which legs exist and in what
// order, and what a leg that produced nothing is recorded as.
//
// Untagged (no //go:build !unit_test): main.go carries the Dagger build tag
// because the generated SDK panics outside a session, and for as long as these
// rules lived beside the dag calls no test could reach them.
package main

import (
	"fmt"
	"time"
)

// byoTestRequested says whether the consumer supplied its own test execution.
// Either input means quality.Test runs and quality.Check runs lint-only
// (ADR-002); missing the legs case here would run cicd's own per-language
// tests *and* the declared legs — two verdicts on the same code, and the
// composite budget paying for both.
func byoTestRequested(testCmd, testLegs string) bool {
	return testCmd != "" || testLegs != ""
}

// validateStage2Inputs refuses the inputs no leg could act on, in the order
// Run checked them before: parallelism, the node project limit, then a
// prepared container with nothing to run in it. The messages are what the
// composites and scripts/smoke/stage-orchestrators.sh see.
func validateStage2Inputs(parallelism, nodeProjectLimit int, hasPrepared, byoTest bool) error {
	if err := ValidateParallelism(parallelism); err != nil {
		return err
	}
	if nodeProjectLimit < 1 {
		return fmt.Errorf("node-project-limit must be positive")
	}
	if hasPrepared && !byoTest {
		return fmt.Errorf("prepared execution requires witnessed BYO tests")
	}
	return nil
}

// stage2Leg is one leg's evidence beside the name it is recorded under.
type stage2Leg[T any] struct {
	name  string
	value T
}

// stage2Legs is the leg order Run returns evidence in, each value paired with
// the name its leg is recorded under when it produced none. The pairing is
// made here, once, because two parallel slices — one of files, one of names —
// let a leg added to one and not the other misattribute every later failure
// or index past the end. The witnessed-tests leg exists only when the
// consumer requested it, and its value is dropped otherwise; every other leg
// always reports, because a gate missing from an audit and a gate that passed
// look identical afterwards.
//
// Generic so the order can be proven with plain values: the entry passes
// *dagger.File, the test passes strings.
func stage2Legs[T any](byoTest bool, quality, tests, security, licences, risk, intent T) []stage2Leg[T] {
	legs := []stage2Leg[T]{{"quality", quality}}
	if byoTest {
		legs = append(legs, stage2Leg[T]{"witnessed tests", tests})
	}
	return append(legs,
		stage2Leg[T]{"source security", security},
		stage2Leg[T]{"source licences", licences},
		stage2Leg[T]{"risk", risk},
		stage2Leg[T]{"intent", intent},
	)
}

// unusableEvidence is the envelope a leg is recorded under when its module
// returned no evidence file at all: failed, outcome ERROR, with the leg named
// in errors[]. A failed module becomes failed evidence so the other legs'
// completed checks survive into the audit.
func unusableEvidence(name string, repo repoContext, now time.Time) envelope {
	return envelope{
		SchemaVersion: evidenceSchemaVersion,
		ModuleName:    "stage-2",
		Stage:         "stage-2",
		Repo:          repo,
		Tool:          toolInfo{Name: name},
		TimestampUTC:  now,
		Passed:        false,
		Outcome:       OutcomeError,
		Errors:        []string{name + ": execution did not produce usable evidence; inspect the execution log"},
	}
}
