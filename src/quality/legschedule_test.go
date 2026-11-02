//go:build unit_test

package main

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunLegsBoundedKeepsDeclarationOrder(t *testing.T) {
	// The first leg finishes last: completion order is the reverse of the
	// declared order, and the slice must not follow it.
	labels := []string{"a", "b", "c"}
	out, err := runLegsBounded(context.Background(), labels, 3, func(i int) legOutcome {
		time.Sleep(time.Duration(len(labels)-i) * 20 * time.Millisecond)
		return legOutcome{Ran: true, Output: labels[i]}
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i, o := range out {
		if o.Output != labels[i] {
			t.Fatalf("slot %d holds %q, want %q", i, o.Output, labels[i])
		}
		if o.Duration <= 0 {
			t.Fatalf("slot %d has no duration", i)
		}
	}
}

func TestRunLegsBoundedHonoursTheBound(t *testing.T) {
	var inFlight, peak atomic.Int32
	labels := []string{"a", "b", "c", "d", "e", "f"}
	_, err := runLegsBounded(context.Background(), labels, 2, func(int) legOutcome {
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		inFlight.Add(-1)
		return legOutcome{Ran: true}
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := peak.Load(); got != 2 {
		t.Fatalf("peak legs in flight = %d, want 2", got)
	}
}

func TestRunLegsBoundedSequentialByDefault(t *testing.T) {
	var inFlight, peak atomic.Int32
	_, err := runLegsBounded(context.Background(), []string{"a", "b", "c"}, 1, func(int) legOutcome {
		if n := inFlight.Add(1); n > peak.Load() {
			peak.Store(n)
		}
		time.Sleep(5 * time.Millisecond)
		inFlight.Add(-1)
		return legOutcome{Ran: true}
	})
	if err != nil || peak.Load() != 1 {
		t.Fatalf("peak = %d, err = %v; want one leg at a time", peak.Load(), err)
	}
}

func TestRunLegsBoundedRefusesALegThatNeverStarted(t *testing.T) {
	// A cancelled context leaves slots no leg wrote. Folding them would report
	// a leg that ran and said nothing, so the run is an error naming the leg.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out, err := runLegsBounded(ctx, []string{"unit", "integration"}, 1, func(int) legOutcome {
		t.Fatal("no leg may start under a cancelled context")
		return legOutcome{}
	})
	if err == nil || out != nil {
		t.Fatalf("out = %v, err = %v; want an error and no outcomes", out, err)
	}
	if !strings.Contains(err.Error(), "test-leg unit did not start") {
		t.Fatalf("error = %v, want it to name the first leg", err)
	}
}

func TestLegDurationReachesTheReport(t *testing.T) {
	legs := []testLeg{{Label: "unit", Language: "go", Cmd: "go test ./..."}}
	fold := newByoTestFold(legs, []string{"golang:1"}, make([]ToolchainResolution, 1), false, nil)
	fold.addLeg(0, legOutcome{Ran: true, Passed: true, Duration: 1500 * time.Millisecond})
	if got := fold.LegReports[0].DurationMS; got != 1500 {
		t.Fatalf("durationMs = %d, want 1500", got)
	}
}
