package concurrency

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

func TestBoundAndFailureIsolation(t *testing.T) {
	for _, limit := range []int{1, 2, 4} {
		t.Run(string(rune('0'+limit)), func(t *testing.T) {
			var active, peak, visited atomic.Int32
			started := make(chan struct{}, limit)
			release := make(chan struct{})
			done := make(chan []error, 1)
			boom := errors.New("failed group")
			go func() {
				done <- RunBounded(context.Background(), 8, limit, func(i int) error {
					n := active.Add(1)
					for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
					}
					if visited.Add(1) <= int32(limit) {
						started <- struct{}{}
					}
					<-release
					active.Add(-1)
					if i == 1 {
						return boom
					}
					return nil
				})
			}()
			for range limit {
				<-started
			}
			close(release)
			errs := <-done
			if peak.Load() != int32(limit) || visited.Load() != 8 || !errors.Is(errs[1], boom) {
				t.Fatalf("peak=%d visited=%d errors=%v", peak.Load(), visited.Load(), errs)
			}
			for i, err := range errs {
				if i != 1 && err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestCancelledAndInvalidLimits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, limit := range []int{-1, 0, 1, 5} {
		errs := RunBounded(ctx, 3, limit, func(int) error { t.Fatal("unexpected execution"); return nil })
		for _, err := range errs {
			if err == nil {
				t.Fatal("missing error")
			}
		}
	}
}
