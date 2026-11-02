package main

import "testing"

func TestDivide(t *testing.T) {
	if got := Divide(10, 2); got != 5 {
		t.Errorf("Divide(10, 2) = %d, want 5", got)
	}
}
