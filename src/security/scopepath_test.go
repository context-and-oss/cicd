package main

import "testing"

func TestCheckScopePath(t *testing.T) {
	for _, ok := range []string{"", "src", "src/api"} {
		if err := checkScopePath(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"/", "/etc", "../x", "src/../../x", ".."} {
		if err := checkScopePath(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
