package main

import (
	"reflect"
	"sort"
	"testing"
)

func TestChangeScopePaths(t *testing.T) {
	tests := []struct {
		name string
		diff string
		want []string
	}{
		{
			name: "added and modified files",
			diff: "diff --git a/specs/x.md b/specs/x.md\n" +
				"--- a/specs/x.md\n+++ b/specs/x.md\n" +
				"diff --git a/src/main.go b/src/main.go\n" +
				"--- a/src/main.go\n+++ b/src/main.go\n",
			want: []string{"specs/x.md", "src/main.go"},
		},
		{
			name: "deleted file excluded (b side is /dev/null)",
			diff: "diff --git a/.capsules/old.yaml b/.capsules/old.yaml\n" +
				"--- a/.capsules/old.yaml\n+++ /dev/null\n",
			want: nil,
		},
		{
			name: "newly added file (a side is /dev/null) is included",
			diff: "diff --git a/specs/new.md b/specs/new.md\n" +
				"--- /dev/null\n+++ b/specs/new.md\n",
			want: []string{"specs/new.md"},
		},
		{
			name: "pure rename captures target",
			diff: "diff --git a/specs/old.md b/specs/new.md\n" +
				"similarity index 100%\nrename from specs/old.md\nrename to specs/new.md\n",
			want: []string{"specs/new.md"},
		},
		{
			name: "empty diff",
			diff: "",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := changeScope(tt.diff)
			if err != nil {
				t.Fatalf("changeScope: %v", err)
			}
			var keys []string
			for k := range got {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			sort.Strings(tt.want)
			if len(keys) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(keys, tt.want) {
				t.Errorf("changeScope() = %v, want %v", keys, tt.want)
			}
		})
	}
}

func TestFilterToChanged(t *testing.T) {
	artifacts := []string{
		".capsules/CAPS-001.yaml",
		"specs/feature/purpose.md",
		"docs/specs/other.md",
	}
	changed := map[string]bool{
		"specs/feature/purpose.md": true,
		"src/main.go":              true, // not an artifact — must not leak in
	}
	got := filterToChanged(artifacts, changed)
	want := []string{"specs/feature/purpose.md"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("filterToChanged() = %v, want %v", got, want)
	}

	// No overlap → empty, which drives the scoped-presence failure.
	none := filterToChanged(artifacts, map[string]bool{"README.md": true})
	if len(none) != 0 {
		t.Errorf("filterToChanged() with no overlap = %v, want empty", none)
	}
}
