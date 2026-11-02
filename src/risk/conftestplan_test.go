package main

import (
	"reflect"
	"testing"
)

func TestConftestGroupPlan(t *testing.T) {
	group := infraGroup{Parser: "yaml", Namespace: "pipeline", Paths: []string{
		".github/workflows/ci.yml", "deploy/a file.yml", "-weird.yml",
	}}
	args, mounts := conftestGroupPlan(group)
	wantArgs := []string{
		"conftest", "test", "--policy", "/policy",
		"--parser", "yaml", "--namespace", "pipeline",
		"--no-fail", "--output", "json",
		"/inputs/f0000", "/inputs/f0001", "/inputs/f0002",
	}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Errorf("args = %q", args)
	}
	wantMounts := []conftestMount{
		{"/inputs/f0000", ".github/workflows/ci.yml"},
		{"/inputs/f0001", "deploy/a file.yml"},
		{"/inputs/f0002", "-weird.yml"},
	}
	if !reflect.DeepEqual(mounts, wantMounts) {
		t.Errorf("mounts = %#v", mounts)
	}
	// A repository path never reaches the command line: a leading dash or a
	// space would otherwise be conftest's to interpret.
	for _, a := range args {
		if a == "-weird.yml" || a == "deploy/a file.yml" {
			t.Errorf("repository path leaked into args: %q", a)
		}
	}
	m := mountMap(mounts)
	if m["/inputs/f0002"] != "-weird.yml" || len(m) != 3 {
		t.Errorf("mountMap = %#v", m)
	}
}

func TestConftestGroupPlanEmptyGroup(t *testing.T) {
	args, mounts := conftestGroupPlan(infraGroup{Parser: "json", Namespace: "azure"})
	if len(mounts) != 0 {
		t.Errorf("mounts = %#v", mounts)
	}
	if args[len(args)-1] != "json" {
		t.Errorf("an empty group must add no input path: %q", args)
	}
}
