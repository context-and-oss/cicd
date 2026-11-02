// How one infra group is handed to conftest: the command line, and the mount
// each input file gets.
//
// Untagged (no //go:build !unit_test): the mount scheme is what lets a
// violation's filename be resolved back to a repository path, so a change to
// it that nothing tests is a change that silently detaches every infra
// finding from the file it names.
package main

import "fmt"

// conftestMount pairs the path a file is mounted at inside the container with
// the repository-relative path it came from.
type conftestMount struct {
	Mount string
	Rel   string
}

// conftestGroupPlan returns the conftest arguments for one group and the
// mounts the caller must perform, in the order the arguments name them. Files
// are mounted under fixed names (/inputs/f0000, ...) rather than their own
// paths so a repository path with a space, a colon or a leading dash cannot
// be read by conftest as a flag or a parser hint.
func conftestGroupPlan(group infraGroup) ([]string, []conftestMount) {
	args := []string{
		"conftest", "test", "--policy", "/policy",
		"--parser", group.Parser, "--namespace", group.Namespace,
		"--no-fail", "--output", "json",
	}
	mounts := make([]conftestMount, 0, len(group.Paths))
	for i, rel := range group.Paths {
		mountPath := fmt.Sprintf("/inputs/f%04d", i)
		mounts = append(mounts, conftestMount{Mount: mountPath, Rel: rel})
		args = append(args, mountPath)
	}
	return args, mounts
}

// mountMap is the reverse index resolveConftestFilename reads.
func mountMap(mounts []conftestMount) map[string]string {
	m := make(map[string]string, len(mounts))
	for _, mt := range mounts {
		m[mt.Mount] = mt.Rel
	}
	return m
}
