//go:build !unit_test

// The container half of the zizmor leg: two runs over a copy of the tree and
// reading back what they left. Every decision is in zizmor.go, untagged, where
// the unit suite reaches it.
package main

import (
	"context"
	"dagger/security/internal/dagger"
	"fmt"
)

// runZizmor audits every workflow, composite action and Dependabot file in
// the tree. A tree with none returns a result with Present false: no row.
func runZizmor(ctx context.Context, src *dagger.Directory) zizmorResult {
	ctr := dag.Container().
		From(zizmorImage).
		WithDirectory(zizmorMount, src).
		WithWorkdir(zizmorMount).
		WithoutEntrypoint().
		WithExec([]string{"sh", "-c", zizmorScript()})

	// The script always exits 0 and writes every stream down, so an
	// unreadable file means the exec itself did not complete.
	read := func(name string) (string, error) {
		s, err := ctr.File(zizmorOutDir + "/" + name).Contents(ctx)
		if err != nil {
			return "", fmt.Errorf("%s: SAST did not run — the zizmor container did not complete (%s "+
				"unreadable): %w", zizmorToolName, name, err)
		}
		return s, nil
	}
	var primary, shadow zizmorRun
	for _, f := range []struct {
		name string
		dst  *string
	}{
		{"primary.sarif", &primary.SARIF}, {"primary.err", &primary.Stderr}, {"primary.exit", &primary.Exit},
		{"shadow.sarif", &shadow.SARIF}, {"shadow.err", &shadow.Stderr}, {"shadow.exit", &shadow.Exit},
	} {
		s, err := read(f.name)
		if err != nil {
			return zizmorResult{Present: true, Err: err}
		}
		*f.dst = s
	}
	return analyseZizmor(primary, shadow)
}
