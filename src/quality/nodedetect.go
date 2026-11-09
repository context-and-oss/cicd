//go:build !unit_test

package main

import (
	"context"
	"dagger/quality/internal/dagger"
	"path"
	"slices"
)

// detectNodeProject reads what detectNodePackageManager decides on from one
// Node project directory of src: its listing, package.json and yarn.lock. A
// file listed and then unreadable is an error, never an absent file — a
// package.json cicd could not read must not decide "npm, no packageManager".
//
// It reads the project directory only and never walks up: nodeProjectDirs
// picks the topmost package.json of a tree, which is the one beside the
// workspace lockfile, so the legs install where the lockfile is.
func detectNodeProject(ctx context.Context, src *dagger.Directory, dir string) (nodePM, []string, error) {
	d := src
	if dir != "." {
		d = src.Directory(dir)
	}
	entries, err := d.Entries(ctx)
	if err != nil {
		return nodePM{}, nil, &readError{path.Join(dir, "."), err}
	}
	read := func(name string) (string, error) {
		if !slices.Contains(entries, name) {
			return "", nil
		}
		s, err := d.File(name).Contents(ctx)
		if err != nil {
			return "", &readError{path.Join(dir, name), err}
		}
		return s, nil
	}
	pkg, err := read("package.json")
	if err != nil {
		return nodePM{}, nil, err
	}
	yarnLock, err := read("yarn.lock")
	if err != nil {
		return nodePM{}, nil, err
	}
	return detectNodePackageManager(pkg, entries, yarnLock)
}

// projectNpmrc is the .npmrc beside a Node project's package.json, "" when
// there is none. ok is false when it could not be read. It only feeds a
// warning (nodeFeedRoutingWarning), so an unreadable file must not fail the
// leg, and must not be reported as a file that routes nothing either.
func projectNpmrc(ctx context.Context, src *dagger.Directory, dir string) (npmrc string, ok bool) {
	d := src
	if dir != "." {
		d = src.Directory(dir)
	}
	entries, err := d.Entries(ctx)
	if err != nil {
		return "", false
	}
	if !slices.Contains(entries, ".npmrc") {
		return "", true
	}
	s, err := d.File(".npmrc").Contents(ctx)
	if err != nil {
		return "", false
	}
	return s, true
}

// nodeFeedWarnings is every feed warning a Node leg that installs its own
// dependencies states for one project.
func nodeFeedWarnings(ctx context.Context, src *dagger.Directory, dir string, pm nodePM, feedURL, routing string, token *dagger.Secret) []string {
	if feedURL == "" || token == nil {
		return nil
	}
	var out []string
	if w := nodeFeedWarning(pm, true); w != "" {
		out = append(out, w)
	}
	if npmrc, ok := projectNpmrc(ctx, src, dir); ok {
		if w := nodeFeedRoutingWarning(pm, routing, feedURL, npmrc); w != "" {
			out = append(out, w)
		}
		if w := nodeFeedShadowWarning(pm, feedURL, npmrc); w != "" {
			out = append(out, w)
		}
	}
	return out
}

type readError struct {
	path string
	err  error
}

func (e *readError) Error() string { return "could not read " + e.path + ": " + e.err.Error() }

// withNodeFeed points every Node package manager cicd can configure at the
// private feed, the token bound as a secret and credentialed to the feed's host
// only (nodeFeedConfig). It is the one place the Node legs, Prepare and the
// consumer command legs set it, so pnpm cannot again be missed at one of them.
func withNodeFeed(ctr *dagger.Container, feedURL, routing string, token *dagger.Secret) *dagger.Container {
	if feedURL == "" || token == nil {
		return ctr
	}
	f := nodeFeedConfig(feedURL, routing)
	ctr = ctr.WithNewFile(f.npmrcPath, f.npmrc)
	for _, kv := range f.env {
		ctr = ctr.WithEnvVariable(kv[0], kv[1])
	}
	return ctr.WithSecretVariable(f.secretVar, token)
}
