package main

import (
	"fmt"
	"strings"
)

// gitleaksConfigOrigin says whether the scanned root carries a .gitleaks.toml
// and, when cicd put it there, which file in the source tree it was copied
// from. Every disclosure that blames the config (SUPPRESSED, NARROWED RULES)
// names that file, so a reader of the envelope can open the acceptance.
type gitleaksConfigOrigin struct {
	// present: the root of the tree gitleaks scanned carries the config file.
	present bool
	// supplied: the source-tree path the config was copied from, or "" when the
	// tree carried its own.
	supplied string
}

// phrase names the config for a warning: fallback (the tree's own file) when
// nothing was supplied, otherwise the supplied file and where it came from.
func (o gitleaksConfigOrigin) phrase(fallback string) string {
	if o.supplied == "" {
		return fallback
	}
	return "the gitleaks config supplied from " + o.supplied + " in the source tree"
}

// checkGitleaksConfigPath refuses a --gitleaks-config that could name a file
// outside the source tree, or that is not a file at all. Empty means "not
// given" and is accepted; the shape rule is checkScopePath's, plus a trailing
// separator, which names a directory.
func checkGitleaksConfigPath(path string) error {
	if path == "" {
		return nil
	}
	if strings.HasPrefix(path, "/") || strings.Contains(path, "..") || strings.HasSuffix(path, "/") {
		return fmt.Errorf("gitleaks-config %q: must be a file path relative to the source root with no '..' components", path)
	}
	return nil
}

// gitleaksConfigConflict refuses two configs for one scan: a supplied file
// and a .gitleaks.toml the build wrote into its own output root. Injecting
// over it would silently replace the one the output carries, and honouring
// the output's would silently drop the one the consumer named. entries is the
// output root's listing.
func gitleaksConfigConflict(entries []string, supplied string) error {
	if supplied == "" {
		return nil
	}
	if hasConfig, _ := gitleaksSuppressionFiles(entries); !hasConfig {
		return nil
	}
	return fmt.Errorf("gitleaks-config: the build output already carries a %s at its root; one config per scan — remove it from the build output or drop --gitleaks-config", gitleaksConfigFile)
}

// gitleaksConfigPresent says whether a Directory.Glob of the source tree for
// path returned that file. Existence is asked of a listing, never of
// File().Contents(): a missing file fails that read inside the engine, and
// the dagger CLI then prints the failed span (`Directory.stat(...)`: `stat
// /x.toml: no such file`) and drops the error the function returned, wrapped
// or quoted — measured on dagger v0.20, the consumer never saw cicd's
// wording. Glob answers "no match" with an empty list and no failed span. A
// directory of that name is listed with a trailing separator and is not the
// config; a path holding glob metacharacters matches only itself.
func gitleaksConfigPresent(matches []string, path string) bool {
	for _, m := range matches {
		if m == path {
			return true
		}
	}
	return false
}

// gitleaksConfigMissing is the error for a --gitleaks-config the source tree
// does not hold, in cicd's words: the scan must not run without the config
// the consumer named.
func gitleaksConfigMissing(path string) error {
	return fmt.Errorf("gitleaks-config %q: not found in the source tree, or not a file", path)
}
