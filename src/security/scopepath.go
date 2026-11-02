package main

import (
	"fmt"
	"strings"
)

// checkScopePath refuses a --path that could leave the mounted source tree.
//
// The path is handed to Directory(path) on the uploaded tree, which Dagger
// resolves inside the mount; the refusal exists so a consumer who typed an
// absolute path or a ".." gets told, rather than scanning a directory that is
// not the one they named. Empty means "the whole tree" and is accepted.
func checkScopePath(path string) error {
	if path == "" {
		return nil
	}
	if strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
		return fmt.Errorf("invalid path %q: must be a relative subdirectory with no '..' components", path)
	}
	return nil
}
