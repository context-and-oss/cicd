//go:build unit_test

package main

import (
	"os"
	"strings"
	"testing"
)

// The NuGet packages volume must be mounted PRIVATE: NuGet's cross-process
// lock is container-local, and two containers restoring into one shared volume
// were measured corrupting each other's extraction (see dotnetexec.go). The mount is
// Dagger wiring the unit suite cannot execute, so the guard reads the source.
func TestNuGetCacheIsNeverShared(t *testing.T) {
	raw, err := os.ReadFile("dotnetexec.go")
	if err != nil {
		t.Fatalf("cannot read dotnetexec.go, so the guard did not run: %v", err)
	}
	mounts := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.Contains(line, "WithMountedCache(") || !strings.Contains(line, `nugetPackagesPath, dag.CacheVolume`) {
			continue
		}
		mounts++
		if !strings.Contains(line, "Sharing: dagger.CacheSharingModePrivate") {
			t.Errorf("NuGet cache mounted without CacheSharingModePrivate:\n%s", strings.TrimSpace(line))
		}
	}
	if mounts == 0 {
		t.Fatal("no NuGet cache mount found in dotnetexec.go; the guard matched nothing")
	}
}
