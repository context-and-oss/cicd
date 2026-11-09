//go:build unit_test

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestNodeFeedTokenReachesNpmThroughDash runs a consumer command the way every
// consumer leg does — byoTestArgv's `sh -c` wrapping an inner `sh -c "$1"` —
// with `sh` resolved to dash, against a local registry that records the
// Authorization header of every request. The environment is exactly what
// nodeFeedConfig tells withNodeFeed to apply, plus the token under its secret
// variable, so the bytes under test are the ones the containers get.
//
// The control row binds the token the way cicd used to, as
// `NPM_CONFIG_//<dart>:_authToken`, and must arrive with no Authorization
// header. If it does arrive, `sh` was not a shell that drops such names and
// the passing rows prove nothing, so the test fails instead of passing.
func TestNodeFeedTokenReachesNpmThroughDash(t *testing.T) {
	dash, errDash := exec.LookPath("dash")
	npm, errNpm := exec.LookPath("npm")
	if errDash != nil || errNpm != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("the shell regression needs dash and npm on the CI runner (dash: %v, npm: %v)", errDash, errNpm)
		}
		t.Skipf("dash or npm is not installed (dash: %v, npm: %v)", errDash, errNpm)
	}

	const token = "fixture-token-not-a-secret" // gitleaks:allow — invented, never valid anywhere
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		mu.Lock()
		switch auth {
		case "":
			seen = append(seen, "none")
		case "Bearer " + token:
			seen = append(seen, "bearer")
		default:
			seen = append(seen, "other")
		}
		mu.Unlock()
		http.NotFound(w, r)
	}))
	defer srv.Close()
	feed := srv.URL + "/feed/npm/"

	// A bin directory whose `sh` is dash, so the wrapper's inner `sh -c` and
	// the outer one are both dash, the way they are on a Debian-based image.
	bin := t.TempDir()
	if err := os.Symlink(dash, filepath.Join(bin, "sh")); err != nil {
		t.Fatal(err)
	}
	basePath := bin + string(os.PathListSeparator) + filepath.Dir(npm) + string(os.PathListSeparator) + os.Getenv("PATH")

	run := func(t *testing.T, routing, cmd string, legacy bool) []string {
		t.Helper()
		home, project, out := t.TempDir(), t.TempDir(), t.TempDir()
		env := []string{
			"PATH=" + basePath,
			"HOME=" + home,
			"NPM_CONFIG_CACHE=" + filepath.Join(home, "cache"),
			"NPM_CONFIG_UPDATE_NOTIFIER=false",
			"NPM_CONFIG_FETCH_RETRIES=0",
		}
		if routing == npmRoutingNpmrc {
			if err := os.WriteFile(filepath.Join(project, ".npmrc"), []byte("@example-org:registry="+feed+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		f := nodeFeedConfig(feed, routing)
		if legacy {
			env = append(env, "NPM_CONFIG_"+npmNerfDart(feed)+":_authToken="+token)
			for _, kv := range f.env {
				if strings.HasSuffix(kv[0], "_REGISTRY") {
					env = append(env, kv[0]+"="+kv[1])
				}
			}
		} else {
			// The container path is /etc/cicd/npmrc; the content and the
			// variables pointing at it are nodeFeedConfig's own.
			userconfig := filepath.Join(home, "cicd-npmrc")
			if err := os.WriteFile(userconfig, []byte(f.npmrc), 0o644); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(f.npmrc, token) {
				t.Fatalf("the npmrc carries the token itself: %q", f.npmrc)
			}
			for _, kv := range f.env {
				v := kv[1]
				if v == f.npmrcPath {
					v = userconfig
				}
				env = append(env, kv[0]+"="+v)
			}
			env = append(env, f.secretVar+"="+token)
		}

		mu.Lock()
		seen = nil
		mu.Unlock()
		argv := byoTestArgv(cmd, filepath.Join(out, "out"), filepath.Join(out, "exit"))
		c := exec.Command(dash, argv[1:]...)
		c.Dir, c.Env = project, env
		if b, err := c.CombinedOutput(); err != nil {
			t.Fatalf("wrapper failed: %v\n%s", err, b)
		}
		log, _ := os.ReadFile(filepath.Join(out, "out"))
		mu.Lock()
		defer mu.Unlock()
		if len(seen) == 0 {
			t.Fatalf("the registry saw no request; npm output:\n%s", log)
		}
		return append([]string(nil), seen...)
	}

	cases := []struct {
		name, routing, cmd string
	}{
		{"registry routing", npmRoutingRegistry, "npm view example-pkg"},
		{"npmrc routing", npmRoutingNpmrc, "npm view @example-org/example-pkg"},
		{"bash started by dash", npmRoutingNpmrc, `if command -v bash >/dev/null; then bash -c 'npm view @example-org/example-pkg'; else npm view @example-org/example-pkg; fi`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(t, tc.routing, tc.cmd, true); strings.Join(got, ",") != strings.Repeat("none,", len(got)-1)+"none" {
				t.Fatalf("control: the old variable name reached npm through sh (%v), so sh is not dropping it and this test proves nothing", got)
			}
			got := run(t, tc.routing, tc.cmd, false)
			for _, a := range got {
				if a != "bearer" {
					t.Fatalf("Authorization per request = %v, want Bearer with the feed token on every one", got)
				}
			}
		})
	}
}
