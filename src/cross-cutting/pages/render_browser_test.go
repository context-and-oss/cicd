package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDashboardTreatsEvidenceAsTextInBrowser(t *testing.T) {
	var browser string
	for _, candidate := range []string{"google-chrome", "chromium", "chromium-browser", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"} {
		if path, err := exec.LookPath(candidate); err == nil {
			browser = path
			break
		}
	}
	if browser == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("browser regression requires Chrome/Chromium on the CI runner")
		}
		t.Skip("Chrome/Chromium is not installed")
	}
	warmUpBrowser(t, browser)
	// No network callback: a successful injection only marks the document.
	payload := `<svg onload="document.documentElement.dataset.injected='yes'"></svg>`
	for _, hostile := range []bool{false, true} {
		name := "clean"
		if hostile {
			name = "hostile"
		}
		t.Run(name, func(t *testing.T) {
			doc := map[string]any{
				"passed": true, "findingsCount": 2, "durationMs": 1200,
				"repo":      map[string]any{"repoUrl": "https://example.com/example/repo", "branch": "main", "commitSha": "local"},
				"languages": []string{"go"}, "coverageByLanguage": map[string]any{"go": 80},
				"warnings": []string{"a warning"}, "errors": []string{}, "moduleName": "pipeline",
			}
			if hostile {
				doc["repo"] = map[string]any{"repoUrl": payload, "branch": payload, "commitSha": payload}
				doc["languages"], doc["warnings"], doc["errors"] = []string{payload}, []string{payload}, []string{payload}
				doc["moduleName"], doc["findingsCount"], doc["durationMs"] = payload, payload, payload
				doc["coverageByLanguage"] = map[string]any{payload: payload}
			}
			data, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			page, err := renderPage(htmlTemplate, string(data))
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "index.html")
			if err := os.WriteFile(path, []byte(page), 0o600); err != nil {
				t.Fatal(err)
			}
			output, stderr, err := dumpDOM(browser, dir, path, pageBudget)
			if err != nil {
				t.Fatalf("browser failed within %s on a warm browser: %v\n%s", pageBudget, err, stderr)
			}
			dom := string(output)
			if strings.Contains(dom, `data-injected="yes"`) {
				t.Fatal("evidence executed JavaScript in the dashboard")
			}
			if !strings.Contains(dom, `<div class="container">`) || !strings.Contains(dom, "Pipeline passed") {
				t.Fatal("dashboard did not render; an empty page is not an XSS fix")
			}
			if hostile && (!strings.Contains(dom, "&lt;svg") || !strings.Contains(dom, "Not stated")) {
				t.Fatal("hostile text was lost, or malformed numeric input was not named")
			}
		})
	}
}

// The per-page budget and the warm-up budget are separate because they guard
// different things. A rendered page takes well under a second once Chrome is in
// the page cache, so pageBudget is a hang guard for the dashboard itself. The
// first launch on a fresh hosted runner instead pays for reading Chrome and its
// libraries off a disk that is filled lazily on first access. With the page
// cache dropped and disk reads throttled, the first page launch was killed at
// 30s and the second took 16s, then both took about 0.3s: the same shape as
// the CI failure this split closes. warmUpBudget absorbs that cold read once,
// so a slow disk can no longer read as a broken dashboard.
const (
	pageBudget   = 30 * time.Second
	warmUpBudget = 3 * time.Minute
)

// warmUpBrowser renders a local page with text and a script, so the browser,
// its renderer, the script engine and the fonts are all read from disk before
// the timed launches. It fails rather than skips: a browser that cannot render
// an empty page within warmUpBudget cannot run the regression either, and in
// CI a regression that did not run must not read as one that passed.
func warmUpBrowser(t *testing.T, browser string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "warm-up.html")
	page := `<!doctype html><title>warm-up</title><p id="p">text</p>` +
		`<script>document.getElementById("p").textContent = "warm";</script>`
	if err := os.WriteFile(path, []byte(page), 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	output, stderr, err := dumpDOM(browser, dir, path, warmUpBudget)
	if err != nil {
		t.Fatalf("browser could not render a local page within %s: %v\n%s", warmUpBudget, err, stderr)
	}
	if !strings.Contains(string(output), ">warm<") {
		t.Fatalf("warm-up page did not run its script; DOM:\n%s", output)
	}
	t.Logf("browser warm-up took %s", time.Since(start).Round(time.Millisecond))
}

// dumpDOM loads a local file in a headless browser with a fresh profile under
// dir and returns the serialised DOM. WaitDelay bounds the wait for the
// output pipes after a timeout kill, because a renderer child that outlives
// the browser process would otherwise hold stdout open past the budget.
func dumpDOM(browser, dir, path string, budget time.Duration) ([]byte, string, error) {
	args := []string{"--headless", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
		"--disable-background-networking", "--disable-component-update", "--disable-sync",
		"--host-resolver-rules=MAP * ~NOTFOUND", "--user-data-dir=" + filepath.Join(dir, "profile"),
		"--dump-dom", "--virtual-time-budget=1000"}
	if runtime.GOOS == "linux" {
		args = append(args, "--no-sandbox") // Disposable CI browser; no external requests.
	}
	args = append(args, (&url.URL{Scheme: "file", Path: path}).String())
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	cmd := exec.CommandContext(ctx, browser, args...)
	cmd.WaitDelay = 5 * time.Second
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	return output, stderr.String(), err
}
