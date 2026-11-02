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
			args := []string{"--headless", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
				"--disable-background-networking", "--disable-component-update", "--disable-sync",
				"--host-resolver-rules=MAP * ~NOTFOUND", "--user-data-dir=" + filepath.Join(dir, "profile"),
				"--dump-dom", "--virtual-time-budget=1000"}
			if runtime.GOOS == "linux" {
				args = append(args, "--no-sandbox") // Disposable CI browser; no external requests.
			}
			args = append(args, (&url.URL{Scheme: "file", Path: path}).String())
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, browser, args...)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			output, err := cmd.Output()
			if err != nil {
				t.Fatalf("browser failed: %v\n%s", err, stderr.String())
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
