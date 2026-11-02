package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// The production scan client (directConversation, callLLMWithRetry) against
// the real claude-proxy.js on loopback, with testdata/fake-claude standing in
// for the CLI. No model and no subscription are involved.

// Synthetic, test-only value; it authorises nothing anywhere.
const fakeProxyToken = "fake-proxy-token-" + "fedcba9876543210fedcba9876543210"

// syncBuf collects a child's output from more than one goroutine.
type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func startClaudeProxy(t *testing.T) (baseURL string, logs func() string) {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("node is required to test claude-proxy.js (the proxy is Node): %v", err)
	}
	fake, err := filepath.Abs(filepath.Join("testdata", "fake-claude"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, node, "claude-proxy.js", "--port", "0")
	cmd.Env = append(os.Environ(),
		"PATH="+fake+string(os.PathListSeparator)+os.Getenv("PATH"),
		"TMPDIR="+t.TempDir(),
		claudeProxyTokenEnv+"="+fakeProxyToken,
	)
	var stderr, out syncBuf
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})
	ready := make(chan string, 1)
	go func() {
		re := regexp.MustCompile(`listening on (http://127\.0\.0\.1:\d+)`)
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			_, _ = out.Write([]byte(sc.Text() + "\n"))
			if m := re.FindStringSubmatch(sc.Text()); m != nil {
				ready <- m[1]
			}
		}
	}()
	select {
	case u := <-ready:
		return u, func() string { return out.String() + stderr.String() }
	case <-time.After(15 * time.Second):
		t.Fatalf("claude-proxy.js did not start: %s", stderr.String())
	}
	return "", nil
}

func TestScanClientThroughAuthenticatedProxy(t *testing.T) {
	url, logs := startClaudeProxy(t)
	ctx := context.Background()

	mode, endpoint, err := resolveLLMEndpoint(false, url, true)
	if err != nil || mode != llmModeLLMURL || endpoint != url {
		t.Fatalf("resolveLLMEndpoint = %q %q %v", mode, endpoint, err)
	}
	conv := newDirectConversation(endpoint, fakeProxyToken)
	reply, err := callLLMWithRetry(ctx, conv, buildScanPrompt([]scannedFile{{Path: "main.go", Content: "package main"}}, "{}"), 1)
	if err != nil {
		t.Fatalf("authenticated scan call failed: %v", err)
	}
	var parsed struct {
		Findings []rawFinding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stripMarkdownFences(reply)), &parsed); err != nil || parsed.Findings == nil {
		t.Fatalf("reply %q is not a findings document: %v", reply, err)
	}

	for _, tok := range []string{"", "wrong-" + fakeProxyToken} {
		_, err := callLLMWithRetry(ctx, newDirectConversation(endpoint, tok), "hello", 0)
		if err == nil || !strings.Contains(err.Error(), "401") {
			t.Fatalf("token %q: want a 401 refusal, got %v", tok, err)
		}
		if strings.Contains(err.Error(), fakeProxyToken) {
			t.Errorf("the error string carries the token: %v", err)
		}
	}
	if strings.Contains(logs(), fakeProxyToken) {
		t.Error("the proxy's output carries the token")
	}
}

func TestScanClientWithholdsCredentialsEchoedByGateway(t *testing.T) {
	for _, prefix := range []string{"", strings.Repeat("x", 480)} {
		t.Run(fmt.Sprintf("prefix-%d", len(prefix)), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadGateway)
				_, _ = fmt.Fprint(w, prefix+r.Header.Get("Authorization"))
			}))
			defer server.Close()
			_, err := newDirectConversation(server.URL, fakeProxyToken).send(context.Background(), "safe source")
			if err == nil || !strings.Contains(err.Error(), "502") {
				t.Fatalf("expected the gateway failure, got %v", err)
			}
			wire, marshalErr := json.Marshal(map[string]string{"error": err.Error()})
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			// Check the distinctive prefix too: truncating before redaction
			// would publish the start of a token crossing the error-body cap.
			if strings.Contains(string(wire), fakeProxyToken[:12]) {
				t.Fatal("gateway feedback exposed a credential or its truncated prefix")
			}
		})
	}
}

func TestResolveLLMEndpoint(t *testing.T) {
	cases := []struct {
		cli      bool
		url      string
		token    bool
		mode     string
		endpoint string
		errHas   string
	}{
		{cli: true, token: true, mode: llmModeClaudeCLI, endpoint: claudeProxyURL},
		{cli: true, errHas: "--llm-token"},
		{cli: true, url: "http://gw:4000", token: true, errHas: "mutually exclusive"},
		{url: "http://gw:4000", mode: llmModeLLMURL, endpoint: "http://gw:4000"},
		{url: "http://gw:4000", token: true, mode: llmModeLLMURL, endpoint: "http://gw:4000"},
		{mode: llmModeNative},
		{token: true, errHas: "--llm-token is only used"},
	}
	for _, c := range cases {
		mode, endpoint, err := resolveLLMEndpoint(c.cli, c.url, c.token)
		if c.errHas != "" {
			if err == nil || !strings.Contains(err.Error(), c.errHas) {
				t.Errorf("%+v: err = %v, want %q", c, err, c.errHas)
			}
			continue
		}
		if err != nil || mode != c.mode || endpoint != c.endpoint {
			t.Errorf("%+v: got %q %q %v", c, mode, endpoint, err)
		}
	}
}

// The manifest is the one scan output that records how the model was reached;
// it names the mode and never a credential.
func TestScanManifestCarriesNoToken(t *testing.T) {
	m := buildScanManifest(collectedSource{ignoreRules: ignoreRulesGit, files: []scannedFile{{Path: "a.go", Content: "x"}}}, llmModeClaudeCLI, "t")
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	conv := newDirectConversation(claudeProxyURL, fakeProxyToken)
	if strings.Contains(string(data), fakeProxyToken) || strings.Contains(conv.baseURL, fakeProxyToken) {
		t.Error("token reached the manifest or the URL")
	}
	if !strings.Contains(string(data), `"ignore_rules":"git"`) || !strings.Contains(string(data), `"llm_mode":"claude_cli"`) {
		t.Errorf("manifest = %s", data)
	}
}
