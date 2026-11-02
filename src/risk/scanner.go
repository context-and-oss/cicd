package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// llmConversation is a single-method interface for stateful multi-turn LLM calls.
type llmConversation interface {
	send(ctx context.Context, userMsg string) (string, error)
}

// directConversation calls an OpenAI-compatible HTTP endpoint.
type directConversation struct {
	baseURL  string
	model    string
	token    string
	messages []map[string]any
}

// llmHTTPTimeout caps individual LLM HTTP requests. LLM responses can be slow
// (large context → long generation) so 10 minutes is generous but not infinite.
var llmHTTPClient = &http.Client{Timeout: 10 * time.Minute}

// llmMaxResponseBytes bounds how much of a proxy response is read into memory.
// A findings document is tens of KB; anything past this is a misbehaving
// endpoint, and the read says so rather than growing without limit.
const llmMaxResponseBytes = 8 << 20

// newDirectConversation talks to baseURL, sending token as a bearer credential
// when it is not empty. The token only ever travels in the Authorization header:
// never in the URL, an error string or the scan manifest.
func newDirectConversation(baseURL, token string) *directConversation {
	return &directConversation{baseURL: baseURL, model: "claude-sonnet-4-6", token: token}
}

// claudeProxyURL is the address of claude-proxy.js on the Docker host.
// Dagger module code runs inside a container; host.docker.internal reaches
// the developer's machine on Docker Desktop (Windows/Mac). On Linux, use
// --llm-url instead.
const claudeProxyURL = "http://host.docker.internal:4000"

// claudeProxyTokenEnv is the variable claude-proxy.js reads its token from, and
// the one the documented scan command hands Dagger as env:<name>.
const claudeProxyTokenEnv = "CICD_RISK_PROXY_TOKEN"

const claudeProxySetup = `Start it in a separate terminal and keep it running:

  Step 1 — export the proxy script (once per machine):
    dagger -m ./src/risk call proxy export --path ./claude-proxy.js

  Step 2 — install the Claude CLI and log in (once per machine):
    npm install -g @anthropic-ai/claude-code

  Step 3 — create a token and start the proxy (leave this terminal open):
    export ` + claudeProxyTokenEnv + `="$(openssl rand -hex 32)"
    node claude-proxy.js

Then re-run from a shell that has the same ` + claudeProxyTokenEnv + `:
  dagger -m ./src/risk call scan --source <dir> --use-claude-cli \
    --llm-token env:` + claudeProxyTokenEnv + ` export --path <out>

The token is handed to Dagger as a secret; never paste its value into a flag.
Note: on Linux, use --llm-url <proxy-url> --llm-token env:` + claudeProxyTokenEnv + `
instead of --use-claude-cli.`

const claudeProxyInstructions = `claude-proxy.js is not reachable at ` + claudeProxyURL + `, or refused the request.

` + claudeProxySetup

// LLM modes recorded in scan-manifest.json.
const (
	llmModeNative    = "native"
	llmModeClaudeCLI = "claude_cli"
	llmModeLLMURL    = "llm_url"
)

// resolveLLMEndpoint decides where a scan's prompt goes from its flags, before
// any file is collected. claude-proxy.js refuses every request without a
// token, so --use-claude-cli without --llm-token is refused here, with the
// setup, rather than after the repository has been read.
func resolveLLMEndpoint(useClaudeCLI bool, llmURL string, hasToken bool) (mode, url string, err error) {
	switch {
	case useClaudeCLI && llmURL != "":
		return "", "", fmt.Errorf("--use-claude-cli and --llm-url are mutually exclusive")
	case useClaudeCLI && !hasToken:
		return "", "", fmt.Errorf("--use-claude-cli needs --llm-token: claude-proxy.js only answers requests that carry its token.\n\n%s", claudeProxySetup)
	case useClaudeCLI:
		return llmModeClaudeCLI, claudeProxyURL, nil
	case llmURL != "":
		return llmModeLLMURL, llmURL, nil
	case hasToken:
		return "", "", fmt.Errorf("--llm-token is only used with --use-claude-cli or --llm-url; the native mode takes its credentials from Dagger's LLM configuration")
	default:
		return llmModeNative, "", nil
	}
}

func (c *directConversation) send(ctx context.Context, msg string) (string, error) {
	c.messages = append(c.messages, map[string]any{"role": "user", "content": msg})
	reply, err := c.post(ctx)
	if err != nil {
		return "", err
	}
	c.messages = append(c.messages, map[string]any{"role": "assistant", "content": reply})
	return reply, nil
}

func (c *directConversation) post(ctx context.Context) (string, error) {
	reqBody, err := json.Marshal(map[string]any{"model": c.model, "messages": c.messages})
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(c.baseURL, "/")+"/v1/chat/completions",
		bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := llmHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("POST %s: %w", c.baseURL, err)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, llmMaxResponseBytes))
	closeErr := resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// A gateway may echo its request headers in an error. Remove the
		// credential before truncating: the cap could otherwise publish a
		// token prefix that no full-value scrub can recognise afterwards.
		detail := string(body)
		if c.token != "" {
			detail = strings.ReplaceAll(detail, c.token, redactedMarker)
		}
		const maxErrBody = 512
		if len(detail) > maxErrBody {
			detail = detail[:maxErrBody] + "…"
		}
		return "", fmt.Errorf("proxy returned %d: %s", resp.StatusCode, detail)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close response: %w", closeErr)
	}
	if len(body) == llmMaxResponseBytes {
		return "", fmt.Errorf("proxy response exceeded %d bytes", llmMaxResponseBytes)
	}
	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("empty response from proxy")
	}
	return result.Choices[0].Message.Content, nil
}

// callLLMWithRetry sends prompt via conv, retrying up to maxRetries times when
// the response is not valid JSON. Returns the last reply regardless of validity.
func callLLMWithRetry(ctx context.Context, conv llmConversation, prompt string, maxRetries int) (string, error) {
	reply, err := conv.send(ctx, prompt)
	if err != nil {
		return "", err
	}
	for range maxRetries {
		if json.Valid([]byte(stripMarkdownFences(reply))) {
			return reply, nil
		}
		const correction = `Your previous response was not valid JSON. ` +
			`Return ONLY a raw JSON object with a "findings" array. ` +
			`No markdown, no code fences, no explanation.`
		reply, err = conv.send(ctx, correction)
		if err != nil {
			return "", err
		}
	}
	return reply, nil
}

type scannedFile struct {
	Path    string
	Content string
}

// rawFinding is the AI response shape before ID assignment and confidence filtering.
type rawFinding struct {
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Confidence  float64  `json:"confidence"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Evidence    Evidence `json:"evidence"`
}

// filterFindings drops findings below minConfidence and assigns stable IDs.
func filterFindings(raw []rawFinding, minConfidence float64) []Finding {
	var out []Finding
	for _, r := range raw {
		if r.Confidence < minConfidence {
			continue
		}
		out = append(out, Finding{
			ID:          hashFinding(r.Category, r.Evidence.File, r.Evidence.StartLine),
			Category:    r.Category,
			Severity:    r.Severity,
			Confidence:  r.Confidence,
			Title:       r.Title,
			Description: r.Description,
			Evidence:    r.Evidence,
		})
	}
	return out
}

var priority1 = []string{
	"README.md", "CODEOWNERS", "Dockerfile", "docker-compose.yml",
	"go.mod", "package.json", "requirements.txt", "pom.xml",
}

var skipDirsScanner = map[string]bool{
	".git": true, "node_modules": true, "vendor": true,
	".terraform": true, "out": true, "risk": true,
}

// collectWorkspaceFiles walks workspace on local disk and returns text files
// under budgetBytes. Used in unit tests; production Scan uses dag.Container()
// for file listing. A directory the walk could not enter is an error, not a
// directory with nothing in it.
func collectWorkspaceFiles(workspace string, budgetBytes int) ([]scannedFile, error) {
	var results []scannedFile
	used := 0
	add := func(relPath string) {
		if used >= budgetBytes {
			return
		}
		data, err := os.ReadFile(filepath.Join(workspace, relPath))
		if err != nil || bytes.ContainsRune(data, 0) || used+len(data) > budgetBytes {
			return
		}
		results = append(results, scannedFile{Path: relPath, Content: string(data)})
		used += len(data)
	}
	for _, name := range priority1 {
		add(name)
	}
	walkErr := filepath.WalkDir(workspace, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if used >= budgetBytes {
			return nil
		}
		if d.IsDir() {
			if skipDirsScanner[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		lower := strings.ToLower(d.Name())
		for _, kw := range []string{"policy", "compliance", "gdpr", "privacy", "security"} {
			if strings.Contains(lower, kw) {
				rel, relErr := filepath.Rel(workspace, path)
				if relErr != nil {
					return relErr
				}
				add(rel)
				return nil
			}
		}
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("walk %s: %w", workspace, walkErr)
	}
	return results, nil
}

// stripMarkdownFences removes optional ```json ... ``` or ``` ... ``` wrapping.
func stripMarkdownFences(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "```") {
		return s
	}
	nl := strings.IndexByte(s, '\n')
	if nl == -1 {
		return s
	}
	s = s[nl+1:]
	if idx := strings.LastIndex(s, "```"); idx != -1 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}

// buildScanPrompt assembles the AI prompt from collected files and the findings schema.
func buildScanPrompt(files []scannedFile, schema string) string {
	var b strings.Builder
	b.WriteString(`You are a compliance and architectural risk reviewer. Analyse the repository files and identify risks that deterministic tools cannot detect — risks that require reading across multiple files, understanding intent, or applying regulatory knowledge.

Output ONLY valid JSON as a root object with a "findings" array. No markdown, no explanation.

## What to find

Focus on four categories that require semantic reasoning:

**compliance** — Regulatory control gaps (GDPR, ISO 27001, SOC 2, PCI DSS):
- Personal data processed without a documented legal basis, consent mechanism, or right-to-erasure path
- Sensitive data (health, financial, location, authentication) logged, stored, or transmitted without masking or encryption
- Third-party services receiving personal data without data processing agreements visible in the repo
- Missing audit trails for privileged operations or data access
- No data-retention or data-deletion policy for user data stores

**data_governance** — How personal and sensitive data flows across the system:
- PII fields (email, name, IP address, user ID, health data) appearing in log statements, error messages, or metrics exports
- Database schema or API payloads containing personal data without field-level classification
- Personal data in configuration files, environment variable defaults, or documentation examples
- Event/message payloads transmitting personal data without documented data-processing agreements

**trust_boundary** — Implicit trust and missing authorisation checks:
- Service-to-service calls that treat "internal network" as authorisation (no token, mTLS, or HMAC verification between services)
- User-controlled input passed to internal APIs or message queues without a validation or sanitisation boundary
- Admin or privileged operations reachable without a secondary verification step
- Multi-tenant code paths where tenant isolation relies on client-supplied values rather than server-side enforcement

**lifecycle_risk** — Dependencies and operational readiness:
- Runtimes, frameworks, or base libraries nearing or past end-of-life (e.g. Go versions, Node.js LTS, Python EOL schedule)
- Critical security dependencies that are many major versions behind the current release (creating hidden security debt, not just CVEs)
- Deprecated or broken cryptographic primitives in use (MD5, SHA-1 for security purposes, ECB mode, RC4)
- Missing operational documentation: no incident runbook, no SLA definition, no rollback procedure for data migrations

## What NOT to find — already covered by deterministic OPA policies

Do not report findings in these areas. They are already detected and gated by existing policy rules:

- GitHub Actions: action SHA pinning, missing permissions block, pull_request_target trigger
- Dockerfile: missing USER instruction, unpinned or :latest base images
- Azure ARM/Bicep: TLS version settings, public network access, Key Vault ACLs, soft delete,
  storage public access, SQL network exposure, ACR admin user, App Service HTTPS enforcement
- Azure identity/RBAC: role assignments, privileged role definitions
- Azure database: connection security, audit logging settings
- Azure tags: required tag enforcement
- Azure AKS: cluster configuration settings

## Rules

- Include only findings with concrete evidence: a specific file path, line numbers, and a code or config snippet
- Assign confidence 0.0–1.0; omit any finding below 0.6
- Reason across multiple files when the risk spans them (cite all relevant files in the description)
- Do not guess. A missing finding is better than a false positive.
- Severity: critical = active exposure of personal data or broken auth; high = likely violation without mitigating controls; medium = missing control that regulatory frameworks require; low = gap in documentation or process evidence

`)
	b.WriteString("Schema for each finding:\n")
	b.WriteString(schema)
	b.WriteString("\n\nRepository files:\n")
	for _, f := range files {
		b.WriteString("<file: ")
		b.WriteString(f.Path)
		b.WriteString(">\n")
		b.WriteString(f.Content)
		b.WriteString("\n</file>\n")
	}
	b.WriteString("\nRespond with ONLY valid JSON. No markdown fences.\n")
	return b.String()
}
