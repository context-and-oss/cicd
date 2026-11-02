// Outbound HTTP delivery seam for every notify channel.
//
// This file carries no build tag on purpose. The Dagger entry functions live in
// teams.go / github.go / ado.go behind `//go:build !unit_test`, so `go test
// -tags unit_test` compiles this file and delivery_test.go without needing a
// generated Dagger SDK — while production still executes exactly these
// functions. There is no mock transport: delivery_test.go drives the code below
// against a local httptest server, which is the same request-building and
// response-handling path Teams/GitHub/ADO take in a real pipeline.
//
// Endpoints are compile-time constants, not Dagger inputs. `githubAPI`/`adoAPI`
// are package-internal struct fields so a test can point them at 127.0.0.1;
// nothing a consumer can pass on the command line redirects a notification.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// githubAPIBase and adoAPIBase are the production endpoints. Consumers
	// cannot override them (see the file comment).
	githubAPIBase = "https://api.github.com"
	adoAPIBase    = "https://dev.azure.com"

	adoAPIVer = "7.1"

	// deliveryTimeout bounds every outbound notification request. Without it
	// http.DefaultClient waits forever, so a hung Teams webhook or a black-holed
	// ADO endpoint would stall the whole pipeline behind a notification that is
	// explicitly non-fatal.
	deliveryTimeout = 30 * time.Second

	// maxResponseBytes bounds how much of a response is read into memory. A
	// GitHub comment page is a few hundred KB; anything past this is a
	// misbehaving or hostile endpoint, not a payload we owe processing to.
	maxResponseBytes = 8 << 20

	// errorBodySnippetLen caps how much of a failed response body is quoted in
	// the returned error so one verbose 500 page cannot flood the pipeline log.
	errorBodySnippetLen = 512

	// maxCommentPages bounds the GitHub comment-listing walk. The marker search
	// is a `for page := 1; ; page++` loop over an endpoint we do not control; an
	// endpoint that keeps returning full pages would otherwise spin forever
	// inside a notification step. 20 pages is 2000 comments — far past any real
	// PR, and a miss here only means the comment is appended instead of updated.
	maxCommentPages = 20
)

// noRetryPolicy documents the deliberate delivery policy: exactly one HTTP
// attempt per notification request, no retry, no backoff.
//
// Notifications are non-fatal by contract (src/notify/CLAUDE.md — composites
// ignore the error), so a retry loop would trade pipeline wall-clock for an
// outcome nobody blocks on, and a bounded-but-repeated POST to a webhook that
// already accepted the body risks duplicate cards. A failed delivery is
// reported and dropped. delivery_test.go asserts the request count is exactly
// one for 2xx, 5xx and malformed responses alike.
const noRetryPolicy = "one attempt per request; no retry"

// delivery is the single outbound HTTP seam shared by Teams, GitHub and ADO.
//
// Production callers use newDelivery(); tests construct it against a local
// server. Every returned error is passed through scrubSecrets with the values
// in `secrets`, so a credential can never reach a pipeline log or the evidence
// envelope's Errors[] — not even when the remote endpoint echoes it back.
type delivery struct {
	client    *http.Client
	githubAPI string
	adoAPI    string

	// secrets holds the plaintext credential values used by this delivery.
	// Scrubbed out of every error this type produces.
	secrets []string
}

// newDelivery returns the production delivery seam. Pass every plaintext
// secret the delivery will use so it can be scrubbed from error output.
func newDelivery(secrets ...string) *delivery {
	return &delivery{
		client:    &http.Client{Timeout: deliveryTimeout},
		githubAPI: githubAPIBase,
		adoAPI:    adoAPIBase,
		secrets:   secrets,
	}
}

// scrubSecrets removes literal secret values from a string destined for a log,
// an error or the evidence envelope. Empty entries are skipped: replacing ""
// would splice the placeholder between every character.
func scrubSecrets(s string, secrets []string) string {
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		s = strings.ReplaceAll(s, secret, "***")
	}
	return s
}

// redactURL keeps scheme+host and drops path, query and userinfo.
//
// A Teams incoming-webhook URL *is* the credential — its token lives in the
// path — and net/http puts the full URL into every transport error
// (`Post "https://…/token": dial tcp: …`). Returning that verbatim would print
// the webhook secret into the pipeline log. Callers supply the non-secret
// identity (repo, PR id, channel) in the error label instead.
func redactURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return "<redacted-url>"
	}
	return parsed.Scheme + "://" + parsed.Host + "/<redacted>"
}

// errorf builds a scrubbed error. Every error path in this file goes through it.
func (d *delivery) errorf(format string, a ...any) error {
	return errors.New(scrubSecrets(fmt.Sprintf(format, a...), d.secrets))
}

// do performs exactly one HTTP attempt (see noRetryPolicy) and returns the
// response body on 2xx. A non-2xx status, a transport failure and a truncated
// or unreadable body are all explicit errors — never a silent success.
func (d *delivery) do(req *http.Request, label string) ([]byte, error) {
	resp, err := d.client.Do(req)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			// Rebuild without the raw URL; urlErr.Err carries host:port at
			// most, never the webhook path.
			return nil, d.errorf("%s: %s %s: %v", label, urlErr.Op, redactURL(urlErr.URL), urlErr.Err)
		}
		return nil, d.errorf("%s: %v", label, err)
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	closeErr := resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, d.errorf("%s: endpoint returned HTTP %d: %s",
			label, resp.StatusCode, snippet(string(body)))
	}
	if readErr != nil {
		return nil, d.errorf("%s: read response: %v", label, readErr)
	}
	if closeErr != nil {
		return nil, d.errorf("%s: close response: %v", label, closeErr)
	}
	if len(body) == maxResponseBytes {
		return nil, d.errorf("%s: response exceeded %d bytes", label, maxResponseBytes)
	}
	return body, nil
}

func snippet(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "<empty body>"
	}
	if len(s) > errorBodySnippetLen {
		return s[:errorBodySnippetLen] + "…"
	}
	return s
}

// ── Teams ────────────────────────────────────────────────────────────────────

// postTeamsCard POSTs an adaptive card to a Teams incoming webhook.
//
// webhookURL is the secret itself, so it is never echoed into an error — the
// caller registers it via newDelivery so scrubSecrets catches it even if the
// endpoint reflects it in a response body.
func (d *delivery) postTeamsCard(ctx context.Context, webhookURL string, card teamsCard) error {
	payload, err := json.Marshal(card)
	if err != nil {
		return d.errorf("teams: marshal card: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(payload))
	if err != nil {
		return d.errorf("teams: build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	_, err = d.do(req, "teams webhook")
	return err
}

// ── GitHub ───────────────────────────────────────────────────────────────────

type githubComment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
}

func (d *delivery) setGitHubHeaders(req *http.Request, token string) {
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
}

func escapeGitHubRepoPath(repo string) (string, error) {
	parts := strings.Split(repo, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" ||
		parts[0] == "." || parts[0] == ".." || parts[1] == "." || parts[1] == ".." {
		return "", fmt.Errorf("repository must be exactly two non-empty owner/name segments")
	}
	return url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1]), nil
}

// upsertGitHubComment updates an existing pipeline comment (identified by its
// hidden marker) or creates a new one if none exists yet.
func (d *delivery) upsertGitHubComment(ctx context.Context, token, repo string, prNumber int, pipelineName, body string) error {
	repoPath, err := escapeGitHubRepoPath(repo)
	if err != nil {
		return d.errorf("github: invalid repository %q: %v", repo, err)
	}
	marker := PipelineMarker(pipelineName)
	id, err := d.findGitHubComment(ctx, token, repo, prNumber, marker)
	if err != nil {
		return err
	}
	if id != 0 {
		url := fmt.Sprintf("%s/repos/%s/issues/comments/%d", d.githubAPI, repoPath, id)
		return d.githubCommentRequest(ctx, http.MethodPatch, url, token, body,
			fmt.Sprintf("github: update comment %d on %s", id, repo))
	}
	url := fmt.Sprintf("%s/repos/%s/issues/%d/comments", d.githubAPI, repoPath, prNumber)
	return d.githubCommentRequest(ctx, http.MethodPost, url, token, body,
		fmt.Sprintf("github: create comment on %s#%d", repo, prNumber))
}

func (d *delivery) findGitHubComment(ctx context.Context, token, repo string, prNumber int, marker string) (int64, error) {
	repoPath, err := escapeGitHubRepoPath(repo)
	if err != nil {
		return 0, d.errorf("github: invalid repository %q: %v", repo, err)
	}
	const perPage = 100
	label := fmt.Sprintf("github: list comments on %s#%d", repo, prNumber)
	for page := 1; page <= maxCommentPages; page++ {
		url := fmt.Sprintf("%s/repos/%s/issues/%d/comments?per_page=%d&page=%d",
			d.githubAPI, repoPath, prNumber, perPage, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return 0, d.errorf("%s: build request: %v", label, err)
		}
		d.setGitHubHeaders(req, token)
		raw, err := d.do(req, label)
		if err != nil {
			return 0, err
		}
		var comments []githubComment
		if err := json.Unmarshal(raw, &comments); err != nil {
			return 0, d.errorf("%s: decode response: %v", label, err)
		}
		for _, c := range comments {
			if strings.Contains(c.Body, marker) {
				return c.ID, nil
			}
		}
		if len(comments) < perPage {
			return 0, nil
		}
	}
	// Marker not found within the bound: fall through to creating a comment
	// rather than spinning. Duplicate-comment risk beats a hung pipeline.
	return 0, nil
}

func (d *delivery) githubCommentRequest(ctx context.Context, method, url, token, body, label string) error {
	payload, err := json.Marshal(map[string]string{"body": body})
	if err != nil {
		return d.errorf("%s: marshal payload: %v", label, err)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(payload))
	if err != nil {
		return d.errorf("%s: build request: %v", label, err)
	}
	d.setGitHubHeaders(req, token)
	req.Header.Set("Content-Type", "application/json")
	raw, err := d.do(req, label)
	if err != nil {
		return err
	}
	// A 2xx alone is not proof the comment exists. An intercepting proxy or a
	// misrouted request can answer 200 with something that is not a comment, so
	// require the documented response shape.
	var created githubComment
	if err := json.Unmarshal(raw, &created); err != nil {
		return d.errorf("%s: endpoint answered 2xx with a body that is not a comment: %s",
			label, snippet(string(raw)))
	}
	if created.ID == 0 {
		return d.errorf("%s: endpoint accepted the request but returned no comment id: %s",
			label, snippet(string(raw)))
	}
	return nil
}

// ── Azure DevOps ─────────────────────────────────────────────────────────────

type adoThread struct {
	Comments []adoComment `json:"comments"`
	Status   int          `json:"status"`
}

type adoComment struct {
	Content     string `json:"content"`
	CommentType int    `json:"commentType"`
}

// adoThreadResponse is the subset of ADO's created-thread payload we verify.
//
// Azure DevOps answers an unauthenticated PR-thread POST with HTTP 203
// Non-Authoritative Information and an HTML sign-in page — a 2xx status
// carrying a failure. Requiring the documented `id` is what distinguishes a
// real thread from that sign-in page (the single most common ADO notify
// misconfiguration: "Allow scripts to access the OAuth token" left off).
type adoThreadResponse struct {
	ID int64 `json:"id"`
}

func (d *delivery) postADOComment(ctx context.Context, token, org, project, repoId string, prId int, body string) error {
	label := fmt.Sprintf("ado: create thread on %s/%s PR %d", org, project, prId)
	endpoint := fmt.Sprintf(
		"%s/%s/%s/_apis/git/repositories/%s/pullRequests/%d/threads?api-version=%s",
		d.adoAPI,
		url.PathEscape(org), url.PathEscape(project), url.PathEscape(repoId),
		prId, adoAPIVer,
	)
	payload, err := json.Marshal(adoThread{
		Comments: []adoComment{{Content: body, CommentType: 1}},
		Status:   1,
	})
	if err != nil {
		return d.errorf("%s: marshal payload: %v", label, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return d.errorf("%s: build request: %v", label, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	raw, err := d.do(req, label)
	if err != nil {
		return err
	}
	var created adoThreadResponse
	if err := json.Unmarshal(raw, &created); err != nil {
		return d.errorf("%s: endpoint answered 2xx with a body that is not a thread "+
			"(ADO returns 203 + a sign-in page when the token is not authorised): %s",
			label, snippet(string(raw)))
	}
	if created.ID == 0 {
		return d.errorf("%s: endpoint accepted the request but returned no thread id: %s",
			label, snippet(string(raw)))
	}
	return nil
}
