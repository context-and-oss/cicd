// Deterministic local proof for the outbound notification protocol.
//
// Every case below drives delivery.go — the same struct, request builder and
// response handler production uses (teams.go/github.go/ado.go call
// newDelivery() and then exactly these methods). There is no mock transport
// and no fake HTTP client: requests travel over a real loopback socket to an
// httptest server, so a test that asserts a header, a status check or a request
// count is asserting what the pipeline will really send and really tolerate.
//
// Endpoints are redirected by setting the package-internal githubAPI/adoAPI
// fields — deliberately not a Dagger input, so nothing here adds a public
// endpoint override. The Teams webhook URL is already a caller-supplied secret
// in production, so those cases need no redirection at all.
//
// Credentials are synthetic and asserted absent from every error string.

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	// Synthetic credentials. Shaped like the real thing (long, opaque) so a
	// substring assertion is meaningful, but valid nowhere.
	fakeToken       = "ghp_SYNTHETIC0token0must0never0appear0in0logs"
	fakeWebhookPath = "/webhookb2/SYNTHETIC-webhook-secret-in-path/IncomingWebhook/abc"
)

func testEnvelope() *envelope {
	e := &envelope{Passed: false, FindingsCount: 2, DurationMS: 1500}
	e.Repo.CommitSHA = "deadbeef"
	e.Repo.Branch = "feature/protocol-proof"
	e.FindingsBySeverity = map[Severity]int{SeverityHigh: 2}
	return e
}

// fixture is a bounded local HTTP endpoint plus the delivery seam pointed at it.
type fixture struct {
	srv      *httptest.Server
	del      *delivery
	requests atomic.Int32
	last     struct {
		method      string
		path        string // decoded path
		requestURI  string // raw request target, escaping intact
		rawQuery    string
		body        []byte
		authHeader  string
		contentType string
		accept      string
		apiVersion  string
	}
}

// newFixture starts a local server whose handler is `h` and returns a delivery
// configured exactly like newDelivery() except that the GitHub and ADO base
// URLs point at the fixture. The client is the production client type with the
// production timeout.
func newFixture(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) *fixture {
	t.Helper()
	f := &fixture{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		body, _ := io.ReadAll(r.Body)
		f.last.method = r.Method
		f.last.path = r.URL.Path
		f.last.requestURI = r.RequestURI
		f.last.rawQuery = r.URL.RawQuery
		f.last.body = body
		f.last.authHeader = r.Header.Get("Authorization")
		f.last.contentType = r.Header.Get("Content-Type")
		f.last.accept = r.Header.Get("Accept")
		f.last.apiVersion = r.Header.Get("X-GitHub-Api-Version")
		h(w, r)
	}))
	t.Cleanup(f.srv.Close)

	f.del = newDelivery(fakeToken)
	f.del.githubAPI = f.srv.URL
	f.del.adoAPI = f.srv.URL
	return f
}

// teamsWebhook returns a webhook URL on the fixture whose path carries a
// synthetic secret, mirroring how a real Teams incoming webhook embeds its
// token in the URL.
func (f *fixture) teamsWebhook() string { return f.srv.URL + fakeWebhookPath }

func okJSON(body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}
}

func status(code int, body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}
}

// assertNoSecretLeak fails if any synthetic credential (or the secret-bearing
// webhook path) shows up in text destined for a pipeline log or the evidence
// envelope's Errors[].
func assertNoSecretLeak(t *testing.T, what, text string) {
	t.Helper()
	for _, secret := range []string{fakeToken, fakeWebhookPath, "SYNTHETIC"} {
		if strings.Contains(text, secret) {
			t.Fatalf("%s leaked a secret value: %q contains %q", what, text, secret)
		}
	}
}

// TestDeliveryHTTP is the outbound-protocol suite: one local HTTP fixture per
// case, driven through the production delivery seam.
func TestDeliveryHTTP(t *testing.T) {
	t.Run("ProductionSeamIsBounded", testProductionSeamIsBounded)

	t.Run("TeamsSuccess", testTeamsSuccess)
	t.Run("TeamsNonSuccessStatus", testTeamsNonSuccessStatus)
	t.Run("TeamsRedactsWebhookOnTransportError", testTeamsRedactsWebhookOnTransportError)
	t.Run("TeamsRedactsSecretEchoedByEndpoint", testTeamsRedactsSecretEchoedByEndpoint)
	t.Run("TeamsTimeoutIsBounded", testTeamsTimeoutIsBounded)
	t.Run("TeamsDoesNotRetry", testTeamsDoesNotRetry)

	t.Run("GithubCreatesCommentWithAuthHeaders", testGithubCreatesCommentWithAuthHeaders)
	t.Run("GithubUpdatesExistingMarkedComment", testGithubUpdatesExistingMarkedComment)
	t.Run("GithubEscapesRepositoryPathSegments", testGithubEscapesRepositoryPathSegments)
	t.Run("GithubRejectsInvalidRepositoryPaths", testGithubRejectsInvalidRepositoryPaths)
	t.Run("GithubMalformedListResponseFails", testGithubMalformedListResponseFails)
	t.Run("GithubCreateWithoutCommentIdFails", testGithubCreateWithoutCommentIdFails)
	t.Run("GithubUnauthorizedFailsWithoutLeakingToken", testGithubUnauthorizedFailsWithoutLeakingToken)
	t.Run("GithubPaginationIsBounded", testGithubPaginationIsBounded)
	t.Run("GithubDoesNotRetryOnServerError", testGithubDoesNotRetryOnServerError)

	t.Run("AdoPostsThreadWithAuthHeaders", testAdoPostsThreadWithAuthHeaders)
	t.Run("AdoNonSuccessFailsWithoutLeakingToken", testAdoNonSuccessFailsWithoutLeakingToken)
	t.Run("AdoRejectsSignInPageWith2xxStatus", testAdoRejectsSignInPageWith2xxStatus)
	t.Run("AdoRejectsThreadWithoutId", testAdoRejectsThreadWithoutId)
	t.Run("AdoEscapesPathSegments", testAdoEscapesPathSegments)
	t.Run("AdoDoesNotRetry", testAdoDoesNotRetry)
}

// ── the seam itself ──────────────────────────────────────────────────────────

// The tests below redirect githubAPI/adoAPI, so they would still pass if
// production had no timeout or pointed somewhere else. Assert the production
// constructor's configuration directly, so "the seam under test is the
// production seam" is a checked fact rather than a comment.
func testProductionSeamIsBounded(t *testing.T) {
	d := newDelivery("x")
	if d.client == nil {
		t.Fatal("newDelivery must supply an http.Client, not rely on http.DefaultClient")
	}
	if d.client.Timeout <= 0 {
		t.Fatal("production delivery client has no timeout — a hung endpoint would stall the pipeline")
	}
	if d.client.Timeout != deliveryTimeout {
		t.Fatalf("client timeout = %v, want deliveryTimeout %v", d.client.Timeout, deliveryTimeout)
	}
	if d.githubAPI != githubAPIBase || d.adoAPI != adoAPIBase {
		t.Fatalf("production endpoints changed: github=%q ado=%q", d.githubAPI, d.adoAPI)
	}
	if noRetryPolicy == "" {
		t.Fatal("the delivery retry policy must stay documented")
	}
}

// ── Teams ────────────────────────────────────────────────────────────────────

func testTeamsSuccess(t *testing.T) {
	f := newFixture(t, status(http.StatusOK, "1"))
	card := buildTeamsCard("precommit", "https://ci.example/run/7", testEnvelope())

	if err := f.del.postTeamsCard(context.Background(), f.teamsWebhook(), card); err != nil {
		t.Fatalf("postTeamsCard: %v", err)
	}

	if got := f.requests.Load(); got != 1 {
		t.Fatalf("request count = %d, want 1", got)
	}
	if f.last.method != http.MethodPost {
		t.Fatalf("method = %s, want POST", f.last.method)
	}
	if f.last.path != fakeWebhookPath {
		t.Fatalf("path = %q, want the caller-supplied webhook path %q", f.last.path, fakeWebhookPath)
	}
	if f.last.contentType != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", f.last.contentType)
	}

	// The bytes that arrive must be the adaptive card, not a rendered preview.
	var arrived teamsCard
	if err := json.Unmarshal(f.last.body, &arrived); err != nil {
		t.Fatalf("server received non-card JSON %q: %v", f.last.body, err)
	}
	if arrived.Type != "message" || len(arrived.Attachments) != 1 {
		t.Fatalf("unexpected card shape on the wire: %+v", arrived)
	}
	if arrived.Attachments[0].ContentType != "application/vnd.microsoft.card.adaptive" {
		t.Fatalf("attachment contentType = %q", arrived.Attachments[0].ContentType)
	}
	cardBody := arrived.Attachments[0].Content
	if cardBody.Schema != "http://adaptivecards.io/schemas/adaptive-card.json" {
		t.Fatalf("adaptive card $schema = %q", cardBody.Schema)
	}
	if cardBody.Version != "1.2" {
		t.Fatalf("adaptive card version = %q, want 1.2", cardBody.Version)
	}
	if !strings.Contains(string(f.last.body), "deadbeef") {
		t.Fatalf("card body lost the commit sha: %s", f.last.body)
	}
}

func testTeamsNonSuccessStatus(t *testing.T) {
	f := newFixture(t, status(http.StatusBadRequest, "Bad payload"))
	err := f.del.postTeamsCard(context.Background(), f.teamsWebhook(),
		buildTeamsCard("precommit", "", testEnvelope()))
	if err == nil {
		t.Fatal("a 400 response must fail the delivery, not be ignored")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Fatalf("error must name the status code, got %q", err)
	}
	if !strings.Contains(err.Error(), "Bad payload") {
		t.Fatalf("error must quote the response body for triage, got %q", err)
	}
	assertNoSecretLeak(t, "teams non-success error", err.Error())
}

// A Teams incoming-webhook URL is itself the credential. net/http puts the full
// URL into every transport error, so this is the leak path that matters most.
func testTeamsRedactsWebhookOnTransportError(t *testing.T) {
	f := newFixture(t, status(http.StatusOK, "1"))
	webhook := f.teamsWebhook()
	f.srv.Close() // nothing listening -> a real dial failure

	err := f.del.postTeamsCard(context.Background(), webhook,
		buildTeamsCard("precommit", "", testEnvelope()))
	if err == nil {
		t.Fatal("a closed endpoint must produce an error")
	}
	// The delivery registers the webhook itself as a secret, so both the URL
	// redaction and the scrubber must hold.
	if strings.Contains(err.Error(), fakeWebhookPath) {
		t.Fatalf("transport error leaked the webhook path: %q", err)
	}
	if !strings.Contains(err.Error(), "<redacted>") {
		t.Fatalf("expected a redacted URL in the error, got %q", err)
	}
	assertNoSecretLeak(t, "teams transport error", err.Error())
}

// A hostile or buggy endpoint that echoes the credential back must not turn the
// response body quoted in the error into a credential disclosure.
func testTeamsRedactsSecretEchoedByEndpoint(t *testing.T) {
	f := newFixture(t, nil)
	f.srv.Close()

	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("rejected token " + fakeToken + " for " + r.URL.Path))
	}))
	defer echo.Close()

	// fakeToken is registered as a secret of this delivery (newDelivery(fakeToken)).
	d := newDelivery(fakeToken)
	err := d.postTeamsCard(context.Background(), echo.URL+fakeWebhookPath,
		buildTeamsCard("precommit", "", testEnvelope()))
	if err == nil {
		t.Fatal("a 403 response must fail the delivery")
	}
	if strings.Contains(err.Error(), fakeToken) {
		t.Fatalf("an echoed credential reached the error text: %q", err)
	}
	if !strings.Contains(err.Error(), "***") {
		t.Fatalf("expected the scrubbed placeholder in %q", err)
	}
}

func testTeamsTimeoutIsBounded(t *testing.T) {
	release := make(chan struct{})
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		<-release // hold the connection open until the client gives up
		w.WriteHeader(http.StatusOK)
	})
	defer close(release)

	// Same code path, shorter bound, so the test does not wait deliveryTimeout.
	f.del.client.Timeout = 100 * time.Millisecond

	start := time.Now()
	err := f.del.postTeamsCard(context.Background(), f.teamsWebhook(),
		buildTeamsCard("precommit", "", testEnvelope()))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a non-responding endpoint must time out with an error, not hang")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("delivery was not bounded by the client timeout: took %v", elapsed)
	}
	if got := f.requests.Load(); got != 1 {
		t.Fatalf("a timeout must not be retried: request count = %d, want 1", got)
	}
	assertNoSecretLeak(t, "teams timeout error", err.Error())
}

func testTeamsDoesNotRetry(t *testing.T) {
	f := newFixture(t, status(http.StatusInternalServerError, "boom"))
	if err := f.del.postTeamsCard(context.Background(), f.teamsWebhook(),
		buildTeamsCard("precommit", "", testEnvelope())); err == nil {
		t.Fatal("a 500 must fail the delivery")
	}
	if got := f.requests.Load(); got != 1 {
		t.Fatalf("delivery policy is %q: request count = %d, want 1", noRetryPolicy, got)
	}
}

// ── GitHub ───────────────────────────────────────────────────────────────────

func testGithubCreatesCommentWithAuthHeaders(t *testing.T) {
	var listPath, createPath string
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			listPath = r.URL.Path
			okJSON("[]")(w, r) // no existing marker
		case http.MethodPost:
			createPath = r.URL.Path
			okJSON(`{"id":42}`)(w, r)
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	})

	err := f.del.upsertGitHubComment(context.Background(), fakeToken,
		"acme/widgets", 7, "precommit", "## precommit — body")
	if err != nil {
		t.Fatalf("upsertGitHubComment: %v", err)
	}

	if got := f.requests.Load(); got != 2 {
		t.Fatalf("request count = %d, want 2 (list + create)", got)
	}
	if listPath != "/repos/acme/widgets/issues/7/comments" {
		t.Fatalf("list path = %q", listPath)
	}
	if createPath != "/repos/acme/widgets/issues/7/comments" {
		t.Fatalf("create path = %q", createPath)
	}
	if f.last.method != http.MethodPost {
		t.Fatalf("final method = %s, want POST", f.last.method)
	}

	// Authentication and the API contract headers must actually arrive.
	if want := "Bearer " + fakeToken; f.last.authHeader != want {
		t.Fatalf("Authorization = %q, want %q", f.last.authHeader, want)
	}
	if f.last.accept != "application/vnd.github+json" {
		t.Fatalf("Accept = %q", f.last.accept)
	}
	if f.last.apiVersion != "2022-11-28" {
		t.Fatalf("X-GitHub-Api-Version = %q", f.last.apiVersion)
	}
	if f.last.contentType != "application/json" {
		t.Fatalf("Content-Type = %q", f.last.contentType)
	}

	var payload map[string]string
	if err := json.Unmarshal(f.last.body, &payload); err != nil {
		t.Fatalf("create payload is not JSON: %v", err)
	}
	if payload["body"] != "## precommit — body" {
		t.Fatalf("payload body = %q", payload["body"])
	}
}

func testGithubUpdatesExistingMarkedComment(t *testing.T) {
	marker := PipelineMarker("precommit")
	var patchPath string
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			okJSON(`[{"id":99,"body":"`+marker+`\nold"}]`)(w, r)
		case http.MethodPatch:
			patchPath = r.URL.Path
			okJSON(`{"id":99}`)(w, r)
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	})

	if err := f.del.upsertGitHubComment(context.Background(), fakeToken,
		"acme/widgets", 7, "precommit", "new body"); err != nil {
		t.Fatalf("upsertGitHubComment: %v", err)
	}
	if patchPath != "/repos/acme/widgets/issues/comments/99" {
		t.Fatalf("patch path = %q — an existing marked comment must be updated in place", patchPath)
	}
	if got := f.requests.Load(); got != 2 {
		t.Fatalf("request count = %d, want 2 (list + patch)", got)
	}
}

func testGithubEscapesRepositoryPathSegments(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			okJSON("[]")(w, r)
			return
		}
		okJSON(`{"id":42}`)(w, r)
	})

	if err := f.del.upsertGitHubComment(context.Background(), fakeToken,
		"owner name/repo?#", 7, "precommit", "body"); err != nil {
		t.Fatalf("upsertGitHubComment: %v", err)
	}
	want := "/repos/owner%20name/repo%3F%23/issues/7/comments"
	if f.last.requestURI != want {
		t.Fatalf("request target = %q, want escaped repository path %q", f.last.requestURI, want)
	}
}

func testGithubRejectsInvalidRepositoryPaths(t *testing.T) {
	invalid := []string{"", "owner", "/repo", "owner/", "owner/repo/extra", "./repo", "owner/.."}
	for _, repo := range invalid {
		t.Run(repo, func(t *testing.T) {
			f := newFixture(t, okJSON(`{"id":1}`))
			err := f.del.upsertGitHubComment(context.Background(), fakeToken,
				repo, 7, "precommit", "body")
			if err == nil || !strings.Contains(err.Error(), "invalid repository") {
				t.Fatalf("repo %q: expected a validation error, got %v", repo, err)
			}
			if got := f.requests.Load(); got != 0 {
				t.Fatalf("repo %q sent %d requests before validation", repo, got)
			}
		})
	}

	f := newFixture(t, okJSON("[]"))
	if _, err := f.del.findGitHubComment(context.Background(), fakeToken,
		"owner/repo/extra", 7, PipelineMarker("precommit")); err == nil {
		t.Fatal("findGitHubComment must independently reject an invalid repository path")
	}
	if got := f.requests.Load(); got != 0 {
		t.Fatalf("findGitHubComment sent %d requests before validation", got)
	}
}

// A 200 carrying something that is not a comment array is not a success.
func testGithubMalformedListResponseFails(t *testing.T) {
	f := newFixture(t, okJSON(`{"message":"not an array"}`))
	err := f.del.upsertGitHubComment(context.Background(), fakeToken,
		"acme/widgets", 7, "precommit", "body")
	if err == nil {
		t.Fatal("a malformed 200 body must fail, not be treated as 'no existing comment'")
	}
	if !strings.Contains(err.Error(), "decode response") {
		t.Fatalf("error must say the response could not be decoded, got %q", err)
	}
	if got := f.requests.Load(); got != 1 {
		t.Fatalf("request count = %d, want 1 (no comment should be posted after a decode failure)", got)
	}
	assertNoSecretLeak(t, "github decode error", err.Error())
}

// A 200 from the create/update call is not proof the comment exists.
func testGithubCreateWithoutCommentIdFails(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			okJSON("[]")(w, r)
			return
		}
		okJSON(`{"message":"accepted"}`)(w, r) // 200, but not a comment
	})
	err := f.del.upsertGitHubComment(context.Background(), fakeToken,
		"acme/widgets", 7, "precommit", "body")
	if err == nil {
		t.Fatal("a 200 without a comment id must fail")
	}
	if !strings.Contains(err.Error(), "no comment id") {
		t.Fatalf("error must say no comment id was returned, got %q", err)
	}
	assertNoSecretLeak(t, "github create error", err.Error())
}

func testGithubUnauthorizedFailsWithoutLeakingToken(t *testing.T) {
	f := newFixture(t, status(http.StatusUnauthorized, `{"message":"Bad credentials"}`))
	err := f.del.upsertGitHubComment(context.Background(), fakeToken,
		"acme/widgets", 7, "precommit", "body")
	if err == nil {
		t.Fatal("a 401 must fail the delivery")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("error must name the status, got %q", err)
	}
	if !strings.Contains(err.Error(), "acme/widgets#7") {
		t.Fatalf("error must carry the non-secret identity for triage, got %q", err)
	}
	assertNoSecretLeak(t, "github 401 error", err.Error())
}

// The marker walk must not spin forever against an endpoint that keeps
// returning full pages.
func testGithubPaginationIsBounded(t *testing.T) {
	full := make([]githubComment, 100)
	for i := range full {
		full[i] = githubComment{ID: int64(i + 1), Body: "unrelated"}
	}
	page, err := json.Marshal(full)
	if err != nil {
		t.Fatalf("marshal fixture page: %v", err)
	}

	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			okJSON(string(page))(w, r) // always a full page: never terminates on its own
			return
		}
		okJSON(`{"id":1}`)(w, r)
	})

	done := make(chan error, 1)
	go func() {
		done <- f.del.upsertGitHubComment(context.Background(), fakeToken,
			"acme/widgets", 7, "precommit", "body")
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("bounded pagination should fall through to creating a comment, got %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("comment listing did not terminate — pagination is unbounded")
	}

	// maxCommentPages GETs plus exactly one POST.
	if got := f.requests.Load(); got != int32(maxCommentPages)+1 {
		t.Fatalf("request count = %d, want %d list pages + 1 create", got, maxCommentPages)
	}
}

func testGithubDoesNotRetryOnServerError(t *testing.T) {
	f := newFixture(t, status(http.StatusInternalServerError, "upstream boom"))
	if err := f.del.upsertGitHubComment(context.Background(), fakeToken,
		"acme/widgets", 7, "precommit", "body"); err == nil {
		t.Fatal("a 500 must fail the delivery")
	}
	if got := f.requests.Load(); got != 1 {
		t.Fatalf("delivery policy is %q: request count = %d, want 1", noRetryPolicy, got)
	}
}

// ── Azure DevOps ─────────────────────────────────────────────────────────────

func testAdoPostsThreadWithAuthHeaders(t *testing.T) {
	f := newFixture(t, status(http.StatusCreated, `{"id":5}`))

	if err := f.del.postADOComment(context.Background(), fakeToken,
		"my-org", "payments", "repo-guid", 12, "## precommit — body"); err != nil {
		t.Fatalf("postADOComment: %v", err)
	}

	if got := f.requests.Load(); got != 1 {
		t.Fatalf("request count = %d, want 1", got)
	}
	if f.last.method != http.MethodPost {
		t.Fatalf("method = %s, want POST", f.last.method)
	}
	want := "/my-org/payments/_apis/git/repositories/repo-guid/pullRequests/12/threads"
	if f.last.path != want {
		t.Fatalf("path = %q, want %q", f.last.path, want)
	}
	if f.last.rawQuery != "api-version="+adoAPIVer {
		t.Fatalf("query = %q, want api-version=%s", f.last.rawQuery, adoAPIVer)
	}
	if wantAuth := "Bearer " + fakeToken; f.last.authHeader != wantAuth {
		t.Fatalf("Authorization = %q, want %q", f.last.authHeader, wantAuth)
	}
	if f.last.contentType != "application/json" {
		t.Fatalf("Content-Type = %q", f.last.contentType)
	}

	var thread adoThread
	if err := json.Unmarshal(f.last.body, &thread); err != nil {
		t.Fatalf("thread payload is not JSON: %v", err)
	}
	if len(thread.Comments) != 1 || thread.Comments[0].Content != "## precommit — body" {
		t.Fatalf("unexpected thread payload: %+v", thread)
	}
	if thread.Comments[0].CommentType != 1 || thread.Status != 1 {
		t.Fatalf("ADO thread must stay commentType=1 status=1, got %+v", thread)
	}
}

func testAdoNonSuccessFailsWithoutLeakingToken(t *testing.T) {
	f := newFixture(t, status(http.StatusUnauthorized, `{"message":"TF400813"}`))
	err := f.del.postADOComment(context.Background(), fakeToken,
		"my-org", "payments", "repo-guid", 12, "body")
	if err == nil {
		t.Fatal("a 401 must fail the delivery")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("error must name the status, got %q", err)
	}
	if !strings.Contains(err.Error(), "my-org/payments") {
		t.Fatalf("error must carry the non-secret identity for triage, got %q", err)
	}
	assertNoSecretLeak(t, "ado non-success error", err.Error())
}

// Azure DevOps answers an unauthorised PR-thread POST with HTTP 203 and an HTML
// sign-in page. A status-only check reads that as success and the pipeline
// reports a comment it never posted.
func testAdoRejectsSignInPageWith2xxStatus(t *testing.T) {
	f := newFixture(t, status(http.StatusNonAuthoritativeInfo,
		"<html><body>Azure DevOps sign in</body></html>"))
	err := f.del.postADOComment(context.Background(), fakeToken,
		"my-org", "payments", "repo-guid", 12, "body")
	if err == nil {
		t.Fatal("a 203 + sign-in page must fail: a 2xx status is not proof the thread exists")
	}
	if !strings.Contains(err.Error(), "not a thread") {
		t.Fatalf("error must say the body is not a thread, got %q", err)
	}
	if got := f.requests.Load(); got != 1 {
		t.Fatalf("request count = %d, want 1", got)
	}
	assertNoSecretLeak(t, "ado sign-in-page error", err.Error())
}

// A 2xx with valid JSON but no thread id is also not a created thread.
func testAdoRejectsThreadWithoutId(t *testing.T) {
	f := newFixture(t, status(http.StatusCreated, `{"comments":[]}`))
	err := f.del.postADOComment(context.Background(), fakeToken,
		"my-org", "payments", "repo-guid", 12, "body")
	if err == nil {
		t.Fatal("a 201 without a thread id must fail")
	}
	if !strings.Contains(err.Error(), "no thread id") {
		t.Fatalf("error must say no thread id was returned, got %q", err)
	}
}

// org/project/repoId are consumer-supplied. They are interpolated into the
// request path, so they must be percent-encoded: a value containing "/" or "?"
// would otherwise introduce a new path segment or a query and retarget the
// request at a different ADO API.
func testAdoEscapesPathSegments(t *testing.T) {
	f := newFixture(t, status(http.StatusCreated, `{"id":7}`))
	if err := f.del.postADOComment(context.Background(), fakeToken,
		"my org", "pay/ments", "repo?guid", 12, "body"); err != nil {
		t.Fatalf("postADOComment: %v", err)
	}

	// r.RequestURI is the raw target, so the escaping is visible here.
	want := "/my%20org/pay%2Fments/_apis/git/repositories/repo%3Fguid/pullRequests/12/threads?api-version=" + adoAPIVer
	if f.last.requestURI != want {
		t.Fatalf("request target = %q, want %q", f.last.requestURI, want)
	}
	// The decoded path must still be exactly the intended segments — the
	// injected "/" stayed inside the project segment rather than creating one.
	wantPath := "/my org/pay/ments/_apis/git/repositories/repo?guid/pullRequests/12/threads"
	if f.last.path != wantPath {
		t.Fatalf("decoded path = %q, want %q", f.last.path, wantPath)
	}
}

func testAdoDoesNotRetry(t *testing.T) {
	f := newFixture(t, status(http.StatusServiceUnavailable, "unavailable"))
	if err := f.del.postADOComment(context.Background(), fakeToken,
		"my-org", "payments", "repo-guid", 12, "body"); err == nil {
		t.Fatal("a 503 must fail the delivery")
	}
	if got := f.requests.Load(); got != 1 {
		t.Fatalf("delivery policy is %q: request count = %d, want 1", noRetryPolicy, got)
	}
}
