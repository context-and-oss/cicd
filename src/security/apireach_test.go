package main

import (
	"strings"
	"testing"
)

// probeRequestedURLs is what the pinned image actually requested, measured on
// zaproxy 2.17.0 against a document declaring /api/tasks, /api/tasks/{id},
// /api/projects and /api/projects/{projectId}/members. It is here verbatim
// because every matching rule in apireach.go is a claim about these bytes.
var probeRequestedURLs = []string{
	"http://probe-target:8000",
	"http://probe-target:8000/api",
	"http://probe-target:8000/api/actuator",
	"http://probe-target:8000/api/actuator/health",
	"http://probe-target:8000/api/projects",
	"http://probe-target:8000/api/projects/projectId",
	"http://probe-target:8000/api/projects/projectId/members",
	"http://probe-target:8000/api/tasks",
	"http://probe-target:8000/api/tasks/10",
	"http://probe-target:8000/swagger.json",
}

var probeDeclaredPaths = []string{
	"/api/projects",
	"/api/projects/{projectId}/members",
	"/api/tasks",
	"/api/tasks/{id}",
}

// reach reconciles with no target origin, which means no origin filtering —
// the shape most of these tests want, because they are about path matching and
// not about which host served a path.
func reach(declared, prefixes []string, urls []string) apiReach {
	return reachFrom("", declared, prefixes, urls)
}

func reachFrom(target string, declared, prefixes []string, urls []string) apiReach {
	requested, unparsed, offOrigin := requestedAPIPaths(urls, target)
	out := reconcileAPIReach(declared, prefixes, requested)
	out.Unparsed = unparsed
	out.OffOrigin = offOrigin
	return out
}

func joined(in []string) string { return strings.Join(in, " ") }

func TestATemplatedPathMatchesTheConcreteURLZAPGeneratedForIt(t *testing.T) {
	got := reach(probeDeclaredPaths, []string{""}, probeRequestedURLs)
	if len(got.Unreached) != 0 {
		t.Errorf("every declared path was requested in the measured run, got unreached %v", got.Unreached)
	}
	if len(got.Reached) != 4 {
		t.Errorf("want all 4 declared paths reached, got %v", got.Reached)
	}
}

func TestAPathZAPRequestedThatTheDocumentDoesNotDeclareIsNotCountedAsReach(t *testing.T) {
	// ZAP probes for things nobody declared — /api/actuator/health here, and
	// the swagger document it was pointed at. They are evidence the scan was
	// alive and are never evidence an endpoint was covered.
	got := reach(probeDeclaredPaths, []string{""}, probeRequestedURLs)
	for _, want := range []string{"/api/actuator/health", "/swagger.json", "/"} {
		if !strings.Contains(joined(got.Extra), want) {
			t.Errorf("want %s reported as unexplained, got %v", want, got.Extra)
		}
	}
	if strings.Contains(joined(got.Reached), "actuator") {
		t.Error("a probe path must never be counted as a declared endpoint")
	}
}

func TestATemplatedSegmentNeverMatchesAnEmptyOne(t *testing.T) {
	// A request for the collection is not a request for a member of it. If
	// {id} could match nothing, every declared /thing/{id} would be reported
	// reached on the strength of a request for /thing — a false green in the
	// one place this file exists to prevent one.
	got := reach([]string{"/api/tasks/{id}"}, []string{""}, []string{"http://app/api/tasks", "http://app/api/tasks/"})
	if len(got.Unreached) != 1 {
		t.Fatalf("want the templated path unreached, got reached=%v unreached=%v", got.Reached, got.Unreached)
	}
}

func TestATemplatedSegmentStopsAtASeparator(t *testing.T) {
	// {id} is one segment. If it matched across "/", then /a/{id} would be
	// reached by a request for /a/b/c/d and the reconciliation would report
	// coverage it cannot see.
	got := reach([]string{"/a/{id}"}, []string{""}, []string{"http://app/a/b/c"})
	if len(got.Unreached) != 1 {
		t.Errorf("want /a/{id} unreached, got %v", got.Reached)
	}
}

func TestAPathWithARegexpMetacharacterIsMatchedLiterally(t *testing.T) {
	got := reach([]string{"/api/v1.0/tasks"}, []string{""}, []string{"http://app/api/v1X0/tasks"})
	if len(got.Reached) != 0 {
		t.Errorf("a dot in a declared path is a dot, not any character: %v", got.Reached)
	}
	got = reach([]string{"/api/v1.0/tasks"}, []string{""}, []string{"http://app/api/v1.0/tasks"})
	if len(got.Reached) != 1 {
		t.Errorf("the literal path must still match itself, got %v", got.Unreached)
	}
}

func TestTrailingSlashesAreTheSameEndpoint(t *testing.T) {
	got := reach([]string{"/api/tasks/"}, []string{""}, []string{"http://app/api/tasks"})
	if len(got.Reached) != 1 {
		t.Errorf("want the trailing slash ignored, got unreached %v", got.Unreached)
	}
	if joined(got.Reached) != "/api/tasks" {
		t.Errorf("the path must be named in one shape, got %v", got.Reached)
	}
}

func TestRequestedURLsLoseTheirQueryStringBecauseAnEndpointIsNotAParameterList(t *testing.T) {
	got := reach([]string{"/api/tasks"}, []string{""}, []string{"http://app/api/tasks?page=2&sort=name"})
	if len(got.Reached) != 1 {
		t.Errorf("want the query dropped, got unreached %v", got.Unreached)
	}
}

func TestAServerPrefixIsTriedAndSoIsNoPrefix(t *testing.T) {
	// The document says its paths live under /v2. ZAP requested them there.
	got := reach([]string{"/pets"}, []string{"/v2", ""}, []string{"http://app/v2/pets"})
	if len(got.Reached) != 1 {
		t.Errorf("want the prefix applied, got unreached %v", got.Unreached)
	}
	// And the same document deployed at the root: a servers[] entry is what
	// the document claims, never what the deployment does, so a match without
	// the prefix still counts.
	got = reach([]string{"/pets"}, []string{"/v2", ""}, []string{"http://app/pets"})
	if len(got.Reached) != 1 {
		t.Errorf("want the bare path to match too, got unreached %v", got.Unreached)
	}
}

func TestTheDeclaredPathIsNamedAsTheDocumentWroteItAndNotAsThePrefixedSpelling(t *testing.T) {
	// A reader has to find the path in their own source. /v2/pets is not in
	// it; /pets is.
	got := reach([]string{"/pets"}, []string{"/v2", ""}, []string{"http://app/v2/pets"})
	if joined(got.Reached) != "/pets" {
		t.Errorf("want the document's own spelling, got %v", got.Reached)
	}
}

func TestServerPrefixesAreReadFromBothSpellingsAndAlwaysIncludeNone(t *testing.T) {
	cases := map[string]string{
		"openapi3 absolute": `{"servers":[{"url":"https://example.com/v2"}],"paths":{}}`,
		"openapi3 bare":     `{"servers":[{"url":"/v2"}],"paths":{}}`,
		"swagger2 basePath": `{"basePath":"/v2","paths":{}}`,
	}
	for name, doc := range cases {
		got := openAPIServerPrefixes([]byte(doc))
		if len(got) != 2 || got[0] != "/v2" || got[1] != "" {
			t.Errorf("%s: want [/v2 \"\"], got %#v", name, got)
		}
	}
}

func TestAServerURLWithATemplateHostContributesOnlyItsPath(t *testing.T) {
	// https://{region}.example.com/v2 is legal OpenAPI and unresolvable here.
	// Treating the whole string as a path would prefix every declared path
	// with "https:/{region}.example.com/v2" and report the entire API
	// unreached — a red build caused by cicd's own parsing.
	got := openAPIServerPrefixes([]byte(`{"servers":[{"url":"https://{region}.example.com/v2"}],"paths":{}}`))
	if len(got) != 2 || got[0] != "/v2" {
		t.Errorf("want the path component alone, got %#v", got)
	}
}

func TestADocumentWithNoServerBlockStillHasThEmptyPrefix(t *testing.T) {
	for _, doc := range []string{`{"paths":{}}`, `not json at all`, `{"servers":[{"url":"/"}]}`} {
		got := openAPIServerPrefixes([]byte(doc))
		if len(got) != 1 || got[0] != "" {
			t.Errorf("%s: want exactly the empty prefix, got %#v", doc, got)
		}
	}
}

func TestUnparsedEntriesAreCountedAndNeverSilentlyDropped(t *testing.T) {
	_, unparsed, _ := requestedAPIPaths([]string{"http://app/a", "http://[::1", "  "}, "")
	if unparsed != 1 {
		t.Errorf("want the one unparseable entry counted, got %d", unparsed)
	}
}

func TestEveryDeclaredPathReachedDisclosesNothing(t *testing.T) {
	got := reach(probeDeclaredPaths, []string{""}, probeRequestedURLs)
	if msg := apiReachError(got); msg != "" {
		t.Errorf("a complete scan must not fail: %s", msg)
	}
	if w := apiReachWarnings(got); len(w) != 0 {
		t.Errorf("a complete scan must say nothing: %v", w)
	}
}

func TestNoDeclaredPathReachedIsAnErrorAndNamesTheOtherURLsZAPDidRequest(t *testing.T) {
	// The run this change was written for: ZAP alive, requesting the swagger
	// surface and its own probes, and not one path the document declares.
	got := reach(probeDeclaredPaths, []string{""}, []string{
		"http://app/", "http://app/swagger/index.html", "http://app/robots.txt",
	})
	msg := apiReachError(got)
	if msg == "" {
		t.Fatal("a scan that requested no declared path must fail")
	}
	if !strings.Contains(msg, "API NOT REACHED") {
		t.Errorf("want the verdict named, got %q", msg)
	}
	if !strings.Contains(msg, "/api/tasks") {
		t.Errorf("the error must name the endpoints, got %q", msg)
	}
	if !strings.Contains(msg, "swagger/index.html") {
		t.Errorf("the error must name what ZAP did request, so a reader can tell a live scan from a dead one: %q", msg)
	}
	if w := apiReachWarnings(got); len(w) != 0 {
		t.Errorf("the error is the whole story; a warning beside it is the same fact twice: %v", w)
	}
}

func TestSomeReachedIsAWarningAndNeverAnError(t *testing.T) {
	// An OpenAPI document routinely declares paths ZAP's importer skips. A
	// partial gap is worth naming and is not worth failing a scan that
	// demonstrably ran.
	got := reach(probeDeclaredPaths, []string{""}, []string{"http://app/api/tasks"})
	if msg := apiReachError(got); msg != "" {
		t.Errorf("a partial gap must not fail the scan: %s", msg)
	}
	w := apiReachWarnings(got)
	if len(w) != 1 {
		t.Fatalf("want exactly one warning, got %v", w)
	}
	if !strings.Contains(w[0], "1 of the 4") {
		t.Errorf("the warning must state both numbers, got %q", w[0])
	}
	for _, want := range []string{"/api/projects", "/api/tasks/{id}"} {
		if !strings.Contains(w[0], want) {
			t.Errorf("want %s named, got %q", want, w[0])
		}
	}
}

func TestADocumentDeclaringNothingProducesNoVerdict(t *testing.T) {
	got := reach(nil, []string{""}, probeRequestedURLs)
	if msg := apiReachError(got); msg != "" {
		t.Errorf("no denominator, no verdict: %s", msg)
	}
	if w := apiReachWarnings(got); len(w) != 0 {
		t.Errorf("no denominator, nothing to say: %v", w)
	}
}

func TestAnUnreadEntryIsDisclosedBecauseTheReachedCountIsThenAFloor(t *testing.T) {
	got := reach([]string{"/a"}, []string{""}, []string{"http://app/a", "http://[::1"})
	w := apiReachWarnings(got)
	if len(w) != 1 || !strings.Contains(w[0], "SITE TREE PARTLY UNREAD") {
		t.Fatalf("want the unread entry disclosed, got %v", w)
	}
}

func TestTheSentenceNamesSomePathsAndSaysHowManyItLeftOut(t *testing.T) {
	var many []string
	for i := 0; i < maxSentencePaths+7; i++ {
		many = append(many, "/p")
	}
	got := namePaths(many)
	if strings.Count(got, "/p") != maxSentencePaths {
		t.Errorf("want exactly %d named, got %q", maxSentencePaths, got)
	}
	if !strings.Contains(got, "and 7 more") {
		t.Errorf("want the remainder counted, got %q", got)
	}
}

func TestTheReportBoundsItsListsAndKeepsItsCountsWhole(t *testing.T) {
	var declared []string
	for i := 0; i < maxNamedReachPaths+13; i++ {
		declared = append(declared, "/p"+strings.Repeat("x", i))
	}
	got := reach(declared, []string{""}, []string{"http://app/elsewhere"})
	rep := newAPIReachReport(got, []string{""}, "zap_pre_shutdown")

	if rep.UnreachedPaths != maxNamedReachPaths+13 {
		t.Errorf("the count must be whole, got %d", rep.UnreachedPaths)
	}
	if len(rep.Unreached) != maxNamedReachPaths {
		t.Errorf("the list must be bounded, got %d names", len(rep.Unreached))
	}
	if rep.UnreachedNotNamed != 13 {
		t.Errorf("want the unnamed remainder stated, got %d", rep.UnreachedNotNamed)
	}
	if rep.DeclaredPaths != rep.ReachedPaths+rep.UnreachedPaths {
		t.Errorf("the two must partition the declared set: %d != %d + %d",
			rep.DeclaredPaths, rep.ReachedPaths, rep.UnreachedPaths)
	}
}

func TestReachIsMeasuredInPathsAndNeverInOperations(t *testing.T) {
	// EndpointsFromSpec counts operations; this counts paths. One path with
	// four methods is one thing to reach, and mixing the two units is how a
	// ratio between different things gets read as a coverage percentage.
	doc := []byte(`{"paths":{"/api/tasks":{"get":{},"post":{},"put":{},"delete":{}}}}`)
	ops, err := countOpenAPIOperations(doc)
	if err != nil || ops != 4 {
		t.Fatalf("want 4 operations, got %d (%v)", ops, err)
	}
	got := reach(openAPIPaths(doc), openAPIServerPrefixes(doc), []string{"http://app/api/tasks"})
	rep := newAPIReachReport(got, nil, "")
	if rep.DeclaredPaths != 1 || rep.ReachedPaths != 1 {
		t.Errorf("want 1 declared path fully reached, got %#v", rep)
	}
}

func TestTheReportCarriesWhatWasComparedSoAVerdictCanBeDisputed(t *testing.T) {
	got := reach([]string{"/pets"}, []string{"/v2", ""}, []string{"http://app/v2/pets"})
	rep := newAPIReachReport(got, []string{"/v2", ""}, "pre_exit")
	if len(rep.ServerPrefixes) != 2 {
		t.Errorf("want the prefixes recorded, got %#v", rep.ServerPrefixes)
	}
	if rep.Trigger != "pre_exit" {
		t.Errorf("want the trigger recorded so a salvaged list is recognisable, got %q", rep.Trigger)
	}
}

// The tests below were written against review findings on the original pull request. Each one
// fails on the implementation as first written.

func TestAPathServedByAnotherHostIsNotReachOfThisOne(t *testing.T) {
	// ZAP's site tree holds every host it proxied, redirects included. Without
	// an origin check, an external host answering /api/tasks marks the
	// target's declared /api/tasks reached — a declared endpoint credited to a
	// request nobody made to the application under test.
	got := reachFrom("http://app:5000", []string{"/api/tasks"}, []string{""},
		[]string{"http://evil.example/api/tasks"})
	if len(got.Reached) != 0 {
		t.Errorf("a foreign host must not satisfy a declared path, got reached %v", got.Reached)
	}
	if joined(got.OffOrigin) != "evil.example" {
		t.Errorf("the excluded host must be named, got %v", got.OffOrigin)
	}
	if len(got.Extra) != 0 {
		t.Errorf("an off-origin URL is excluded, not counted as an unexplained request, got %v", got.Extra)
	}
}

func TestTheSameHostOnAnotherSchemeOrPortIsStillTheTarget(t *testing.T) {
	// An app that redirects http to https is the same app, and a deployment
	// answering on two ports is the same deployment. Matching strictly here
	// would report a reached API as unreached, which is the louder failure.
	got := reachFrom("http://app:5000", []string{"/api/tasks", "/api/projects"}, []string{""},
		[]string{"https://app/api/tasks", "http://app:8080/api/projects"})
	if len(got.Unreached) != 0 {
		t.Errorf("scheme and port must not decide origin, got unreached %v", got.Unreached)
	}
	if len(got.OffOrigin) != 0 {
		t.Errorf("same host is not off-origin, got %v", got.OffOrigin)
	}
}

func TestATargetCicdCannotParseFiltersNothing(t *testing.T) {
	// cicd cannot say which origin is the target's, and inventing one would
	// turn every requested path into an off-origin one and a complete scan
	// into a reported non-run.
	for _, target := range []string{"", "   ", "::not a url"} {
		got := reachFrom(target, []string{"/api/tasks"}, []string{""},
			[]string{"http://anywhere/api/tasks"})
		if len(got.Reached) != 1 {
			t.Errorf("target %q: want no filtering, got reached %v", target, got.Reached)
		}
	}
}

func TestTheTargetsOwnPathIsAPrefixTheDocumentNeverMentions(t *testing.T) {
	// Measured on the pinned image: -O http://probe-target:8000/service makes
	// ZAP request /service/api/tasks for a document that declares /api/tasks.
	// Reading only servers[] compares the two, matches nothing, and reports a
	// fully scanned API as entirely unreached.
	doc := []byte(`{"servers":[{"url":"http://localhost:5000"}],"paths":{"/api/tasks":{"get":{}}}}`)
	prefixes := apiReachPrefixes(doc, "http://probe-target:8000/service")
	got := reachFrom("http://probe-target:8000", openAPIPaths(doc), prefixes,
		[]string{"http://probe-target:8000/service/api/tasks"})
	if len(got.Unreached) != 0 {
		t.Errorf("the target's path prefix must be tried, got unreached %v", got.Unreached)
	}
	if got.Reached[0] != "/api/tasks" {
		t.Errorf("the path is still named as the document wrote it, got %v", got.Reached)
	}
}

func TestATargetWithNoPathAddsNoPrefix(t *testing.T) {
	doc := []byte(`{"paths":{"/api/tasks":{"get":{}}}}`)
	for _, target := range []string{"http://app:5000", "http://app:5000/", ""} {
		if joined(apiReachPrefixes(doc, target)) != "" {
			t.Errorf("target %q: want only the empty prefix, got %v", target, apiReachPrefixes(doc, target))
		}
	}
}

func TestTheTargetPathIsNotAddedTwice(t *testing.T) {
	// The document and the target can agree. A duplicate prefix costs a reader
	// nothing but makes serverPrefixes read as though two things were tried.
	doc := []byte(`{"servers":[{"url":"https://prod.example/service"}],"paths":{"/api/tasks":{"get":{}}}}`)
	got := apiReachPrefixes(doc, "http://app:5000/service")
	if joined(got) != "/service " {
		t.Errorf("want /service once and the empty prefix last, got %v", got)
	}
}

func TestAConcretePathTakesPrecedenceOverTheTemplateThatWouldAlsoMatch(t *testing.T) {
	// OpenAPI routes /pets/special to the declared /pets/special, not to
	// /pets/{id}. Crediting both means an API whose /pets/{id} was never
	// requested reports it reached and the gap warning never fires.
	got := reach([]string{"/pets/special", "/pets/{id}"}, []string{""},
		[]string{"http://app/pets/special"})
	if joined(got.Reached) != "/pets/special" {
		t.Errorf("only the concrete path is reached, got %v", got.Reached)
	}
	if joined(got.Unreached) != "/pets/{id}" {
		t.Errorf("the template was never requested, got %v", got.Unreached)
	}
}

func TestAConcreteRequestStillReachesTheTemplateWhenNoLiteralDeclaresIt(t *testing.T) {
	got := reach([]string{"/pets/special", "/pets/{id}"}, []string{""},
		[]string{"http://app/pets/17"})
	if joined(got.Reached) != "/pets/{id}" {
		t.Errorf("a value no literal claims routes to the template, got %v", got.Reached)
	}
}

func TestTwoTemplatesThatCannotBeToldApartAreBothCredited(t *testing.T) {
	// OpenAPI leaves an ambiguous template match to tooling. Over-crediting
	// two declarations that genuinely cannot be distinguished is honest;
	// picking one by an order cicd invented is not.
	got := reach([]string{"/pets/{id}", "/pets/{name}"}, []string{""},
		[]string{"http://app/pets/17"})
	if len(got.Reached) != 2 {
		t.Errorf("want both indistinguishable templates credited, got %v", got.Reached)
	}
}

func TestAnUnreadEntryWeakensTheClaimWithoutSilencingIt(t *testing.T) {
	// Suppressing the warning would let one malformed site-tree entry hide a
	// real gap — the silence this whole change exists to end. The sentence
	// reports what cicd saw instead of what ZAP did.
	r := apiReach{
		Reached:   []string{"/api/tasks"},
		Unreached: []string{"/api/projects"},
		Unparsed:  1,
	}
	got := apiReachWarnings(r)
	var gap string
	for _, w := range got {
		if strings.Contains(w, "ENDPOINTS NOT REACHED") {
			gap = w
		}
	}
	if gap == "" {
		t.Fatalf("the gap must still be named, got %v", got)
	}
	if !strings.Contains(gap, "/api/projects") {
		t.Errorf("the unreached path must still be named, got %q", gap)
	}
	if strings.Contains(gap, "were never asked for") {
		t.Errorf("with an entry unread, cicd cannot claim ZAP never asked: %q", gap)
	}
	if !strings.Contains(gap, "unreadable") {
		t.Errorf("the sentence must say why it is hedged, got %q", gap)
	}
}

func TestAFullyReadTreeMakesTheFlatClaim(t *testing.T) {
	r := apiReach{Reached: []string{"/api/tasks"}, Unreached: []string{"/api/projects"}}
	got := apiReachWarnings(r)
	if len(got) != 1 || !strings.Contains(got[0], "were never asked for") {
		t.Errorf("with every entry read the claim is a fact about the scan, got %v", got)
	}
}

func TestExcludedOriginsAreDisclosedAndCarriedInTheReport(t *testing.T) {
	r := apiReach{Reached: []string{"/api/tasks"}, OffOrigin: []string{"cdn.example"}}
	got := apiReachWarnings(r)
	if len(got) != 1 || !strings.Contains(got[0], "OFF-ORIGIN URLS EXCLUDED") ||
		!strings.Contains(got[0], "cdn.example") {
		t.Errorf("an excluded input must be named, got %v", got)
	}
	if joined(newAPIReachReport(r, nil, "").OffOriginHosts) != "cdn.example" {
		t.Errorf("the report must carry the excluded hosts")
	}
}

func TestReachIsSilentWhenThereIsNothingToDisclose(t *testing.T) {
	// A disclosure on a run with nothing to disclose is the noise that makes
	// every other run unreadable.
	if got := apiReachWarnings(apiReach{Reached: []string{"/api/tasks"}}); len(got) != 0 {
		t.Errorf("want silence, got %v", got)
	}
}
