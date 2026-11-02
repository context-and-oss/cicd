// Which declared endpoints ZAP actually requested, and which it never touched.
//
// The counts zapscope.go reads say how much ZAP reached. They cannot say what
// it reached, and the difference is the whole point: a run against a
// consumer's API fetched a ~400-operation document, alerted on under twenty URLs,
// and every one of them was the swagger surface or one of ZAP's own probe
// paths. Not a single /api/ URL appeared anywhere in the evidence, and nothing
// in the envelope said so — the scan exited 0, the report described a site,
// and "no findings" read as "clean".
//
// A count would not have caught it either. Under twenty alerted URLs against a
// ~400-operation document is a ratio, and a ratio needs a threshold, and a
// threshold is a number nobody can defend: a document with many methods on few
// paths is healthy and looks like a gap. Naming the paths needs no threshold.
// Either ZAP asked the target for a path or it did not.
//
// Deliberately untagged (no //go:build !unit_test).
package main

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// apiReach is the reconciliation: what the document declared, set against what
// ZAP asked for.
type apiReach struct {
	// Reached and Unreached partition the declared paths, named as the
	// document names them — the template, not the concrete URL ZAP generated
	// from it, because the template is what a reader can find in their own
	// source.
	Reached   []string
	Unreached []string
	// Extra is every path ZAP requested that no declared path explains: the
	// swagger UI, ZAP's own probes for /robots.txt and /api/actuator/health,
	// anything a redirect led to. It is kept because it is the evidence that
	// ZAP was alive and requesting things — an empty Reached beside a
	// populated Extra is a scan that ran and missed the API, which is a
	// different diagnosis from a scan that never started.
	Extra []string
	// Unparsed counts requested entries that were not URLs. Counted rather
	// than dropped: silently discarding an input is how a reconciliation
	// starts disagreeing with the tree it reconciled.
	Unparsed int
	// OffOrigin names the hostnames in ZAP's site tree that are not the scan
	// target's. Their paths took no part in the reconciliation; recording them
	// keeps an excluded input visible rather than silently dropped, which is
	// the same rule Unparsed follows.
	OffOrigin []string
}

// apiPathParam matches one OpenAPI path templating group.
//
// ZAP does not request the template; its OpenAPI importer generates a concrete
// value per parameter and requests that. Measured against the pinned image
// (zaproxy 2.17.0) on a document declaring /api/tasks/{id} with an integer id
// and /api/projects/{projectId}/members with a string projectId, ZAP requested:
//
//	http://host:8000/api/tasks/10
//	http://host:8000/api/projects/projectId/members
//
// So an integer parameter becomes a number and a string parameter becomes the
// parameter's own name. Neither is predictable enough to generate and compare,
// and both are one path segment, which is.
var apiPathParam = regexp.MustCompile(`\{[^/{}]*\}`)

// apiPathPattern turns a declared path template into a pattern that matches
// the concrete paths ZAP generates from it.
//
// Each templating group becomes [^/]+ — one or more characters that are not a
// separator. Not [^/]* : a generated value is never empty, and allowing empty
// would make /api/tasks/{id} match /api/tasks/, reporting an endpoint as
// reached on the strength of a request for its parent collection. That is a
// false green in the exact place this file exists to prevent one.
//
// Everything outside a group is quoted, so a document declaring a path with a
// regexp metacharacter in it — a dot in a file extension, a plus in a matrix
// parameter — is matched literally rather than loosely.
func apiPathPattern(template string) *regexp.Regexp {
	var sb strings.Builder
	sb.WriteString(`\A`)
	last := 0
	for _, loc := range apiPathParam.FindAllStringIndex(template, -1) {
		sb.WriteString(regexp.QuoteMeta(template[last:loc[0]]))
		sb.WriteString(`[^/]+`)
		last = loc[1]
	}
	sb.WriteString(regexp.QuoteMeta(template[last:]))
	sb.WriteString(`\z`)
	// The pattern is assembled from quoted literals and a fixed class, so it
	// always compiles; MustCompile states that rather than returning an error
	// no caller could act on.
	return regexp.MustCompile(sb.String())
}

// normalizeAPIPath puts a path in the one shape both sides are compared in.
//
// A leading slash is added and a trailing one removed, because "/api/tasks"
// and "/api/tasks/" are the same endpoint to every server cicd will meet and
// the document and the scanner disagree about which to write. The root is the
// exception: trimming it to "" would make every declared path a suffix of
// nothing.
func normalizeAPIPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	for len(p) > 1 && strings.HasSuffix(p, "/") {
		p = strings.TrimSuffix(p, "/")
	}
	return p
}

// requestedAPIPaths reduces the URLs ZAP requested to normalized paths, keeping
// only the ones the scan target itself served.
//
// The query string is dropped: two requests for the same endpoint with
// different parameters are one endpoint, and an endpoint is what the document
// declares.
//
// The host is dropped only after it has been checked. ZAP's site tree holds
// every host it proxied, redirects included, so an external host answering
// /api/tasks would otherwise mark the target's declared /api/tasks reached —
// a path credited to a request nobody made to the application under test,
// which is the false green this file exists to prevent. Off-origin hosts are
// counted and named rather than dropped in silence, for the same reason
// unparsed entries are.
//
// The comparison is on hostname alone: not the scheme, because an app that
// redirects http to https is the same app, and not the port, because a
// deployment answering on two ports is the same deployment. A different
// hostname is the case worth refusing, and matching loosely here risks only a
// credited request, while matching strictly risks reporting a reached API as
// unreached — a red build caused by cicd's own accounting.
//
// An unparseable or empty target means no filtering at all. cicd cannot say
// which origin is the target's, and inventing one would turn every requested
// path into an off-origin one and the whole API into a non-run.
func requestedAPIPaths(urls []string, targetURL string) (paths []string, unparsed int, offOrigin []string) {
	want := requestHost(targetURL)
	seen := map[string]bool{}
	seenHost := map[string]bool{}
	for _, raw := range urls {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			unparsed++
			continue
		}
		if want != "" {
			got := strings.ToLower(u.Hostname())
			if got != "" && got != want {
				if !seenHost[got] {
					seenHost[got] = true
					offOrigin = append(offOrigin, got)
				}
				continue
			}
		}
		p := normalizeAPIPath(u.Path)
		if p == "" {
			// A URL with no path at all is a request for the root, which is
			// what the seed URL is. It is a real request and belongs in the
			// set, under the name every other root request has.
			p = "/"
		}
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	sort.Strings(offOrigin)
	return paths, unparsed, offOrigin
}

// requestHost is the lowercased hostname of a URL cicd holds, or "" when there
// is none to compare against.
func requestHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// openAPIServerPrefixes lists the path prefixes a document's own server
// declarations put in front of every path it declares.
//
// Without this the reconciliation compares "/pets" against a request for
// "/v2/pets" and reports an endpoint ZAP reached as unreached. OpenAPI 3 puts
// it in servers[].url, which may be a full URL or a bare path; Swagger 2 puts
// it in basePath. Both are read, because cicd accepts whichever document the
// consumer serves and the two spellings are the same fact.
//
// The empty prefix is always included, and always last. A servers[] entry is
// frequently a production URL with a path the local deployment does not have,
// and -O replaces the host without touching the path — so a declared prefix is
// a candidate and never a requirement, and a path that matches with no prefix
// is reached no matter what the document claims about where it lives.
func openAPIServerPrefixes(raw []byte) []string {
	var doc struct {
		Servers []struct {
			URL string `json:"url"`
		} `json:"servers"`
		BasePath string `json:"basePath"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return []string{""}
	}

	var out []string
	seen := map[string]bool{"": true}
	add := func(s string) {
		p := normalizeAPIPath(serverURLPath(s))
		if p == "" || p == "/" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, s := range doc.Servers {
		add(s.URL)
	}
	add(doc.BasePath)

	sort.Strings(out)
	return append(out, "")
}

// apiReachPrefixes is every path prefix the reconciliation will try: the ones
// the document declares, and the one the scan's own target URL carries.
//
// The target's path is not optional decoration. Measured on the pinned image:
// with -O http://probe-target:8000/service against a document declaring
// /api/tasks, ZAP requested http://probe-target:8000/service/api/tasks. The
// override's path is prepended to every imported path, and the document says
// nothing about it — so a reconciliation reading only servers[] compares
// /api/tasks against /service/api/tasks, matches nothing, and reports an API
// ZAP scanned completely as entirely unreached. That is a false red on every
// consumer whose target URL has a path, and it is louder than the false green
// this file was written to stop.
func apiReachPrefixes(raw []byte, targetURL string) []string {
	prefixes := openAPIServerPrefixes(raw)
	p := normalizeAPIPath(serverURLPath(targetURL))
	if p == "" || p == "/" {
		return prefixes
	}
	for _, have := range prefixes {
		if have == p {
			return prefixes
		}
	}
	// Ahead of the empty prefix, which stays last, and ahead of the document's
	// own claims, which describe where the API lives in production rather than
	// where this scan pointed.
	return append([]string{p}, prefixes...)
}

// serverURLPath is the path component of a servers[] entry, which may be an
// absolute URL, a bare path, or a template like https://{host}/v2. A template
// is not resolvable here, so only its path survives — which is the part that
// matters and the part templating rarely touches.
func serverURLPath(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		return u.Path
	}
	if strings.Contains(s, "://") {
		// A scheme cicd could not parse, usually because of a {template} in
		// the host. Take everything after the authority by hand rather than
		// treating the whole string as a path, which would prefix every
		// declared path with "https:/example.com".
		rest := s[strings.Index(s, "://")+3:]
		if i := strings.Index(rest, "/"); i >= 0 {
			return rest[i:]
		}
		return ""
	}
	return s
}

// reconcileAPIReach partitions the declared paths by whether ZAP requested
// them, and names the requests no declared path explains.
//
// It routes each request the way a server would, rather than asking each
// declared path whether anything matched it. The difference is the concrete
// path: a request for /pets/special is a request for the declared /pets/special
// and not for the declared /pets/{id}, and OpenAPI says so — a concrete path
// takes precedence over a templated one that would also match. Asking per
// declared path credited both, so an API whose /pets/{id} was never requested
// reported it reached and the gap warning never fired.
//
// Among templates there is no precedence and none is invented: OpenAPI leaves
// an ambiguous template match to tooling, so a request matching /pets/{id} and
// /pets/{name} credits both. Over-crediting two declarations that genuinely
// cannot be told apart is honest; picking one by an order cicd made up is not.
//
// Matching stays one-directional: a declared path is a claim about what exists,
// a requested path is a fact about what happened, and only the first can be
// missing from the second in a way that matters.
func reconcileAPIReach(declared []string, prefixes []string, requested []string) apiReach {
	var out apiReach
	if len(prefixes) == 0 {
		prefixes = []string{""}
	}

	type declaredPath struct {
		Norm      string
		Literals  map[string]bool
		Patterns  []*regexp.Regexp
		Templated bool
		Reached   bool
	}

	var paths []*declaredPath
	seen := map[string]bool{}
	for _, d := range declared {
		norm := normalizeAPIPath(d)
		if norm == "" || seen[norm] {
			continue
		}
		seen[norm] = true
		dp := &declaredPath{
			Norm:      norm,
			Literals:  map[string]bool{},
			Templated: apiPathParam.MatchString(norm),
		}
		for _, prefix := range prefixes {
			spelling := normalizeAPIPath(prefix + norm)
			if dp.Templated {
				dp.Patterns = append(dp.Patterns, apiPathPattern(spelling))
			} else {
				dp.Literals[spelling] = true
			}
		}
		paths = append(paths, dp)
	}

	for _, r := range requested {
		var concrete []*declaredPath
		for _, dp := range paths {
			if dp.Literals[r] {
				concrete = append(concrete, dp)
			}
		}
		if len(concrete) > 0 {
			for _, dp := range concrete {
				dp.Reached = true
			}
			continue
		}
		matched := false
		for _, dp := range paths {
			for _, re := range dp.Patterns {
				if re.MatchString(r) {
					dp.Reached = true
					matched = true
					break
				}
			}
		}
		if !matched {
			out.Extra = append(out.Extra, r)
		}
	}

	for _, dp := range paths {
		if dp.Reached {
			out.Reached = append(out.Reached, dp.Norm)
		} else {
			out.Unreached = append(out.Unreached, dp.Norm)
		}
	}

	sort.Strings(out.Reached)
	sort.Strings(out.Unreached)
	sort.Strings(out.Extra)
	return out
}

// maxNamedReachPaths bounds the lists the envelope carries.
//
// The counts beside them are always exact, so the bound costs a reader names
// and never the size of the gap. It exists because a full scan of a large
// application requests tens of thousands of URLs, and an evidence envelope
// that cannot be opened is a disclosure nobody reads.
const maxNamedReachPaths = 200

// apiReachReport is the reconciliation as the envelope carries it.
//
// It is a pointer on the payload, and the pointer is the claim: absent means
// no reconciliation was attempted or it could not be, which the warnings say
// in words. Present means cicd compared the two lists, and then every count in
// here is a real number rather than a zero standing in for silence.
type apiReachReport struct {
	// DeclaredPaths is how many paths the document declared — paths, not
	// operations. EndpointsFromSpec counts operations, and the two differ by
	// however many methods each path carries, which is why they are separate
	// fields and never subtracted from one another.
	DeclaredPaths  int `json:"declaredPaths"`
	ReachedPaths   int `json:"reachedPaths"`
	UnreachedPaths int `json:"unreachedPaths"`
	// Unreached names the paths ZAP never requested, up to maxNamedReachPaths,
	// and UnreachedNotNamed says how many more there were.
	Unreached         []string `json:"unreached,omitempty"`
	UnreachedNotNamed int      `json:"unreachedNotNamed,omitempty"`
	// Unexplained names paths ZAP requested that the document does not
	// declare, and UnexplainedPaths counts them all. They are the proof the
	// scan was alive: zero reached beside a populated list here is a scan that
	// ran and missed the API entirely, which is what happened on the run this
	// change was written for.
	UnexplainedPaths    int      `json:"unexplainedPaths"`
	Unexplained         []string `json:"unexplained,omitempty"`
	UnexplainedNotNamed int      `json:"unexplainedNotNamed,omitempty"`
	// ServerPrefixes is every path prefix the reconciliation tried, so a
	// reader who disagrees with the verdict can see what was compared.
	ServerPrefixes []string `json:"serverPrefixes,omitempty"`
	// Trigger is the ZAP hook trigger the URL list came from. A list salvaged
	// at pre_exit came from a scan that did not finish normally.
	Trigger string `json:"trigger,omitempty"`
	// UnparsedURLs counts entries in ZAP's site tree that were not URLs.
	UnparsedURLs int `json:"unparsedUrls,omitempty"`
	// OffOriginHosts names hosts in ZAP's site tree that are not the scan
	// target — reached through a redirect, usually. Their paths were excluded
	// from the reconciliation, and naming them is what keeps that exclusion
	// auditable instead of invisible.
	OffOriginHosts []string `json:"offOriginHosts,omitempty"`
}

// newAPIReachReport bounds the lists and keeps the counts whole.
func newAPIReachReport(r apiReach, prefixes []string, trigger string) *apiReachReport {
	out := &apiReachReport{
		DeclaredPaths:    len(r.Reached) + len(r.Unreached),
		ReachedPaths:     len(r.Reached),
		UnreachedPaths:   len(r.Unreached),
		UnexplainedPaths: len(r.Extra),
		ServerPrefixes:   prefixes,
		Trigger:          strings.TrimSpace(trigger),
		UnparsedURLs:     r.Unparsed,
		OffOriginHosts:   r.OffOrigin,
	}
	out.Unreached, out.UnreachedNotNamed = capPaths(r.Unreached)
	out.Unexplained, out.UnexplainedNotNamed = capPaths(r.Extra)
	return out
}

func capPaths(in []string) (named []string, notNamed int) {
	if len(in) <= maxNamedReachPaths {
		return in, 0
	}
	return in[:maxNamedReachPaths], len(in) - maxNamedReachPaths
}

// maxSentencePaths is how many paths a warning or error sentence names inline.
// The envelope carries up to maxNamedReachPaths; a PR comment is read by a
// human, and a sentence with two hundred paths in it is not read at all.
const maxSentencePaths = 10

// apiReachError is the non-run verdict: ZAP requested none of the paths the
// document declares.
//
// This is the founding doctrine in its original shape. The scan exited a
// status that means "no findings", it left a report describing a site, and
// every rule it ran examined a surface the document does not declare — so the
// clean result is clean about something nobody asked to be scanned. It is an
// errors[] entry and therefore passed=false at every threshold including NONE,
// because NONE suppresses failure over findings and this is not a finding.
//
// Zero and not a ratio. A partial gap is a warning (see apiReachWarnings)
// because an OpenAPI document routinely declares paths ZAP's importer
// legitimately skips, and failing over those would red a scan that genuinely
// ran; there is no honest threshold between "some" and "most". Zero is not a
// point on that scale — it is the scan not having happened.
func apiReachError(r apiReach) string {
	if len(r.Unreached) == 0 || len(r.Reached) > 0 {
		return ""
	}
	msg := "dast: API NOT REACHED — ZAP requested none of the " +
		plural(len(r.Unreached), "path", "paths") + " the API document declares, " +
		"so this scan's result describes no endpoint the document names"
	if len(r.Extra) > 0 {
		msg += ". It did request " + plural(len(r.Extra), "other path", "other paths") +
			" (" + namePaths(r.Extra) + "), so ZAP was running and the document's paths " +
			"never entered its site tree"
	}
	return msg + ". Unreached: " + namePaths(r.Unreached)
}

// apiReachWarnings states a partial gap, and the accounting cicd could not do.
//
// Silent when every declared path was reached: a disclosure on a run with
// nothing to disclose is the noise that makes the other runs unreadable.
func apiReachWarnings(r apiReach) []string {
	var out []string
	if len(r.Unreached) > 0 && len(r.Reached) > 0 {
		msg := "dast: ENDPOINTS NOT REACHED — ZAP requested " +
			strconv.Itoa(len(r.Reached)) + " of the " +
			strconv.Itoa(len(r.Reached)+len(r.Unreached)) +
			" path(s) the API document declares. "
		// The claim is weakened exactly as far as the evidence was. With every
		// site-tree entry read, "never asked for" is a fact about the scan;
		// with entries unread, one of them may have been a request for a path
		// named here, so the sentence reports what cicd saw rather than what
		// ZAP did. It is not suppressed: a real gap going unnamed because one
		// entry was malformed is the silence this whole change exists to end.
		if r.Unparsed > 0 {
			msg += "cicd saw no request for the rest, so this scan evidences nothing about them — " +
				"though " + plural(r.Unparsed, "site-tree entry was", "site-tree entries were") +
				" unreadable and may have been a request for one of them: "
		} else {
			msg += "The rest were never asked for, so no rule ran against them and this scan " +
				"says nothing about them: "
		}
		out = append(out, msg+namePaths(r.Unreached))
	}
	if r.Unparsed > 0 {
		out = append(out, "dast: SITE TREE PARTLY UNREAD — "+
			plural(r.Unparsed, "entry", "entries")+" in ZAP's site tree could not be read as a URL "+
			"and took no part in the reconciliation, so the reached count is a floor.")
	}
	if len(r.OffOrigin) > 0 {
		out = append(out, "dast: OFF-ORIGIN URLS EXCLUDED — ZAP's site tree holds "+
			plural(len(r.OffOrigin), "host", "hosts")+" that are not the scan target ("+
			namePaths(r.OffOrigin)+"). Their paths were not counted as reach, because a path "+
			"served by another host is not the declared endpoint of this one.")
	}
	return out
}

// namePaths renders up to maxSentencePaths of them, and says how many it left
// out. It never renders none: a sentence about paths that names no path is a
// sentence a reader cannot act on.
func namePaths(paths []string) string {
	if len(paths) == 0 {
		return "none"
	}
	shown := paths
	var tail string
	if len(shown) > maxSentencePaths {
		shown = shown[:maxSentencePaths]
		tail = ", and " + strconv.Itoa(len(paths)-maxSentencePaths) + " more"
	}
	return strings.Join(shown, ", ") + tail
}

func plural(n int, one, many string) string {
	if n == 1 {
		return strconv.Itoa(n) + " " + one
	}
	return strconv.Itoa(n) + " " + many
}
