// vuln-app is cicd's DAST fixture: a deliberately vulnerable HTTP server whose
// findings are known in advance, so the DAST leg can be proven against a target
// this repository controls rather than against a host on the public internet.
//
// Do not deploy this. Every defect here is planted; see README.md for the list
// and for which scan mode is expected to report each one.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", health)
	mux.HandleFunc("/api/items", items)
	mux.HandleFunc("/openapi.json", openapi)
	mux.HandleFunc("/greet", greet)
	mux.HandleFunc("/", index)

	log.Printf("vuln-app listening on :%s", port)
	srv := &http.Server{Addr: ":" + port, Handler: leakServerHeader(mux)}
	log.Fatal(srv.ListenAndServe())
}

// leakServerHeader plants "Server Leaks Version Information" (passive, LOW) on
// every response. Go's net/http sends no Server header of its own, so without
// this the rule has nothing to fire on.
func leakServerHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "vuln-app/0.1.0")
		next.ServeHTTP(w, r)
	})
}

// health is the readiness endpoint and is deliberately free of planted defects.
// The reachability probe hits this path, so a defect here would make a probe
// failure and a finding indistinguishable.
func health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fmt.Fprint(w, `{"status":"ok"}`)
}

// index plants the passive header findings and a cookie with neither HttpOnly
// nor SameSite. It also links every other path, because ZAP's spider reaches
// only what the pages it fetched pointed at.
func index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	// Planted: no Content-Security-Policy, no X-Frame-Options, no
	// X-Content-Type-Options. Planted: a session cookie with no HttpOnly, no
	// Secure and no SameSite.
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "fixture-session-value", Path: "/"})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html>
<html lang="en">
<head><title>vuln-app</title></head>
<body>
<h1>vuln-app</h1>
<p>cicd DAST fixture. Every defect here is planted.</p>
<ul>
  <li><a href="/greet?name=world">greet</a></li>
  <li><a href="/api/items">items</a></li>
  <li><a href="/openapi.json">openapi</a></li>
  <li><a href="/health">health</a></li>
</ul>
<form action="/greet" method="get">
  <input type="text" name="name" value="world">
  <input type="submit" value="Greet">
</form>
</body>
</html>`)
}

// greet plants the reflected XSS an active scan finds and a passive one cannot.
// The parameter is written into the response body with no escaping at all.
func greet(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html>
<html lang="en">
<head><title>greet</title></head>
<body><h1>Hello, %s</h1><p><a href="/">back</a></p></body>
</html>`, name)
}

func items(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"items":[{"id":1,"name":"first"},{"id":2,"name":"second"}]}`)
}

// openapi serves the document mode=api can be driven from, so the api scan can
// be proven without a checked-in spec file as well as with one.
func openapi(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, openapiDoc)
}
