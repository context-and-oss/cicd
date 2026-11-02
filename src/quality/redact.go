// Credential scrubbing for tool output that is about to be quoted into an
// evidence envelope. Untagged so `go test -tags unit_test` reaches it.
//
// src/risk/redact.go is the sibling, not a copy: it scrubs the *value* of a
// suspected secret assignment out of a finding snippet while keeping the key,
// because triage needs to see what was assigned; this file removes the whole
// credential shape from quoted tool output, where nothing downstream needs
// the key either.
package main

import "regexp"

// credentialPlaceholder is what a matched credential becomes. Fixed-width and
// obviously synthetic, so a reader knows something was there and that cicd
// removed it — an edited line that looks unedited is the quieter failure.
const credentialPlaceholder = "***"

// credentialPatterns are the shapes a credential takes when a .NET tool echoes
// it. The list is deliberately pattern-based rather than value-based: the quality
// module hands feed tokens to NuGet as *dagger.Secret and never holds their
// plaintext, so it cannot do what notify's scrubSecrets does and replace a known
// value. What it can know is the shape of the places a secret appears in
// `dotnet` output:
//
//   - a feed URL carrying userinfo (`https://user:pat@pkgs.dev.azure.com/…`) in
//     a NuGet restore error — "Unable to load the service index for source …";
//   - an `Authorization: Bearer …` / `Basic …` header echoed by a transport
//     diagnostic;
//   - a `key=value` or NuGet.Config `<add key="ClearTextPassword" value="…"/>`
//     pair naming the value as a password, token or API key;
//   - the fixed prefixes of GitHub tokens (`ghp_`, `github_pat_`) and NuGet.org
//     API keys (`oy2` + 43 chars), and the 52-character lowercase alphanumeric
//     shape of a classic Azure DevOps PAT.
//
// Every pattern here trades over-redaction for under-redaction on purpose. A
// parser message reading `token: expected ']'` loses the word after the colon; a
// 52-character lowercase hash loses itself. Both cost a reader one word of a
// diagnostic whose full shape is still visible. The alternative failure — a PAT
// in an audit bundle that a whole team can download — is not one word.
//
// The last pattern's floor is 52 exactly, not "long": a 40-character git SHA and
// a 64-character SHA-256 pass through untouched, because \b on both sides makes
// the width exact.
var credentialPatterns = []struct {
	re   *regexp.Regexp
	repl string
}{
	// URL userinfo. The host part excludes ':' so `https://host:8080/path` (a port,
	// not a password) is not matched — the '@' is what makes it userinfo.
	{regexp.MustCompile(`(?i)\b(https?|ftp)://[^\s/@:]+:[^\s/@]+@`), "$1://" + credentialPlaceholder + ":" + credentialPlaceholder + "@"},
	// Bearer and Basic authorization values.
	{regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`), "$1 " + credentialPlaceholder},
	// Named secret assignments: `password=…`, `_authToken: …`, `apikey=…`, and the
	// NuGet.Config attribute form `key="ClearTextPassword" value="…"`. The name
	// must stand as its own word, so CancellationToken is not a token and
	// `passwordless` is not a password.
	{regexp.MustCompile(`(?i)\b(password|passwd|pwd|cleartextpassword|apikey|api[_-]key|_authToken|authToken|access[_-]?token|token|secret|pat)\b("?\s*value\s*=\s*"|\s*[:=]\s*"?)[^\s"'<>&;,]+`), "$1$2" + credentialPlaceholder},
	// GitHub token families.
	{regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b`), credentialPlaceholder},
	{regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`), credentialPlaceholder},
	// NuGet.org API key.
	{regexp.MustCompile(`\boy2[a-z0-9]{43}\b`), credentialPlaceholder},
	// Classic Azure DevOps PAT: 52 lowercase alphanumerics, exactly.
	{regexp.MustCompile(`\b[a-z0-9]{52}\b`), credentialPlaceholder},
}

// scrubCredentials replaces anything in s shaped like a credential with
// credentialPlaceholder and reports whether it changed anything, so the caller
// can say in the evidence that the text was edited. Applied to every line of
// tool output this module quotes into an envelope — the tail it keeps, the
// diagnostics it lists, and the single line dotnetDiagnosticLine picks.
func scrubCredentials(s string) (string, bool) {
	out := s
	for _, p := range credentialPatterns {
		out = p.re.ReplaceAllString(out, p.repl)
	}
	return out, out != s
}
