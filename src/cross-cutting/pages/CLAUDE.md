# cross-cutting/pages

Generates a self-contained static site from `combined-evidence.json` for deployment to GitHub Pages.

## Entry function

```go
func (m *Pages) Build(ctx context.Context, evidence *dagger.File) (*dagger.Directory, error)
// Returns directory with: index.html (self-contained — no external deps)
```

## Run locally

```sh
cd src/cross-cutting/pages && dagger develop   # once

echo '{"schemaVersion":"1.0.0","moduleName":"cross-cutting/evidence","stage":"cross-cutting","tool":{"name":"cicd-evidence"},"repo":{"repoUrl":"https://github.com/example/repo","commitSha":"abc123def456","branch":"main"},"timestampUtc":"2024-01-01T00:00:00Z","durationMs":12345,"passed":true,"findingsCount":2,"findingsBySeverity":{"HIGH":2}}' \
  > /tmp/mock-evidence.json

dagger -m ./src/cross-cutting/pages call build \
  --evidence /tmp/mock-evidence.json \
  export --path /tmp/pages-out

open /tmp/pages-out/index.html
```

## Design

- The HTML template (`template.html`) is embedded via `//go:embed` at compile time — no runtime file access.
- Evidence JSON is injected into a `<script type="application/json">` tag; the
  escaping below protects that boundary, not subsequent HTML rendering.
- The page builds DOM nodes and assigns evidence through text sinks, never
  `innerHTML`. Numeric values must be finite non-negative numbers; malformed
  inputs display `Not stated`. `render_browser_test.go` executes the production
  page with clean and hostile evidence in Chrome/Chromium (required in CI).
- Every `</` in the document is written as `<\/` before injection (`render.go`,
  untagged and unit-tested): the HTML tokenizer ends script data at the first
  `</script` in any letter case, and `\/` is a JSON escape the page's own
  `JSON.parse` reads back as `/`. A document that is not JSON, or a template
  holding the `__EVIDENCE_JSON__` marker other than exactly once, is refused
  before a page is built.
- No external dependencies, no build step, no npm.

## Key files

- `main.go` — `Build()`: reads the evidence file and writes `index.html`
- `render.go` — the embedded template, the marker and `renderPage()` (untagged, unit-tested)
- `template.html` — the page; its only `__EVIDENCE_JSON__` sits inside the `id="ev"` JSON script element

## Constraints

- Does not embed `schema.go` — it reads the evidence file as raw text and passes it to the HTML. No Go-level schema parsing needed.
- Not in `SYNCED_MODULES` in the Makefile (no schema.go to sync).
