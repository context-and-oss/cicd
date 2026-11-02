# Scan inline JavaScript as code

## Why

A generated evidence page embedded its JSON safely but interpolated the parsed
values into `innerHTML`. Synthetic evidence containing an SVG load handler ran
JavaScript when the page was opened in Chrome. The embedding tests passed because
they checked the earlier script-element boundary, not the later HTML sink.

The default SAST scan also reported no finding. Two independent controls showed
why: JavaScript rules detected URL-derived HTML injection in a `.js` file but
not inside a `.html` script, and the pinned browser rules did not model the
DOM-text/JSON-to-HTML flow even when it was extracted. A scanned-file count and
a loaded-rule catalogue were not evidence that embedded JavaScript was analysed.
HTML-only pull requests additionally skipped executable CI validation.

## The mechanism

`src/security/semgrep_inline.py` consumes the ordinary scan's selected-file list.
It extracts ordinary inline JavaScript from UTF-8 HTML/HTM using a non-executing
parser, never a regex that searches an entire file for script-shaped strings.
Classic blocks share one document scope; module and template blocks are
independent. Template scripts can execute when cloned and inserted, so they are
analysed too. Data scripts, external-script bodies and inert text contexts do not
become JavaScript targets. Unsupported escaped/nested script states, foreign content,
self-closing markup and malformed source are disclosed as partial coverage.

Only selected pinned JavaScript/TypeScript rules and cicd's new
`src/security/rules/dom-text-to-html.yml` run against the extracted inputs. The
upstream rule bodies remain fetched at run time, not copied into this tree.
Custom/live rules are not rewritten onto synthetic paths. Custom-only and
secrets-only configurations keep their explicit rule selection.

The new taint rule covers DOM `textContent`/`innerText` reaching `innerHTML`,
`outerHTML` or `insertAdjacentHTML`. It models numeric conversion and supported
imports of DOMPurify. A custom escaping helper is not trusted merely because of
its name: a reviewed rule-specific suppression remains the escape hatch and is
visible through the existing suppression disclosure. This is bounded analysis,
not a promise of general equivalence to another scanner.

The adapter checks both extracted-input coverage and loaded membership. Internal
extraction, execution or mapping failures become non-runs, including at NONE;
malformed-source notifications retain the existing partial-parser-warning policy.
A failed inline pass does not discard findings from the original scan.

Byte segment maps restore original HTML paths, lines and UTF-16 columns before
the existing source-redaction boundary. Runs retain their own rule catalogues and
indices; the inline run has an explicit automation identity. Original source files
are counted once, not again as generated snippets. The evidence names the inline
scope and its limits.

`src/cross-cutting/pages/template.html` constructs DOM nodes and assigns evidence
through text sinks. Numeric values must be finite non-negative numbers; malformed
values display `Not stated`, never markup or a fabricated zero. Existing JSON
script-element escaping remains necessary and is not removed.

## Validation

The adapter's Python mechanics are invoked by the canonical Go module-unit runner.
The pinned-engine source-module smoke in `scripts/smoke/semgrep-inline.sh` checks
unsafe and safe controls, cross-block flow, module/case/Unicode handling, original
locations, exclusions, HIGH/NONE evidence verdicts, custom selection and parser
source redaction. The synthetic source inputs use `.fixture` filenames and are
materialized with real language extensions by the smoke, because intentional
positive controls are test data rather than product-code alerts. The tests still
require all unsafe controls to be found; no scanner suppression is added.
Browser tests render both clean and hostile evidence through the production page, requiring visible output and no payload execution. HTML changes
now take full CI and dogfood validation rather than a documentation exemption.

## Rejected and limits

- Moving only the page's JavaScript to a standalone file works around this one
  repository's scan gap and leaves consumers exposed to the same mechanism.
- A blanket dynamic-`innerHTML` rule would also gate ordinary sanitized markup.
- Semgrep's deprecated OSS extract mode is not a supported switch to enable.
- No second scanner, new tool image, schema or consumer flag is introduced.
- Event-handler attributes, server-side templates, framework single-file
  components and inter-module/inter-file flows are not covered by this adapter.
  It is not an HTML5-complete browser parser. The input inventory inherits
  Semgrep's existing file-size and ignore limits; the inline pass cannot recover
  a file the original scan never selected.

The separate Go allocation-arithmetic warnings are not addressed by this change.
No CodeQL setting is changed and no claim of complete scanner replacement is made.
