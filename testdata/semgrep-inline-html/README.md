# Inline JavaScript SAST controls

These synthetic pages are intentionally not applications to run or deploy.
Their source files end in `.fixture`: the smoke copies them to temporary real
HTML/HTM/JS filenames before scanning. This keeps intentional vulnerable controls
as test data rather than presenting them to repository-wide scanners as product
code; the test still requires the production scanner to detect every control.
`unsafe/` contains four DOM-text-to-HTML findings, including a flow between
classic script blocks, an independent module script and a template script. Its ignored directory
must stay excluded. `safe/` uses text sinks, static markup, numeric conversion
and an imported DOMPurify sanitizer. Data and textarea bodies are inert; template
scripts are scanned separately because cloning can activate them.

`scripts/smoke/semgrep-inline.sh` scans both with the production source module,
checks original HTML locations and the normal evidence verdict, and exercises
partial parsing, source redaction and custom-only rule selection.
