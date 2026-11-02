#!/usr/bin/env bash
# stage-orchestrators.sh — behavioral fixture smoke for the two stage
# orchestrators.
#
# `module-test` in ci.yml only proves stage-2/stage-4 *compile*
# (`dagger functions -m ./src/stage-N`) — that is function discovery, not
# behavioral proof: a `Run` that silently dropped a dependency (e.g. stopped
# calling risk.Validate) would still "load" and still show up in
# `dagger functions`. This script actually calls `Run` against a fixture and
# inspects the *produced evidence* for each expected dependency's trace.
#
# List-of-File chaining trick: `dagger call <fn> ... contents --json` applies
# `contents` element-wise across a []*dagger.File return and prints a JSON
# array of `{"contents": "<evidence-json-string>"}`, in return order. This
# lets us assert on every evidence envelope without needing per-element
# export/indexing.
#
# It also proves precommit and stage-2 cannot silently drift apart
# (precommit-stage2-cannot-drift): a static check that precommit still
# delegates to a single `dag.Stage2().Run` call (no direct duplicate
# composition), and that every non-positional stage-2 `Run` parameter is
# still forwarded through precommit's `Stage2RunOpts{...}` — so an option
# added to stage-2 and forgotten in precommit's passthrough fails loudly
# here instead of silently shipping a precommit pipeline that can't
# configure it.
set -uo pipefail

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || { echo "not in a git repository" >&2; exit 1; }
cd "$repo_root"

for tool in dagger python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing required command: $tool" >&2; exit 127; }
done

rc=0

# ---------------------------------------------------------------------------
# 1. Static equivalence guard: precommit cannot silently drift from stage-2.
# ---------------------------------------------------------------------------
echo "== precommit / stage-2 equivalence guard =="
# The brace group is for Semgrep: its bash parser drops a heredoc used
# directly as an if-condition, and with it the rest of the function.
if {
  python3 - <<'PY'
import re
import sys

def extract_params(path, func_sig_re, end_re):
    text = open(path).read()
    m = re.search(func_sig_re, text)
    if not m:
        print(f"FAIL: could not find Run signature in {path}", file=sys.stderr)
        sys.exit(1)
    start = m.end()
    end_m = re.search(end_re, text[start:])
    if not end_m:
        print(f"FAIL: could not find end of Run signature in {path}", file=sys.stderr)
        sys.exit(1)
    block = text[start:start + end_m.start()]
    params = []
    for line in block.splitlines():
        s = line.strip()
        if not s or s.startswith("//"):
            continue
        mm = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s+\S', s)
        if mm:
            params.append(mm.group(1))
    return params

def norm(s):
    return re.sub(r'[^a-z0-9]', '', s.lower())

precommit_text = open("src/composites/precommit/main.go").read()

failed = False

# precommit must delegate via a single dag.Stage2().Run call ...
if "dag.Stage2().Run(" not in precommit_text:
    print("FAIL: precommit/main.go no longer calls dag.Stage2().Run — "
          "it must delegate to stage-2 rather than re-composing quality/"
          "security/risk/intent directly.", file=sys.stderr)
    failed = True

# ... and must not also duplicate stage-2's own composition directly.
for direct in ("dag.Quality()", "dag.Security()", "dag.Risk()", "dag.Intent()"):
    if direct in precommit_text:
        print(f"FAIL: precommit/main.go calls {direct} directly — this "
              "duplicates stage-2's composition and can silently drift from "
              "it. Delegate via dag.Stage2().Run instead.", file=sys.stderr)
        failed = True

if failed:
    sys.exit(1)

stage2_params = extract_params(
    "src/stage-2/main.go",
    r'func \(m \*Stage2\) Run\(',
    r'\)\s*\(\[\]\*dagger\.File,\s*error\)\s*\{',
)
# context.Context is supplied by Dagger itself. It is intentionally absent
# from both the generated Stage2RunOpts type and precommit's public surface.
stage2_params = [p for p in stage2_params if norm(p) != "ctx"]

m = re.search(r'dagger\.Stage2RunOpts\{', precommit_text)
if not m:
    print("FAIL: precommit/main.go does not construct a dagger.Stage2RunOpts{} "
          "literal — cannot verify option passthrough.", file=sys.stderr)
    sys.exit(1)
start = m.end()
end = precommit_text.index("\n\t\t},", start)
opts_block = precommit_text[start:end]
opts_fields = re.findall(r'^\s*([A-Za-z0-9_]+):', opts_block, re.M)
opts_norm = {norm(f) for f in opts_fields}

# src/commitSha/branch/repoUrl are forwarded positionally, not via the opts
# struct — every other stage-2 Run parameter must appear in Stage2RunOpts.
positional = {"src", "commitsha", "branch", "repourl"}
missing = [p for p in stage2_params if norm(p) not in positional and norm(p) not in opts_norm]

if missing:
    print("FAIL: stage-2.Run gained/kept parameter(s) that precommit's "
          f"Stage2RunOpts{{}} passthrough does not forward: {missing}. "
          "precommit and stage-2 have drifted — thread the option through "
          "precommit.Run and its Stage2RunOpts{} literal.", file=sys.stderr)
    sys.exit(1)

# The opts literal alone is not enough: precommit could satisfy it by
# hardcoding a value, which forwards the option internally while silently
# removing it from the pipeline consumers actually configure. Require every
# stage-2 option to also be a parameter of precommit.Run itself.
precommit_params = extract_params(
    "src/composites/precommit/main.go",
    r'func \(m \*Precommit\) Run\(',
    r'\)\s*\(\*dagger\.Directory,\s*error\)\s*\{',
)
precommit_norm = {norm(p) for p in precommit_params}
unexposed = [p for p in stage2_params if norm(p) not in precommit_norm]

if unexposed:
    print("FAIL: stage-2.Run parameter(s) are not exposed on precommit.Run: "
          f"{unexposed}. precommit forwards them internally but consumers of "
          "the precommit pipeline can no longer set them — the two have "
          "drifted at the public surface.", file=sys.stderr)
    sys.exit(1)

print(f"OK: precommit forwards all {len(stage2_params) - 4} non-positional "
      f"stage-2.Run option(s) via dag.Stage2().Run, and exposes all "
      f"{len(stage2_params)} on its own Run")
PY
}; then
  echo "  ✓ precommit delegates to stage-2 and forwards every option"
else
  rc=1
fi

# jassert_trace <label> <json-file> <python-expr> — evaluate <python-expr>
# against the list of parsed evidence envelopes (`envelopes`) loaded from the
# `contents --json` output at <json-file>. Passes when the expression, run
# with `any(... for e in envelopes)`, is truthy.
assert_trace() {
  local label="$1" file="$2" expr="$3"
  if [ ! -s "$file" ]; then
    echo "  ✗ ${label}: missing or empty $(basename "$file")" >&2
    return 1
  fi
  # The brace group is for Semgrep: its bash parser drops a heredoc used
  # directly as an if-condition, and with it the rest of the function.
  if {
    EXPR="$expr" python3 - "$file" <<'PY'
import json
import os
import sys

try:
    raw = json.load(open(sys.argv[1]))
except Exception as e:  # noqa: BLE001
    print(f"parse error: {e}", file=sys.stderr)
    sys.exit(1)

if not isinstance(raw, list) or not raw:
    print("expected a non-empty JSON array of {contents: ...} objects", file=sys.stderr)
    sys.exit(1)

envelopes = []
for item in raw:
    try:
        envelopes.append(json.loads(item["contents"]))
    except Exception as e:  # noqa: BLE001
        print(f"could not parse evidence envelope: {e}", file=sys.stderr)
        sys.exit(1)

sys.exit(0 if eval(  # noqa: S307
    os.environ["EXPR"],
    {"envelopes": envelopes, "any": any, "all": all, "len": len},
) else 1)
PY
  }; then
    echo "  ✓ ${label}"
    return 0
  fi
  echo "  ✗ ${label}: assertion failed on $(basename "$file"): ${expr}" >&2
  return 1
}

# ---------------------------------------------------------------------------
# 2. stage-2 behavioral fixture: quality, the source scan, the license scan and
#    risk must each leave a real evidence trace — not just compile — and the
#    opt-in intent gate must leave one saying it was never asked to look.
# ---------------------------------------------------------------------------
echo "== stage-2 fixture (testdata/go-app) =="
# Create every temp file before arming the trap: under `set -u` a trap that
# referenced a not-yet-assigned $stage4_out would itself fail if the script
# exited between the assignments.
stage2_out=$(mktemp)
stage2_intent_out=$(mktemp)
stage4_out=$(mktemp)
trap 'rm -f "$stage2_out" "$stage2_intent_out" "$stage4_out"' EXIT

if ! dagger -m ./src/stage-2 call run \
    --src ./testdata/go-app \
    --commit-sha local --branch main --repo-url https://example.com \
    --fail-on NONE \
    contents --json > "$stage2_out" 2>/tmp/stage2-orchestrator.err
then
  echo "  ✗ stage-2 Run failed to execute" >&2
  cat /tmp/stage2-orchestrator.err >&2
  rc=1
else
  assert_trace "quality ran"  "$stage2_out" 'any(e.get("moduleName")=="quality"  for e in envelopes)' || rc=1
  # The security module now produces two envelopes from stage-2 — the source
  # scan and the license scan — so moduleName alone no longer identifies
  # either. Both are asserted on tool.name, the same way stage-4 identifies
  # security-image below; on moduleName alone a dropped source scan would be
  # masked by the license envelope that replaced it.
  assert_trace "source scan ran (security-source)" "$stage2_out" \
    'any(e.get("moduleName")=="security" and e.get("tool",{}).get("name")=="security-source" for e in envelopes)' || rc=1
  assert_trace "license scan ran (security-license)" "$stage2_out" \
    'any(e.get("moduleName")=="security" and e.get("tool",{}).get("name")=="security-license" for e in envelopes)' || rc=1
  assert_trace "risk ran"     "$stage2_out" 'any(e.get("moduleName")=="risk"     for e in envelopes)' || rc=1
  # The intent gate is opt-in, and this call did not opt in. It must still be in
  # the evidence, saying it checked nothing: an audit that simply lacks the
  # module cannot tell a gate nobody asked for from a gate that passed. Both
  # channels are asserted because both are load-bearing — `required` is what a
  # machine reads, the warning is what a reviewer reads in the PR comment.
  assert_trace "intent reported without being asked" "$stage2_out" \
    'any(e.get("moduleName")=="intent" and (e.get("genericReport") or {}).get("required") is False for e in envelopes)' || rc=1
  assert_trace "intent says NOT REQUIRED in a warning" "$stage2_out" \
    'any("NOT REQUIRED" in w for e in envelopes if e.get("moduleName")=="intent" for w in (e.get("warnings") or []))' || rc=1
  assert_trace "exactly 5 evidence files (no testCmd)" "$stage2_out" 'len(envelopes) == 5' || rc=1
fi

# ---------------------------------------------------------------------------
# 2b. --require-intent must actually reach intent.Check.
#     A flag wired to nothing is the failure this whole gate exists to prevent:
#     the pipeline would report a change-intent gate the consumer asked for and
#     never run it. Note the inversion it proves — stage-2 sends intent's
#     negative `notRequired` flag, because Dagger's generated client silently
#     drops optional arguments holding their zero value, so `required=false`
#     could never travel. Quality/security/risk are unchanged between the two
#     calls, so the engine serves them from cache and only intent re-runs.
# ---------------------------------------------------------------------------
echo "== stage-2 fixture with --require-intent (testdata/go-app) =="
if ! dagger -m ./src/stage-2 call run \
    --src ./testdata/go-app \
    --commit-sha local --branch main --repo-url https://example.com \
    --fail-on NONE \
    --require-intent \
    contents --json > "$stage2_intent_out" 2>/tmp/stage2-intent.err
then
  echo "  ✗ stage-2 Run --require-intent failed to execute" >&2
  cat /tmp/stage2-intent.err >&2
  rc=1
else
  assert_trace "intent gate was required" "$stage2_intent_out" \
    'any(e.get("moduleName")=="intent" and (e.get("genericReport") or {}).get("required") is True for e in envelopes)' || rc=1
  # Proof it did the work, not just flipped a field: go-app carries one capsule,
  # and only a gate that globbed for artifacts can count it.
  assert_trace "intent gate checked the fixture's artifact" "$stage2_intent_out" \
    'any("artifact(s) checked" in w for e in envelopes if e.get("moduleName")=="intent" for w in (e.get("warnings") or []))' || rc=1
fi

# ---------------------------------------------------------------------------
# 3. stage-4 behavioral fixture: sbom (build/trivy) and image security scan
#    must each leave a real evidence trace.
# ---------------------------------------------------------------------------
echo "== stage-4 fixture (testdata/go-app) =="

if ! dagger -m ./src/stage-4 call run \
    --src ./testdata/go-app \
    --commit-sha local --branch main --repo-url https://example.com \
    --fail-on NONE \
    contents --json > "$stage4_out" 2>/tmp/stage4-orchestrator.err
then
  echo "  ✗ stage-4 Run failed to execute" >&2
  cat /tmp/stage4-orchestrator.err >&2
  rc=1
else
  assert_trace "sbom ran (build/trivy)"        "$stage4_out" 'any(e.get("moduleName")=="build" and e.get("tool",{}).get("name")=="trivy" for e in envelopes)' || rc=1
  assert_trace "image scan ran (security-image)" "$stage4_out" 'any(e.get("moduleName")=="security" and e.get("tool",{}).get("name")=="security-image" for e in envelopes)' || rc=1
  assert_trace "exactly 2 evidence files" "$stage4_out" 'len(envelopes) == 2' || rc=1
fi

if [ "$rc" -ne 0 ]; then
  echo "FAIL: stage-orchestrators.sh" >&2
  exit 1
fi
echo "PASS: stage-orchestrators.sh"
