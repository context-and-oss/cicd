#!/usr/bin/env bash
# dast-shapes.sh — composite-smoke for the running-app DAST composite
# (src/composites/dast). Runs `dast scan`, then `dast package`, for one shape against
# testdata/vuln-app and asserts on the exported audit directory.
#
# Usage: bash scripts/smoke/dast-shapes.sh <container|service|guardrails>
#
# Shapes and what each one proves:
#   container   — W2, "we start it, we scan it". cicd builds the fixture image
#                 from its Dockerfile, runs it, probes it and scans it in
#                 --mode full. Asserts the planted reflected-XSS HIGH, which is
#                 the only thing that separates a full scan from a baseline one:
#                 a `full` run reporting no HIGH did not run a full scan
#                 whatever its exit code said. Also asserts the ABSENCE of the
#                 provenance disclosure — this is the one shape whose evidence
#                 may say the running code was built in this run.
#   service     — W1, "you start it, we scan it". The fixture runs in Docker on
#                 this machine and reaches the engine through a host tunnel, in
#                 --mode api driven from a path the target serves. Asserts the
#                 provenance disclosure IS present, and the operation count the
#                 API document declares.
#   guardrails  — the shape selector refuses what it cannot honour, before any
#                 container starts. Fast: no scan runs in this arm.
#
# --mode baseline is deliberately not a shape here. ci.yml's module-test cell
# for src/security already runs it against this same fixture, and a second full
# composite execution to re-prove the same passive alerts buys nothing.
#
# The mode-set and port refusals validateApp also makes are proven by the unit
# suite (src/composites/dast/shape_test.go), not here: `--mode ""` on a CLI is
# a question about the CLI's own zero-value handling, and a smoke that asserted
# it would be measuring the wrong layer.
#
# JSON assertions use python3 (not jq) — same reason as commit-shapes.sh: jq is
# not guaranteed in the validation environment, python3 is.
set -uo pipefail

repo_root=$(git rev-parse --show-toplevel) || { echo "not in a git repository" >&2; exit 1; }
cd "$repo_root" || exit 1

shape="${1:?"usage: dast-shapes.sh <container|service|guardrails>"}"

for tool in dagger python3; do
  command -v "$tool" >/dev/null || { echo "missing required command: $tool" >&2; exit 127; }
done

fixture="./testdata/vuln-app"
sha="local"
branch="main"
repo="https://example.com"

# jassert <label> <file> <python-expr> — evaluate <python-expr> against the JSON
# document loaded from <file> as `d`. Passes when the expression is truthy;
# fails loudly on a missing, empty or unparseable file.
jassert() {
  local label="$1" file="$2" expr="$3"
  if [ ! -s "$file" ]; then
    echo "  ✗ ${label}: missing or empty $(basename "$file")" >&2
    return 1
  fi
  # The brace group is for Semgrep: its bash parser drops a heredoc used
  # directly as an if-condition, and with it the rest of the function.
  if {
    EXPR="$expr" python3 - "$file" <<'PY'
import json, os, re, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:  # noqa: BLE001
    print(f"parse error: {e}", file=sys.stderr)
    sys.exit(1)
sys.exit(0 if eval(os.environ["EXPR"], {"d": d, "re": re}) else 1)  # noqa: S307
PY
  }; then
    echo "  ✓ ${label}"
    return 0
  fi
  echo "  ✗ ${label}: assertion failed on $(basename "$file"): ${expr}" >&2
  return 1
}

# dast_part <audit-dir> — path of the DAST envelope inside parts/. The composite
# wraps exactly one envelope, but the file is located by its genericFormat
# rather than by name: partFileName composes the name from the module and tool,
# so a rename there would silently turn every assertion below into a
# missing-file failure that reads like a broken scan.
dast_part() {
  python3 - "$1" <<'PY'
import json, pathlib, sys
for path in sorted((pathlib.Path(sys.argv[1]) / "parts").glob("*.json")):
    if path.name == "index.json":
        continue
    try:
        if json.load(open(path)).get("genericFormat") == "dast/1.0":
            print(path)
            break
    except Exception:  # noqa: BLE001, S110
        continue
PY
}

# assert_scan_ran <audit-dir> <expected-source> <expected-mode> — the facts every
# shape owes regardless of how the application got started. The readiness
# assertion is the load-bearing one: an application that never came up produces
# a ZAP report with no alerts, which is byte-for-byte the shape of a clean scan.
assert_scan_ran() {
  local dir="$1" source="$2" mode="$3" rc=0
  local combined="${dir}/combined-evidence.json"
  local part
  part=$(dast_part "$dir")

  echo "the scan ran:"
  if [ -z "$part" ]; then
    echo "  ✗ no dast/1.0 envelope in ${dir}/parts/" >&2
    return 1
  fi
  echo "  ✓ dast/1.0 envelope present ($(basename "$part"))"

  jassert "no errors"        "$part" 'not (d.get("errors") or [])' || rc=1
  jassert "readiness ok"     "$part" '(d["genericReport"]["readiness"] or {}).get("ok") is True' || rc=1
  jassert "source ${source}" "$part" "d['genericReport']['source'] == '${source}'" || rc=1
  jassert "mode ${mode}"     "$part" "d['genericReport']['mode'] == '${mode}'" || rc=1
  jassert "compact ZAP alert report kept" "$part" 'd["genericReport"].get("zapReport") is not None' || rc=1
  # scanCompleted is what every disclosure reads instead of the readiness probe,
  # which answers 200 whether or not ZAP survives it. A shape that scanned must
  # set it, or the guard it feeds is untested on the passing path.
  jassert "scan recorded as completed" "$part" 'd["genericReport"].get("scanCompleted") is True' || rc=1
  # The clean-target sentence must never appear beside an errors[] entry. Here
  # there are no errors, so this asserts only that the pairing is consistent.
  jassert "no clean-scan claim on a failed scan" "$part" \
    'd["genericReport"].get("scanCompleted") is True or not any("NO ALERTED URL" in w for w in (d.get("warnings") or []))' || rc=1
  # A clean completed scan carries no log tail: the bytes would ride in every
  # consumer's bundle for the benefit of a failure that did not happen. The
  # pairing is what is asserted and not the bare absence, because a completed
  # scan that recorded an errors[] entry is the one case that must keep its
  # log. The "no errors" assertion above already fixes which side this run is
  # on, so the disjunct below is a guard against that changing silently.
  jassert "no log tail on a clean completed scan" "$part" \
    'd["genericReport"].get("zapLog") is None or bool(d.get("errors") or [])' || rc=1
  # cicd searched ZAP's own log and got an answer. This is the only assertion
  # that proves zapDaemonLogPath is still where the pinned image writes, and it
  # is worth an arm of its own because the failure it catches is silent by
  # construction: a moved log yields status 127, no rejection found, and an
  # envelope identical to one from a scan whose document imported cleanly.
  jassert "ZAP's own log was searched" "$part" \
    'not any("IMPORT LOG UNREAD" in w for w in (d.get("warnings") or []))' || rc=1
  # And it found nothing to report. The fixture's document is small enough that
  # a rejection here means something is wrong with the fixture or the scan, not
  # with the consumer — so the absence is asserted on every shape, including the
  # two that import no document at all.
  jassert "no refused API document" "$part" \
    'd["genericReport"].get("apiImport") is None and not any("API DOCUMENT REFUSED" in e for e in (d.get("errors") or []))' || rc=1

  # The audit directory is the deliverable, not the envelope. comment.md is
  # notify.GithubBuildComment's real output and is where a reviewer reads the
  # verdict, so its absence is a delivery failure even with perfect evidence.
  for name in combined-evidence.json findings.sarif comment.md; do
    if [ -s "${dir}/${name}" ]; then
      echo "  ✓ ${name} written"
    else
      echo "  ✗ ${name} missing or empty" >&2
      rc=1
    fi
  done
  jassert "combined envelope is a gated result" "$combined" \
    "'passed' in d and 'findingsCount' in d" || rc=1
  return "$rc"
}

# start_fixture <port> — build and run the fixture on this machine, so the
# service shape has something on the runner's loopback to tunnel to.
start_fixture() {
  local port="$1"
  docker rm -f dast-smoke-app >/dev/null
  docker build -t dast-smoke-app:latest "$fixture" || return 1
  docker run -d --name dast-smoke-app -p "${port}:8080" dast-smoke-app:latest || return 1
  local i
  for i in $(seq 1 30); do
    if curl -fsS "http://localhost:${port}/health" >/dev/null; then
      echo "fixture answering on localhost:${port}"
      return 0
    fi
    sleep 1
  done
  echo "fixture never answered on localhost:${port}" >&2
  docker logs dast-smoke-app >&2
  return 1
}

stop_fixture() {
  docker rm -f dast-smoke-app >/dev/null
}

# refused <label> <expected-substring> <args...> — the call must exit non-zero
# AND say why. A non-zero exit alone would be satisfied by any failure,
# including the composite failing to load at all.
refused() {
  local label="$1" want="$2"; shift 2
  local out
  echo "guardrail: ${label}"
  if out=$(dagger -m ./src/composites/dast call scan \
      --commit-sha "$sha" --branch "$branch" --repo-url "$repo" \
      "$@" export --path /tmp/dast-smoke-guardrail.json 2>&1); then
    echo "  ✗ accepted (expected non-zero exit)" >&2
    return 1
  fi
  if printf '%s\n' "$out" | grep -qF "$want"; then
    echo "  ✓ refused with: ${want}"
    return 0
  fi
  echo "  ✗ failed, but not with '${want}':" >&2
  printf '%s\n' "$out" >&2
  return 1
}

case "$shape" in
  container)
    out_dir=$(mktemp -d)
    evidence_file=$(mktemp)
    trap 'rm -rf "$out_dir"; rm -f "$evidence_file"' EXIT
    echo "== dast shape: container (W2, --mode full, testdata/vuln-app) =="
    # 15 minutes is a cap and not a budget: an uncapped active scan can run for
    # hours, and a cap that truncates the scan would drop the HIGH this arm
    # exists to assert. If this ever trips, the assertion below fails loudly
    # rather than the run passing on a shortened scan.
    dagger -m ./src/composites/dast call scan \
      --app container \
      --src "$fixture" \
      --port 8080 \
      --health-path /health \
      --mode full \
      --max-duration-minutes 15 \
      --fail-on NONE \
      --commit-sha "$sha" --branch "$branch" --repo-url "$repo" \
      export --path "$evidence_file"
    dagger -m ./src/composites/dast call package \
      --evidence "$evidence_file" \
      --commit-sha "$sha" --branch "$branch" --repo-url "$repo" \
      export --path "$out_dir"

    rc=0
    assert_scan_ran "$out_dir" container full || rc=1
    part=$(dast_part "$out_dir")

    echo "active scan reached the planted defect:"
    # The one finding a baseline scan cannot produce. Asserted by name and by
    # severity: a HIGH from some other rule would satisfy a count and prove
    # nothing about /greet.
    jassert "reflected XSS reported HIGH" "$part" \
      'any(f.get("severity")=="HIGH" and "Cross Site Scripting" in (f.get("message") or "") for f in (d.get("findings") or []))' || rc=1

    echo "provenance:"
    # Silence is the signal here. cicd built and started the thing it scanned,
    # so the disclosure the other two shapes carry must be absent — a
    # disclosure on every run is noise a reader learns to skip.
    jassert "no PROVENANCE NOT ATTESTED record" "$part" \
      'not any("PROVENANCE NOT ATTESTED" in x for x in (d.get("warnings") or []))' || rc=1
    jassert "no BASELINE ONLY record" "$part" \
      'not any("BASELINE ONLY" in x for x in (d.get("warnings") or []))' || rc=1

    echo "the empty SBOM is not read as an inventory:"
    # evidence.Wrap always writes all three merged documents. A DAST run
    # produces no components, and the file being present-and-empty is the
    # documented state — asserted so a future change that starts populating it
    # from somewhere is a decision rather than a surprise.
    jassert "sbom.cdx.json carries no components" "${out_dir}/sbom.cdx.json" \
      'not (d.get("components") or [])' || rc=1

    if [ "$rc" -ne 0 ]; then
      echo "FAIL: dast-shapes.sh container" >&2
      exit 1
    fi
    echo "PASS: dast-shapes.sh container"
    ;;

  service)
    port=18081
    out_dir=$(mktemp -d)
    evidence_file=$(mktemp)
    trap 'rm -rf "$out_dir"; rm -f "$evidence_file"; stop_fixture' EXIT
    echo "== dast shape: service (W1, --mode api, testdata/vuln-app on the runner) =="
    start_fixture "$port" || { echo "FAIL: dast-shapes.sh service (fixture)" >&2; exit 1; }

    dagger -m ./src/composites/dast call scan \
      --app service \
      --service "tcp://localhost:${port}" \
      --port "$port" \
      --health-path /health \
      --mode api \
      --api-spec-path /openapi.json \
      --profile SmokeFixture \
      --fail-on NONE \
      --commit-sha "$sha" --branch "$branch" --repo-url "$repo" \
      export --path "$evidence_file"
    dagger -m ./src/composites/dast call package \
      --evidence "$evidence_file" \
      --commit-sha "$sha" --branch "$branch" --repo-url "$repo" \
      export --path "$out_dir"

    rc=0
    assert_scan_ran "$out_dir" service api || rc=1
    part=$(dast_part "$out_dir")

    echo "api mode was driven from the document the target served:"
    # The fixture's openapi.json declares three operations. Asserting the count
    # rather than its presence is what proves the document was fetched from the
    # running app and parsed, not merely named on the command line.
    jassert "three operations counted" "$part" \
      'd["genericReport"].get("endpointsFromSpec") == 3' || rc=1
    jassert "API SCAN scope disclosed" "$part" \
      'any("API SCAN" in x for x in (d.get("warnings") or []))' || rc=1
    # The document was imported, not merely counted. endpointsFromSpec is
    # cicd's own reading and would be 3 against a ZAP that refused the
    # document outright; the import count is ZAP's, and it is the number that
    # went missing on the consumer run this check exists for. It includes the
    # target seed, so it is asserted as a floor over the three declared paths
    # rather than as an equality.
    jassert "ZAP imported the document" "$part" \
      '(d["genericReport"].get("urlsImported") or 0) >= 3' || rc=1

    echo "ZAP's own site tree names every path the document declares:"
    # The strongest assertion in this file. It passes only if the hook was
    # mounted, ran inside ZAP, wrote its dump, was read back out of the
    # container, and reconciled against the served document — five links, one
    # number. The fixture declares /health, /api/items and /greet; an api-mode
    # scan that reaches fewer than all three is the defect this shape exists to
    # catch, so the count is asserted and not its presence.
    jassert "every declared path reached" "$part" \
      'd["genericReport"]["apiReach"]["declaredPaths"] == 3 and d["genericReport"]["apiReach"]["reachedPaths"] == 3' || rc=1
    jassert "no unreached-endpoint record" "$part" \
      'not any("ENDPOINTS NOT REACHED" in x for x in (d.get("warnings") or []))' || rc=1
    # Silence here would be the founding doctrine's own failure mode: an
    # envelope with no apiReach block and no warning reads exactly like one
    # written before this check existed.
    jassert "the reconciliation ran" "$part" \
      'not any("RECONCILIATION NOT RUN" in x for x in (d.get("warnings") or []))' || rc=1

    echo "the disclosures a consumer-started app owes its reader:"
    jassert "PROVENANCE NOT ATTESTED" "$part" \
      'any("PROVENANCE NOT ATTESTED" in x for x in (d.get("warnings") or []))' || rc=1
    jassert "NOT AUTHENTICATED" "$part" \
      'any("NOT AUTHENTICATED" in x for x in (d.get("warnings") or []))' || rc=1
    jassert "PROFILE SmokeFixture" "$part" \
      'any("PROFILE SmokeFixture" in x for x in (d.get("warnings") or []))' || rc=1

    # A warning nobody renders is a warning nobody reads. comment.md is the
    # channel a reviewer actually opens.
    if grep -qF "PROVENANCE NOT ATTESTED" "${out_dir}/comment.md"; then
      echo "  ✓ provenance disclosure rendered into comment.md"
    else
      echo "  ✗ comment.md does not carry the provenance disclosure" >&2
      rc=1
    fi

    if [ "$rc" -ne 0 ]; then
      echo "FAIL: dast-shapes.sh service" >&2
      exit 1
    fi
    echo "PASS: dast-shapes.sh service"
    ;;

  guardrails)
    echo "== dast guardrails (no scan runs in this arm) =="
    rc=0
    # Short substrings on purpose. These messages are long, and a terminal
    # that wraps one would turn a precise assertion into a false failure; the
    # exact wording is pinned by shape_test.go, which reads the string rather
    # than a rendering of it.
    refused "unknown --app is refused, never defaulted" \
      "invalid --app" --app compose --target http://example.com || rc=1
    refused "--app container with no --src" \
      "needs --src" --app container || rc=1
    refused "--app url with no --target" \
      "needs --target" --app url || rc=1
    refused "--app url with a --src it would not build" \
      "given a --src" --app url --target http://example.com --src "$fixture" || rc=1

    if [ "$rc" -ne 0 ]; then
      echo "FAIL: dast-shapes.sh guardrails" >&2
      exit 1
    fi
    echo "PASS: dast-shapes.sh guardrails"
    ;;

  *)
    echo "unknown shape '$shape' — want container|service|guardrails" >&2
    exit 2
    ;;
esac
