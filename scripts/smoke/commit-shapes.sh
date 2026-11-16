#!/usr/bin/env bash
# commit-shapes.sh — composite-smoke for the unified, artifact-agnostic commit
# stage (ADR-005). Runs `src/composites/commit` for one artifact shape and
# asserts that the exported audit directory carries evidence from every
# source-gate code check (quality, SAST, secrets, dependency-vuln, risk), the
# record proving change intent was not gated here, and the correct artifact
# evidence for that shape.
#
# The container shape additionally asserts that every digest-pinned runtime tool
# image in scripts/runtime-images.json resolves on this architecture (ADR-004) —
# see assert_pinned_images_resolve for why the offline pin checker cannot prove
# that on its own.
#
# Usage: bash scripts/smoke/commit-shapes.sh <container|archive|none|archive-identity>
#
# Shapes and their fixtures:
#   none              — testdata/python-app (source-only, no Dockerfile)
#   container         — testdata/go-app     (has a Dockerfile → OCI image scan)
#   archive           — testdata/node-app   (build command → output-dir secrets scan)
#   archive-identity  — testdata/node-app, same run as archive, but focused on
#                        proving the merged SBOM has no duplicate identity. The
#                        archive shape is the sharpest regression case: both
#                        security.ScanSource and security.ScanArchive run a
#                        Trivy-FS scan over the SAME source tree, so an
#                        append-only aggregator doubles every component's
#                        bom-ref — exactly the defect evidence.mergeCycloneDX
#                        must collapse.
#
# The `none` shape also runs the invalid-artifact guardrail: a bad --artifact
# value must exit non-zero. Smokes always use --fail-on NONE so fixture debt
# never fails the smoke — we assert that each check *ran and produced evidence*,
# not that the repo is clean.
#
# JSON assertions use python3 (not jq) — jq is not guaranteed in the validation
# environment, whereas python3 is (it is what ci.yml uses to check evidence).
set -uo pipefail

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || { echo "not in a git repository" >&2; exit 1; }
cd "$repo_root"

# The envelope's schemaVersion, read from the tree under test rather than
# written here as a literal. A literal would be one more copy of the fact that
# stood at 1.0.0 for four additive field changes, and it would fail this smoke
# on the next legitimate bump — which is how a smoke teaches people to edit it
# without reading it.
expected_schema_version=$(sed -n 's/^const SchemaVersion = "\(.*\)"$/\1/p' \
  src/internal/evidence/schema.go)
[ -n "$expected_schema_version" ] || {
  echo "could not read SchemaVersion from src/internal/evidence/schema.go" >&2
  exit 1
}

shape="${1:?"usage: commit-shapes.sh <container|archive|none|archive-identity>"}"

for tool in dagger python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing required command: $tool" >&2; exit 127; }
done

# jassert <label> <file> <python-expr> — evaluate <python-expr> against the JSON
# document loaded from <file> as `d` (with `re` available). Passes when the
# expression is truthy; fails loudly on a missing/empty/unparseable file or a
# falsey result.
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

# sarif_has <driver> — python expr: some SARIF run has tool.driver.name == driver.
sarif_has() {
  printf 'any((r.get("tool") or {}).get("driver",{}).get("name")==%s for r in (d.get("runs") or []))' "\"$1\""
}

# sarif_uri_endswith <suffix> — python expr: some SARIF result has a location
# whose artifactLocation.uri ends with <suffix>. Used to prove the archive
# shape's built-output secrets scan flagged a file that exists only in the
# built artifact (dist/leaked.env), not in source (leaked.env.fixture).
sarif_uri_endswith() {
  printf 'any((loc.get("physicalLocation",{}).get("artifactLocation",{}).get("uri","") or "").endswith(%s) for run in (d.get("runs") or []) for res in (run.get("results") or []) for loc in (res.get("locations") or []))' "\"$1\""
}

# unique_bomrefs_expr <field> — python expr: every non-empty bom-ref among
# sbom.cdx.json's <field> ("components" or "vulnerabilities") is unique. An
# append-only aggregator that never collapses identity fails this whenever a
# component/vulnerability is reported by more than one scanning step.
unique_bomrefs_expr() {
  printf '(lambda refs: len(refs) == len(set(refs)))([x.get("bom-ref") for x in (d.get(%s) or []) if x.get("bom-ref")])' "\"$1\""
}

# unique_run_identity_expr — python expr: no two runs in findings.sarif share
# GitHub Code Scanning's (tool driver name, automationDetails.id) identity.
# Since 2025-07-22 a collision rejects the *entire* upload, and the workflows'
# Advanced-Security tolerance would read that refusal as a repo with nothing to
# report — so the merged document every shape uploads must never carry one.
# Guarded by uniqueRunIdentities in cross-cutting/evidence; this proves it on
# real pipeline output (specs/one-sarif-run-per-category.md).
unique_run_identity_expr() {
  printf '(lambda ids: len(ids) == len(set(ids)))([(((r.get("tool") or {}).get("driver") or {}).get("name"), (r.get("automationDetails") or {}).get("id")) for r in (d.get("runs") or [])])'
}

# assert_unique_identity <audit-dir> — the merged SBOM must carry no duplicate
# non-empty bom-ref among components or among vulnerabilities, and the merged
# SARIF no duplicate Code Scanning run identity.
assert_unique_identity() {
  local dir="$1" rc=0
  local sbom="${dir}/sbom.cdx.json"
  local sarif="${dir}/findings.sarif"
  echo "merged-artifact identity:"
  jassert "unique component bom-ref"      "$sbom" "$(unique_bomrefs_expr components)"      || rc=1
  jassert "unique vulnerability bom-ref"  "$sbom" "$(unique_bomrefs_expr vulnerabilities)"  || rc=1
  jassert "unique SARIF run identity"     "$sarif" "$(unique_run_identity_expr)"            || rc=1
  return "$rc"
}

# assert_source_gate <audit-dir> <lang> — verify every source-gate check left
# a trace in the exported evidence. Reused by every shape; <lang> is the fixture
# language (go|node|python) so the quality assertion works across shapes.
#   quality  → the fixture's language present in combined-evidence .languages.
#              Only the quality module populates .languages (per-language lint +
#              test), and its lint SARIF driver name differs per language
#              (golangci-lint/eslint/pylint) and — for golangci-lint — is not a
#              stable single-run name, so .languages is the robust cross-shape
#              proof that quality ran (combined-evidence.json)
#   SAST     → opengrep SARIF run (findings.sarif)
#   secrets  → gitleaks SARIF run (findings.sarif)
#   dep-vuln → non-empty CycloneDX components (sbom.cdx.json, Trivy-FS source scan)
#   risk     → risk-validate finding, or the no-risk-files warning it emits on a
#              clean fixture (combined-evidence.json)
#   intent   → NOT a gate here: the commit stage runs after the merge it could
#              have blocked, so it never requires a change-intent artifact. What
#              is asserted is the record proving that — see below.
assert_source_gate() {
  local dir="$1" lang="$2" rc=0
  local sarif="${dir}/findings.sarif"
  local sbom="${dir}/sbom.cdx.json"
  local combined="${dir}/combined-evidence.json"

  echo "source-gate checks:"
  jassert "quality (${lang} lint+test)" "$combined" \
    "\"${lang}\" in (d.get(\"languages\") or [])" || rc=1
  # Opengrep's SARIF driver name is "Opengrep", so match a case-insensitive
  # substring rather than an exact name.
  jassert "SAST (opengrep)"    "$sarif" \
    'any("opengrep" in ((r.get("tool") or {}).get("driver",{}).get("name") or "").lower() for r in (d.get("runs") or []))' || rc=1
  jassert "secrets (gitleaks)" "$sarif" "$(sarif_has gitleaks)" || rc=1
  jassert "dependency-vuln (Trivy-FS SBOM)" "$sbom" 'len(d.get("components") or []) > 0' || rc=1
  jassert "risk (risk-validate)" "$combined" \
    'any(f.get("tool")=="risk-validate" for f in (d.get("findings") or [])) or any("risk file" in x for x in ((d.get("warnings") or []) + (d.get("errors") or [])))' \
    || rc=1
  # The commit composite exposes no way to require change intent, so the only
  # correct outcome is the explicit "not required" record. Asserting the record —
  # rather than asserting nothing — is what keeps the removal honest: if a future
  # change re-enables the gate here, or drops intent from the audit entirely,
  # this fails instead of quietly passing. A finding from intent-gate means the
  # gate ran on a pipeline that must never run it.
  jassert "intent recorded as not required" "$combined" \
    'any("NOT REQUIRED" in x for x in (d.get("warnings") or []))' || rc=1
  jassert "intent did not gate the commit stage" "$combined" \
    'not any(f.get("tool")=="intent-gate" for f in (d.get("findings") or []))' || rc=1

  # The aggregate envelope must be a well-formed, gated result.
  jassert "combined-evidence schema" "$combined" \
    "d.get('schemaVersion')=='$expected_schema_version' and 'passed' in d and 'findingsCount' in d" || rc=1
  return "$rc"
}

# assert_artifact_not_attested <audit-dir> — the none shape must state, in the
# evidence AND in the rendered PR comment, that no artifact was built or
# attested. Before build.NoArtifact existed this branch recorded nothing, so a
# none-shape audit was byte-identical to the audit of a repository whose
# artifact had been built and scanned clean. Asserting the record — in both
# channels — is what keeps that honest: a future change that drops the warning,
# or one that keeps it in the envelope while notify stops rendering warnings,
# fails here instead of quietly returning to silence.
assert_artifact_not_attested() {
  local dir="$1" rc=0
  local combined="${dir}/combined-evidence.json"
  local comment="${dir}/comment.md"

  echo "artifact evidence (nothing attested, and it says so):"
  jassert "no-artifact record in the envelope" "$combined" \
    'any("NOT ATTESTED" in x for x in (d.get("warnings") or []))' || rc=1
  jassert "no-artifact record is a warning, not a failure" "$combined" \
    'not any("NOT ATTESTED" in x for x in (d.get("errors") or []))' || rc=1

  # The warning only does its job if a reviewer sees it, and the PR comment is
  # where they look. comment.md is notify.GithubBuildComment's real output.
  if [ -s "$comment" ] && grep -qF "artifact: NOT ATTESTED" "$comment"; then
    echo "  ✓ no-artifact record rendered into comment.md"
  else
    echo "  ✗ comment.md does not carry the no-artifact record" >&2
    rc=1
  fi
  return "$rc"
}

# assert_artifact_attested <audit-dir> — the inverse, for the shapes that DO
# build something. A disclosure that appears on every run is noise a reader
# learns to skip, so the container and archive shapes must not carry it.
assert_artifact_attested() {
  local dir="$1" rc=0
  echo "artifact attested (no no-artifact record):"
  jassert "no spurious NOT ATTESTED record" "${dir}/combined-evidence.json" \
    'not any("NOT ATTESTED" in x for x in ((d.get("warnings") or []) + (d.get("errors") or [])))' || rc=1
  return "$rc"
}

# assert_pinned_images_resolve — every image in the defended runtime image
# inventory (scripts/runtime-images.json) must resolve, by digest, on the
# architecture this smoke runs on.
#
# Why this lives here and not in the offline checker: check-runtime-image-pins.py
# proves the pin has the immutable *form* (tag@sha256:<digest>) without touching a
# registry. It cannot prove the digest is a real, pullable, correct-platform
# manifest — a typo'd or single-architecture digest passes the form check and then
# fails at run time, hours later, inside somebody's pipeline. `container from
# --address` resolves the reference against the engine, so a bad digest fails here
# in seconds.
#
# The container shape's own pipeline already executes the security (semgrep,
# gitleaks, trivy, trufflehog), quality (golangci-lint, golang, alpine), risk
# (alpine, conftest) and build (trivy) images for real. This loop also checks
# every declared reference directly, including image paths the fixture-based
# pipeline may not exercise on a particular run.
assert_pinned_images_resolve() {
  local rc=0
  echo "pinned runtime images resolve by digest:"
  local refs
  refs=$(python3 - <<'PY'
import json, pathlib
inv = json.load(open(pathlib.Path("scripts/runtime-images.json")))
for entry in inv["images"]:
    print(f"{entry['repository']}:{entry['tag']}@{entry['digest']}")
PY
  ) || { echo "  ✗ could not read scripts/runtime-images.json" >&2; return 1; }

  if [ -z "$refs" ]; then
    echo "  ✗ the runtime image inventory produced no references" >&2
    return 1
  fi

  local ref resolved
  while IFS= read -r ref; do
    [ -n "$ref" ] || continue
    if resolved=$(dagger core container from --address "$ref" image-ref 2>/dev/null) \
       && printf '%s' "$resolved" | grep -qF "${ref#*@}"; then
      echo "  ✓ ${ref%@*}"
    else
      echo "  ✗ ${ref} did not resolve on this architecture" >&2
      rc=1
    fi
  # A here-string, not <<EOF: Semgrep's bash parser drops an expanding heredoc
  # inside a function; a pipe would run the loop in a subshell and lose rc.
  done <<< "$refs"
  return "$rc"
}

# guardrail_invalid — a bad --artifact value must exit non-zero (the switch
# default returns an error before any scanning runs).
guardrail_invalid() {
  local out
  echo "guardrail: invalid --artifact rejected"
  if out=$(dagger -m ./src/composites/commit call run \
      --src ./testdata/python-app \
      --artifact totally-bogus \
      --sast-rulesets "p/security-audit,p/secrets" \
      --fail-on NONE \
      --commit-sha local --branch main --repo-url https://example.com \
      export --path /tmp/commit-smoke-guardrail 2>&1); then
    echo "  ✗ invalid --artifact was accepted (expected non-zero exit)" >&2
    return 1
  fi
  if printf '%s\n' "$out" | grep -qi "invalid --artifact"; then
    echo "  ✓ invalid --artifact rejected with an invalid-artifact error"
    return 0
  fi
  echo "  ✗ run failed but without an invalid-artifact error:" >&2
  printf '%s\n' "$out" >&2
  return 1
}

case "$shape" in
  none)
    out_dir=$(mktemp -d)
    trap 'rm -rf "$out_dir"' EXIT
    echo "== commit shape: none (testdata/python-app) =="
    dagger -m ./src/composites/commit call run \
      --src ./testdata/python-app \
      --artifact none \
      --sast-rulesets "p/security-audit,p/secrets" \
      --fail-on NONE \
      --commit-sha local --branch main --repo-url https://example.com \
      export --path "$out_dir"

    rc=0
    assert_source_gate "$out_dir" python || rc=1

    # "none" builds no artifact, so no image/archive scan error may surface.
    jassert "no artifact-scan error" "${out_dir}/combined-evidence.json" \
      'not any(re.search("scan-image|scan-archive|BuildArchive|trufflehog|image scan", x, re.I) for x in (d.get("errors") or []))' \
      || rc=1

    # ... and the audit must say that out loud, in the envelope and in the
    # rendered comment (specs/say-what-no-artifact-left-unattested.md).
    assert_artifact_not_attested "$out_dir" || rc=1

    # Single-source SBOM (source Trivy-FS only), so identity must be unique
    # trivially — asserted anyway so all three shapes CI runs carry the guard
    # and an aggregator that duplicates within one document cannot hide here.
    assert_unique_identity "$out_dir" || rc=1

    guardrail_invalid || rc=1

    if [ "$rc" -ne 0 ]; then
      echo "FAIL: commit-shapes.sh none" >&2
      exit 1
    fi
    echo "PASS: commit-shapes.sh none"
    ;;

  container)
    out_dir=$(mktemp -d)
    trap 'rm -rf "$out_dir"' EXIT
    echo "== commit shape: container (testdata/go-app) =="
    dagger -m ./src/composites/commit call run \
      --src ./testdata/go-app \
      --artifact container \
      --sast-rulesets "p/security-audit,p/secrets" \
      --fail-on NONE \
      --commit-sha local --branch main --repo-url https://example.com \
      export --path "$out_dir"

    rc=0
    assert_source_gate "$out_dir" go || rc=1

    # Artifact tail: the container shape builds the go-app image, TruffleHog
    # secrets-scans it (always emits a "trufflehog" SARIF run, even clean) and
    # Trivy image-scans it (a second CycloneDX SBOM).
    echo "artifact evidence (image scan):"
    jassert "image secrets scan (trufflehog)" "${out_dir}/findings.sarif" \
      "$(sarif_has trufflehog)" || rc=1
    # The merged SBOM carries the source Trivy-FS components AND the image
    # components — a non-empty merge guards the two-CycloneDX append
    # (evidence/cyclonedx.go mergeCycloneDX).
    jassert "merged SBOM non-empty" "${out_dir}/sbom.cdx.json" \
      'len(d.get("components") or []) > 0' || rc=1
    assert_artifact_attested "$out_dir" || rc=1
    assert_unique_identity "$out_dir" || rc=1

    # ADR-004: the pipeline above ran the security, quality, risk and build tool
    # images by digest, which is the behavioural half of the proof. This asserts
    # the same for every declared image including the ones no shape reaches.
    assert_pinned_images_resolve || rc=1

    if [ "$rc" -ne 0 ]; then
      echo "FAIL: commit-shapes.sh container" >&2
      exit 1
    fi
    echo "PASS: commit-shapes.sh container"
    ;;

  archive)
    out_dir=$(mktemp -d)
    trap 'rm -rf "$out_dir"' EXIT
    echo "== commit shape: archive (testdata/node-app) =="
    dagger -m ./src/composites/commit call run \
      --src ./testdata/node-app \
      --artifact archive \
      --build-cmd "npm install --ignore-scripts && npm run build" \
      --output-path dist \
      --sast-rulesets "p/security-audit,p/secrets" \
      --fail-on NONE \
      --commit-sha local --branch main --repo-url https://example.com \
      export --path "$out_dir"

    rc=0
    assert_source_gate "$out_dir" node || rc=1

    # Artifact tail: the archive shape secrets-scans the BUILT OUTPUT (Gitleaks
    # dir mode). node-app's build deterministically writes dist/leaked.env (an
    # AWS example key) — a finding whose URI ends in "leaked.env" (not the
    # source-tree "leaked.env.fixture") proves the built-output scan ran.
    echo "artifact evidence (built-output secrets scan):"
    jassert "built-output secret (dist/leaked.env)" "${out_dir}/findings.sarif" \
      "$(sarif_uri_endswith leaked.env)" || rc=1
    assert_artifact_attested "$out_dir" || rc=1

    # Same SBOM the archive-identity shape interrogates, asserted here too so
    # the three shapes CI runs all carry the identity guard without paying for
    # a fourth full pipeline execution. archive-identity stays as the focused
    # standalone command for the identity fact.
    assert_unique_identity "$out_dir" || rc=1

    if [ "$rc" -ne 0 ]; then
      echo "FAIL: commit-shapes.sh archive" >&2
      exit 1
    fi
    echo "PASS: commit-shapes.sh archive"
    ;;

  archive-identity)
    out_dir=$(mktemp -d)
    trap 'rm -rf "$out_dir"' EXIT
    echo "== commit shape: archive-identity (testdata/node-app) =="
    dagger -m ./src/composites/commit call run \
      --src ./testdata/node-app \
      --artifact archive \
      --build-cmd "npm install --ignore-scripts && npm run build" \
      --output-path dist \
      --sast-rulesets "p/security-audit,p/secrets" \
      --fail-on NONE \
      --commit-sha local --branch main --repo-url https://example.com \
      export --path "$out_dir"

    rc=0
    # security.ScanSource (source gate) and security.ScanArchive (artifact
    # tail) both run Trivy-FS over the identical testdata/node-app source
    # tree, so the merged SBOM only stays duplicate-free if
    # evidence.mergeCycloneDX collapses shared identity instead of
    # appending both reports' components/vulnerabilities verbatim.
    jassert "merged SBOM non-empty" "${out_dir}/sbom.cdx.json" \
      'len(d.get("components") or []) > 0' || rc=1
    assert_unique_identity "$out_dir" || rc=1

    if [ "$rc" -ne 0 ]; then
      echo "FAIL: commit-shapes.sh archive-identity" >&2
      exit 1
    fi
    echo "PASS: commit-shapes.sh archive-identity"
    ;;

  *)
    echo "unknown shape: ${shape} (want container|archive|none|archive-identity)" >&2
    exit 2
    ;;
esac
