#!/usr/bin/env bash
# Production source scan: real rules, inline locations, evidence verdict and redaction.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# Intentional positive controls are data in the tree, not shipped executable
# sources. Materialize their real names only for the scanner under test.
fixtures="$work/fixtures"
python3 - testdata/semgrep-inline-html "$fixtures" <<'PY'
from pathlib import Path
import shutil, sys
source, target = map(Path, sys.argv[1:])
for path in source.rglob('*'):
    if not path.is_file():
        continue
    relative = path.relative_to(source)
    if relative.name.endswith('.fixture'):
        relative = relative.with_suffix('')
    output = target / relative
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(path, output)
PY
scan() {
  dagger -m ./src/security call scan-source --src "$1" --code-only \
    --fail-on "${3:-HIGH}" --commit-sha local --branch main --repo-url https://example.com \
    export --path "$2"
}
scan "$fixtures/unsafe" "$work/unsafe.json"
python3 - "$work/unsafe.json" "$fixtures/unsafe/module.htm" <<'PY'
import json, sys
x = json.load(open(sys.argv[1]))
assert x['passed'] is False and not x.get('errors'), x.get('errors')
results = [r for run in x['sarifReport']['runs'] for r in run.get('results', [])
           if r['ruleId'].endswith('cicd.javascript.dom-text-to-html')]
assert len(results) == 4, len(results)
locations = {(r['locations'][0]['physicalLocation']['artifactLocation']['uri'],
              r['locations'][0]['physicalLocation']['region']['startLine']) for r in results}
assert locations == {('page.html', 7), ('module.htm', 5), ('standalone.js', 2), ('template.html', 2)}, locations
module = next(r for r in results if r['locations'][0]['physicalLocation']['artifactLocation']['uri'] == 'module.htm')
line = open(sys.argv[2]).read().splitlines()[4]
column = len(line[:line.rfind('message')].encode('utf-16-le')) // 2 + 1
assert module['locations'][0]['physicalLocation']['region']['startColumn'] == column
assert 'inline-000' not in json.dumps(x), 'synthetic location escaped'
assert not any('PARTIAL' in w for w in x.get('warnings', [])), x.get('warnings')
source = next(s for s in x['sources'] if s['tool'] == 'semgrep')
assert source['findingsCount'] == 4 and source['rules']['count'] >= 726, source
PY
scan "$fixtures/unsafe" "$work/none.json" NONE
jq -e '.passed == true and ([.errors[]?] | length == 0) and .findingsCount >= 4' "$work/none.json" >/dev/null
scan "$fixtures/safe" "$work/safe.json"
jq -e '.passed == true and .findingsCount == 0 and ([.errors[]?] | length == 0)' "$work/safe.json" >/dev/null

# A parser warning names the original HTML, but never quotes its source.
mkdir "$work/partial"
printf '%s\n' '<script>const marker="INLINE_SOURCE_MUST_BE_WITHHELD"; function broken( {</script>' > "$work/partial/page.html"
scan "$work/partial" "$work/partial.json"
python3 - "$work/partial.json" <<'PY'
import json, sys
raw = open(sys.argv[1]).read()
x = json.loads(raw)
assert 'INLINE_SOURCE_MUST_BE_WITHHELD' not in raw
assert 'inline-000' not in raw
assert any('PARTIAL SCAN' in w and 'page.html' in w for w in x.get('warnings', [])), x.get('warnings')
PY

# An explicit custom-only config must not silently gain cicd's default rules.
mkdir "$work/custom"
printf '%s\n' '<script>document.body.innerHTML = document.body.textContent;</script>' > "$work/custom/page.html"
printf '%s\n' 'rules:' '  - id: custom-only' '    languages: [html]' '    message: custom control' '    severity: INFO' '    pattern: <never-present />' > "$work/custom/semgrep.yml"
dagger -m ./src/security call scan-source --src "$work/custom" --code-only \
  --sast-rulesets ./semgrep.yml --fail-on HIGH --commit-sha local --branch main \
  --repo-url https://example.com export --path "$work/custom.json"
jq -e '.passed == true and .findingsCount == 0 and ([.sources[] | select(.tool == "semgrep")][0].rules.count == 1)' "$work/custom.json" >/dev/null
# The public composites must carry the same findings and fail the evidence gate.
# No deployment or notification credentials are supplied.
bash scripts/ci/dagger-develop.sh src/composites/commit
dagger -m ./src/composites/commit call run --src "$fixtures/unsafe" \
  --artifact none --fail-on HIGH --commit-sha local --branch main --repo-url https://example.com \
  export --path "$work/commit"
bash scripts/ci/dagger-develop.sh src/composites/precommit
dagger -m ./src/composites/precommit call run --src "$fixtures/unsafe" \
  --fail-on HIGH --commit-sha local --branch main --repo-url https://example.com \
  export --path "$work/precommit"
for pipeline in commit precommit; do
  jq -e '.passed == false and ([.errors[]?] | length == 0)
    and ([.findings[]? | select(.rule | endswith("dom-text-to-html"))] | length == 4)' \
    "$work/$pipeline/combined-evidence.json" >/dev/null
done
printf '%s\n' 'Inline JavaScript SAST smoke: OK'
