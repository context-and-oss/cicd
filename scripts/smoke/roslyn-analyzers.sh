#!/usr/bin/env bash
# Production source scan of the Roslyn security-analyzer leg: the real pinned
# SDK builds testdata/roslyn-sast, and the evidence must say what it analysed,
# what it could not, what the repository switched off and what it found.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# The projects are data in the tree, not buildable sources of this repository.
# Materialize their real names only for the scanner under test.
fixtures="$work/fixtures"
python3 -I scripts/smoke/materialise-fixtures.py testdata/roslyn-sast "$fixtures"
# Default --fail-on: the CA3003 path-injection finding is HIGH and must fail.
dagger -m ./src/security call scan-source --src "$fixtures" --code-only \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path "$work/roslyn.json"
python3 - "$work/roslyn.json" <<'PY'
import json, sys
x = json.load(open(sys.argv[1]))
assert x['passed'] is False, 'a HIGH Roslyn finding must fail the default gate'
assert not x.get('errors'), x.get('errors')

row = next(s for s in x['sources'] if s['tool'] == 'roslyn-analyzers')
assert row['concern'] == 'sast', row
# web/ and broken/ were built; legacy/ was not; the F# project is not counted.
assert row['examined'] == {'unit': 'C#/VB projects', 'count': 2, 'total': 3, 'partial': 1}, row['examined']
assert row['findingsCount'] == 2, row
assert row['rules']['count'] > 0 and '(bundled analyzers)' in row['rules']['pinned'], row['rules']

runs = [r for r in x['sarifReport']['runs'] if r['tool']['driver']['name'] == 'roslyn-analyzers']
assert len(runs) == 1, [r['tool']['driver']['name'] for r in x['sarifReport']['runs']]
results = {(r['ruleId'], r['level'], r['locations'][0]['physicalLocation']['artifactLocation']['uri'],
            bool(r.get('suppressions'))) for r in runs[0]['results']}
assert results == {
    ('CA3003', 'error', 'web/OrderController.cs', False),
    ('CA5350', 'warning', 'web/Hashing.cs', False),
    ('CA5351', 'warning', 'web/Hashing.cs', True),
}, results
text = json.dumps(runs[0])
assert 'file://' not in text and '/src/' not in text, 'a container path escaped into the SARIF'
# The .editorconfig switches CA5394 off: it must not fire, and must be named.
assert 'CA5394' not in {r['ruleId'] for r in runs[0]['results']}

warnings = [w for w in x.get('warnings', []) if w.startswith('roslyn-analyzers:')]
def has(*needles):
    assert any(all(n in w for n in needles) for w in warnings), (needles, warnings)
has('legacy/Legacy.csproj', 'legacy (non-SDK)')
has('F# project', 'fn/Pricing.fsproj')
has('PARTIAL SCAN', 'broken/Broken.csproj')
has('NARROWED RULES', 'CA5394')
has('1 finding suppressed in source')
assert not any('PARTIAL SCAN' in w and 'web/Web.csproj' in w for w in warnings), warnings
# The combined build analysed both buildable projects. Only broken/, whose
# build failed inside it, is rebuilt on its own; web/ never is.
has('the combined build left 1 of 2', 'rebuilt one at a time: broken/Broken.csproj')
assert not any('combined build' in w and 'web/Web.csproj' in w for w in warnings), warnings
PY
echo "roslyn-analyzers smoke: ok"

# Second scenario: a project whose restore fails stops the combined solution
# build. The per-project fallback must still analyse the project that can
# build, and the evidence must say the slow path ran.
fallback="$work/fallback"
python3 -I scripts/smoke/materialise-fixtures.py testdata/roslyn-sast-fallback "$fallback"
dagger -m ./src/security call scan-source --src "$fallback" --code-only --fail-on NONE \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path "$work/fallback.json"
python3 - "$work/fallback.json" <<'PY'
import json, sys
x = json.load(open(sys.argv[1]))
assert not x.get('errors'), x.get('errors')

row = next(s for s in x['sources'] if s['tool'] == 'roslyn-analyzers')
assert row['examined']['count'] == 1 and row['examined']['total'] == 2, row['examined']

runs = [r for r in x['sarifReport']['runs'] if r['tool']['driver']['name'] == 'roslyn-analyzers']
results = {(r['ruleId'], r['locations'][0]['physicalLocation']['artifactLocation']['uri']) for r in runs[0]['results']}
assert ('CA5350', 'web/Hashing.cs') in results, results

warnings = [w for w in x.get('warnings', []) if w.startswith('roslyn-analyzers:')]
def has(*needles):
    assert any(all(n in w for n in needles) for w in warnings), (needles, warnings)
has('the combined build left 2 of 2', 'rebuilt one at a time', 'norestore/NoRestore.csproj', 'web/Web.csproj')
has('not analysed', 'norestore/NoRestore.csproj')
PY
echo "roslyn-analyzers fallback smoke: ok"
