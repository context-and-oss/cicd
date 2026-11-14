#!/usr/bin/env bash
# Production run of security.ScanTaint over testdata/interfile-taint: the
# pinned Opengrep engine and rules, both runs, the delta between them.
#
# The fixture has, per language, one source-to-sink flow inside one function
# (ScanSource already reports it, so ScanTaint must not), one through a helper
# in the same file and one through a helper in another file (only the
# interfile run finds them), and a Go chain five calls deep that the default
# depth of 3 cannot follow and must say so.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fixtures="$work/fixtures"
python3 -I scripts/smoke/materialise-fixtures.py testdata/interfile-taint "$fixtures"

# Default: advisory, depth 3.
dagger -m ./src/security call scan-taint --src "$fixtures" \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path "$work/warn.json"
# Enforced, no depth limit: the deep chain is followed and the gate fails.
dagger -m ./src/security call scan-taint --src "$fixtures" \
  --taint-gate gate --interfile-depth=-1 \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path "$work/gate.json"

python3 - "$work/warn.json" "$work/gate.json" <<'PY'
import json, sys

def load(path):
    x = json.load(open(path))
    assert not x.get('errors'), x.get('errors')
    assert x['tool']['name'] == 'security-taint', x['tool']
    assert x['concern'] == 'sast', x['concern']
    (row,) = x['sources']
    assert row['tool'] == 'opengrep-interfile' and row['concern'] == 'sast', row
    assert row['rules']['count'] == 27, row['rules']
    assert row['rules']['pinned'].startswith('cicd/interfile-taint = '), row['rules']
    assert row['examined'] == {'unit': 'files', 'count': 12}, row['examined']
    (run,) = x['sarifReport']['runs']
    assert run['automationDetails']['id'] == 'opengrep-interfile', run.get('automationDetails')
    got = {(r['locations'][0]['physicalLocation']['artifactLocation']['uri'],
            r['locations'][0]['physicalLocation']['region']['startLine'])
           for r in run['results']}
    text = json.dumps(run)
    # The Java fixture's own path has a src/ in it, so the test is for an
    # absolute container path, not the substring.
    assert 'file://' not in text and '"/src/' not in text, 'a container path escaped into the SARIF'
    assert not any(u.startswith('/') for u, _ in got), sorted(got)
    return x, row, got

cross = {
    ('go/handlers.go', 20), ('go/repo.go', 6),
    ('java/src/main/java/app/Controller.java', 21), ('java/src/main/java/app/Repo.java', 5),
    ('js/routes.js', 9), ('js/repo.js', 4),
}
# Found by the single-function pass, so ScanSource's; never repeated here.
same = {('go/handlers.go', 10), ('java/src/main/java/app/Controller.java', 11), ('js/routes.js', 5)}

warn, row, got = load(sys.argv[1])
assert got == cross, (sorted(got), sorted(cross))
assert not got & same
assert warn['passed'] is True, 'warn mode must not fail over findings'
assert warn['failOnSeverity'] == 'NONE', warn['failOnSeverity']
assert row['findingsCount'] == 6 and warn['findingsCount'] == 6, (row, warn['findingsCount'])
ws = warn.get('warnings', [])
def has(ws, *needles):
    assert any(all(n in w for n in needles) for w in ws), (needles, ws)
has(ws, 'call depth 3', 'none for C#')
has(ws, 'DEPTH CAPPED', 'tainted-sql-string', 'depth 3')
has(ws, '6 cross-function finding(s)', '"warn"')

gate, row, got = load(sys.argv[2])
assert got == cross | {('deep/E.go', 6)}, sorted(got)
assert gate['passed'] is False, 'an enforced gate with HIGH findings must fail'
assert gate['failOnSeverity'] == 'HIGH', gate['failOnSeverity']
ws = gate.get('warnings', [])
has(ws, 'call depth unlimited')
assert not any('DEPTH CAPPED' in w for w in ws), ws
assert not any('reported and not enforced' in w for w in ws), ws
PY
echo "interfile-taint smoke: ok"
