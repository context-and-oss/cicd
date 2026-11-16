#!/usr/bin/env bash
# Production run of security.ScanTaint over testdata/interfile-taint: the
# pinned Opengrep engine and rules, both runs, the delta between them.
#
# The fixture has, per language, one source-to-sink flow inside one function
# (ScanSource already reports it, so ScanTaint must not), one through a helper
# in the same file and one through a helper in another file (only the
# interfile run finds them), and a Go chain five calls deep that the default
# depth of 3 cannot follow and must say so. The C# flows run through cicd's own
# log-forging and secret-in-log rules, and a ScanSource call over the C# alone
# proves the default scan reports the single-function ones without gating on
# them.
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
# The default source scan of the C# alone, at the default threshold.
dagger -m ./src/security call scan-source --src "$fixtures" --path csharp --code-only \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path "$work/source.json"

python3 - "$work/warn.json" "$work/gate.json" "$work/source.json" <<'PY'
import json, sys

def load(path):
    x = json.load(open(path))
    assert not x.get('errors'), x.get('errors')
    assert x['tool']['name'] == 'security-taint', x['tool']
    assert x['concern'] == 'sast', x['concern']
    (row,) = x['sources']
    assert row['tool'] == 'opengrep-interfile' and row['concern'] == 'sast', row
    assert row['rules']['count'] == 29, row['rules']
    assert row['rules']['pinned'].startswith('cicd/interfile-taint = '), row['rules']
    assert row['rules']['byLanguage'].get('cicd') == 2, row['rules']
    assert row['examined'] == {'unit': 'files', 'count': 14}, row['examined']
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
    # log-forging across a function and across a file; secret-in-log across a file.
    ('csharp/OrdersController.cs', 35), ('csharp/OrderAudit.cs', 17), ('csharp/OrderAudit.cs', 23),
}
# Found by the single-function pass, so ScanSource's; never repeated here.
same_cs = {('csharp/OrdersController.cs', 23), ('csharp/OrdersController.cs', 27)}
same = {('go/handlers.go', 10), ('java/src/main/java/app/Controller.java', 11), ('js/routes.js', 5)} | same_cs

warn, row, got = load(sys.argv[1])
assert got == cross, (sorted(got), sorted(cross))
assert not got & same
assert warn['passed'] is True, 'warn mode must not fail over findings'
assert warn['failOnSeverity'] == 'NONE', warn['failOnSeverity']
assert row['findingsCount'] == 9 and warn['findingsCount'] == 9, (row, warn['findingsCount'])
ws = warn.get('warnings', [])
def has(ws, *needles):
    assert any(all(n in w for n in needles) for w in ws), (needles, ws)
has(ws, 'call depth 3', 'C# log-forging and secret-in-log')
has(ws, 'DEPTH CAPPED', 'tainted-sql-string', 'depth 3')
has(ws, '9 cross-function finding(s)', '"warn"')

gate, row, got = load(sys.argv[2])
assert got == cross | {('deep/E.go', 6)}, sorted(got)
assert gate['passed'] is False, 'an enforced gate with HIGH findings must fail'
assert gate['failOnSeverity'] == 'HIGH', gate['failOnSeverity']
ws = gate.get('warnings', [])
has(ws, 'call depth unlimited')
assert not any('DEPTH CAPPED' in w for w in ws), ws
assert not any('reported and not enforced' in w for w in ws), ws

# ScanSource over the C# alone: the single-function findings, cicd's rules,
# MEDIUM, so the default HIGH threshold passes.
src = json.load(open(sys.argv[3]))
assert not src.get('errors'), src.get('errors')
cs = {}
for run in src['sarifReport']['runs']:
    for r in run.get('results', []):
        if r['ruleId'].endswith(('cicd.csharp.log-forging', 'cicd.csharp.secret-in-log')):
            loc = r['locations'][0]['physicalLocation']
            cs[(loc['artifactLocation']['uri'], loc['region']['startLine'])] = r['ruleId'].rsplit('.', 1)[1]
want = {('OrdersController.cs', 23): 'log-forging', ('OrdersController.cs', 27): 'secret-in-log'}
assert cs == want, (cs, want)
assert src['passed'] is True and src['failOnSeverity'] == 'HIGH', (src['passed'], src['failOnSeverity'])
PY
echo "interfile-taint smoke: ok"
