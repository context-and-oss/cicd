#!/usr/bin/env bash
# Production source scan of the zizmor leg: the real pinned image audits
# testdata/zizmor-workflows, and the evidence must say what it audited, what it
# could not parse, which audits an offline run skipped, what an ignore comment
# and the repository's zizmor.yml removed, and what it found.
#
# The same tree's verbatim output is the unit suite's capture
# (src/security/testdata/zizmor-1.32.0); this smoke is what notices when a
# Renovate bump changes the log grammar that capture froze.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fixtures="$work/fixtures"
python3 -I scripts/smoke/materialise-fixtures.py testdata/zizmor-workflows "$fixtures"
# Default --fail-on: two template injections are HIGH and must fail.
dagger -m ./src/security call scan-source --src "$fixtures" --code-only \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path "$work/zizmor.json"
python3 - "$work/zizmor.json" <<'PY'
import json, sys
x = json.load(open(sys.argv[1]))
assert x['passed'] is False, 'a HIGH zizmor finding must fail the default gate'
assert not x.get('errors'), x.get('errors')

row = next(s for s in x['sources'] if s['tool'] == 'zizmor')
assert row['concern'] == 'sast', row
# 7 audited, broken.yml and schemabad.yml not; nested/ is never collected.
assert row['examined'] == {'unit': 'workflow, action and Dependabot files', 'count': 7, 'total': 9}, row['examined']
assert row['findingsCount'] == 4, row
assert row['rules']['count'] >= 30 and row['rules']['pinned'].startswith('zizmor '), row['rules']

runs = [r for r in x['sarifReport']['runs'] if r['tool']['driver']['name'] == 'zizmor']
assert len(runs) == 1, [r['tool']['driver']['name'] for r in x['sarifReport']['runs']]
got = {(r['ruleId'], r['level'], r['locations'][0]['physicalLocation']['artifactLocation']['uri'],
        r['locations'][0]['physicalLocation']['region']['startLine'], bool(r.get('suppressions')))
       for r in runs[0]['results']}
assert got == {
    ('zizmor/template-injection', 'error', '.github/actions/act1/action.yml', 6, False),
    ('zizmor/dependabot-cooldown', 'warning', '.github/dependabot.yml', 3, False),
    ('zizmor/template-injection', 'error', '.github/workflows/inject.yml', 11, False),
    # zizmor's HIGH, graded MEDIUM by cicd.
    ('zizmor/unpinned-uses', 'warning', '.github/workflows/inject.yml', 8, False),
    # Removed by the ignore comment, by zizmor.yml's disable and by its ignore list.
    ('zizmor/template-injection', 'error', '.github/workflows/ignored.yml', 8, True),
    ('zizmor/dangerous-triggers', 'error', '.github/workflows/inject.yml', 2, True),
    ('zizmor/artipacked', 'warning', '.github/workflows/inject.yml', 8, True),
}, got
text = json.dumps(runs[0])
assert 'file://' not in text and '/src/' not in text, 'a container path escaped into the SARIF'

warnings = [w for w in x.get('warnings', []) if w.startswith('zizmor:')]
def has(*needles):
    assert any(all(n in w for n in needles) for w in warnings), (needles, warnings)
has('PARTIAL SCAN', '2 of 9', '.github/workflows/broken.yml', '.github/workflows/schemabad.yml')
has('NARROWED AUDITS', 'impostor-commit', 'known-vulnerable-actions')
has('3 findings removed', 'dangerous-triggers at .github/workflows/inject.yml:2')
PY
echo "zizmor smoke: ok"
