#!/usr/bin/env bash
# Regression for the SAST engine's GitHub Actions embedded-Bash parser, over
# testdata/semgrep-github-actions. Semgrep 1.161.0 reported all three parser
# fixtures as partially scanned: expressions inside a quoted URL, command
# substitution around a multiline printf, and a multiline Markdown argument.
# The scan still exited 0, so only the SARIF notifications exposed the gap.
# The fixture also carries a Go lock graph so the Trivy leg has a real target;
# the assertions stay specifically about the SAST engine's warning and prove
# it examined all six fixture files, including the three YAML parser targets
# and unsafe.yml.
#
# The workflows are stored as *.yml.fixture so neither this repository's own
# zizmor audit nor GitHub reads them as workflows; they are materialised only
# for the scan under test. The zizmor leg runs over them too and must not
# error: a workflow-only fixture is the shape it exists for.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fixtures="$work/fixtures"
python3 -I scripts/smoke/materialise-fixtures.py testdata/semgrep-github-actions "$fixtures"
# A real clone, because that is what every consumer hands the scan: the engine
# lists a git project's files with `git ls-files`, its base image has no git,
# and the scan of any checkout with a .git did not run until cicd stopped
# handing it the .git. Without this, every fixture here is a bare directory and
# nothing proves it.
git -C "$fixtures" init -q
git -C "$fixtures" add -A
git -C "$fixtures" -c user.name=smoke -c user.email=smoke@example.com -c commit.gpgsign=false commit -qm fixture
dagger -m ./src/security call scan-source \
  --src "$fixtures" \
  --sast-rulesets p/security-audit,r/yaml.github-actions.security.gha-curl-pipe-shell.gha-curl-pipe-shell \
  --fail-on NONE \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path "$work/gha.json"
python3 - "$work/gha.json" <<'PY'
import json, sys
x = json.load(open(sys.argv[1]))
assert x['passed'] is True, x.get('errors')
assert not x.get('errors'), x.get('errors')
warnings = x.get('warnings', [])
assert not [w for w in warnings if w.startswith('opengrep: PARTIAL SCAN')], warnings
assert len([w for w in warnings if w.startswith('opengrep: RULE FALLBACK')]) == 1, warnings
results = [res for run in x['sarifReport']['runs']
           if 'opengrep' in run['tool']['driver']['name'].lower()
           for res in run.get('results', [])]
hits = [r for r in results if r['ruleId'].endswith('cicd.yaml.github-actions.security.gha-curl-pipe-shell')]
assert len(hits) == 2, [r['ruleId'] for r in results]
og = next(s for s in x['sources'] if s['tool'] == 'opengrep')
assert og['examined']['unit'] == 'files' and og['examined']['count'] == 6, og['examined']
zz = next(s for s in x['sources'] if s['tool'] == 'zizmor')
assert zz['examined']['count'] == 4 and zz['examined'].get('total') == 4, zz['examined']
PY
echo "opengrep-github-actions smoke: ok"
