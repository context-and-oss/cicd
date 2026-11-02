#!/usr/bin/env bash
# Real shared-module executions. A green unit suite is not a substitute for this.
set -euo pipefail
repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"
audit_root=$(mktemp -d "${TMPDIR:-/tmp}/commit-apps.XXXXXX")

run_app() {
  local app=$1
  local broken=${2:-false}
  local lint tests build image prepare
  image=node:24-bookworm
  build="sh ci/node.sh build $app"
  lint=$(jq -cn --arg app "$app" '[{label:"client",language:"node",cmd:("sh ci/node.sh lint "+$app),reportPath:("evidence-out/lint-"+$app+".json"),format:"eslint",toolchainImage:"node:24-bookworm"}]')
  tests=$(jq -cn --arg app "$app" '[{label:"client",language:"node",cmd:("sh ci/node.sh test "+$app),toolchainImage:"node:24-bookworm"}]')
  local extra=(--source-paths "apps/$app" --source-paths packages/shared --source-paths scan.yml)
  if [[ "$app" == b ]]; then
    # Install once. A random token proves that lint/tests/package branch from
    # the same executed preparation; branch-local files must never leak.
    extra+=(--parallelism 2 --prepare-language node --prepare-test-label client
      --prepare-cmd 'npm install --global pnpm@11.19.0 && pnpm install --frozen-lockfile --ignore-scripts && node -e '\''require("fs").writeFileSync(".prepared-token", require("crypto").randomUUID())'\'' && mkdir -p evidence-out && printf "SF:apps/b/index.mjs\nDA:1,1\nend_of_record\n" > evidence-out/stale.info')
    lint=$(jq -c '.[0].cmd="test -s .prepared-token && test ! -f .test-only && touch .lint-only && mkdir -p evidence-out && pnpm exec eslint apps/b packages/shared --format json --output-file evidence-out/lint-b.json"' <<< "$lint")
    tests=$(jq -c '.[0].cmd="test -s .prepared-token && test ! -f .lint-only && touch .test-only && printf PREPARED_TOKEN: && cat .prepared-token && echo && node ci/test.mjs b"' <<< "$tests")
    build='test ! -f .lint-only && test ! -f .test-only && sh ci/node.sh build b && cp .prepared-token dist/b/prepared-token'
  fi
  if [[ "$app" == a ]]; then
    image=mcr.microsoft.com/dotnet/sdk:10.0
    extra+=(--source-paths plugins/a)
    prepare=$(cat <<'PREPARE'
set -eu
dotnet restore plugins/a/tests/PluginChecks.csproj
dotnet build plugins/a/tests/PluginChecks.csproj -c Release --no-restore
cat > Directory.Build.targets <<'TARGETS'
<Project><Target Name="RefuseSecondCompile" BeforeTargets="CoreCompile" Condition="'$(DesignTimeBuild)' != 'true'"><Error Text="Compilation repeated after shared preparation" /></Target></Project>
TARGETS
PREPARE
)
    extra+=(--prepare-language dotnet --prepare-test-label plugin --prepare-cmd "$prepare")
    lint=$(jq -c '.+[{label:"plugin",language:"dotnet",cmd:"mkdir -p evidence-out && dotnet format plugins/a/AppPlugin.csproj --no-restore --verify-no-changes --report evidence-out/lint-plugin.json",reportPath:"evidence-out/lint-plugin.json",format:"dotnet-format",toolchainImage:"mcr.microsoft.com/dotnet/sdk:10.0"}]' <<< "$lint")
    tests=$(jq -c '.+[{label:"plugin",language:"dotnet",cmd:"dotnet run --project plugins/a/tests/PluginChecks.csproj -c Release --no-build --no-restore",toolchainImage:"mcr.microsoft.com/dotnet/sdk:10.0"}]' <<< "$tests")
    build+=' && dotnet publish plugins/a/AppPlugin.csproj -c Release --no-build --no-restore -o dist/a/plugin'
  fi
  local destination="$audit_root/$app"
  if [[ "$broken" == true ]]; then
    destination="$audit_root/broken"
    tests=$(jq -c '.[0].cmd="exit 7"' <<< "$tests")
  fi
  if [[ "$broken" == stale ]]; then
    destination="$audit_root/stale"
    tests=$(jq -c '.[0].coveragePath="evidence-out/stale.info"' <<< "$tests")
  fi
  dagger --progress=plain -m ./src/composites/commit call run \
    --src ./testdata/app-workspace --app-id "app-$app" "${extra[@]}" \
    --lint-legs "$lint" --test-legs "$tests" \
    --artifact archive --build-cmd "$build" --output-path "dist/$app" \
    --toolchain-image "$image" --sast-rulesets ./scan.yml --fail-on NONE \
    --commit-sha fixture-commit --branch main --repo-url https://example.test/workspace \
    --run-url https://example.test/runs/42 \
    export --path "$destination"
}

run_app a
run_app b
run_app b true
run_app b stale

for app in a b; do
  python3 scripts/verify-build-artifact.py "$audit_root/$app/artifacts" \
    --repo https://example.test/workspace --commit fixture-commit --branch main \
    --run-url https://example.test/runs/42 --app-id "app-$app"
done
if python3 scripts/verify-build-artifact.py "$audit_root/broken/artifacts" \
  --repo https://example.test/workspace --commit fixture-commit --branch main \
  --run-url https://example.test/runs/42 --app-id app-b; then
  echo "failed tests produced a deployable bundle" >&2
  exit 1
fi

# Even an explicit metadata-only request cannot switch off source collection
# when the caller asks for a source-only licence verdict.
dagger --progress=plain -m ./src/security call scan-licenses \
  --src ./testdata/app-workspace/packages/shared --source-only --license-full=false \
  --commit-sha fixture-commit --branch main --repo-url https://example.test/workspace \
  export --path "$audit_root/source-license.json"

python3 - "$audit_root" <<'PY'
import json
import pathlib
import re
import sys
import tarfile

root = pathlib.Path(sys.argv[1])
source_only = json.loads((root / "source-license.json").read_text())
assert source_only["passed"], source_only.get("errors")
assert source_only["examined"]["count"] > 0, source_only
for app in ("a", "b"):
    folder = root / app
    combined = json.loads((folder / "combined-evidence.json").read_text())
    parts = [json.loads(p.read_text()) for p in sorted((folder / "parts").glob("*.json")) if p.name != "index.json"]
    assert combined["passed"], combined.get("errors")
    assert combined["repo"]["appId"] == f"app-{app}"
    assert all(p["repo"]["appId"] == f"app-{app}" for p in parts)
    assert not (folder / "comment.md").exists(), "app mode invoked a renderer"
    paths = {f.get("artifactPath", "") for f in combined.get("findings", [])}
    assert "packages/shared/index.mjs" in paths, paths
    neighbour = "b" if app == "a" else "a"
    assert not any(p.startswith(f"apps/{neighbour}/") for p in paths), paths
    if app == "b":
        test_parts = [p for p in parts if p.get("tool", {}).get("name") == "byo-test"]
        token = re.search(r"PREPARED_TOKEN:([a-f0-9-]+)", test_parts[0]["rawOutputRef"]).group(1)
        with tarfile.open(folder / "artifacts/application.tar.gz") as archive:
            assert archive.extractfile("./prepared-token").read().decode() == token, "preparation was not shared"
        assert "apps/b/index.mjs" in paths, paths
        assert not any(p.startswith("plugins/") for p in paths), paths
    else:
        assert "plugins/a/Plugin.cs" in paths, paths
        assert "dotnet" in combined["languages"]
        with tarfile.open(folder / "artifacts/application.tar.gz") as archive:
            assert "./plugin/AppPlugin.dll" in archive.getnames(), "compiled plugin not retained"
    source_licences = [p for p in parts if any("Source-file licence" in w for w in p.get("warnings", []))]
    assert source_licences and source_licences[0]["examined"]["count"] > 0, source_licences
    assert not (folder / "sbom.cdx.json").exists(), "disabled SBOM emitted an inventory"
    assert not any(p.get("cyclonedxReport") for p in parts), "inventory generation still ran"
    assert any("Dependencies: NOT ASSESSED" in w for w in combined.get("warnings", []))
    for concern in ("sbom", "sca"):
        status = json.loads((folder / "concerns" / f"{concern}.json").read_text())
        assert status["outcome"] == "SKIPPED", status
    licences = json.loads((folder / "concerns/licenses.json").read_text())
    assert any(t.get("scope") == "application-dependencies" and t["outcome"] == "SKIPPED" for t in licences["tools"])
failed = json.loads((root / "broken" / "combined-evidence.json").read_text())
assert failed["passed"] is False, "failed tests passed despite dependency deferral"
assert not (root / "broken/sbom.cdx.json").exists()
assert "findings.sarif" in {p.name for p in (root / "broken").iterdir()}, "lost independent scan evidence"
stale = json.loads((root / "stale/combined-evidence.json").read_text())
assert stale["passed"] is False, "prepared coverage passed without a fresh test report"
assert any("coverage" in e for e in stale.get("errors", [])), stale
print("Application isolation and failure evidence verified:", root)
PY
