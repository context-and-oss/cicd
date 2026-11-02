#!/usr/bin/env bash
# dotnet-runner-shapes.sh — proves that `quality.Check` asks which `dotnet test`
# command-line surface a repository has, instead of assuming one.
#
# `dotnet test` is two mutually exclusive CLIs. VSTest takes `--logger trx` and
# `--collect:"XPlat Code Coverage"`; Microsoft.Testing.Platform (MTP) takes
# `--report-trx --coverage --coverage-output-format cobertura` and rejects the
# VSTest flags outright. Measured on SDK 10.0.400, cicd's single VSTest-shaped
# invocation made every MTP repository a NON-RUN — exit 1 without the opt-in
# ("Testing with VSTest target is no longer supported"), exit 5 with it
# ("Unknown option '--logger'") — which `gatedPassed` fails at every threshold
# including `--fail-on NONE`. See specs/detect-the-dotnet-test-runner.md.
#
# Usage: bash scripts/smoke/dotnet-runner-shapes.sh
#
# Env (supplied by the module-test job): MODULE, SHA, BRANCH, REPO.
#
# This lives in a script rather than inline in .github/workflows/ci.yml because
# the quality arm of that job is the repository's largest `run:` body and a body
# over roughly 24 KB makes GitHub refuse the workflow at STARTUP — no job, no
# check run, an absence from the PR check list rather than a red tick. See
# docs/reference/workflow-step-size.md.
set -euo pipefail

MODULE="${MODULE:-src/quality}"
SHA="${SHA:-local}"
BRANCH="${BRANCH:-main}"
REPO="${REPO:-https://example.com}"

# --- 1. The VSTest fixture must NAME its runner ------------------------------
# `check` returns a File, so passed=false never fails the CLI — the jq
# assertions are the whole proof. A run whose runner is unnamed is a run whose
# invocation nobody can audit from the evidence, which is why this is asserted
# for both surfaces and not only the new one.
dagger -m "./$MODULE" call check --src ./testdata/dotnet-app --include dotnet \
  --commit-sha "$SHA" --branch "$BRANCH" --repo-url "$REPO" \
  export --path /tmp/evidence-dotnet-vstest-runner.json
jq -e '.passed == true
  and ((.errors // []) | length == 0)
  and ((.warnings // [])
       | map(select(test("dotnet test: runner VSTest"))) | length > 0)' \
  /tmp/evidence-dotnet-vstest-runner.json

# --- 2. The MTP fixture must run, and must measure coverage -----------------
# Two assertions, because two separate defects had to be fixed for this to pass.
# The invocation: an MTP project cannot be driven through the VSTest target at
# all on the .NET 10 SDK. The harvest: MTP writes <guid>.cobertura.xml, so the
# old glob on coverlet's literal `coverage.cobertura.xml` matched ZERO files over
# a pooled run holding two reports — fixing only the invocation would have
# shipped a green .NET leg that measured nothing.
#
# testdata/dotnet-mtp-app is also a detection test. Every original entry in
# dotnetTestMarkers was VSTest vocabulary, and an MSTest 4 project references no
# adapter and no Microsoft.NET.Test.Sdk, so it was reported as "not a test
# project" and this whole path was unreachable. Its .csproj deliberately contains
# no marker literal in prose — it once passed discovery only because the runner
# name appeared in an XML comment.
dagger -m "./$MODULE" call check --src ./testdata/dotnet-mtp-app --include dotnet \
  --commit-sha "$SHA" --branch "$BRANCH" --repo-url "$REPO" \
  export --path /tmp/evidence-dotnet-mtp.json
jq -e '.passed == true
  and ((.errors // []) | length == 0)
  and (.coverageByLanguage.dotnet > 0)
  and (.coverageLinesByLanguage.dotnet > 0)
  and ((.warnings // [])
       | map(select(test("runner Microsoft.Testing.Platform"))) | length > 0)
  and ((.warnings // [])
       | map(select(test("ran [0-9]+ of [0-9]+ \\.csproj found under the source root"))) | length > 0)
  and ((.warnings // [])
       | map(select(test("carr(y|ies) no test marker in the project file itself"))) | length > 0)' \
  /tmp/evidence-dotnet-mtp.json

# --- 3. An empty coverage report is not a 100% measurement ------------------
# A test project that instruments no code writes a well-formed 178-byte
# cobertura: <packages />, line-rate="1", and no lines-valid. That parsed as
# 100%, and mergeDotnetCoverage falls through to an unweighted mean when no
# report carries a line count — so this repository reported 100% over nil lines.
# An inflated figure is wrong in the direction that SURVIVES a ratchet: it sets
# the bar, and every later run is measured against a number nothing measured.
#
# The fixture is written here rather than committed under testdata/ because it
# exists to be refused, and a permanently failing fixture under testdata/ would
# be picked up by every other consumer of that directory.
rm -rf /tmp/dotnet-mtp-empty
mkdir -p /tmp/dotnet-mtp-empty/tests
cat > /tmp/dotnet-mtp-empty/global.json <<'JSON'
{ "test": { "runner": "Microsoft.Testing.Platform" } }
JSON
cat > /tmp/dotnet-mtp-empty/tests/only.Tests.csproj <<'CSPROJ'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <EnableMSTestRunner>true</EnableMSTestRunner>
    <OutputType>Exe</OutputType>
    <IncludeTestAssemblyInCoverage>false</IncludeTestAssemblyInCoverage>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="MSTest" Version="4.0.2" />
  </ItemGroup>
</Project>
CSPROJ
cat > /tmp/dotnet-mtp-empty/tests/OnlyTests.cs <<'CS'
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public class OnlyTests
{
    [TestMethod]
    public void Passes() => Assert.IsTrue(true);
}
CS
# --fail-on NONE is deliberate: NONE suppresses findings and must not suppress a
# measurement that could not be made.
dagger -m "./$MODULE" call check --src /tmp/dotnet-mtp-empty --include dotnet \
  --min-coverage 50 --fail-on NONE \
  --commit-sha "$SHA" --branch "$BRANCH" --repo-url "$REPO" \
  export --path /tmp/evidence-dotnet-mtp-empty.json
jq -e '.failOnSeverity == "NONE" and .passed == false
  and (.coverageByLanguage.dotnet == null)
  and ((.errors // [])
       | map(select(test("no coverage was measured"))) | length > 0)
  and ((.warnings // [])
       | map(select(test("none carried a coverable line count"))) | length > 0)' \
  /tmp/evidence-dotnet-mtp-empty.json

echo "dotnet runner shapes: OK (VSTest named, MTP ran and measured, empty report refused)"
