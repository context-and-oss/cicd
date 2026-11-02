#!/bin/sh
set -eu
mkdir -p evidence-out
case "$1" in
  lint) dotnet format plugins/a/AppPlugin.csproj --verify-no-changes --report evidence-out/lint-plugin.json ;;
  test) dotnet run --project plugins/a/tests/PluginChecks.csproj ;;
  *) exit 2 ;;
esac
