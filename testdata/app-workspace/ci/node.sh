#!/bin/sh
set -eu
kind=$1
app=$2
case "$app" in a|b) ;; *) exit 2 ;; esac
mkdir -p evidence-out
case "$kind" in
  lint)
    npm install --global pnpm@11.19.0
    pnpm install --frozen-lockfile --ignore-scripts
    pnpm exec eslint "apps/$app" packages/shared --format json --output-file "evidence-out/lint-$app.json"
    ;;
  test) node ci/test.mjs "$app" ;;
  build)
    mkdir -p "dist/$app"
    cp "apps/$app/index.mjs" "dist/$app/index.mjs"
    ;;
  *) exit 2 ;;
esac
