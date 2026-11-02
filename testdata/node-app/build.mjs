// Minimal build script for the node-app fixture — stands in for a real bundler
// emitting dist/. Used by archive-shape integration tests (BuildArchive /
// ScanArchive). Node stdlib only — no devDependencies.
import { cpSync, mkdirSync, rmSync } from 'node:fs';

rmSync('dist', { recursive: true, force: true });
mkdirSync('dist', { recursive: true });

// The built entry file.
cpSync('index.js', 'dist/index.js');

// Plant the fake-secret fixture into the built output so secrets-scanner
// integration tests get a deterministic gitleaks finding. The key is fake
// (AWS's documented example) — see leaked.env.fixture.
cpSync('leaked.env.fixture', 'dist/leaked.env');

console.log('build.mjs: wrote dist/index.js and dist/leaked.env');
