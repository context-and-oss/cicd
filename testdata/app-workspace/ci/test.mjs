import assert from 'node:assert/strict';
import { test } from 'node:test';
const app = process.argv[2];
assert.ok(['a', 'b'].includes(app));
const { answer } = await import(`../apps/${app}/index.mjs`);
test(`app ${app} uses its shared library`, () => assert.equal(answer(), 42));
