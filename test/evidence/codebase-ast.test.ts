import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, it } from 'node:test';
import { collectDependentUsage, DEPENDENT_MAX_FILES } from '../../src/evidence/codebase.ts';
import { tempDir } from './helpers.ts';

async function write(root: string, rel: string, content: string): Promise<void> {
  await mkdir(path.dirname(path.join(root, rel)), { recursive: true });
  await writeFile(path.join(root, rel), content);
}

// query-string@6.14.1 uses decode-uri-component, import line 3, call line 7
const QUERY_STRING = [
  "'use strict';",
  "const strictUriEncode = require('strict-uri-encode');",
  "const decodeComponent = require('decode-uri-component');",
  '',
  'function decode(value, options) {',
  '\tif (options.decode) {',
  '\t\treturn decodeComponent(value);',
  '\t}',
  '\treturn value;',
  '}',
  'exports.parse = (query, options) => decode(query, options);',
  '',
].join('\n');

describe('codebase: dependent usage under node_modules', () => {
  it('finds the calls inside a dependent and skips nested node_modules, dist, tests and minified files', async () => {
    const tmp = await tempDir('pp-deps-');
    try {
      const root = tmp.dir;
      await write(root, 'node_modules/query-string/package.json', '{ "name": "query-string", "version": "6.14.1" }');
      await write(root, 'node_modules/query-string/index.js', QUERY_STRING);
      await write(root, 'node_modules/query-string/lib/extra.mjs', "import decode from 'decode-uri-component';\nexport const once = (s) => decode(s);\n");
      await write(root, 'node_modules/query-string/node_modules/other/index.js', "require('decode-uri-component')('x');\n");
      await write(root, 'node_modules/query-string/dist/bundle.js', "require('decode-uri-component')('x');\n");
      await write(root, 'node_modules/query-string/test/index.js', "require('decode-uri-component')('x');\n");
      await write(root, 'node_modules/query-string/min.js', `var d=require('decode-uri-component');${'d("x");'.repeat(600)}`);
      await write(root, 'node_modules/query-string/index.min.js', "require('decode-uri-component')('x');\n");
      await write(root, 'node_modules/decode-uri-component/package.json', '{ "name": "decode-uri-component", "version": "0.2.0" }');
      const found = await collectDependentUsage(root, ['decode-uri-component'], [{ name: 'query-string', version: '6.14.1', dir: 'node_modules/query-string' }]);
      assert.deepEqual(found, [
        { dependent: 'query-string', version: '6.14.1', path: 'node_modules/query-string/index.js', line: 7, member: null, text: 'return decodeComponent(value);' },
        { dependent: 'query-string', version: '6.14.1', path: 'node_modules/query-string/lib/extra.mjs', line: 2, member: null, text: 'export const once = (s) => decode(s);' },
      ]);
      // hoisted, plus a dependent that never uses it
      await write(root, 'node_modules/other-dep/package.json', '{ "name": "other-dep", "version": "1.0.0" }');
      await write(root, 'node_modules/other-dep/index.js', 'module.exports = () => 1;\n');
      const hoisted = await collectDependentUsage(root, ['decode-uri-component'], [
        { name: 'query-string', version: '6.14.1' },
        { name: 'other-dep', version: '1.0.0' },
        { name: 'missing', version: '2.0.0' },
      ]);
      assert.equal(hoisted?.length, 2);
      assert.deepEqual(await collectDependentUsage(root, ['decode-uri-component'], [{ name: 'other-dep', version: '1.0.0' }]), [], 'scanned, no calls');
    } finally {
      await tmp.cleanup();
    }
  });

  it('finds a pnpm layout, caps the files per dependent, and returns undefined without node_modules', async () => {
    const tmp = await tempDir('pp-deps-');
    try {
      const root = tmp.dir;
      assert.equal(await collectDependentUsage(root, ['decode-uri-component'], [{ name: 'query-string', version: '6.14.1' }]), undefined);
      const dir = 'node_modules/.pnpm/query-string@6.14.1/node_modules/query-string';
      await write(root, `${dir}/package.json`, '{ "name": "query-string", "version": "6.14.1" }');
      for (let i = 0; i < DEPENDENT_MAX_FILES + 5; i += 1) await write(root, `${dir}/a${String(i).padStart(3, '0')}.js`, 'module.exports = 1;\n');
      await write(root, `${dir}/zz-last.js`, "require('decode-uri-component')('x');\n");
      assert.deepEqual(await collectDependentUsage(root, ['decode-uri-component'], [{ name: 'query-string', version: '6.14.1' }]), [], 'the file cap stops before zz-last.js');
      await write(root, `${dir}/index.js`, QUERY_STRING);
      assert.deepEqual(
        (await collectDependentUsage(root, ['decode-uri-component'], [{ name: 'query-string', version: '6.14.1' }]))?.map((u) => `${u.path}:${u.line}`),
        [`${dir}/index.js:7`],
      );
    } finally {
      await tmp.cleanup();
    }
  });
});
