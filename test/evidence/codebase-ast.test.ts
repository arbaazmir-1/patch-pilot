import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { after, afterEach, before, describe, it } from 'node:test';
import { MemoryAudit } from '../../src/audit.ts';
import { DEFAULT_EXCLUDES, loadConfig } from '../../src/config.ts';
import { runPhase1 } from '../../src/evidence/casefile.ts';
import { collectDependentUsage, collectUsageEvidence, DEPENDENT_MAX_FILES, findUsage } from '../../src/evidence/codebase.ts';
import { captureUi, copyFixtureApp, FIXTURE_APP, fixtureData, fixtureServer, stubFetch, tempDir } from './helpers.ts';

const PACKAGES = ['lodash', 'minimist', 'marked', 'json5', 'semver', 'decode-uri-component'];

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

describe('codebase: the parser path on examples/vulnerable-app', () => {
  it('keeps the wave 1 evidence and adds method ast and the calls through the app modules', async () => {
    const evidence = await collectUsageEvidence(FIXTURE_APP, PACKAGES, { exclude: DEFAULT_EXCLUDES });
    const lodash = evidence.get('lodash');
    assert.deepEqual(
      lodash?.files.map((s) => [s.path, s.line, s.kind, s.binding, s.statement]),
      [['src/config.js', 7, 'cjs-require', '_', "const _ = require('lodash');"]],
    );
    assert.deepEqual(lodash?.membersUsed, { get: 3, merge: 1 });
    assert.equal(evidence.get('minimist')?.bindingCalls, 1);
    assert.equal(evidence.get('marked')?.bindingCalls, 1);
    assert.deepEqual(evidence.get('json5')?.membersUsed, { parse: 1 });
    assert.deepEqual(evidence.get('semver')?.scopes, { source: 0, test: 0, config: 0, scripts: 1 });
    assert.equal(evidence.get('decode-uri-component')?.imported, false);
    for (const name of PACKAGES) {
      const e = evidence.get(name);
      assert.equal(e?.method, 'ast', name);
      assert.equal(e?.dynamicAccess, undefined, `${name}: no dynamic access`);
      assert.equal(e?.dependentUsage, undefined, `${name}: dependents are not scanned here`);
    }
    assert.deepEqual(lodash?.indirectPaths, [
      { path: 'src/cli.js', line: 33, via: ['loadConfig'], member: 'merge' },
      { path: 'src/cli.js', line: 33, via: ['loadConfig'], member: 'get' },
    ]);
    assert.deepEqual(evidence.get('json5')?.indirectPaths, [{ path: 'src/cli.js', line: 33, via: ['loadConfig', 'readConfigFile'], member: 'parse' }]);
    assert.deepEqual(
      evidence.get('marked')?.indirectPaths?.map((p) => `${p.path}:${p.line} ${p.via.join('>')}`),
      ['src/cli.js:34 renderDocument>renderMarkdown', 'test/render.test.js:8 renderMarkdown', 'test/render.test.js:14 renderDocument>renderMarkdown'],
    );
    assert.equal(evidence.get('minimist')?.indirectPaths, undefined, 'minimist is called at the top of main(), not through another module');
  });

  it('findUsage gives the same call sites as before', async () => {
    const evidence = await collectUsageEvidence(FIXTURE_APP, ['lodash'], { exclude: DEFAULT_EXCLUDES });
    const sites = evidence.get('lodash')?.files ?? [];
    assert.deepEqual((await findUsage(FIXTURE_APP, sites, 'get', { contextLines: 2 })).map((u) => u.line), [24, 25, 26]);
    assert.deepEqual((await findUsage(FIXTURE_APP, sites, undefined, {})).map((u) => `${u.line}:${u.member}`), ['22:merge', '24:get', '25:get', '26:get']);
  });
});

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

  describe('runPhase1 attaches the dependent usage of a transitive package', async () => {
    const data = await fixtureData();
    let app: { dir: string; cleanup: () => Promise<void> };
    let home: { dir: string; cleanup: () => Promise<void> };
    let stub: ReturnType<typeof stubFetch> | null = null;
    before(async () => {
      app = await copyFixtureApp();
      home = await tempDir('pp-home-');
    });
    afterEach(() => {
      stub?.restore();
      stub = null;
    });
    after(async () => {
      await app.cleanup();
      await home.cleanup();
    });

    it('leaves dependentUsage undefined without node_modules and fills it when installed', async () => {
      stub = stubFetch(fixtureServer(data));
      const config = await loadConfig({ dir: app.dir, flags: { trust: true }, homeDir: home.dir, stdinIsTTY: false, stdoutIsTTY: false });
      const first = await runPhase1(config, { ui: captureUi().ui, audit: new MemoryAudit() });
      const decode = (cf: typeof first) => cf.packages.find((p) => p.name === 'decode-uri-component');
      assert.equal(decode(first)?.usage.dependentUsage, undefined);
      assert.equal(decode(first)?.usage.method, 'ast');
      await write(app.dir, 'node_modules/query-string/package.json', '{ "name": "query-string", "version": "6.14.1" }');
      await write(app.dir, 'node_modules/query-string/index.js', QUERY_STRING);
      const second = await runPhase1(config, { ui: captureUi().ui, audit: new MemoryAudit() });
      assert.deepEqual(decode(second)?.usage.dependentUsage, [
        { dependent: 'query-string', version: '6.14.1', path: 'node_modules/query-string/index.js', line: 7, member: null, text: 'return decodeComponent(value);' },
      ]);
      assert.equal(second.packages.find((p) => p.name === 'lodash')?.usage.dependentUsage, undefined, 'imported packages are not scanned in node_modules');
    });
  });
});
