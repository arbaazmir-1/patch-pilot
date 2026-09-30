import assert from 'node:assert/strict';
import { mkdir, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { handleCheckDeps, pathsToRoot } from '../../src/investigation/tools/checkDeps.ts';
import { makeGetUsageHandler, type GetUsageData } from '../../src/investigation/tools/getUsage.ts';
import { createToolRegistry } from '../../src/investigation/tools/index.ts';
import { handleReadFile } from '../../src/investigation/tools/readFile.ts';
import { compilePattern, makeSearchCodeHandler } from '../../src/investigation/tools/searchCode.ts';
import type { DependencyGraph, ImportSite, PackageNode, SearchMatch, ToolContext } from '../../src/types.ts';
import { caseFileOf, decodeFixture, fakeFindUsage, lodashFixture, site, tempDir } from './helpers.ts';

function ctxFor(partial: Partial<ToolContext> = {}): ToolContext {
  return { projectRoot: '/proj', config: { exclude: [] } as unknown as ToolContext['config'], caseFile: null, graph: null, cache: null, audit: null, ...partial };
}

describe('get_usage', () => {
  it('reports dynamic member access that could reach the symbol indirectly', async () => {
    const files = { 'src/a.js': "const _ = require('lodash');\nconst fn = process.argv[2];\n_[fn]('x');\n_.merge({}, {});\n" };
    const { pkg } = lodashFixture();
    pkg.usage.files = [site('src/a.js', 1, "const _ = require('lodash');", '_')];
    const read: string[] = [];
    const handler = makeGetUsageHandler({
      findUsage: fakeFindUsage(files),
      readText: async (abs) => {
        read.push(abs);
        return files['src/a.js'];
      },
    });
    const r = await handler({ package: 'lodash', symbol: 'template' }, ctxFor({ projectRoot: '/proj', caseFile: caseFileOf([pkg], []) }));
    assert.equal(r.hint, '0 calls to _.template; project calls _.merge (1); dynamic access at src/a.js:3');
    assert.deepEqual((r.data as GetUsageData).dynamicAccess, ['src/a.js:3']);
    assert.deepEqual(read, [path.join('/proj', 'src/a.js')]);
    assert.match(r.text ?? '', /Dynamic member access \(_\[\.\.\.\]\) at src\/a\.js:3 could reach template indirectly\./);
  });

  it('counts calls of named and subpath imports as calls of the symbol', async () => {
    const files = { 'src/a.js': "const { template: tpl } = require('lodash');\nconst t = require('lodash/trim');\ntpl('x');\nt(' y ');\n" };
    const sites: ImportSite[] = [
      site('src/a.js', 1, "const { template: tpl } = require('lodash');", 'tpl', { kind: 'cjs-destructure', named: { template: 'tpl' } }),
      site('src/a.js', 2, "const t = require('lodash/trim');", 't', { subpath: 'trim' }),
    ];
    const { pkg } = lodashFixture();
    pkg.usage.files = sites;
    const ctx = ctxFor({ caseFile: caseFileOf([pkg], []) });
    const handler = makeGetUsageHandler({ findUsage: fakeFindUsage(files) });
    assert.equal(((await handler({ package: 'lodash', symbol: 'template' }, ctx)).data as GetUsageData).symbolCalls, 1);
    assert.equal(((await handler({ package: 'lodash', symbol: 'trim' }, ctx)).data as GetUsageData).symbolCalls, 1);
    assert.deepEqual(((await handler({ package: 'lodash' }, ctx)).data as GetUsageData).membersUsed, { template: 1, trim: 1 });
  });
});

describe('search_code', () => {
  const matches: SearchMatch[] = [
    { path: 'src/config.js', line: 21, text: '  const merged = _.merge({}, DEFAULTS);', scope: 'source' },
    { path: 'package-lock.json', line: 3, text: '"merge": true', scope: 'config' },
    { path: 'test/a.test.js', line: 5, text: 'merge(x)', scope: 'test' },
    { path: 'dist/app.min.js', line: 1, text: `${'x'.repeat(600)}merge(`, scope: 'source' },
  ];

  it('validates the regex and returns a fixable error', async () => {
    assert.ok('regex' in compilePattern('\\.merge\\('));
    assert.equal((compilePattern('/merge/gi') as { regex: RegExp }).regex.flags, 'i');
    const handler = makeSearchCodeHandler({ searchProject: async () => ({ matches: [], total: 0, truncated: false }) });
    const bad = await handler({ pattern: '(' }, ctxFor());
    assert.equal(bad.ok, false);
    assert.match(bad.error ?? '', /^Invalid regular expression/);
    assert.equal((bad.error ?? '').split('Invalid regular expression').length, 2, 'the prefix appears once');
    assert.match(bad.hint, /backslash/);
    const exec = await (() => {
      const registry = createToolRegistry();
      registry.setHandler('search_code', handler);
      return registry.execute({ name: 'search_code', arguments: { pattern: 'merge(' } }, ctxFor(), 'verdict');
    })();
    assert.equal(exec.status, 'error');
    assert.match(exec.content, /^Error: Invalid regular expression/);
  });

  it('formats path:line: text, drops lockfile and minified lines, tags non-source scopes and passes the glob', async () => {
    let seen: { pattern: RegExp; fileGlob?: string; maxResults: number } | null = null;
    const handler = makeSearchCodeHandler({
      searchProject: async (_root, pattern, options) => {
        seen = { pattern, maxResults: options.maxResults, ...(options.fileGlob ? { fileGlob: options.fileGlob } : {}) };
        return { matches, total: matches.length, truncated: false };
      },
    });
    const r = await handler({ pattern: 'merge\\(', fileGlob: './src/**/*.js' }, ctxFor());
    assert.equal(r.text, 'src/config.js:21: const merged = _.merge({}, DEFAULTS);\ntest/a.test.js:5: merge(x) [test]');
    assert.equal(r.hint, '2 matches in 2 files in src/**/*.js');
    assert.equal(seen!.fileGlob, 'src/**/*.js');
    assert.equal(seen!.maxResults, 20);
    const none = await makeSearchCodeHandler({ searchProject: async () => ({ matches: [], total: 0, truncated: false }) })({ pattern: '\\.template\\(' }, ctxFor());
    assert.equal(none.hint, 'No matches for /\\.template\\(/');
  });

  it('caps results at maxResults and says how many more exist', async () => {
    const many: SearchMatch[] = Array.from({ length: 40 }, (_, i) => ({ path: `src/f${i % 3}.js`, line: i + 1, text: `merge(${i})`, scope: 'source' }));
    const handler = makeSearchCodeHandler({ searchProject: async (_r, _p, o) => ({ matches: many.slice(0, o.maxResults), total: 40, truncated: true }) });
    const r = await handler({ pattern: 'merge', maxResults: 5 }, ctxFor());
    assert.equal(r.text?.split('\n').length, 6);
    assert.match(r.hint, /^40 matches \(showing 5\) in 3\+ files$/);
    assert.equal(r.truncated, true);
  });
});

describe('read_file', () => {
  let tmp: Awaited<ReturnType<typeof tempDir>>;
  before(async () => {
    tmp = await tempDir('pp-readfile-');
    await mkdir(path.join(tmp.dir, 'src'), { recursive: true });
    await writeFile(path.join(tmp.dir, 'src', 'long.js'), Array.from({ length: 200 }, (_, i) => `line ${i + 1}`).join('\n') + '\n');
    await writeFile(path.join(tmp.dir, 'src', 'bin.dat'), Buffer.from([1, 0, 2]));
    await symlink('/etc/hosts', path.join(tmp.dir, 'src', 'escape.js')).catch(() => {});
  });
  after(async () => {
    await tmp.cleanup();
  });
  const ctx = (): ToolContext => ctxFor({ projectRoot: tmp.dir });

  it('reads 40 numbered lines by default and points at the rest', async () => {
    const r = await handleReadFile({ path: './src/long.js' }, ctx());
    const lines = (r.text ?? '').split('\n');
    assert.equal(lines[0], 'src/long.js (lines 1-40 of 200)');
    assert.equal(lines[1], ' 1| line 1');
    assert.equal(lines[40], '40| line 40');
    assert.equal(lines[41], '160 more lines below; read them with startLine 41');
    assert.equal(r.hint, 'src/long.js:1-40 of 200 lines');
  });

  it('caps a range at 120 lines with "N lines omitted, narrow the range"', async () => {
    const r = await handleReadFile({ path: 'src/long.js', startLine: 11, endLine: 190 }, ctx());
    assert.match(r.text ?? '', /^src\/long\.js \(lines 11-130 of 200\)/);
    assert.match(r.text ?? '', /60 lines omitted, narrow the range \(at most 120 lines per call\)$/);
    assert.equal(r.truncated, true);
    assert.equal(r.hint, 'src/long.js:11-130 of 200 lines, 60 lines omitted');
    const reversed = await handleReadFile({ path: 'src/long.js', startLine: 30, endLine: 20 }, ctx());
    assert.match(reversed.text ?? '', /lines 20-30 of 200/);
  });

  it('refuses paths outside the project, symlink escapes, missing files, directories and binaries', async () => {
    assert.match((await handleReadFile({ path: '../../etc/passwd' }, ctx())).error ?? '', /outside the project/);
    assert.match((await handleReadFile({ path: '/etc/passwd' }, ctx())).error ?? '', /outside the project/);
    assert.match((await handleReadFile({ path: 'src/escape.js' }, ctx())).error ?? '', /outside the project/);
    assert.match((await handleReadFile({ path: 'src/nope.js' }, ctx())).error ?? '', /^File not found: src\/nope\.js/);
    assert.match((await handleReadFile({ path: 'src' }, ctx())).error ?? '', /is a directory/);
    assert.match((await handleReadFile({ path: 'src/bin.dat' }, ctx())).error ?? '', /binary/);
    assert.match((await handleReadFile({ path: 'src/long.js', startLine: 500 }, ctx())).error ?? '', /has only 200 lines/);
  });
});

describe('check_deps', () => {
  function node(key: string, name: string, version: string, extra: Partial<PackageNode> = {}): PackageNode {
    return { key, name, version, dev: false, optional: false, devOptional: false, peer: false, bundled: false, isDirect: false, parents: [], requires: {}, edges: {}, ...extra };
  }
  function graph(): DependencyGraph {
    const nodes = [
      node('node_modules/query-string', 'query-string', '6.14.1', { isDirect: true, parents: [''], requires: { 'decode-uri-component': '^0.2.0' } }),
      node('node_modules/decode-uri-component', 'decode-uri-component', '0.2.0', { parents: ['node_modules/query-string'] }),
      node('node_modules/lodash', 'lodash', '4.17.20', { isDirect: true, parents: ['', 'node_modules/other'] }),
      node('node_modules/other', 'other', '1.0.0', { isDirect: true, parents: [''], requires: { lodash: '^4.17.0' } }),
      node('node_modules/other/node_modules/lodash', 'lodash', '3.10.1', { parents: ['node_modules/other'] }),
      node('node_modules/semver', 'semver', '5.7.1', { isDirect: true, dev: true, parents: [''] }),
    ];
    const byName = new Map<string, string[]>();
    for (const n of nodes) byName.set(n.name, [...(byName.get(n.name) ?? []), n.key]);
    return {
      root: { name: 'vulnerable-app', version: '1.0.0', dependencies: { lodash: '4.17.20', 'query-string': '6.14.1', other: '1.0.0' }, devDependencies: { semver: '5.7.1' }, optionalDependencies: {}, peerDependencies: {}, workspaces: [], engines: {}, edges: {} },
      lockfileVersion: 3,
      nodes: new Map(nodes.map((n) => [n.key, n])),
      byName,
      workspaceKeys: [],
    };
  }

  it('describes a transitive dependency with its parent range and whether the fix fits', async () => {
    const d = decodeFixture();
    const ctx = ctxFor({ graph: graph(), caseFile: caseFileOf([d.pkg], [d.vuln]) });
    const r = await handleCheckDeps({ package: 'decode-uri-component' }, ctx);
    assert.equal(r.hint, 'decode-uri-component@0.2.0: transitive production dependency via query-string@6.14.1 (^0.2.0, accepts 0.2.1)');
    assert.deepEqual((r.data as { pathsFromRoot: string[] }).pathsFromRoot, ['vulnerable-app > query-string@6.14.1 > decode-uri-component@0.2.0']);
  });

  it('describes direct, dev-only and multi-version packages', async () => {
    const lodash = lodashFixture();
    const ctx = ctxFor({ graph: graph(), caseFile: caseFileOf([lodash.pkg], [lodash.template]), focus: { package: 'lodash', version: '4.17.20' } });
    const r = await handleCheckDeps({ package: 'lodash' }, ctx);
    const data = r.data as { isDirect: boolean; declared: unknown; otherVersionsInstalled: string[]; dependents: { name: string; acceptsFix?: boolean }[] };
    assert.equal(data.isDirect, true);
    assert.deepEqual(data.declared, { section: 'dependencies', spec: '4.17.20' });
    assert.deepEqual(data.otherVersionsInstalled, ['3.10.1']);
    assert.deepEqual(data.dependents, [{ name: 'other', version: '1.0.0', range: '^4.17.0', acceptsFix: true }]);
    assert.match(r.hint, /^lodash@4\.17\.20: direct production dependency \(dependencies: 4\.17\.20\); also required by other@1\.0\.0/);
    const semver = await handleCheckDeps({ package: 'semver' }, ctxFor({ graph: graph() }));
    assert.match(semver.hint, /^semver@5\.7\.1: direct dev-only dependency \(devDependencies: 5\.7\.1\); no other package depends on it$/);
    assert.deepEqual(pathsToRoot(graph(), 'node_modules/decode-uri-component', 'app'), ['app > query-string@6.14.1 > decode-uri-component@0.2.0']);
  });

  it('falls back to the case file without a graph, and errors for unknown packages', async () => {
    const d = decodeFixture();
    const r = await handleCheckDeps({ package: 'decode-uri-component' }, ctxFor({ caseFile: caseFileOf([d.pkg], [d.vuln]) }));
    assert.equal((r.data as { source: string }).source, 'case-file');
    assert.match(r.hint, /via query-string@6\.14\.1/);
    const missing = await handleCheckDeps({ package: 'left-pad' }, ctxFor({ graph: graph() }));
    assert.equal(missing.ok, false);
    assert.match(missing.error ?? '', /not in the lockfile/);
  });
});
