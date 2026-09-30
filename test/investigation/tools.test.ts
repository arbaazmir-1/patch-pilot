import assert from 'node:assert/strict';
import { mkdir, readFile, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { handleCheckDeps, pathsToRoot } from '../../src/investigation/tools/checkDeps.ts';
import { handleGetAdvisory } from '../../src/investigation/tools/getAdvisory.ts';
import { makeGetUsageHandler, normalizeSymbol, type GetUsageData } from '../../src/investigation/tools/getUsage.ts';
import { createToolRegistry } from '../../src/investigation/tools/index.ts';
import { handleReadFile } from '../../src/investigation/tools/readFile.ts';
import { compilePattern, makeSearchCodeHandler } from '../../src/investigation/tools/searchCode.ts';
import type { DependencyGraph, ImportSite, PackageNode, SearchMatch, ToolContext } from '../../src/types.ts';
import { caseFileOf, decodeFixture, fakeFindUsage, lodashFixture, markedParseFixture, minimistFixture, osvRecordFor, site, tempDir, testConfig } from './helpers.ts';

const APP = fileURLToPath(new URL('../../examples/vulnerable-app/', import.meta.url));
const read = (rel: string): Promise<string> => readFile(path.join(APP, rel), 'utf8');

async function appFiles(): Promise<Record<string, string>> {
  return { 'src/cli.js': await read('src/cli.js'), 'src/config.js': await read('src/config.js'), 'src/render.js': await read('src/render.js') };
}

function ctxFor(partial: Partial<ToolContext> = {}): ToolContext {
  return { projectRoot: APP, config: { exclude: [] } as unknown as ToolContext['config'], caseFile: null, graph: null, cache: null, audit: null, ...partial };
}

// matches the example app's imports
async function appCaseFile() {
  const files = await appFiles();
  const lineOf = (file: string, needle: string): number => (files[file] ?? '').split('\n').findIndex((l) => l.includes(needle)) + 1;
  const lodash = lodashFixture();
  lodash.pkg.usage.files = [site('src/config.js', lineOf('src/config.js', "require('lodash')"), "const _ = require('lodash');", '_')];
  const minimist = minimistFixture();
  minimist.pkg.usage.files = [site('src/cli.js', lineOf('src/cli.js', "require('minimist')"), "const parseArgs = require('minimist');", 'parseArgs')];
  const decode = decodeFixture();
  const records = { [lodash.template.id]: osvRecordFor(lodash.template, 'Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.') };
  return { files, lodash, minimist, decode, caseFile: caseFileOf([lodash.pkg, minimist.pkg, decode.pkg], [lodash.template, minimist.vuln, decode.vuln], APP, records) };
}

describe('get_usage', () => {
  it('lists members and binding calls without a symbol', async () => {
    const { files, caseFile } = await appCaseFile();
    const handler = makeGetUsageHandler({ findUsage: fakeFindUsage(files) });
    const r = await handler({ package: 'lodash' }, ctxFor({ caseFile }));
    const data = r.data as GetUsageData;
    assert.equal(r.ok, true);
    assert.equal(r.hint, 'lodash imported in src/config.js as _; calls _.get (3), _.merge (1)');
    assert.deepEqual(data.membersUsed, { merge: 1, get: 3 });
    assert.equal(data.bindingCalls, 0);
    assert.equal(data.symbolCalls, null);
    assert.match(r.text ?? '', /Members called: _\.get \(3\), _\.merge \(1\); the binding itself is never called\./);
    assert.match(r.text ?? '', /> \s*\d+\| \s*const merged = _\.merge/);
  });

  it('answers "where is minimist called?" with the binding call site and context', async () => {
    const { files, caseFile } = await appCaseFile();
    const r = await makeGetUsageHandler({ findUsage: fakeFindUsage(files) })({ package: 'minimist' }, ctxFor({ caseFile }));
    const data = r.data as GetUsageData;
    assert.match(r.hint, /^minimist imported in src\/cli\.js as parseArgs; called directly 1 time \(src\/cli\.js:\d+\)$/);
    assert.equal(data.bindingCalls, 1);
    assert.equal(data.callSites[0]?.member, null);
    assert.match(r.text ?? '', /parseArgs\(\) is called directly 1 time/);
    assert.match(r.text ?? '', /function main\(argv\)/, 'two context lines before the call');
  });

  it('reports a symbol with zero calls together with what the project calls instead', async () => {
    const { files, caseFile } = await appCaseFile();
    const handler = makeGetUsageHandler({ findUsage: fakeFindUsage(files) });
    const r = await handler({ package: 'lodash', symbol: 'template' }, ctxFor({ caseFile }));
    const data = r.data as GetUsageData;
    assert.equal(r.hint, '0 calls to _.template; project calls _.get (3), _.merge (1)');
    assert.equal(data.symbolCalls, 0);
    assert.equal(data.fallback, true);
    assert.ok(data.callSites.length >= 4);
    assert.match(r.text ?? '', /No call to _\.template was found\./);
    assert.match(r.text ?? '', /No dynamic member access \(_\[\.\.\.\]\) was found in the importing files either\./);
    assert.deepEqual(data.dynamicAccess, []);
    const setKey = await makeGetUsageHandler({ findUsage: fakeFindUsage(files) })({ package: 'minimist', symbol: 'setKey()' }, ctxFor({ caseFile }));
    assert.equal(setKey.hint, "0 calls to parseArgs.setKey, but the package itself is called 1 time (src/cli.js:21); the default call is the package's main entry point");
    assert.equal((setKey.data as GetUsageData).entryPointCalled, true);
  });

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

  it('says so when a blamed member has no calls but the package itself (its entry point) is called', async () => {
    const files = await appFiles();
    const { pkg, vuln } = markedParseFixture();
    pkg.usage.files = [site('src/render.js', (files['src/render.js'] ?? '').split('\n').findIndex((l) => l.includes("require('marked')")) + 1, "const marked = require('marked');", 'marked')];
    const r = await makeGetUsageHandler({ findUsage: fakeFindUsage(files) })({ package: 'marked', symbol: 'parse' }, ctxFor({ caseFile: caseFileOf([pkg], [vuln]) }));
    const data = r.data as GetUsageData;
    assert.equal(r.hint, "0 calls to marked.parse, but the package itself is called 1 time (src/render.js:8); the default call is the package's main entry point");
    assert.equal(data.symbolCalls, 0);
    assert.equal(data.entryPointCalled, true);
    assert.deepEqual(data.callSites.map((c) => [c.path, c.line, c.member]), [['src/render.js', 8, null]]);
    const text = r.text ?? '';
    assert.match(text, /No call to marked\.parse was found, but the package itself is called 1 time: the default call is the package's main entry point\./);
    assert.match(text, /The package itself is called here:\nsrc\/render\.js:8\n/);
    assert.match(text, /function renderMarkdown\(userMarkdown, options = \{\}\) \{/, 'context lines around the call');
    assert.match(text, />\s+8\| return marked\(userMarkdown, \{/);
  });

  it('finds the call sites of a symbol that is called', async () => {
    const { files, caseFile } = await appCaseFile();
    const r = await makeGetUsageHandler({ findUsage: fakeFindUsage(files) })({ package: 'lodash', symbol: '_.merge' }, ctxFor({ caseFile }));
    const data = r.data as GetUsageData;
    assert.match(r.hint, /^1 call to _\.merge in 1 file: src\/config\.js:\d+$/);
    assert.equal(data.symbolCalls, 1);
    assert.equal(data.fallback, false);
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

  it('scans imports with the walker when the case file has no evidence, and reports packages that are not imported', async () => {
    const files = await appFiles();
    const handler = makeGetUsageHandler({
      findUsage: fakeFindUsage(files),
      walkProject: async () => ({ files: Object.keys(files).map((p) => ({ path: p, abs: path.join(APP, p), size: 1, ext: '.js', scope: 'source' as const })), truncated: false, skipped: [] }),
      readText: async (abs) => files[path.relative(APP, abs)] ?? '',
      findImportsInSource: (source, rel, pkgs) =>
        source.includes(`require('${pkgs[0]}')`) ? [site(rel, source.split('\n').findIndex((l) => l.includes(`require('${pkgs[0]}')`)) + 1, 'require', 'marked')] : [],
    });
    const marked = await handler({ package: 'marked' }, ctxFor());
    assert.match(marked.hint, /^marked imported in src\/render\.js as marked; called directly 1 time/);
    const { caseFile } = await appCaseFile();
    const decode = await handler({ package: 'decode-uri-component', symbol: 'decode' }, ctxFor({ caseFile }));
    assert.equal(decode.hint, 'decode-uri-component is not imported in the project (6 files scanned); it is installed for query-string@6.14.1');
    assert.equal((decode.data as GetUsageData).imported, false);
  });

  it('runs through the registry with aliases and the focus package', async () => {
    const { files, caseFile } = await appCaseFile();
    const registry = createToolRegistry();
    registry.setHandler('get_usage', makeGetUsageHandler({ findUsage: fakeFindUsage(files) }));
    const exec = await registry.execute({ name: 'get_usage', arguments: { fn: 'template' } }, ctxFor({ caseFile, focus: { package: 'lodash', version: '4.17.20' } }), 'verdict');
    assert.equal(exec.ok, true);
    assert.deepEqual(exec.args, { symbol: 'template', package: 'lodash' });
    assert.ok(exec.content.startsWith('0 calls to _.template'));
    assert.ok(exec.content.length <= 1500);
    assert.equal(normalizeSymbol("_['template']"), 'template');
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

describe('get_advisory', () => {
  it('serves the full record by OSV id or CVE alias, case-insensitively', async () => {
    const { caseFile, lodash } = await appCaseFile();
    const ctx = ctxFor({ caseFile });
    for (const id of [lodash.template.id, 'CVE-2021-23337', 'cve-2021-23337']) {
      const r = await handleGetAdvisory({ id }, ctx);
      assert.equal(r.ok, true, id);
      assert.equal(r.hint, 'GHSA-35jh-r3h4-6jhm: Command Injection in lodash (HIGH, CWE-77, CWE-94)');
    }
    const text = (await handleGetAdvisory({ id: 'CVE-2021-23337' }, ctx)).text ?? '';
    assert.match(text, /^GHSA-35jh-r3h4-6jhm \(CVE-2021-23337\) · HIGH · CVSS 7\.2/);
    assert.match(text, /Published: 2021-02-15/);
    assert.match(text, /CWE: CWE-77, CWE-94/);
    assert.match(text, /Affected lodash: <4\.17\.21; fixed in 4\.17\.21/);
    assert.match(text, /Details:\nLodash versions prior to 4\.17\.21/);
    assert.match(text, /References:\n- https:\/\/github\.com\/advisories\/GHSA-35jh-r3h4-6jhm \(advisory\)/);
  });

  it('falls back to the case entry and lists known ids for an unknown one', async () => {
    const { caseFile } = await appCaseFile();
    const r = await handleGetAdvisory({ id: 'GHSA-xvch-5gv4-984h' }, ctxFor({ caseFile }));
    assert.equal(r.ok, true);
    assert.match(r.text ?? '', /setKey/);
    const unknown = await handleGetAdvisory({ id: 'GHSA-nope' }, ctxFor({ caseFile, focus: { package: 'lodash', version: '4.17.20' } }));
    assert.equal(unknown.ok, false);
    assert.equal(unknown.hint, 'Known ids for lodash: GHSA-35jh-r3h4-6jhm, CVE-2021-23337');
  });

  it('works from a config built by loadConfig', async () => {
    const tmp = await tempDir('pp-adv-');
    try {
      const config = await testConfig(tmp.dir);
      const { caseFile } = await appCaseFile();
      const r = await handleGetAdvisory({ id: 'CVE-2021-44906' }, { ...ctxFor({ caseFile }), config });
      assert.equal(r.ok, true);
    } finally {
      await tmp.cleanup();
    }
  });
});
