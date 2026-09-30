import assert from 'node:assert/strict';
import path from 'node:path';
import { describe, it } from 'node:test';
import { makeGetUsageHandler, type GetUsageData } from '../../src/investigation/tools/getUsage.ts';
import type { DependentUsage, ToolContext, UsageEvidence } from '../../src/types.ts';
import { caseFileOf, decodeFixture, fakeFindUsage, lodashFixture, site } from './helpers.ts';

const ROOT = '/proj';

function ctxFor(caseFile: ToolContext['caseFile']): ToolContext {
  return { projectRoot: ROOT, config: { exclude: [] } as unknown as ToolContext['config'], caseFile, graph: null, cache: null, audit: null };
}

function handlerFor(files: Record<string, string>, extra: Parameters<typeof makeGetUsageHandler>[0] = {}) {
  return makeGetUsageHandler({
    findUsage: fakeFindUsage(files),
    readText: async (abs) => {
      const text = files[path.relative(ROOT, abs)];
      if (text === undefined) throw new Error(`no file ${abs}`);
      return text;
    },
    hasNodeModules: () => false,
    ...extra,
  });
}

function lodashCase(files: Record<string, string>, usage: Partial<UsageEvidence>) {
  const { pkg, template } = lodashFixture();
  const sites = Object.entries(files)
    .filter(([, text]) => text.includes("require('lodash')"))
    .map(([p, text]) => site(p, text.split('\n').findIndex((l) => l.includes("require('lodash')")) + 1, "const _ = require('lodash');", '_'));
  pkg.usage = { ...pkg.usage, files: sites, membersUsed: {}, method: 'ast', ...usage };
  return { pkg, template, caseFile: caseFileOf([pkg], [template], ROOT) };
}

const WRAPPER = {
  'src/utils.js': "const _ = require('lodash');\nfunction compile(md) {\n  return _.template(md);\n}\nmodule.exports = { compile };\n",
  'src/cli.js': "const { compile } = require('./utils');\nconst input = process.argv[2];\nconst html = compile(input)({});\nconsole.log(html);\n",
};

describe('get_usage: calls through the project\'s own functions', () => {
  it('adds the indirect call sites to a direct call ("called indirectly: src/cli.js:3 via compile() -> _.template()")', async () => {
    const { caseFile } = lodashCase(WRAPPER, { membersUsed: { template: 1 }, indirectPaths: [{ path: 'src/cli.js', line: 3, via: ['compile'], member: 'template' }] });
    const r = await handlerFor(WRAPPER)({ package: 'lodash', symbol: 'template' }, ctxFor(caseFile));
    const data = r.data as GetUsageData;
    assert.equal(r.hint, '1 call to _.template in 1 file: src/utils.js:3; called indirectly once: src/cli.js:3 via compile() -> _.template()');
    assert.equal(data.symbolCalls, 1);
    assert.equal(data.indirectCalls, 1);
    assert.deepEqual(data.indirectPaths, [{ path: 'src/cli.js', line: 3, via: ['compile'], member: 'template' }]);
    assert.match(r.text ?? '', /Called indirectly \(through the project's own functions\):\n {2}src\/cli\.js:3 via compile\(\) -> _\.template\(\)/);
    assert.equal(data.method, 'ast');
  });

  it('counts a symbol reached only indirectly as called and shows the outer call sites', async () => {
    const files = {
      'src/all.js': "module.exports = require('lodash');\n",
      'src/app.js': "const L = require('./all');\n\nL.template(userInput)({});\n",
      'src/config.js': "const _ = require('lodash');\n_.get(o, 'a');\n",
    };
    const { caseFile } = lodashCase(files, { membersUsed: { get: 1 }, indirectPaths: [{ path: 'src/app.js', line: 3, via: ['template'], member: 'template' }] });
    const r = await handlerFor(files)({ package: 'lodash', symbol: 'template' }, ctxFor(caseFile));
    const data = r.data as GetUsageData;
    assert.equal(r.hint, '0 direct calls to _.template, but it is called indirectly once: src/app.js:3 via template() -> _.template()');
    assert.equal(data.symbolCalls, 0);
    assert.equal(data.indirectCalls, 1);
    assert.equal(data.fallback, false);
    assert.deepEqual(data.callSites.map((c) => [c.path, c.line, c.text]), [['src/app.js', 3, 'L.template(userInput)({});']]);
    const text = r.text ?? '';
    assert.match(text, /No direct call to _\.template was found, but the project calls it through its own modules:/);
    assert.match(text, /> 3\| L\.template\(userInput\)\(\{\}\);/);
    assert.match(text, /What the project calls directly: _\.get \(1\); the binding itself is never called\./);
  });

  it('lists the indirect calls without a symbol too', async () => {
    const { caseFile } = lodashCase(WRAPPER, { membersUsed: { template: 1 }, indirectPaths: [{ path: 'src/cli.js', line: 3, via: ['compile'], member: 'template' }] });
    const r = await handlerFor(WRAPPER)({ package: 'lodash' }, ctxFor(caseFile));
    assert.equal(r.hint, 'lodash imported in src/utils.js as _; calls _.template (1); called indirectly: src/cli.js:3 via compile() -> _.template()');
    assert.equal((r.data as GetUsageData).indirectCalls, 1);
  });
});

describe('get_usage: accesses that cannot be resolved statically', () => {
  const files = { 'src/x.js': "const _ = require('lodash');\nconst name = pick();\n_.merge({}, {});\n_[name](input);\n" };

  it('renders a computed access from the case file ("1 computed access `_[name]` at src/x.js:4 cannot be resolved statically")', async () => {
    const { caseFile } = lodashCase(files, { membersUsed: { merge: 1 }, dynamicAccess: [{ path: 'src/x.js', line: 4, text: '_[name]', reason: 'computed-member' }] });
    const r = await handlerFor(files)({ package: 'lodash', symbol: 'template' }, ctxFor(caseFile));
    const data = r.data as GetUsageData;
    assert.equal(r.hint, '0 calls to _.template; project calls _.merge (1); dynamic access at src/x.js:4');
    assert.deepEqual(data.dynamicAccess, ['src/x.js:4']);
    assert.deepEqual(data.dynamicDetails, [{ path: 'src/x.js', line: 4, text: '_[name]', reason: 'computed-member' }]);
    assert.match(r.text ?? '', /^1 computed access `_\[name\]` at src\/x\.js:4 cannot be resolved statically; it could reach template\.$/m);
    assert.doesNotMatch(r.text ?? '', /No dynamic member access/);
    const all = await handlerFor(files)({ package: 'lodash' }, ctxFor(caseFile));
    assert.match(all.hint, /; 1 computed access cannot be resolved statically$/);
  });

  it('renders dynamic requires, reassigned bindings and unparsed files', async () => {
    const plain = { 'src/x.js': "const _ = require('lodash');\n_.merge({}, {});\n" };
    const { caseFile } = lodashCase(plain, {
      membersUsed: { merge: 1 },
      dynamicAccess: [
        { path: 'src/load.js', line: 2, text: "require(process.env.LIB || 'lodash')", reason: 'dynamic-require' },
        { path: 'src/x.js', line: 7, text: "_ = require('underscore')", reason: 'reassigned-binding' },
        { path: 'src/flow.js', line: 3, text: "not parsed (';' expected.); scanned with patterns instead", reason: 'unparsed-file' },
      ],
    });
    const r = await handlerFor(plain)({ package: 'lodash', symbol: 'template' }, ctxFor(caseFile));
    const text = r.text ?? '';
    assert.match(text, /^1 dynamic require `require\(process\.env\.LIB \|\| 'lodash'\)` at src\/load\.js:2 cannot be resolved statically; it may load the package\.$/m);
    assert.match(text, /^The binding is reassigned at src\/x\.js:7 \(`_ = require\('underscore'\)`\), so later uses may hold another value\.$/m);
    assert.match(text, /^src\/flow\.js:3: not parsed \(';' expected\.\); scanned with patterns instead\.$/m);
    assert.match(text, /No dynamic member access \(_\[\.\.\.\]\) was found in the importing files either\./, 'no computed member access itself');
    assert.deepEqual((r.data as GetUsageData).dynamicAccess, ['src/load.js:2', 'src/x.js:7', 'src/flow.js:3']);
  });
});

describe('get_usage: a transitive package and its dependents', () => {
  const usageInQs: DependentUsage = {
    dependent: 'query-string',
    version: '6.14.1',
    path: 'node_modules/query-string/index.js',
    line: 45,
    member: null,
    text: 'return decodeComponent(value);',
  };

  it('shows the calls inside the dependents ("query-string calls decodeUriComponent() in node_modules/query-string/index.js:45")', async () => {
    const { pkg, vuln } = decodeFixture();
    pkg.usage = { ...pkg.usage, dependentUsage: [usageInQs] };
    const r = await handlerFor({})({ package: 'decode-uri-component' }, ctxFor(caseFileOf([pkg], [vuln], ROOT)));
    const data = r.data as GetUsageData;
    assert.equal(
      r.hint,
      'decode-uri-component is not imported in the project (6 files scanned); it is installed for query-string@6.14.1; query-string calls decodeUriComponent() in node_modules/query-string/index.js:45',
    );
    assert.equal(data.dependentsScanned, 'scanned');
    assert.deepEqual(data.dependentUsage, [usageInQs]);
    assert.match(r.text ?? '', /^Inside its dependents: query-string calls decodeUriComponent\(\) in node_modules\/query-string\/index\.js:45\.$/m);
    assert.match(r.text ?? '', /^ {2}node_modules\/query-string\/index\.js:45\| return decodeComponent\(value\);$/m);
    const other = await handlerFor({})({ package: 'decode-uri-component', symbol: 'parse' }, ctxFor(caseFileOf([pkg], [vuln], ROOT)));
    assert.match(other.text ?? '', /^None of them calls parse\.$/m);
  });

  it('says when the dependents were scanned and do not call it', async () => {
    const { pkg, vuln } = decodeFixture();
    pkg.usage = { ...pkg.usage, dependentUsage: [] };
    const r = await handlerFor({})({ package: 'decode-uri-component' }, ctxFor(caseFileOf([pkg], [vuln], ROOT)));
    assert.equal(r.hint, 'decode-uri-component is not imported in the project (6 files scanned); it is installed for query-string@6.14.1');
    assert.match(r.text ?? '', /^Its dependents' installed code was scanned: none of them calls decode-uri-component directly\.$/m);
  });

  it('says "dependents not scanned: node_modules is not installed", and scans them when the case file predates it', async () => {
    const { pkg, vuln } = decodeFixture();
    const caseFile = caseFileOf([pkg], [vuln], ROOT);
    const absent = await handlerFor({})({ package: 'decode-uri-component' }, ctxFor(caseFile));
    assert.equal((absent.data as GetUsageData).dependentsScanned, 'no-node-modules');
    assert.equal((absent.data as GetUsageData).dependentUsage, undefined);
    assert.match(absent.text ?? '', /^Dependents not scanned: node_modules is not installed\.$/m);
    const scans: string[][] = [];
    const live = await handlerFor(
      {},
      {
        hasNodeModules: () => true,
        scanDependents: async (_root, names, dependents) => {
          scans.push([...names, ...dependents.map((d) => `${d.name}@${d.version}`)]);
          return [usageInQs];
        },
      },
    )({ package: 'decode-uri-component' }, ctxFor(caseFile));
    assert.deepEqual(scans, [['decode-uri-component', 'query-string@6.14.1']]);
    assert.equal((live.data as GetUsageData).dependentsScanned, 'scanned');
    assert.match(live.hint, /; query-string calls decodeUriComponent\(\) in node_modules\/query-string\/index\.js:45$/);
  });
});
