import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { parseModule, type FileSummary } from '../../src/evidence/ast.ts';
import { computeIndirectPaths, createResolver, extractSpecifiers, loadPathAliases } from '../../src/evidence/callgraph.ts';
import { collectUsageEvidence } from '../../src/evidence/codebase.ts';
import type { IndirectPath } from '../../src/types.ts';
import { tempDir } from './helpers.ts';

const INDIRECT_APP = fileURLToPath(new URL('./fixtures/indirect-app/', import.meta.url));

async function project(files: Record<string, string>): Promise<{ dir: string; cleanup: () => Promise<void> }> {
  const tmp = await tempDir('pp-callgraph-');
  for (const [rel, content] of Object.entries(files)) {
    await mkdir(path.dirname(path.join(tmp.dir, rel)), { recursive: true });
    await writeFile(path.join(tmp.dir, rel), content);
  }
  return tmp;
}

const show = (paths: readonly IndirectPath[] | undefined): string[] => (paths ?? []).map((p) => `${p.path}:${p.line} ${p.via.join(' > ')} > ${p.member ?? '()'}`);

async function indirect(files: Record<string, string>, pkg = 'lodash'): Promise<string[]> {
  const tmp = await project(files);
  try {
    return show((await collectUsageEvidence(tmp.dir, [pkg], { exclude: [] })).get(pkg)?.indirectPaths);
  } finally {
    await tmp.cleanup();
  }
}

describe('callgraph: resolving project imports', () => {
  const files = new Set([
    'src/util.js',
    'src/lib/index.ts',
    'src/lib/x.ts',
    'src/esm.mts',
    'src/Comp.tsx',
    'src/data.cjs',
    'index.js',
    'packages/a/src/main.ts',
  ]);
  const resolve = createResolver(files, { baseUrl: null, paths: [] });

  it('resolves relative specifiers with the Node and TypeScript extension rules and index files', () => {
    assert.equal(resolve('./util', 'src/app.js'), 'src/util.js');
    assert.equal(resolve('./util.js', 'src/app.js'), 'src/util.js');
    assert.equal(resolve('./lib', 'src/app.js'), 'src/lib/index.ts');
    assert.equal(resolve('./lib/x.js', 'src/app.ts'), 'src/lib/x.ts', './x.js means x.ts in TypeScript sources');
    assert.equal(resolve('./esm.mjs', 'src/app.ts'), 'src/esm.mts');
    assert.equal(resolve('./Comp.jsx', 'src/app.tsx'), 'src/Comp.tsx');
    assert.equal(resolve('./data.cjs', 'src/app.js'), 'src/data.cjs');
    assert.equal(resolve('../util', 'src/lib/x.ts'), 'src/util.js');
    assert.equal(resolve('..', 'src/app.js'), 'index.js');
  });

  it('never resolves outside the project, into node_modules or to bare packages', () => {
    assert.equal(resolve('../../outside', 'src/app.js'), null);
    assert.equal(resolve('lodash', 'src/app.js'), null);
    assert.equal(resolve('./node_modules/lodash', 'src/app.js'), null);
    assert.equal(createResolver(new Set(['node_modules/lodash/index.js']))('./node_modules/lodash', 'app.js'), null);
    assert.equal(resolve('/abs/path', 'src/app.js'), null);
    assert.equal(resolve('node:fs', 'src/app.js'), null);
  });

  it('follows tsconfig paths (with a wildcard) and baseUrl', () => {
    const aliased = createResolver(files, { baseUrl: '.', paths: [{ pattern: '@lib/*', targets: ['src/lib/*'] }, { pattern: '@util', targets: ['src/util.js'] }] });
    assert.equal(aliased('@lib/x', 'src/app.ts'), 'src/lib/x.ts');
    assert.equal(aliased('@util', 'src/app.ts'), 'src/util.js');
    assert.equal(aliased('src/lib', 'packages/a/src/main.ts'), 'src/lib/index.ts', 'baseUrl');
    assert.equal(aliased('lodash', 'src/app.ts'), null, 'a package is not a project file');
  });

  it('reads paths and baseUrl from tsconfig.json (comments, trailing commas, relative extends)', async () => {
    const tmp = await project({
      'tsconfig.base.json': '{ "compilerOptions": { "paths": { "~/*": ["./src/*"] } } }',
      'tsconfig.json': '{\n  // project settings\n  "extends": "./tsconfig.base.json",\n  "compilerOptions": { "baseUrl": "./src", },\n}\n',
    });
    try {
      assert.deepEqual(await loadPathAliases(tmp.dir), { baseUrl: 'src', paths: [{ pattern: '~/*', targets: ['src/src/*'] }] });
    } finally {
      await tmp.cleanup();
    }
    const js = await project({ 'jsconfig.json': '{ "compilerOptions": { "paths": { "@/*": ["src/*"] } } }' });
    try {
      assert.deepEqual(await loadPathAliases(js.dir), { baseUrl: null, paths: [{ pattern: '@/*', targets: ['src/*'] }] });
    } finally {
      await js.cleanup();
    }
    const none = await project({ 'src/a.js': '' });
    try {
      assert.deepEqual(await loadPathAliases(none.dir), { baseUrl: null, paths: [] });
    } finally {
      await none.cleanup();
    }
  });

  it('indexes import specifiers with a cheap text scan', () => {
    const text = "import a from './a';\nconst b = require('../b.js');\nexport * from './c';\nconst d = await import('./d');\nimport 'lodash';\nconst e = require(`./e`);\n";
    assert.deepEqual(extractSpecifiers(text), ['./a', '../b.js', './c', './d', './e']);
    assert.deepEqual(extractSpecifiers("import x from '@app/x';\nimport y from 'lodash';", true), ['@app/x', 'lodash']);
    assert.deepEqual(extractSpecifiers('const x = Array.from([1]);'), []);
  });
});

describe('callgraph: indirect paths', () => {
  it('a three-file call chain: server.js -> page() -> render() -> compile() -> _.template()', async () => {
    const paths = await indirect({
      'src/templates.js': "const _ = require('lodash');\nfunction compile(md) {\n  return _.template(md);\n}\nfunction render(md, data) {\n  return compile(md)(data);\n}\nmodule.exports = { render };\n",
      'src/page.js': "const { render } = require('./templates');\nfunction page(req) {\n  return render(req.body, {});\n}\nexports.page = page;\n",
      'src/server.js': "const pages = require('./page');\nrequire('http').createServer((req, res) => res.end(pages.page(req)));\n",
    });
    assert.deepEqual(paths, ['src/page.js:3 render > compile > template', 'src/server.js:2 page > render > compile > template']);
  });

  it('a two-file re-export chain (named, whole-module and ESM star re-exports)', async () => {
    assert.deepEqual(
      await indirect({
        'src/lib.js': "const _ = require('lodash');\nmodule.exports = { template: _.template, clean: require('lodash').omit };\n",
        'src/app.js': "const lib = require('./lib');\nlib.template(input);\nconst { clean } = require('./lib');\nclean(o, 'a');\n",
      }),
      ['src/app.js:2 template > template', 'src/app.js:4 clean > omit'],
    );
    assert.deepEqual(
      await indirect({
        'src/all.js': "module.exports = require('lodash');\n",
        'src/app.js': "const L = require('./all');\nL.unset(obj, path);\n",
      }),
      ['src/app.js:2 unset > unset'],
    );
    assert.deepEqual(
      await indirect({
        'src/lib/index.ts': "export { merge as deepMerge } from 'lodash';\nexport * from './helpers';\n",
        'src/lib/helpers.ts': "import get from 'lodash/get';\nexport const pick = (o: object, p: string) => get(o, p);\n",
        'src/app.ts': "import { deepMerge, pick } from './lib/index.js';\ndeepMerge({}, input);\nexport const read = (o: object) => pick(o, 'a');\n",
      }),
      ['src/app.ts:2 deepMerge > merge', 'src/app.ts:3 pick > get'],
    );
  });

  it('follows tsconfig paths, ESM default objects and callbacks passed by reference', async () => {
    assert.deepEqual(
      await indirect({
        'tsconfig.json': '{ "compilerOptions": { "baseUrl": ".", "paths": { "@app/*": ["src/*"] } } }',
        'src/tools.mjs': "import _ from 'lodash';\nexport default { run: (x) => _.template(x) };\n",
        'src/routes.ts': "import tools from '@app/tools.mjs';\nimport { handler } from '@app/handlers';\nrouter.get('/', handler);\nexport function use(md: string) { return tools.run(md); }\n",
        'src/handlers.ts': "import { merge } from 'lodash';\nexport function handler(req: unknown) { return merge({}, req); }\n",
      }),
      ['src/routes.ts:3 handler > merge', 'src/routes.ts:4 run > template'],
    );
  });

  it('a CommonJS module value registered as a callback reaches the package; a plain object does not', async () => {
    assert.deepEqual(
      await indirect({
        'src/routes.js': "const _ = require('lodash');\nmodule.exports = function routes(req, res) { res.send(_.template(req.query.t)()); };\n",
        'src/utils.js': "const _ = require('lodash');\nmodule.exports = { a: () => _.merge({}, {}), b: 1 };\n",
        'src/app.js': "const routes = require('./routes');\nconst utils = require('./utils');\napp.use(routes);\nregister(utils);\n",
      }),
      ['src/app.js:3 routes > template'],
    );
  });

  it('stops at five functions', async () => {
    const files: Record<string, string> = { 'src/f0.js': "const _ = require('lodash');\nexports.f0 = (x) => _.template(x);\n" };
    for (let i = 1; i <= 6; i += 1) files[`src/f${i}.js`] = `const { f${i - 1} } = require('./f${i - 1}');\nexports.f${i} = (x) => f${i - 1}(x);\n`;
    const paths = await indirect(files);
    assert.deepEqual(paths.map((p) => p.split(' ')[0]), ['src/f1.js:2', 'src/f2.js:2', 'src/f3.js:2', 'src/f4.js:2', 'src/f5.js:2']);
    assert.equal(paths.at(-1), 'src/f5.js:2 f4 > f3 > f2 > f1 > f0 > template');
  });

  it('caps the parsing work and says so', async () => {
    const summaries = new Map<string, FileSummary | null>();
    const seed = parseModule("const _ = require('lodash');\nexports.t = (x) => _.template(x);\n", 'src/seed.js');
    assert.ok(seed.ok);
    const resolve = createResolver(new Set(['src/seed.js', 'src/a.js', 'src/b.js']));
    summaries.set('src/seed.js', seed.model.summarize(['lodash'], resolve));
    const importer = (name: string) => `const { t } = require('./seed');\nt('${name}');\n`;
    let loads = 0;
    const result = await computeIndirectPaths(
      {
        specifiers: new Map([
          ['src/a.js', ['./seed']],
          ['src/b.js', ['./seed']],
        ]),
        resolve,
        summaries,
        load: async (rel) => {
          loads += 1;
          const parsed = parseModule(importer(rel), rel);
          return { summary: parsed.ok ? parsed.model.summarize(['lodash'], resolve) : null, bytes: 50 };
        },
      },
      { maxFiles: 1 },
    );
    assert.equal(loads, 1);
    assert.equal(result.capped, true);
    assert.deepEqual(result.skipped, ['src/b.js']);
    assert.deepEqual(show(result.byPackage.get('lodash')), ['src/a.js:2 t > template']);
  });

  it('the indirect-app fixture: a wrapper module and a computed member access', async () => {
    const evidence = (await collectUsageEvidence(INDIRECT_APP, ['lodash'], { exclude: [] })).get('lodash');
    assert.equal(evidence?.method, 'ast');
    assert.deepEqual(evidence?.files.map((f) => `${f.path}:${f.line}`), ['src/dynamic.js:4', 'src/templates.js:4']);
    assert.deepEqual(evidence?.membersUsed, { template: 1 });
    assert.deepEqual(show(evidence?.indirectPaths), ['src/cli.js:9 render > compile > template']);
    assert.deepEqual(evidence?.dynamicAccess, [{ path: 'src/dynamic.js', line: 7, text: '_[name]', reason: 'computed-member' }]);
  });
});
