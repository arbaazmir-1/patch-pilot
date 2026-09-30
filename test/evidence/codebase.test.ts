import assert from 'node:assert/strict';
import { mkdir, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, it } from 'node:test';
import { DEFAULT_EXCLUDES } from '../../src/config.ts';
import {
  classifyFile,
  extractBlamedSymbols,
  findImportsInSource,
  findUsageInSource,
  globToRegExp,
  IMPORT_KINDS,
  isGitignored,
  maskSource,
  matchesGlob,
  normalizeSymbol,
  parseGitignore,
  searchProject,
  walkProject,
} from '../../src/evidence/codebase.ts';
import type { ImportSite, UsageEvidence } from '../../src/types.ts';
import { tempDir } from './helpers.ts';

const noUsage = (pkg: string): UsageEvidence => ({
  package: pkg,
  imported: false,
  files: [],
  scopes: { source: 0, test: 0, config: 0, scripts: 0 },
  membersUsed: {},
  bindingCalls: 0,
  scannedFiles: 0,
});

const imports = (source: string, pkgs: string[] = ['lodash'], file = 'src/app.js'): ImportSite[] => findImportsInSource(source, file, pkgs);
const one = (source: string, pkgs?: string[], file?: string): ImportSite => {
  const sites = imports(source, pkgs, file);
  assert.equal(sites.length, 1, `expected one site in: ${source}\n${JSON.stringify(sites)}`);
  return sites[0] as ImportSite;
};

describe('findImportsInSource: every ImportKind', () => {
  it('esm-default, with and without named imports', () => {
    const site = one("import _ from 'lodash';");
    assert.equal(site.kind, 'esm-default');
    assert.equal(site.binding, '_');
    assert.equal(site.line, 1);
    assert.equal(site.statement, "import _ from 'lodash';");
    const mixed = one('import _, { merge as m, get } from "lodash"');
    assert.equal(mixed.kind, 'esm-default');
    assert.deepEqual(mixed.named, { merge: 'm', get: 'get' });
    const viaDefault = one("import { default as md, parse } from 'marked'", ['marked']);
    assert.equal(viaDefault.kind, 'esm-default');
    assert.equal(viaDefault.binding, 'md');
    assert.deepEqual(viaDefault.named, { parse: 'parse' });
  });

  it('esm-namespace', () => {
    const site = one("import * as lo from 'lodash'");
    assert.equal(site.kind, 'esm-namespace');
    assert.equal(site.binding, 'lo');
    const both = imports("import _, * as ns from 'lodash'");
    assert.deepEqual(
      both.map((s) => [s.kind, s.binding]),
      [
        ['esm-default', '_'],
        ['esm-namespace', 'ns'],
      ],
    );
  });

  it('esm-named across lines, skipping `type` imports', () => {
    const site = one("const a = 1;\nimport {\n  merge,\n  type LoDashStatic,\n  get as lodashGet,\n} from 'lodash';\n");
    assert.equal(site.kind, 'esm-named');
    assert.equal(site.binding, null);
    assert.equal(site.line, 2);
    assert.deepEqual(site.named, { merge: 'merge', get: 'lodashGet' });
    assert.equal(site.statement, "import { merge, type LoDashStatic, get as lodashGet, } from 'lodash';");
    assert.deepEqual(imports("import type { LoDashStatic } from 'lodash';", ['lodash'], 'src/a.ts'), []);
  });

  it('esm-side-effect', () => {
    const site = one("import 'lodash';\n");
    assert.equal(site.kind, 'esm-side-effect');
    assert.equal(site.binding, null);
  });

  it('cjs-require, including TypeScript import-equals and an immediate call', () => {
    const site = one("const _ = require('lodash');");
    assert.equal(site.kind, 'cjs-require');
    assert.equal(site.binding, '_');
    assert.equal(one('import lo = require("lodash");', ['lodash'], 'src/a.ts').binding, 'lo');
    const called = one("const debug = require('debug')('app');", ['debug']);
    assert.equal(called.kind, 'cjs-require');
    assert.equal(called.binding, null);
    assert.equal(one("let x;\nx = require('lodash')").binding, 'x');
  });

  it('cjs-destructure with renames and defaults', () => {
    const site = one("const { merge, get: lodashGet, template = null } = require('lodash');");
    assert.equal(site.kind, 'cjs-destructure');
    assert.equal(site.binding, null);
    assert.deepEqual(site.named, { merge: 'merge', get: 'lodashGet', template: 'template' });
  });

  it('cjs-member (with and without a local name)', () => {
    const site = one("const tpl = require('lodash').template;");
    assert.equal(site.kind, 'cjs-member');
    assert.deepEqual(site.named, { template: 'tpl' });
    const bare = one("require('lodash').merge(a, b);");
    assert.equal(bare.kind, 'cjs-member');
    assert.equal(bare.named, undefined);
    const bracket = one("const m = require('lodash')['merge'];");
    assert.deepEqual(bracket.named, { merge: 'm' });
    const viaDefault = one("const marked = require('marked').default;", ['marked']);
    assert.equal(viaDefault.kind, 'cjs-require');
    assert.equal(viaDefault.binding, 'marked');
  });

  it('dynamic-import with a binding or a destructure', () => {
    const site = one("async function f() { const lo = await import('lodash'); }");
    assert.equal(site.kind, 'dynamic-import');
    assert.equal(site.binding, 'lo');
    const destructured = one("const { merge } = await import('lodash');");
    assert.deepEqual(destructured.named, { merge: 'merge' });
    assert.equal(one("import('lodash').then((m) => m.merge)").binding, null);
  });

  it('re-export (named, star, CommonJS)', () => {
    const named = one("export { merge, get as g } from 'lodash';");
    assert.equal(named.kind, 're-export');
    assert.deepEqual(named.named, { merge: 'merge', get: 'g' });
    assert.equal(one("export * from 'lodash';").kind, 're-export');
    assert.equal(one("export * as lo from 'lodash';").kind, 're-export');
    const cjs = one("module.exports = require('lodash');");
    assert.equal(cjs.kind, 're-export');
    assert.deepEqual(one("exports.merge = require('lodash').merge;").named, { merge: 'merge' });
  });

  it('covers every ImportKind in types.ts', () => {
    const source = [
      "import d from 'lodash';",
      "import * as ns from 'lodash';",
      "import { a } from 'lodash';",
      "import 'lodash';",
      "const r = require('lodash');",
      "const { b } = require('lodash');",
      "const c = require('lodash').c;",
      "const dyn = await import('lodash');",
      "export { e } from 'lodash';",
    ].join('\n');
    assert.deepEqual([...new Set(imports(source).map((s) => s.kind))].sort(), [...IMPORT_KINDS].sort());
  });

  it('subpath imports (lodash/template, scoped packages)', () => {
    const site = one("const template = require('lodash/template');");
    assert.equal(site.subpath, 'template');
    assert.equal(site.binding, 'template');
    const fp = one("import fp from 'lodash/fp';");
    assert.equal(fp.subpath, 'fp');
    const scoped = one("import { x } from '@scope/pkg/sub/path';", ['@scope/pkg']);
    assert.equal(scoped.subpath, 'sub/path');
  });

  it('never matches other packages, comments, strings or require.resolve', () => {
    assert.deepEqual(imports("const t = require('lodash.template'); import x from 'lodash-es';"), []);
    assert.deepEqual(imports("// const _ = require('lodash');\n/* import _ from 'lodash' */"), []);
    assert.deepEqual(imports('const s = "const _ = require(\'lodash\')";'), []);
    assert.deepEqual(imports("const p = require.resolve('lodash');"), []);
    assert.deepEqual(imports("const p = `import x from 'lodash'`;"), []);
  });

  it('reads the <script> block of a .vue file and records the scope', () => {
    const vue = "<template>\n  <p>Don't {{ total }}</p>\n</template>\n<script>\nimport _ from 'lodash'\nexport default { computed: { total() { return _.sum([1]) } } }\n</script>\n";
    const site = one(vue, ['lodash'], 'src/components/Total.vue');
    assert.equal(site.line, 5);
    assert.equal(site.scope, 'source');
    const usage = findUsageInSource(vue, 'src/components/Total.vue', [site]);
    assert.deepEqual(usage.map((u) => u.member), ['sum']);
    assert.equal(one("import _ from 'lodash';", ['lodash'], 'test/a.test.js').scope, 'test');
  });
});

describe('findUsageInSource: members, counts and binding calls', () => {
  it('finds bracket access, optional chaining and named-import calls', () => {
    const source = [
      "import _, { get as g } from 'lodash';",
      "_['template']('x');",
      '_?.merge(a, b);',
      "g(obj, 'a.b');",
      "const s = '_.omit(x)'; // _.unset(y)",
    ].join('\n');
    const sites = imports(source);
    assert.deepEqual(
      findUsageInSource(source, 'src/app.js', sites).map((u) => `${u.line}:${u.member}`),
      ['2:template', '3:merge', '4:get'],
    );
  });

  it('records calls of the binding itself (minimist(argv), marked(md))', () => {
    const cli = "const parseArgs = require('minimist');\nconst args = parseArgs(process.argv.slice(2), { string: ['input'] });\n";
    const usage = findUsageInSource(cli, 'src/cli.js', findImportsInSource(cli, 'src/cli.js', ['minimist']));
    assert.deepEqual(
      usage.map((u) => [u.line, u.binding, u.member]),
      [[2, 'parseArgs', null]],
    );
    const render = "const marked = require('marked');\nfunction r(md) { return marked(md, { sanitize: true }); }\nmarked.setOptions({});\n";
    const renderUsage = findUsageInSource(render, 'src/render.js', findImportsInSource(render, 'src/render.js', ['marked']));
    assert.deepEqual(
      renderUsage.map((u) => [u.line, u.member]),
      [
        [2, null],
        [3, 'setOptions'],
      ],
    );
  });

  it('maps named objects, subpath bindings and direct require calls to members', () => {
    const v4 = "const { marked } = require('marked');\nmarked.parse(md);\nmarked(md);\n";
    assert.deepEqual(
      findUsageInSource(v4, 'a.js', findImportsInSource(v4, 'a.js', ['marked'])).map((u) => u.member),
      ['parse', 'marked'],
    );
    const sub = "const template = require('lodash/template');\nconst compiled = template('<%= x %>');\n";
    assert.deepEqual(
      findUsageInSource(sub, 'a.js', findImportsInSource(sub, 'a.js', ['lodash'])).map((u) => u.member),
      ['template'],
    );
    const direct = "require('lodash').merge(a, b);\nrequire('debug')('app');\n";
    assert.deepEqual(
      findUsageInSource(direct, 'a.js', findImportsInSource(direct, 'a.js', ['lodash', 'debug'])).map((u) => [u.line, u.member]),
      [
        [1, 'merge'],
        [2, null],
      ],
    );
    const reexport = "export { template, merge as m } from 'lodash';\n";
    assert.deepEqual(
      findUsageInSource(reexport, 'a.js', findImportsInSource(reexport, 'a.js', ['lodash'])).map((u) => u.member),
      ['template', 'merge'],
    );
  });

  it('filters by symbol (normalised) and adds context lines', () => {
    const source = "const _ = require('lodash');\n\nconst a = _.get(o, 'x');\nconst b = _.merge(a, {});\n\n";
    const sites = imports(source);
    const hits = findUsageInSource(source, 'src/app.js', sites, '_.merge()', 1);
    assert.equal(hits.length, 1);
    assert.equal(hits[0]?.line, 4);
    assert.deepEqual(hits[0]?.context, { before: ["const a = _.get(o, 'x');"], after: [''] });
    assert.deepEqual(findUsageInSource(source, 'src/app.js', sites, 'template'), []);
    assert.equal(normalizeSymbol('lodash.template()'), 'template');
    assert.equal(normalizeSymbol(' new Range '), 'Range');
  });
});

describe('extractBlamedSymbols', () => {
  it('keeps names internal when the sentence says internal, private, helper or names a source file', () => {
    const whole: UsageEvidence = {
      ...noUsage('lodash'),
      imported: true,
      files: [{ path: 'src/a.js', line: 1, statement: '', binding: '_', kind: 'cjs-require', scope: 'source' }],
    };
    const kinds = (details: string): string[] => extractBlamedSymbols(details, '', 'lodash', whole).map((s) => `${s.name}:${s.kind}`);
    assert.deepEqual(kinds('The `baseMerge` function is vulnerable.'), ['baseMerge:exported']);
    assert.deepEqual(kinds('The internal `baseMerge` function is vulnerable.'), ['baseMerge:internal']);
    assert.deepEqual(kinds('A private helper, `baseMerge()`, is vulnerable.'), ['baseMerge:internal']);
    assert.deepEqual(kinds('In `lib/merge.js` the `baseMerge` function is vulnerable. The `cloneDeep` function too.'), ['cloneDeep:exported', 'baseMerge:internal']);
    assert.deepEqual(kinds('The flaw is in the assignValue function of utils.js.'), ['assignValue:internal']);
    assert.deepEqual(kinds('The flaw is in the assignValue function.'), ['assignValue:exported']);
  });

  it('filters stop words, globals, options, file names, URLs and fix sections', () => {
    const details = [
      'Passing `true` to the `options` argument of `Object.assign` or `JSON.parse()` is fine.',
      'The `variable` option and the `isAdmin` key are data, and `lib/index.js` is a file.',
      'See https://marked.js.org/using_advanced#workers and [the docs](https://example.com/_.template).',
      'The vulnerable function is `renderToken()`.',
      '',
      '### Patches',
      'Replace `assignInWith` with `assignWith`.',
    ].join('\n');
    const out = extractBlamedSymbols(details, 'Prototype Pollution via Parse Method', 'example', noUsage('example'));
    assert.deepEqual(
      out.map((s) => `${s.name}:${s.kind}:${s.via}`),
      ['renderToken:internal:call', 'parse:internal:summary'],
    );
  });

  it('knows conventional bindings, express response methods, and ignores prose and data noise', () => {
    const names = (details: string, summary: string, pkg: string): string[] =>
      extractBlamedSymbols(details, summary, pkg, noUsage(pkg)).map((s) => `${s.name}:${s.kind}:${s.via}`);
    // jsonwebtoken advisory excerpts
    assert.deepEqual(
      names(
        'A falsy secret or key in the `jwt.verify()` function can lead to signature validation bypass due to defaulting to the `none` algorithm.',
        "jsonwebtoken's insecure implementation of key retrieval function could lead to Forgeable Tokens",
        'jsonwebtoken',
      ),
      ['verify:exported:member-access'],
    );
    // express advisory excerpts
    assert.deepEqual(
      names('The main method impacted is `res.location()` but this is also called from within `res.redirect()`. Express performs an encode using `encodeurl`.', 'express vulnerable to XSS via response.redirect()', 'express'),
      ['res.location:internal:call', 'res.redirect:internal:call'],
    );
    // axios advisory phrases
    assert.deepEqual(
      names(
        "The shouldBypassProxy() function does pure string matching. Axios will inherit the polluted `validateStatus` function during config merge, and `buildURL` uses its own `encode` function. The `NO_PROXY` value, commit `afca61a`, `foo.txt` and `auth` are data.\n\n```bash\nnode axios.js\n```\n\n```js\nconst axios = require('axios');\naxios.get(url);\n```",
        'Axios: no_proxy bypass',
        'axios',
      ),
      ['get:exported:member-access', 'validateStatus:internal:backticks', 'buildURL:internal:backticks', 'encode:internal:backticks', 'shouldBypassProxy:internal:call'],
    );
  });

  it('classifies a symbol exported when the project calls it or imports it by name', () => {
    const ev: UsageEvidence = {
      ...noUsage('lodash'),
      imported: true,
      files: [{ path: 'a.js', line: 1, statement: '', binding: null, kind: 'cjs-destructure', named: { omit: 'omit' }, scope: 'source' }],
      membersUsed: { merge: 1 },
    };
    const out = extractBlamedSymbols('The `merge` and `omit` helpers and the internal `baseSet` call.', '', 'lodash', ev);
    assert.deepEqual(
      out.map((s) => `${s.name}:${s.kind}`),
      ['merge:exported', 'omit:exported', 'baseSet:internal'],
    );
  });
});

describe('walkProject, excludes and scope classification', () => {
  it('honours built-in excludes, .gitignore, config globs, size and binary limits', async () => {
    const tmp = await tempDir();
    const root = tmp.dir;
    const write = async (rel: string, content: string | Buffer): Promise<void> => {
      await mkdir(path.dirname(path.join(root, rel)), { recursive: true });
      await writeFile(path.join(root, rel), content);
    };
    try {
      await write('src/app.js', "const _ = require('lodash');\n");
      await write('src/util.ts', 'export const x = 1;\n');
      await write('src/types.d.ts', 'export type X = 1;\n');
      await write('src/vendor.min.js', 'var a=1;');
      await write('src/generated/api.js', 'module.exports = {};\n');
      await write('src/keep.generated.js', 'x\n');
      await write('src/drop.generated.js', 'x\n');
      await write('src/big.js', `// ${'x'.repeat(1024 * 1024)}\n`);
      await write('src/blob.js', Buffer.from([0x63, 0x6f, 0x00, 0x01, 0x02]));
      await write('src/readme.md', '# not code\n');
      await write('.env', 'SECRET=1\n');
      await write('node_modules/lodash/index.js', 'module.exports = {};\n');
      await write('packages/a/node_modules/x/index.js', 'x\n');
      await write('dist/bundle.js', 'x\n');
      await write('.git/hooks/pre-commit.js', 'x\n');
      await write('.patch-pilot/tmp/x.js', 'x\n');
      await write('.next/server.js', 'x\n');
      await write('coverage/lcov.js', 'x\n');
      await write('bin/tool', '#!/usr/bin/env node\nrequire("minimist")\n');
      await write('bin/notes', 'plain text\n');
      await write('test/app.test.js', 'x\n');
      await write('.gitignore', '# generated\n*.generated.js\n!keep.generated.js\n/src/generated/\n');
      await symlink(path.join(root, 'src'), path.join(root, 'src-link'));
      const result = await walkProject(root, { exclude: [...DEFAULT_EXCLUDES, 'src/util.*'] });
      assert.deepEqual(
        result.files.map((f) => `${f.path}:${f.scope}`),
        ['bin/tool:scripts', 'src/app.js:source', 'src/keep.generated.js:source', 'test/app.test.js:test'],
      );
      assert.equal(result.files.find((f) => f.path === 'bin/tool')?.ext, '');
      assert.deepEqual(result.skipped, [
        { path: 'src/big.js', reason: 'too-large' },
        { path: 'src/blob.js', reason: 'binary' },
      ]);
      assert.equal(result.truncated, false);
      const capped = await walkProject(root, { exclude: DEFAULT_EXCLUDES, maxFiles: 2 });
      assert.equal(capped.truncated, true);
      assert.equal(capped.files.length, 2);
      const noGitignore = await walkProject(root, { exclude: [], respectGitignore: false });
      assert.ok(noGitignore.files.some((f) => f.path === 'src/generated/api.js'));
      assert.ok(!noGitignore.files.some((f) => f.path.startsWith('node_modules/')), 'node_modules is always pruned');
    } finally {
      await tmp.cleanup();
    }
  });

  it('classifies files by path', () => {
    const table: [string, string][] = [
      ['src/config.js', 'source'],
      ['lib/index.ts', 'source'],
      ['index.js', 'source'],
      ['src/render.test.js', 'test'],
      ['src/render.spec.tsx', 'test'],
      ['test/render.js', 'test'],
      ['src/__tests__/x.js', 'test'],
      ['packages/a/tests/x.js', 'test'],
      ['e2e/login.ts', 'test'],
      ['src/Button.stories.tsx', 'test'],
      ['vite.config.ts', 'config'],
      ['jest.config.cjs', 'config'],
      ['webpack.config.babel.js', 'config'],
      ['karma.conf.js', 'config'],
      ['.eslintrc.js', 'config'],
      ['.storybook/main.js', 'config'],
      ['scripts/check-version.js', 'scripts'],
      ['bin/cli.js', 'scripts'],
      ['tools/release.mjs', 'scripts'],
      ['packages/app/scripts/build.js', 'scripts'],
      ['gulpfile.js', 'scripts'],
      ['src/tools/format.js', 'source'],
    ];
    for (const [rel, scope] of table) assert.equal(classifyFile(rel), scope, rel);
  });
});

describe('searchProject', () => {
  it('searches code and text files with context, skipping minified lines and lockfiles', async () => {
    const tmp = await tempDir();
    try {
      await mkdir(path.join(tmp.dir, 'src'), { recursive: true });
      await writeFile(path.join(tmp.dir, 'src/a.js'), "const _ = require('lodash');\n_.merge(a, b);\n_.merge(c, d);\n");
      await writeFile(path.join(tmp.dir, 'src/min.js'), `${'var x=_.merge(a,b);'.repeat(80)}\n`);
      await writeFile(path.join(tmp.dir, 'notes.md'), 'call _.merge carefully\n');
      await writeFile(path.join(tmp.dir, 'package-lock.json'), '{"_.merge": 1}\n');
      await mkdir(path.join(tmp.dir, 'test'), { recursive: true });
      await writeFile(path.join(tmp.dir, 'test/a.test.js'), '_.merge(x)\n');
      const all = await searchProject(tmp.dir, /_\.merge\(/g, { exclude: DEFAULT_EXCLUDES, maxResults: 10, contextLines: 1 });
      assert.deepEqual(
        all.matches.map((m) => `${m.path}:${m.line}:${m.scope}`),
        ['src/a.js:2:source', 'src/a.js:3:source', 'test/a.test.js:1:test'],
      );
      assert.deepEqual(all.matches[0]?.context, { before: ["const _ = require('lodash');"], after: ['_.merge(c, d);'] });
      assert.equal(all.total, 3);
      const capped = await searchProject(tmp.dir, /_\.merge/, { exclude: DEFAULT_EXCLUDES, maxResults: 1 });
      assert.equal(capped.matches.length, 1);
      assert.equal(capped.total, 4, 'notes.md is searched too');
      assert.equal(capped.truncated, true);
      const onlyMd = await searchProject(tmp.dir, /merge/, { exclude: DEFAULT_EXCLUDES, maxResults: 5, fileGlob: '*.md' });
      assert.deepEqual(onlyMd.matches.map((m) => m.path), ['notes.md']);
      const inSrc = await searchProject(tmp.dir, /merge/, { exclude: DEFAULT_EXCLUDES, maxResults: 5, fileGlob: 'src/**/*.js', skipMinified: false });
      assert.deepEqual(inSrc.matches.map((m) => m.path), ['src/a.js', 'src/a.js', 'src/min.js']);
    } finally {
      await tmp.cleanup();
    }
  });
});

describe('globs, .gitignore and the source mask', () => {
  it('matches globs the way the config and fileGlob use them', () => {
    assert.ok(matchesGlob('dist/x/y.js', 'dist/**'));
    assert.ok(matchesGlob('dist', 'dist/**'));
    assert.ok(matchesGlob('a/node_modules/b', '**/node_modules/**'));
    assert.ok(matchesGlob('src/deep/x.min.js', '*.min.js'), 'a glob without / matches the basename');
    assert.ok(matchesGlob('src/a.ts', 'src/*.{js,ts}'));
    assert.ok(!matchesGlob('src/a/b.ts', 'src/*.ts'));
    assert.ok(matchesGlob('src/a/b.ts', 'src/**/*.ts'));
    assert.ok(matchesGlob('src/b.ts', 'src/**/*.ts'));
    assert.ok(globToRegExp('file?.js').test('file1.js'));
    assert.ok(globToRegExp('[ab].js').test('a.js'));
  });

  it('applies .gitignore rules with anchors, directories and negation', () => {
    const rules = parseGitignore('# c\n*.log\n!keep.log\n/build\nout/\ndocs/**/*.tmp\n');
    assert.ok(isGitignored(rules, 'a/b.log', false));
    assert.ok(!isGitignored(rules, 'a/keep.log', false));
    assert.ok(isGitignored(rules, 'build', true));
    assert.ok(!isGitignored(rules, 'src/build', true), 'a leading slash anchors to the root');
    assert.ok(isGitignored(rules, 'x/out', true));
    assert.ok(!isGitignored(rules, 'x/out', false), 'a trailing slash matches directories only');
    assert.ok(isGitignored(rules, 'docs/a/b/c.tmp', false));
  });

  it('masks comments, strings, templates and regex literals without moving offsets', () => {
    const source = "const a = 'x // y'; // c\nconst r = /['\"]/g; /* b\n c */ const t = `v${_.merge(a)}w`;\n";
    const masked = maskSource(source);
    assert.equal(masked.length, source.length);
    assert.equal(masked.split('\n').length, source.split('\n').length);
    assert.ok(!masked.includes('//'));
    assert.ok(masked.includes('_.merge(a)'), 'template expressions stay code');
    assert.ok(!masked.includes('y'));
    const keep = maskSource(source, { keepStrings: true });
    assert.ok(keep.includes("'x // y'"));
    assert.ok(!keep.includes('/* b'));
  });
});
