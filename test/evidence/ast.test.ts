import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, it } from 'node:test';
import { matchPackageSpecifier, moduleBaseName, parseModule, scriptLangOf, useMember } from '../../src/evidence/ast.ts';
import {
  collectUsageEvidence,
  findImportsInSource,
  findImportsInSourceRegex,
  findUsageInSource,
  findUsageInSourceRegex,
} from '../../src/evidence/codebase.ts';
import type { ImportSite } from '../../src/types.ts';
import { tempDir } from './helpers.ts';

// line:kind:binding:named:subpath
function sitesOf(source: string, file: string, pkgs: string[]): string[] {
  return findImportsInSource(source, file, pkgs).map((s) => `${s.line}:${s.kind}:${s.binding ?? '-'}:${JSON.stringify(s.named ?? {})}${s.subpath ? `:${s.subpath}` : ''}`);
}

// "()" means the binding itself
function usesOf(source: string, file: string, pkgs: string[]): string[] {
  const sites = findImportsInSource(source, file, pkgs);
  return findUsageInSource(source, file, sites).map((u) => `${u.line}:${u.binding}.${u.member ?? '()'}`);
}

function analysis(source: string, file: string, pkg: string) {
  const parsed = parseModule(source, file);
  assert.ok(parsed.ok, `parses: ${file}`);
  return { model: parsed.model, result: parsed.model.analyzePackage(pkg) };
}

function dynamicOf(source: string, file: string, pkg: string): string[] {
  const { model, result } = analysis(source, file, pkg);
  return result.dynamic.map((d) => `${model.lineOf(d.at)}:${d.reason}:${source.slice(d.span.start, d.span.end)}`);
}

describe('ast: every import form in JS, TS, JSX and TSX', () => {
  const forms = [
    "import d from 'lodash';",
    "import * as ns from 'lodash';",
    "import { a, b as bee } from 'lodash';",
    "import 'lodash';",
    "const r = require('lodash');",
    "const { c, e: eee = 1, ...rest } = require('lodash');",
    "const f = require('lodash').f;",
    "const g = require('lodash')['g'];",
    "const dyn = await import('lodash');",
    "export { h, i as eye } from 'lodash';",
    "const sub = require('lodash/fp');",
    "import def, { default as ignored, j } from 'lodash';",
  ].join('\n');
  const expected = [
    '1:esm-default:d:{}',
    '2:esm-namespace:ns:{}',
    '3:esm-named:-:{"a":"a","b":"bee"}',
    '4:esm-side-effect:-:{}',
    '5:cjs-require:r:{}',
    '6:cjs-destructure:rest:{"c":"c","e":"eee"}',
    '7:cjs-member:-:{"f":"f"}',
    '8:cjs-member:-:{"g":"g"}',
    '9:dynamic-import:dyn:{}',
    '10:re-export:-:{"h":"h","i":"eye"}',
    '11:cjs-require:sub:{}:fp',
    '12:esm-default:def:{"j":"j"}',
  ];

  for (const file of ['src/app.js', 'src/app.ts', 'src/App.jsx', 'src/App.tsx']) {
    it(`parses ${path.extname(file)} and finds each form with its exact line`, () => {
      assert.ok(parseModule(forms, file).ok);
      assert.deepEqual(sitesOf(forms, file, ['lodash']), expected);
    });
  }

  it('matches the regex path on every form (same sites, lines and statements)', () => {
    assert.deepEqual(findImportsInSource(forms, 'src/app.js', ['lodash']), findImportsInSourceRegex(forms, 'src/app.js', ['lodash']));
  });

  it('keeps TypeScript-only forms: import-equals, type-only imports and specifiers are skipped', () => {
    const ts = "import type { LoDashStatic } from 'lodash';\nimport { type Dictionary, merge } from 'lodash';\nimport lo = require('lodash');\nexport type { Omit } from 'lodash';\nlet t: typeof lo;\n";
    assert.deepEqual(sitesOf(ts, 'src/a.ts', ['lodash']), ['2:esm-named:-:{"merge":"merge"}', '3:cjs-require:lo:{}']);
    assert.deepEqual(usesOf(ts, 'src/a.ts', ['lodash']), [], 'a `typeof` in a type annotation is not a use');
  });

  it('finds JSX component uses as calls of the binding (and member tags as members)', () => {
    const jsx = "import Markdown from 'react-markdown';\nimport { motion } from 'framer-motion';\nexport const A = ({ text }) => <Markdown>{text}</Markdown>;\nexport const B = () => <motion.div animate />;\nconst markdown = 1; const c = <markdown />;\n";
    for (const file of ['src/A.jsx', 'src/A.tsx', 'src/A.js']) {
      assert.deepEqual(usesOf(jsx, file, ['react-markdown', 'framer-motion']), ['3:Markdown.()', '4:motion.div'], file);
    }
  });

  it('records subpaths, scoped packages and the longest package name', () => {
    assert.deepEqual(sitesOf("import { x } from '@scope/pkg/sub/path';", 'a.js', ['@scope/pkg']), ['1:esm-named:-:{"x":"x"}:sub/path']);
    assert.deepEqual(matchPackageSpecifier('lodash/fp/map', ['lodash', 'lodash/fp']), { pkg: 'lodash/fp', subpath: 'map' });
    assert.equal(matchPackageSpecifier('lodash-es', ['lodash']), null);
    assert.deepEqual(usesOf("const template = require('lodash/template');\ntemplate('<%= x %>');\nconst fp = require('lodash/fp');\nfp.map(f);\n", 'a.js', ['lodash']), ['2:template.template', '4:fp.map']);
  });
});

describe('ast: members, binding calls and within-file aliases', () => {
  it('follows aliases one and two hops (const t = _.template, destructuring, bind, whole-module aliases)', () => {
    const source = [
      "const _ = require('lodash');",
      'const t = _.template;',
      't(a);',
      'const { merge, get: g } = _;',
      "merge({}, b); g(o, 'x');",
      'const tpl = _.template.bind(_);',
      'tpl(c);',
      'const lib = _;',
      'const pick = lib.pick;',
      'pick(o);',
      'lib.omit(o);',
      '_.template.call(null, d);',
      '(0, _.escape)(e);',
      'const maybe = opts.lodash || _;',
      'maybe.zip(x);',
      'const unused = _.unset;',
    ].join('\n');
    assert.deepEqual(usesOf(source, 'src/a.js', ['lodash']), [
      '3:t.template',
      '5:merge.merge',
      '5:g.get',
      '7:tpl.template',
      '10:pick.pick',
      '11:lib.omit',
      '12:_.template',
      '13:_.escape',
      '15:maybe.zip',
    ]);
  });

  it('counts member references (callbacks, exports) but not an alias that is never used', () => {
    const source = "const _ = require('lodash');\nitems.map(_.trim);\nmodule.exports = { template: _.template };\nconst dead = _.unset;\n";
    assert.deepEqual(usesOf(source, 'src/a.js', ['lodash']), ['2:_.trim', '3:_.template']);
  });

  it('tracks import().then callbacks and awaited default imports', () => {
    const source = "import('lodash').then((m) => m.merge(a));\nimport('marked').then(({ parse }) => parse(md));\nconst d = (await import('lodash')).default;\nd.pick(o);\n";
    assert.deepEqual(usesOf(source, 'src/a.mjs', ['lodash', 'marked']), ['1:m.merge', '2:parse.parse', '4:d.pick']);
  });

  it('resolves a constant key and ignores numeric indexes', () => {
    const source = "const _ = require('lodash');\nconst key = 'merge';\n_[key](a, b);\n_[0];\n";
    assert.deepEqual(usesOf(source, 'src/a.js', ['lodash']), ['3:_.merge']);
    assert.deepEqual(dynamicOf(source, 'src/a.js', 'lodash'), []);
  });

  it('resolves require(name) when name is a string constant', () => {
    const source = "const name = 'lodash';\nconst lib = require(name);\nlib.flatten(x);\n";
    assert.deepEqual(sitesOf(source, 'src/a.js', ['lodash']), ['2:cjs-require:lib:{}']);
    assert.deepEqual(usesOf(source, 'src/a.js', ['lodash']), ['3:lib.flatten']);
  });
});

describe('ast: scope-aware bindings', () => {
  it('does not count a parameter or an inner declaration that shadows the import', () => {
    const source = [
      "const _ = require('lodash');",
      'function a(_) { return _.template(x); }',
      'const b = (_) => _.merge(x);',
      'function c() { const _ = other; return _.omit(x); }',
      'function d() { if (y) { let _ = 1; _.trim(); } return _.pick(o); }',
      'try { f(); } catch (_) { _.unset(e); }',
      'class E { m(_) { return _.zip(); } n() { return _.chunk(a); } }',
      'function g() { var _ = 2; { _.flip(); } }',
      '_.get(o);',
    ].join('\n');
    assert.deepEqual(usesOf(source, 'src/a.js', ['lodash']), ['5:_.pick', '7:_.chunk', '9:_.get']);
  });

  it('resolves hoisted function declarations and closures over the import', () => {
    const source = "run();\nfunction run() { return helper(); }\nfunction helper() { return lo.merge({}, {}); }\nimport * as lo from 'lodash';\n";
    assert.deepEqual(usesOf(source, 'src/a.mjs', ['lodash']), ['3:lo.merge']);
  });

  it('shadowing is what the regex path cannot see', () => {
    const source = "const _ = require('lodash');\nfunction a(_) { return _.template(x); }\n";
    const regexSites = findImportsInSourceRegex(source, 'src/a.js', ['lodash']);
    assert.deepEqual(findUsageInSourceRegex(source, 'src/a.js', regexSites).map((u) => u.member), ['template']);
    assert.deepEqual(usesOf(source, 'src/a.js', ['lodash']), []);
  });
});

describe('ast: dynamic accesses are reported, not missed', () => {
  it('computed member access on the binding and on an alias', () => {
    const source = "const _ = require('lodash');\nconst fn = process.argv[2];\n_[fn]('x');\nconst lib = _;\nlib[`${fn}`](y);\n_.merge(a);\n";
    assert.deepEqual(dynamicOf(source, 'src/a.js', 'lodash'), ['3:computed-member:_[fn]', '5:computed-member:lib[`${fn}`]']);
    assert.deepEqual(usesOf(source, 'src/a.js', ['lodash']), ['6:_.merge']);
  });

  it('require(variable) and import(variable) in a file that names the package', () => {
    const source = "const lib = require(process.env.LIB || 'lodash');\nconst plugin = require(path.join(__dirname, 'plugins', name));\nconst other = await import(`./locales/${lang}.js`);\nconst mod = await import(moduleName);\n";
    assert.deepEqual(dynamicOf(source, 'src/a.mjs', 'lodash'), ["1:dynamic-require:require(process.env.LIB || 'lodash')", '4:dynamic-require:import(moduleName)']);
    assert.deepEqual(dynamicOf("const x = require(name);\n", 'src/b.js', 'lodash'), [], 'the file does not name the package');
  });

  it('reassigned bindings, but not the assignment that imports', () => {
    const source = "let _ = require('lodash');\nif (legacy) _ = require('underscore');\n_.merge(a);\nlet t;\nt = require('lodash').template;\nt++;\n";
    assert.deepEqual(dynamicOf(source, 'src/a.js', 'lodash'), ["2:reassigned-binding:_ = require('underscore')", '6:reassigned-binding:t++']);
    const late = "let lib;\nlib = require('lodash');\nlib.merge(a);\n";
    assert.deepEqual(dynamicOf(late, 'src/b.js', 'lodash'), []);
    assert.deepEqual(usesOf(late, 'src/b.js', ['lodash']), ['3:lib.merge']);
  });
});

describe('ast: .vue and .svelte files', () => {
  it('reads the <script> blocks with their lines (JavaScript and TypeScript)', () => {
    const vue = "<template>\n  <p>{{ total }}</p>\n</template>\n<script setup lang=\"ts\">\nimport { sum } from 'lodash';\nconst total: number = sum([1, 2]);\n</script>\n";
    assert.equal(scriptLangOf(vue), 'ts');
    assert.deepEqual(sitesOf(vue, 'src/Total.vue', ['lodash']), ['5:esm-named:-:{"sum":"sum"}']);
    assert.deepEqual(usesOf(vue, 'src/Total.vue', ['lodash']), ['6:sum.sum']);
    const svelte = "<script context=\"module\">\n  export const prerender = true;\n</script>\n<script>\n  import _ from 'lodash';\n  export let items = [];\n  $: sorted = _.sortBy(items, 'name');\n</script>\n<ul>{#each sorted as i}<li>{i.name}</li>{/each}</ul>\n";
    assert.equal(scriptLangOf(svelte), 'js');
    assert.deepEqual(sitesOf(svelte, 'src/List.svelte', ['lodash']), ['5:esm-default:_:{}']);
    assert.deepEqual(usesOf(svelte, 'src/List.svelte', ['lodash']), ['7:_.sortBy']);
  });
});

describe('ast: re-exports', () => {
  it('ESM and CommonJS re-exports give one pseudo-use per exported name, like the regex path', () => {
    const source = "export { template, merge as m } from 'lodash';\nexport * from 'lodash';\nexports.omit = require('lodash').omit;\nmodule.exports.all = require('lodash');\n";
    assert.deepEqual(sitesOf(source, 'src/a.js', ['lodash']), ['1:re-export:-:{"template":"template","merge":"m"}', '2:re-export:-:{}', '3:re-export:-:{"omit":"omit"}', '4:re-export:-:{}']);
    assert.deepEqual(usesOf(source, 'src/a.js', ['lodash']), ['1:(re-export).template', '1:(re-export).merge', '3:(re-export).omit']);
  });
});

describe('ast: regex fallback', () => {
  const broken = "const _ = require('lodash');\nconst x = ;\n_.merge(a);\n";

  it('a file that does not parse falls back to the regex path', () => {
    const parsed = parseModule(broken, 'src/bad.js');
    assert.equal(parsed.ok, false);
    assert.equal(parsed.ok ? 0 : parsed.line, 2);
    assert.deepEqual(sitesOf(broken, 'src/bad.js', ['lodash']), ['1:cjs-require:_:{}']);
    assert.deepEqual(usesOf(broken, 'src/bad.js', ['lodash']), ['3:_.merge']);
  });

  it('a tree nested deeper than the walks allow (generated string concatenation) falls back too', () => {
    const deep = `const _ = require('lodash');\nconst s = ${Array.from({ length: 3000 }, (_, i) => `'p${i}'`).join(' + ')};\n_.merge(a);\n`;
    const parsed = parseModule(deep, 'src/generated.js');
    assert.equal(parsed.ok ? '' : parsed.message, 'nested more than 1000 levels deep');
    assert.deepEqual(usesOf(deep, 'src/generated.js', ['lodash']), ['3:_.merge']);
  });

  it('stale sites that match no import record fall back too', () => {
    const source = "const _ = require('lodash');\n_.merge(a);\n";
    const stale: ImportSite[] = [{ path: 'src/a.js', line: 9, statement: "const _ = require('lodash');", binding: '_', kind: 'cjs-require', scope: 'source' }];
    assert.deepEqual(findUsageInSource(source, 'src/a.js', stale).map((u) => `${u.line}:${u.member}`), ['2:merge']);
  });

  it('collectUsageEvidence reports the file as unparsed and the method as regex or mixed', async () => {
    const tmp = await tempDir('pp-ast-');
    try {
      await mkdir(path.join(tmp.dir, 'src'), { recursive: true });
      await writeFile(path.join(tmp.dir, 'src/bad.js'), broken);
      const only = await collectUsageEvidence(tmp.dir, ['lodash'], { exclude: [] });
      const bad = only.get('lodash');
      assert.equal(bad?.method, 'regex');
      assert.deepEqual(bad?.membersUsed, { merge: 1 });
      assert.deepEqual(bad?.dynamicAccess?.map((d) => [d.path, d.line, d.reason]), [['src/bad.js', 2, 'unparsed-file']]);
      assert.match(bad?.dynamicAccess?.[0]?.text ?? '', /^not parsed \(Expression expected\.\); scanned with patterns instead$/);
      await writeFile(path.join(tmp.dir, 'src/good.js'), "const _ = require('lodash');\n_.get(o, 'a');\n");
      const both = await collectUsageEvidence(tmp.dir, ['lodash'], { exclude: [] });
      assert.equal(both.get('lodash')?.method, 'mixed');
      assert.deepEqual(both.get('lodash')?.membersUsed, { get: 1, merge: 1 });
    } finally {
      await tmp.cleanup();
    }
  });
});

describe('ast: helpers', () => {
  it('names modules and picks the member a use reaches', () => {
    assert.equal(moduleBaseName('src/templates.js'), 'templates');
    assert.equal(moduleBaseName('src/lib/index.ts'), 'lib');
    assert.equal(moduleBaseName('src/date-utils.mjs'), 'dateUtils');
    assert.equal(useMember({ path: [] }), null);
    assert.equal(useMember({ path: ['marked', 'parse'] }), 'parse');
  });

  it('exposes every use with its enclosing named function', () => {
    const source = "const _ = require('lodash');\nfunction render(md) { return [md].map((m) => _.template(m)); }\nconst compile = (s) => _.merge({}, s);\n_.get(o);\n";
    const { model, result } = analysis(source, 'src/a.js', 'lodash');
    const summary = model.summarize(['lodash'], () => null);
    assert.deepEqual(
      result.uses.map((u) => [useMember(u), u.unit === -1 ? '(module)' : summary.units[u.unit]?.name]),
      [
        ['template', 'render'],
        ['merge', 'compile'],
        ['get', '(module)'],
      ],
    );
  });
});
