import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { isLocalHost } from '../../src/config.ts';
import { createToolRegistry } from '../../src/investigation/tools/index.ts';
import { handleReadFile, isSecretPath } from '../../src/investigation/tools/readFile.ts';
import { compilePattern, hasNestedQuantifier, makeSearchCodeHandler } from '../../src/investigation/tools/searchCode.ts';
import type { JsonSchema, SearchMatch, ToolContext } from '../../src/types.ts';
import { coerceToSchema, validateJson } from '../../src/util/schema.ts';

let tmp: string;
before(async () => {
  tmp = await mkdtemp(path.join(os.tmpdir(), 'pp-security-'));
  await mkdir(path.join(tmp, 'src'), { recursive: true });
  await mkdir(path.join(tmp, '.git'), { recursive: true });
  await mkdir(path.join(tmp, 'certs'), { recursive: true });
  await writeFile(path.join(tmp, '.env'), 'TOKEN=secret\n');
  await writeFile(path.join(tmp, '.env.production'), 'TOKEN=secret\n');
  await writeFile(path.join(tmp, '.npmrc'), '//registry.npmjs.org/:_authToken=secret\n');
  await writeFile(path.join(tmp, '.git', 'config'), '[remote "origin"]\n');
  await writeFile(path.join(tmp, 'certs', 'server.pem'), '-----BEGIN PRIVATE KEY-----\n');
  await writeFile(path.join(tmp, 'src', 'index.js'), 'console.log(1);\n');
  await symlink(path.join(tmp, '.env'), path.join(tmp, 'src', 'notes.txt'));
});
after(async () => {
  await rm(tmp, { recursive: true, force: true });
});

const ctx = (): ToolContext => ({ projectRoot: tmp }) as ToolContext;

describe('read_file secret deny list', () => {
  it('flags credential files at any depth and leaves source alone', () => {
    for (const p of ['.env', '.env.local', 'app/.env', '.npmrc', '.yarnrc', '.yarnrc.yml', '.netrc', '.pypirc', '.git/config', 'pkg/.patch-pilot/cache.json', 'certs/a.pem', 'tls/server.key', 'store.p12', '.ssh/id_rsa', 'id_ed25519', '.ENV']) {
      assert.equal(isSecretPath(p), true, p);
    }
    for (const p of ['src/index.js', 'package.json', 'id_rsa.pub', 'src/env.js', 'docs/monkey.md', '.github/workflows/ci.yml', '.gitignore']) {
      assert.equal(isSecretPath(p), false, p);
    }
  });

  it('withholds secrets with the normal error shape', async () => {
    for (const p of ['.env', '.env.production', '.npmrc', '.git/config', 'certs/server.pem', './.env', 'src/../.env']) {
      const r = await handleReadFile({ path: p }, ctx());
      assert.equal(r.ok, false, p);
      assert.match(r.error ?? '', /withheld as a likely secret/, p);
      assert.equal(typeof r.hint, 'string');
    }
  });

  it('follows symlinks before deciding', async () => {
    const r = await handleReadFile({ path: 'src/notes.txt' }, ctx());
    assert.equal(r.ok, false);
    assert.match(r.error ?? '', /withheld/);
  });

  it('still reads ordinary files', async () => {
    const r = await handleReadFile({ path: 'src/index.js' }, ctx());
    assert.equal(r.ok, true);
    assert.match(r.text ?? '', /console\.log/);
  });
});

describe('search_code guard rails', () => {
  it('rejects nested quantifiers with a clear error', () => {
    for (const p of ['(a+)+', '(a*)*', '(\\w+\\s?)+', '(.*)+', '/(a+)+$/i', '(?:x[a-z]+)*', '((a|b)+)+', '(a{1,3})+', '(?<n>a+)+']) {
      const r = compilePattern(p);
      assert.ok('error' in r, p);
      assert.match((r as { error: string }).error, /nested quantifiers/, p);
    }
  });

  it('keeps normal patterns working', () => {
    for (const p of ['\\.merge\\(', 'require\\([\'"]lodash[\'"]\\)', '(foo|bar)+', '(\\.\\d{1,3}){3}', '(a+)?', '[(]+', '\\(a+\\)+', 'a+b*c?', '/template/i', '(?:ab)+']) {
      assert.ok('regex' in compilePattern(p), p);
      assert.equal(hasNestedQuantifier(p.replace(/^\/|\/i$/g, '')), false, p);
    }
  });

  it('applies the line cap before the pattern runs', async () => {
    let passed: RegExp | null = null;
    const handler = makeSearchCodeHandler({
      searchProject: async (_root, pattern) => {
        passed = pattern;
        return { matches: [], total: 0, truncated: false };
      },
    });
    const r = await handler({ pattern: 'merge\\(' }, ctx());
    assert.equal(r.hint, 'No matches for /merge\\(/');
    const re = passed as unknown as RegExp;
    assert.equal(re.test('const m = _.merge({}, a);'), true);
    assert.equal(re.test(`${'x'.repeat(600)}merge(`), false);
    assert.equal(re.test(`${'x'.repeat(480)}merge(`), true);
  });

  it('drops matches in secret files', async () => {
    const matches: SearchMatch[] = [
      { path: '.npmrc', line: 1, text: '_authToken=secret', scope: 'config' },
      { path: 'certs/server.pem', line: 1, text: 'secret', scope: 'source' },
      { path: 'src/index.js', line: 1, text: 'secret()', scope: 'source' },
    ];
    const handler = makeSearchCodeHandler({ searchProject: async () => ({ matches, total: matches.length, truncated: false }) });
    const r = await handler({ pattern: 'secret', fileGlob: '**/*' }, ctx());
    assert.equal(r.text, 'src/index.js:1: secret()');
  });

  it('finishes quickly on a real project with the old redos pattern', async () => {
    await writeFile(path.join(tmp, 'src', 'redos.js'), `const s = "${'a'.repeat(40)}!";\n`);
    const started = Date.now();
    const r = await makeSearchCodeHandler()({ pattern: '(a+)+$' }, ctx());
    assert.equal(r.ok, false);
    assert.ok(Date.now() - started < 1000);
  });
});

describe('isLocalHost', () => {
  it('accepts loopback hosts only', () => {
    for (const h of ['http://localhost:11434', 'http://127.0.0.1:11434', 'http://127.1.2.3', 'http://[::1]:11434', 'http://foo.localhost']) {
      assert.equal(isLocalHost(h), true, h);
    }
    for (const h of ['http://127.attacker.com:11434', 'http://127.0.0.1.nip.io:11434', 'http://evil.localhost.attacker.com', 'http://0.0.0.0:11434', 'https://ollama.com', 'not a url']) {
      assert.equal(isLocalHost(h), false, h);
    }
  });
});

describe('schema helpers ignore inherited keys', () => {
  const schema: JsonSchema = { type: 'object', properties: { package: { type: 'string' } }, required: [], additionalProperties: false };

  it('validateJson treats prototype names as undeclared', () => {
    for (const key of ['toString', 'constructor', 'hasOwnProperty']) {
      assert.deepEqual(validateJson({ [key]: 5 }, schema), [`$: unexpected property "${key}"`], key);
    }
    assert.deepEqual(validateJson(JSON.parse('{"__proto__": 5}'), schema), ['$: unexpected property "__proto__"']);
    assert.deepEqual(validateJson({}, { type: 'object', required: ['toString'] }), ['$: missing required "toString"']);
  });

  it('coerceToSchema never assigns __proto__', () => {
    const r = coerceToSchema(JSON.parse('{"__proto__": {"package": "evil"}, "toString": "x"}'), schema);
    assert.equal(Object.getPrototypeOf(r.value), Object.prototype);
    assert.equal(r.value.package, undefined);
    assert.deepEqual(Object.keys(r.value), ['toString']);
  });

  it('normalizeArgs drops prototype-named args instead of accepting them', () => {
    const registry = createToolRegistry();
    const def = registry.get('read_file');
    assert.ok(def);
    const norm = registry.normalizeArgs(def, JSON.parse('{"path": "src/a.js", "constructor": 1, "toString": 2, "__proto__": {"path": "x"}}'));
    assert.equal(norm.args.path, 'src/a.js');
    assert.equal(Object.hasOwn(norm.args, 'constructor'), false);
    assert.equal(Object.hasOwn(norm.args, 'toString'), false);
    assert.equal(Object.getPrototypeOf(norm.args), Object.prototype);
    assert.deepEqual([...norm.dropped].sort(), ['__proto__', 'constructor', 'toString']);
    assert.deepEqual(norm.errors, []);
  });
});
