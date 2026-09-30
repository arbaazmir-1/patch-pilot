import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, stat, symlink, writeFile } from 'node:fs/promises';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import type { JsonSchema } from '../../src/types.ts';
import {
  atomicWrite,
  detectEol,
  detectIndent,
  hashJson,
  isPathInside,
  PathEscapeError,
  readJsonIfExists,
  resolveInside,
  resolveInsideReal,
  sha256,
  stableStringify,
  updateJsonFile,
} from '../../src/util/fs.ts';
import { fetchWithRetry, getJson, HttpError, NetworkError, postJson, readBodyCapped, tryGetJson } from '../../src/util/http.ts';
import { run, which } from '../../src/util/proc.ts';
import { coerceToSchema, schemaSignature, synthesizeFromSchema, validateJson } from '../../src/util/schema.ts';

let tmp: string;
before(async () => {
  tmp = await mkdtemp(path.join(os.tmpdir(), 'pp-util-'));
});
after(async () => {
  await rm(tmp, { recursive: true, force: true });
});

describe('util/fs', () => {
  it('confines paths to the project root', () => {
    assert.equal(isPathInside('/proj', 'src/a.js'), true);
    assert.equal(isPathInside('/proj', ''), true);
    assert.equal(isPathInside('/proj', './src/../lib/x.js'), true);
    assert.equal(isPathInside('/proj', '../x'), false);
    assert.equal(isPathInside('/proj', 'a/../../x'), false);
    assert.equal(isPathInside('/proj', '/etc/passwd'), false);
    assert.equal(isPathInside('/proj', '/proj/src/a.js'), true);
    assert.equal(isPathInside('/proj', '/project-other/a.js'), false);
    assert.equal(isPathInside('/proj', 'a\0b'), false);
    assert.throws(() => resolveInside('/proj', '../secret'), PathEscapeError);
    assert.equal(resolveInside('/proj', 'src/a.js'), path.resolve('/proj/src/a.js'));
  });

  it('rejects a symlink that points outside the project', async () => {
    const proj = path.join(tmp, 'proj');
    const outside = path.join(tmp, 'outside');
    await mkdir(path.join(proj, 'src'), { recursive: true });
    await mkdir(outside, { recursive: true });
    await writeFile(path.join(outside, 'secret.txt'), 'x');
    await symlink(outside, path.join(proj, 'escape'));
    await writeFile(path.join(proj, 'src', 'ok.js'), 'ok');
    assert.equal(await resolveInsideReal(proj, 'src/ok.js'), path.join(proj, 'src', 'ok.js'));
    assert.equal(await resolveInsideReal(proj, 'src/new-file.js'), path.join(proj, 'src', 'new-file.js'));
    await assert.rejects(resolveInsideReal(proj, 'escape/secret.txt'), PathEscapeError);
  });

  it('hashes, sorts keys and detects formatting', () => {
    assert.equal(sha256('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    assert.equal(stableStringify({ b: 1, a: { d: 2, c: [3, { f: 1, e: 0 }] } }), '{"a":{"c":[3,{"e":0,"f":1}],"d":2},"b":1}');
    assert.equal(hashJson({ a: 1, b: 2 }), hashJson({ b: 2, a: 1 }));
    assert.equal(detectIndent('{\n    "a": 1\n}'), '    ');
    assert.equal(detectIndent('{\n\t"a": 1\n}'), '\t');
    assert.equal(detectIndent('{"a":1}'), '  ');
    assert.equal(detectEol('a\r\nb\r\n'), '\r\n');
    assert.equal(detectEol('a\nb\n'), '\n');
  });

  it('writes atomically and keeps the file mode', async () => {
    const file = path.join(tmp, 'script.sh');
    await writeFile(file, 'old');
    await chmod(file, 0o755);
    await atomicWrite(file, 'new');
    assert.equal(await readFile(file, 'utf8'), 'new');
    assert.equal((await stat(file)).mode & 0o777, 0o755);
    await atomicWrite(path.join(tmp, 'nested', 'dir', 'f.txt'), 'created');
    assert.equal(await readFile(path.join(tmp, 'nested', 'dir', 'f.txt'), 'utf8'), 'created');
  });

  it('updates JSON files preserving indentation, line endings and the final newline', async () => {
    const file = path.join(tmp, 'package.json');
    await writeFile(file, '{\r\n    "name": "app",\r\n    "version": "1.0.0"\r\n}\r\n');
    await updateJsonFile<Record<string, unknown>>(file, (pkg) => ({ ...pkg, overrides: { 'query-string': { 'decode-uri-component': '0.2.1' } } }));
    const text = await readFile(file, 'utf8');
    assert.ok(text.startsWith('{\r\n    "name": "app",'));
    assert.ok(text.includes('"overrides": {\r\n        "query-string"'));
    assert.ok(text.endsWith('}\r\n'));
    assert.equal(await readJsonIfExists(path.join(tmp, 'missing.json')), null);
    await writeFile(path.join(tmp, 'bad.json'), '{');
    await assert.rejects(readJsonIfExists(path.join(tmp, 'bad.json')), /Invalid JSON/);
  });
});

describe('util/proc', () => {
  it('runs commands without a shell and never rejects', async () => {
    const ok = await run(process.execPath, ['-e', 'process.stdout.write("hi"); process.exit(0)']);
    assert.equal(ok.ok, true);
    assert.equal(ok.stdout, 'hi');
    const fail = await run(process.execPath, ['-e', 'process.stderr.write("bad"); process.exit(3)']);
    assert.equal(fail.ok, false);
    assert.equal(fail.code, 3);
    assert.equal(fail.stderr, 'bad');
    const missing = await run('definitely-not-a-command-pp', []);
    assert.equal(missing.ok, false);
    assert.equal(missing.error?.code, 'ENOENT');
    const noShell = await run(process.execPath, ['-e', 'console.log(process.argv[1])', '$(whoami); echo hacked']);
    assert.equal(noShell.stdout.trim(), '$(whoami); echo hacked');
  });

  it('finds executables on PATH', async () => {
    const onPath = await which('node');
    assert.ok(onPath, 'node is on PATH');
    assert.equal(await realpath(onPath), await realpath(process.execPath));
    assert.equal(await which(process.execPath), process.execPath);
    assert.equal(await which('definitely-not-a-command-pp'), null);
  });
});

describe('util/http', () => {
  let server: http.Server;
  let base: string;
  let flakyHits = 0;
  let lastUserAgent = '';

  before(async () => {
    server = http.createServer((req, res) => {
      lastUserAgent = String(req.headers['user-agent'] ?? '');
      if (req.url === '/flaky') {
        flakyHits += 1;
        if (flakyHits === 1) {
          res.writeHead(503).end('busy');
          return;
        }
        res.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}');
        return;
      }
      if (req.url === '/missing') {
        res.writeHead(404).end('{"code":5}');
        return;
      }
      if (req.url === '/echo' && req.method === 'POST') {
        let body = '';
        req.on('data', (c) => (body += c));
        req.on('end', () => res.writeHead(200, { 'content-type': 'application/json' }).end(body));
        return;
      }
      if (req.url === '/big') {
        res.writeHead(200).end('x'.repeat(10_000));
        return;
      }
      if (req.url === '/slow') {
        setTimeout(() => res.writeHead(200).end('late'), 1_000);
        return;
      }
      res.writeHead(500).end();
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  after(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('retries a 503 once and sends the PatchPilot user agent', async () => {
    assert.deepEqual(await getJson(`${base}/flaky`, { retryDelayMs: 5 }), { ok: true });
    assert.equal(flakyHits, 2);
    assert.match(lastUserAgent, /^patch-pilot\//);
  });

  it('maps 404 to HttpError, or null with tryGetJson', async () => {
    await assert.rejects(getJson(`${base}/missing`), (err: unknown) => err instanceof HttpError && err.status === 404);
    assert.equal(await tryGetJson(`${base}/missing`), null);
  });

  it('posts JSON', async () => {
    assert.deepEqual(await postJson(`${base}/echo`, { queries: [1] }), { queries: [1] });
  });

  it('times out per attempt', async () => {
    await assert.rejects(fetchWithRetry(`${base}/slow`, { timeoutMs: 50, retries: 0 }), (err: unknown) => {
      return err instanceof NetworkError && err.kind === 'timeout';
    });
  });

  it('reports refused connections as NetworkError', async () => {
    const closed = http.createServer();
    await new Promise<void>((resolve) => closed.listen(0, '127.0.0.1', resolve));
    const port = (closed.address() as AddressInfo).port;
    await new Promise<void>((resolve) => closed.close(() => resolve()));
    await assert.rejects(getJson(`http://127.0.0.1:${port}/x`, { retries: 0 }), (err: unknown) => err instanceof NetworkError && err.kind === 'refused');
  });

  it('caps response bodies', async () => {
    const res = await fetchWithRetry(`${base}/big`);
    const body = await readBodyCapped(res, 100);
    assert.equal(body.truncated, true);
    assert.equal(body.bytes, 100);
    assert.equal(body.text.length, 100);
  });
});

describe('util/schema', () => {
  const schema: JsonSchema = {
    type: 'object',
    properties: {
      risk: { type: 'string', enum: ['High', 'Low'] },
      confidence: { type: 'number', minimum: 0, maximum: 1 },
      evidence: { type: 'array', items: { type: 'string' }, minItems: 1 },
      steps: { type: 'integer', minimum: 1, maximum: 5 },
    },
    required: ['risk', 'confidence'],
    additionalProperties: false,
  };

  it('validates the supported keywords', () => {
    assert.deepEqual(validateJson({ risk: 'High', confidence: 0.5, evidence: ['a'] }, schema), []);
    const errors = validateJson({ risk: 'Medium', confidence: 2, evidence: [], extra: 1 }, schema);
    assert.ok(errors.some((e) => e.includes('must be one of')));
    assert.ok(errors.some((e) => e.includes('above maximum')));
    assert.ok(errors.some((e) => e.includes('at least 1')));
    assert.ok(errors.some((e) => e.includes('unexpected property "extra"')));
    assert.ok(validateJson({ confidence: 0.5 }, schema).some((e) => e.includes('missing required "risk"')));
    assert.deepEqual(validateJson('x', { type: 'integer' }), ['$: expected integer, got string']);
  });

  it('coerces model arguments', () => {
    const { value, notes } = coerceToSchema({ steps: '9', confidence: '0.3', risk: 'High', evidence: null }, schema);
    assert.deepEqual(value, { steps: 5, confidence: 0.3, risk: 'High' });
    assert.ok(notes.length >= 2);
  });

  it('synthesizes schema-valid placeholders', () => {
    const value = synthesizeFromSchema(schema);
    assert.deepEqual(validateJson(value, { ...schema, required: ['risk', 'confidence'] }), []);
    assert.equal(synthesizeFromSchema({ type: 'string', default: 'x' }), 'x');
    assert.equal(synthesizeFromSchema({ type: 'number', minimum: 0, maximum: 1 }), 0.5);
  });

  it('renders compact signatures', () => {
    assert.equal(schemaSignature('get_usage', { type: 'object', properties: { package: { type: 'string' }, symbol: { type: 'string' } }, required: ['package'] }), 'get_usage(package: string, symbol?: string)');
  });
});
