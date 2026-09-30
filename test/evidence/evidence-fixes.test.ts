import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { excerpt } from '../../src/evidence/casefile.ts';
import { collectDependentUsage, matchesGlob, walkProject } from '../../src/evidence/codebase.ts';
import { openDb } from '../../src/evidence/db.ts';
import { clearRegistryMemo, getPackument } from '../../src/evidence/registry.ts';
import { OllamaProvider, type OllamaProviderOptions } from '../../src/llm/ollama.ts';
import { pullModel } from '../../src/preflight.ts';
import { EnvironmentError } from '../../src/util/errors.ts';
import { tempDir } from './helpers.ts';

const OLLAMA: OllamaProviderOptions = {
  host: 'http://localhost:11434',
  model: 'mistral:7b',
  numCtx: 4096,
  seed: 1,
  temperature: 0,
  timeoutMs: 150,
  keepAlive: '1m',
  debugLog: null,
  retryDelayMs: 5,
};

function refused(): Error {
  const err = new TypeError('fetch failed');
  (err as TypeError & { cause?: unknown }).cause = { code: 'ECONNREFUSED', message: 'connect ECONNREFUSED' };
  return err;
}

// never answers, rejects when the signal fires
function hangingFetch(): { fetch: typeof fetch; calls: () => number } {
  let calls = 0;
  const impl = ((_url: string, init: RequestInit) =>
    new Promise<Response>((_resolve, reject) => {
      calls += 1;
      const signal = init.signal as AbortSignal;
      if (signal.aborted) return reject(signal.reason);
      signal.addEventListener('abort', () => reject(signal.reason), { once: true });
    })) as unknown as typeof fetch;
  return { fetch: impl, calls: () => calls };
}

describe('ollama request retries', () => {
  it('does not retry a turn that timed out', async () => {
    const hang = hangingFetch();
    const provider = new OllamaProvider({ ...OLLAMA, fetch: hang.fetch });
    const started = Date.now();
    await assert.rejects(provider.chat({ messages: [{ role: 'user', content: 'hi' }] }), (err: { kind?: string }) => err.kind === 'timeout');
    assert.equal(hang.calls(), 1);
    assert.ok(Date.now() - started < 290, 'waited for a second attempt');
  });

  it('does not retry after the caller aborts', async () => {
    const hang = hangingFetch();
    const controller = new AbortController();
    const provider = new OllamaProvider({ ...OLLAMA, timeoutMs: 5_000, fetch: hang.fetch });
    setTimeout(() => controller.abort(), 20);
    await assert.rejects(provider.chat({ messages: [{ role: 'user', content: 'hi' }], signal: controller.signal }), (err: { kind?: string }) => err.kind === 'aborted');
    assert.equal(hang.calls(), 1);
  });

  it('still retries a refused connection once', async () => {
    let calls = 0;
    const impl = (async () => {
      calls += 1;
      if (calls === 1) throw refused();
      return new Response(JSON.stringify({ message: { role: 'assistant', content: 'ok' }, done: true }), { status: 200 });
    }) as unknown as typeof fetch;
    const reply = await new OllamaProvider({ ...OLLAMA, fetch: impl }).chat({ messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(calls, 2);
    assert.equal(reply.message.content, 'ok');
  });
});

describe('advisory excerpt markdown', () => {
  it('keeps underscores inside words and code spans', () => {
    assert.equal(excerpt('The `__proto__` key in `merge_with_options` is trusted.'), 'The `__proto__` key in `merge_with_options` is trusted.');
    assert.equal(excerpt('Calls snake_case_name with 2*3*4.'), 'Calls snake_case_name with 2*3*4.');
  });

  it('still strips real emphasis', () => {
    assert.equal(excerpt('A **bold** claim, *soft* words, _em_ and __strong__.'), 'A bold claim, soft words, em and strong.');
    assert.equal(excerpt('***Both*** at once'), 'Both at once');
  });
});

describe('codebase globs and pnpm dependents', () => {
  let tmp: { dir: string; cleanup: () => Promise<void> };
  beforeEach(async () => {
    tmp = await tempDir('pp-fixes-');
  });
  afterEach(async () => {
    await tmp.cleanup();
  });

  it('treats a trailing slash exclude as the directory', async () => {
    assert.ok(matchesGlob('vendor', 'vendor/'));
    assert.ok(matchesGlob('src/util', 'src/util/'));
    for (const rel of ['vendor/lib.js', 'src/util/fs.js', 'src/app.js']) {
      await mkdir(path.join(tmp.dir, path.dirname(rel)), { recursive: true });
      await writeFile(path.join(tmp.dir, rel), 'export const x = 1;\n');
    }
    const walked = await walkProject(tmp.dir, { exclude: ['vendor/', 'src/util/'], respectGitignore: false });
    assert.deepEqual(walked.files.map((f) => f.path).sort(), ['src/app.js']);
  });

  it('finds a pnpm store folder with a peer suffix', async () => {
    const store = 'node_modules/.pnpm/@scope+dep@1.2.3_react@18.2.0/node_modules/@scope/dep';
    await mkdir(path.join(tmp.dir, store), { recursive: true });
    await writeFile(path.join(tmp.dir, store, 'package.json'), JSON.stringify({ name: '@scope/dep', version: '1.2.3', main: 'index.js' }));
    await writeFile(path.join(tmp.dir, store, 'index.js'), "const target = require('vuln-lib');\nmodule.exports = (s) => target.parse(s);\n");
    const found = await collectDependentUsage(tmp.dir, ['vuln-lib'], [{ name: '@scope/dep', version: '1.2.3' }]);
    assert.ok(found && found.length > 0, 'dependent usage not found');
    assert.ok(found.every((u) => u.path.startsWith('node_modules/.pnpm/@scope+dep@1.2.3_react@18.2.0/')));
  });
});

function streamOf(parts: (string | Error)[], onCancel?: () => void): typeof fetch {
  return (async () => {
    let i = 0;
    const enc = new TextEncoder();
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        const part = parts[i++];
        if (part === undefined) return controller.close();
        if (part instanceof Error) return controller.error(part);
        controller.enqueue(enc.encode(part));
      },
      cancel() {
        onCancel?.();
      },
    });
    return new Response(body, { status: 200 });
  }) as unknown as typeof fetch;
}

describe('pullModel stream handling', () => {
  it('cancels the stream when a line reports an error', async () => {
    let cancelled = false;
    const doFetch = streamOf(['{"status":"pulling manifest"}\n{"error":"file does not exist"}\n', '{"status":"never"}\n'], () => (cancelled = true));
    await assert.rejects(pullModel('http://localhost:11434', 'nope:1b', () => {}, { fetch: doFetch }), (err: Error) => err instanceof EnvironmentError && /file does not exist/.test(err.message));
    await new Promise((resolve) => setImmediate(resolve));
    assert.ok(cancelled, 'reader was not cancelled');
  });

  it('skips null and non-object lines', async () => {
    const seen: unknown[] = [];
    await pullModel('http://localhost:11434', 'm:1b', (p) => seen.push(p), { fetch: streamOf(['null\n42\n"x"\n[]\n{"status":"success"}\n']) });
    assert.deepEqual(seen, [{ status: 'success' }]);
  });

  it('turns a mid-stream failure into an environment error', async () => {
    const cut = new TypeError('terminated');
    await assert.rejects(pullModel('http://localhost:11434', 'm:1b', () => {}, { fetch: streamOf(['{"status":"pulling manifest"}\n', cut]) }), (err: Error & { hint?: string }) => {
      assert.ok(err instanceof EnvironmentError);
      assert.match(err.message, /cut off/);
      assert.match(err.hint ?? '', /ollama pull m:1b/);
      return true;
    });
  });
});

describe('registry cache and caller aborts', () => {
  const original = globalThis.fetch;
  let tmp: { dir: string; cleanup: () => Promise<void> };
  beforeEach(async () => {
    clearRegistryMemo();
    tmp = await tempDir('pp-fixes-reg-');
  });
  afterEach(async () => {
    globalThis.fetch = original;
    clearRegistryMemo();
    await tmp.cleanup();
  });

  it('rethrows a caller abort instead of serving the stale row', async () => {
    const db = openDb(path.join(tmp.dir, 'r.db'));
    try {
      db.putRegistry('packument:lodash', { name: 'lodash', versions: {}, 'dist-tags': {} });
      globalThis.fetch = hangingFetch().fetch;
      const controller = new AbortController();
      setTimeout(() => controller.abort(), 20);
      await assert.rejects(getPackument('lodash', { db, offline: false, timeoutMs: 5_000, refresh: true, signal: controller.signal }));
    } finally {
      db.close();
    }
  });

  it('still falls back to the stale row on a network failure', async () => {
    const db = openDb(path.join(tmp.dir, 'r.db'));
    try {
      db.putRegistry('packument:lodash', { name: 'lodash', versions: {}, 'dist-tags': {} });
      globalThis.fetch = (async () => {
        throw refused();
      }) as unknown as typeof fetch;
      const value = await getPackument('lodash', { db, offline: false, timeoutMs: 5_000, refresh: true });
      assert.equal(value?.name, 'lodash');
    } finally {
      db.close();
    }
  });
});
