import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Writable } from 'node:stream';
import { after, before, describe, it } from 'node:test';
import { loadConfig } from '../../src/config.ts';
import {
  applyPreflightModels,
  ensurePreflight,
  LINKS,
  NEEDS,
  pullCommandFor,
  pullModel,
  renderPreflight,
  renderPullProgress,
  resolveModelName,
  runPreflight,
  type PreflightDeps,
  type PullProgress,
} from '../../src/preflight.ts';
import type { Config, InstalledModel, PreflightResult } from '../../src/types.ts';
import { Ui } from '../../src/ui.ts';
import { EnvironmentError, EXIT } from '../../src/util/errors.ts';

let root: string;
const ui = new Ui({ color: false, unicode: true });

before(async () => {
  root = await mkdtemp(path.join(os.tmpdir(), 'pp-preflight-'));
});
after(async () => {
  await rm(root, { recursive: true, force: true });
});

async function config(flags: Record<string, unknown> = {}, env: NodeJS.ProcessEnv = {}): Promise<Config> {
  return loadConfig({ dir: root, homeDir: root, env, flags, stdinIsTTY: false, stdoutIsTTY: false });
}

interface FakeModel {
  name: string;
  caps?: string[];
  size?: string;
}

interface FakeOllama {
  down?: boolean;
  version?: string;
  models?: FakeModel[];
}

const refused = (): Error => Object.assign(new TypeError('fetch failed'), { cause: Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }) });

function deps(ollama: FakeOllama, overrides: Partial<PreflightDeps> = {}): Partial<PreflightDeps> {
  const calls: string[] = [];
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    calls.push(url);
    if (url.startsWith('https://')) return new Response('{}', { status: 200 });
    if (ollama.down) throw refused();
    if (url.endsWith('/api/version')) return Response.json({ version: ollama.version ?? '0.34.4' });
    if (url.endsWith('/api/tags')) {
      return Response.json({
        models: (ollama.models ?? []).map((m) => ({ name: m.name, model: m.name, digest: `sha256:${m.name}`, details: { parameter_size: m.size ?? '7.2B' } })),
      });
    }
    if (url.endsWith('/api/show')) {
      const body = JSON.parse(String(init?.body ?? '{}')) as { model: string };
      const model = (ollama.models ?? []).find((m) => m.name === body.model);
      return model ? Response.json({ capabilities: model.caps ?? ['completion'] }) : new Response('not found', { status: 404 });
    }
    return new Response('?', { status: 404 });
  }) as typeof fetch;
  return {
    nodeVersion: '24.14.1',
    which: async (cmd) => `/usr/local/bin/${cmd}`,
    commandVersion: async (cmd) => (cmd === 'git' ? 'git version 2.54.0' : '11.19.1'),
    fetch: fetchImpl,
    freeBytes: async () => 100 * 1024 ** 3,
    fileInfo: async () => null,
    now: () => 1_000,
    ...overrides,
  };
}

const MISTRAL: FakeModel = { name: 'mistral:7b', caps: ['completion', 'tools'] };

function failureText(result: PreflightResult): string {
  return renderPreflight(result, ui, { mode: 'failure' });
}

function check(result: PreflightResult, id: string) {
  const found = result.checks.find((c) => c.id === id);
  assert.ok(found, `check ${id} missing`);
  return found;
}

describe('runPreflight scenarios', () => {
  it('passes on a healthy machine and renders the doctor view', async () => {
    const result = await runPreflight(await config({ model: 'mistral:7b' }), NEEDS.doctor, deps({ models: [MISTRAL] }));
    assert.equal(result.ok, true);
    assert.equal(check(result, 'model').status, 'ok');
    assert.equal(check(result, 'tools').status, 'ok');
    assert.equal(result.ollama?.resolvedModel, 'mistral:7b');
    const text = renderPreflight(result, ui, { mode: 'doctor' });
    assert.match(text, /^PatchPilot v\d+\.\d+\.\d+ · Environment check/);
    assert.match(text, /Ollama server\s+0\.34\.4 at http:\/\/localhost:11434/);
    assert.match(text, /All required checks passed/);
    assert.match(text, new RegExp(LINKS.ollamaKeys.replace(/[.?]/g, '\\$&')), 'key notice links the settings page');
  });

  it('Ollama not installed: install link, brew, ollama serve; exit block', async () => {
    const result = await runPreflight(await config(), NEEDS.scan, deps({ down: true }, { which: async (cmd) => (cmd === 'ollama' ? null : `/usr/bin/${cmd}`) }));
    assert.equal(result.ok, false);
    assert.equal(check(result, 'ollama-binary').status, 'fail');
    const text = failureText(result);
    assert.match(text, /PatchPilot cannot start: Ollama is not installed\./);
    assert.match(text, /Install Ollama: https:\/\/ollama\.com\/download/);
    assert.match(text, /brew install ollama/);
    assert.match(text, /ollama serve/);
    assert.match(text, /patch-pilot doctor/);
  });

  it('renders the failure block in plain ASCII without colours or a TTY', async () => {
    const result = await runPreflight(await config(), NEEDS.scan, deps({ down: true }));
    const text = renderPreflight(result, new Ui({ color: false }), { mode: 'failure' });
    assert.ok([...text].every((ch) => ch.charCodeAt(0) < 128), text);
    assert.match(text, /^PatchPilot cannot start: Ollama is not running\.\n\nx Ollama server  not reachable/);
    assert.match(text, /\n {4}Start it with: ollama serve/);
  });

  it('Ollama installed but not running: ollama serve plus the probed host', async () => {
    const result = await runPreflight(await config(), NEEDS.scan, deps({ down: true }));
    assert.equal(result.ok, false);
    const server = check(result, 'ollama-server');
    assert.equal(server.status, 'fail');
    assert.match(server.detail, /connection refused/);
    const text = failureText(result);
    assert.match(text, /Ollama is not running/);
    assert.match(text, /Start it with: ollama serve/);
    assert.match(text, /Probed: http:\/\/localhost:11434\/api\/version/);
    assert.match(text, /--ollama-host/);
  });

  it('model missing: ollama pull mistral, the library link and doctor --fix', async () => {
    const result = await runPreflight(await config({ model: 'mistral:7b' }), NEEDS.scan, deps({ models: [{ name: 'llama3:8b', caps: ['completion'] }] }));
    assert.equal(result.ok, false);
    const text = failureText(result);
    assert.match(text, /the model is not installed/);
    assert.match(text, /Pull the model: ollama pull mistral/);
    assert.match(text, /https:\/\/ollama\.com\/library\/mistral/);
    assert.match(text, /patch-pilot doctor --fix/);
    assert.match(text, /Installed models: llama3:8b \(no tools\)/);
  });

  it('default model missing but another tool-capable model installed: falls back with a warning', async () => {
    const cfg = await config();
    const result = await runPreflight(cfg, NEEDS.scan, deps({ models: [{ name: 'mistral:7b', caps: ['completion', 'tools'], size: '7.2B' }] }));
    assert.equal(result.ok, true);
    assert.equal(result.ollama?.fallback, true);
    assert.equal(check(result, 'model').status, 'warn');
    applyPreflightModels(cfg, result);
    assert.equal(cfg.model, 'mistral:7b');
  });

  it('an explicitly chosen model that is missing is a hard failure (no fallback)', async () => {
    const result = await runPreflight(await config({ model: 'mistral-nemo' }), NEEDS.scan, deps({ models: [{ name: 'qwen3:8b', caps: ['tools'] }] }));
    assert.equal(result.ok, false);
    assert.match(failureText(result), /ollama pull mistral-nemo/);
  });

  it('model without tool support: lists tool-capable models, --model and the search link', async () => {
    const result = await runPreflight(
      await config({ model: 'gemma2:2b' }),
      NEEDS.scan,
      deps({ models: [{ name: 'gemma2:2b', caps: ['completion'] }, { name: 'qwen3:8b', caps: ['completion', 'tools'] }] }),
    );
    assert.equal(result.ok, false);
    const text = failureText(result);
    assert.match(text, /cannot call tools/);
    assert.match(text, /Tool-capable models installed: qwen3:8b/);
    assert.match(text, /--model qwen3:8b/);
    assert.match(text, /https:\/\/ollama\.com\/search\?c=tools/);
  });

  it('mistral:7b is satisfied by mistral:latest (ollama pull mistral)', async () => {
    const cfg = await config({ model: 'mistral:7b' });
    const result = await runPreflight(cfg, NEEDS.scan, deps({ models: [{ name: 'mistral:latest', caps: ['completion', 'tools'], size: '7.2B' }] }));
    assert.equal(result.ok, true);
    assert.equal(result.ollama?.resolvedModel, 'mistral:latest');
    assert.match(check(result, 'model').detail, /satisfies mistral:7b/);
    applyPreflightModels(cfg, result);
    assert.equal(cfg.model, 'mistral:latest');
  });

  it('Node older than 22.12 fails with the download link', async () => {
    const result = await runPreflight(await config(), NEEDS.basic, deps({}, { nodeVersion: '20.11.0' }));
    assert.equal(result.ok, false);
    const text = failureText(result);
    assert.match(text, /Node\.js is too old/);
    assert.match(text, /https:\/\/nodejs\.org\/en\/download/);
  });

  it('Ollama older than 0.5 fails with an update link', async () => {
    const result = await runPreflight(await config(), NEEDS.scan, deps({ version: '0.4.7', models: [MISTRAL] }));
    assert.equal(result.ok, false);
    assert.match(failureText(result), /Ollama needs an update/);
  });

  it('the mock provider skips every Ollama check', async () => {
    let fetched = 0;
    const result = await runPreflight(
      await config({ provider: 'mock' }),
      NEEDS.scan,
      deps({ down: true }, { fetch: (async () => { fetched += 1; throw refused(); }) as typeof fetch }),
    );
    assert.equal(result.ok, true);
    assert.equal(result.ollama, null);
    assert.equal(fetched, 0);
    assert.equal(check(result, 'ollama-server').status, 'skip');
  });

  it('npm missing is a hard failure only for commands that patch', async () => {
    const noNpm = deps({ models: [MISTRAL] }, { which: async (cmd) => (cmd === 'npm' ? null : `/usr/bin/${cmd}`) });
    assert.equal((await runPreflight(await config(), NEEDS.scan, noNpm)).ok, false);
    assert.equal((await runPreflight(await config(), NEEDS.investigate, noNpm)).ok, true);
  });

  it('reports the optional search key and git as notices, not failures', async () => {
    const withKey = await runPreflight(await config({}, { OLLAMA_API_KEY: 'k' }), NEEDS.scan, deps({ models: [MISTRAL] }));
    assert.equal(check(withKey, 'search-key').status, 'ok');
    const noGit = await runPreflight(await config(), NEEDS.scan, deps({ models: [MISTRAL] }, { which: async (cmd) => (cmd === 'git' ? null : `/usr/bin/${cmd}`) }));
    assert.equal(noGit.ok, true);
    assert.equal(check(noGit, 'search-key').status, 'info');
    assert.equal(check(noGit, 'git').status, 'warn');
  });

  it('low disk space is a hard failure', async () => {
    const result = await runPreflight(await config(), NEEDS.scan, deps({ models: [MISTRAL] }, { freeBytes: async () => 10 * 1024 * 1024 }));
    assert.equal(result.ok, false);
    assert.match(failureText(result), /not enough disk space/);
  });

  it('never uses an em dash in any rendered text', async () => {
    const scenarios = [
      await runPreflight(await config(), NEEDS.doctor, deps({ down: true })),
      await runPreflight(await config({ model: 'gemma2:2b' }), NEEDS.doctor, deps({ models: [{ name: 'gemma2:2b' }] })),
    ];
    for (const r of scenarios) {
      assert.ok(!renderPreflight(r, ui, { mode: 'doctor' }).includes('\u2014'));
      assert.ok(!failureText(r).includes('\u2014'));
    }
  });
});

describe('renderPreflight with a hand-built result', () => {
  it('shows only hard failures in failure mode', () => {
    const result: PreflightResult = {
      ok: false,
      checks: [
        { id: 'node', label: 'Node.js', status: 'ok', detail: 'v24.14.1', hard: true, fix: [], links: [] },
        { id: 'git', label: 'git', status: 'warn', detail: 'not found', hard: false, fix: ['Install git'], links: [] },
        { id: 'tools', label: 'Tool calling', status: 'fail', detail: 'gemma2 does not support tool calling', hard: true, fix: ['Pick one with: --model qwen3:8b'], links: [LINKS.toolModels] },
      ],
      ollama: null,
      node: { version: '24.14.1' },
      npm: { path: null, version: null },
      git: { path: null, version: null },
      durationMs: 5,
    };
    const text = renderPreflight(result, ui, { mode: 'failure' });
    assert.match(text, /the model cannot call tools/);
    assert.match(text, /--model qwen3:8b/);
    assert.match(text, /search\?c=tools/);
    assert.ok(!text.includes('Node.js'), 'passing checks are not repeated');
    assert.ok(!text.includes('Install git'), 'soft warnings are not part of the failure block');
    const doctor = renderPreflight(result, ui, { mode: 'doctor' });
    assert.match(doctor, /1 required check failed/);
    assert.match(doctor, /✓ Node\.js/);
    assert.match(doctor, /! git {13}not found\n {18}Install git/);
    assert.match(doctor, /✗ Tool calling {4}gemma2/);
  });
});

describe('ensurePreflight', () => {
  it('prints the block on stderr and throws EnvironmentError (exit 3, already printed)', async () => {
    let stderr = '';
    const sink = new Writable({ write(chunk, _enc, cb) { stderr += String(chunk); cb(); } });
    const quietUi = new Ui({ color: false, stderr: sink as never, stdout: new Writable({ write(_c, _e, cb) { cb(); } }) as never });
    await assert.rejects(ensurePreflight(await config(), quietUi, NEEDS.scan, deps({ down: true })), (err: unknown) => {
      assert.ok(err instanceof EnvironmentError);
      assert.equal(err.exitCode, EXIT.ENVIRONMENT);
      assert.equal(err.printed, true);
      return true;
    });
    assert.match(stderr, /ollama serve/);
  });
});

describe('model names', () => {
  const m = (name: string, parameterSize: string | null = '7.2B'): InstalledModel => ({ name, digest: null, sizeBytes: null, parameterSize, capabilities: null });

  it('resolves exact names, untagged names and :latest aliases', () => {
    assert.equal(resolveModelName('mistral:7b', [m('mistral:7b')]), 'mistral:7b');
    assert.equal(resolveModelName('mistral', [m('mistral:7b')]), 'mistral:7b');
    assert.equal(resolveModelName('mistral', [m('mistral:7b'), m('mistral:latest')]), 'mistral:latest');
    assert.equal(resolveModelName('mistral:7b', [m('mistral:latest', '7.2B')]), 'mistral:latest');
    assert.equal(resolveModelName('llama3.1:70b', [m('llama3.1:latest', '8.0B')]), null, 'size must match');
    assert.equal(resolveModelName('qwen3:8b', [m('mistral:7b')]), null);
  });

  it('suggests "ollama pull mistral" for the default model', () => {
    assert.equal(pullCommandFor('mistral:7b'), 'ollama pull mistral');
    assert.equal(pullCommandFor('mistral'), 'ollama pull mistral');
    assert.equal(pullCommandFor('qwen3:8b'), 'ollama pull qwen3:8b');
  });
});

describe('doctor --fix: pullModel', () => {
  function streamingFetch(lines: string[]): typeof fetch {
    return (async () => {
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          const enc = new TextEncoder();
          // split mid-line to test buffering
          const text = lines.join('\n') + '\n';
          controller.enqueue(enc.encode(text.slice(0, 17)));
          controller.enqueue(enc.encode(text.slice(17)));
          controller.close();
        },
      });
      return new Response(body, { status: 200 });
    }) as typeof fetch;
  }

  it('streams NDJSON progress until success', async () => {
    const seen: PullProgress[] = [];
    await pullModel(
      'http://localhost:11434',
      'mistral:7b',
      (p) => seen.push(p),
      {
        fetch: streamingFetch([
          '{"status":"pulling manifest"}',
          '{"status":"pulling 6577803aa9a0","digest":"sha256:6577803aa9a0abc","total":1000,"completed":500}',
          '{"status":"verifying sha256 digest"}',
          '{"status":"success"}',
        ]),
      },
    );
    assert.deepEqual(seen.map((p) => p.status), ['pulling manifest', 'pulling 6577803aa9a0', 'verifying sha256 digest', 'success']);
    assert.match(renderPullProgress(seen[1]!), /pulling 6577803aa9a0\s+50% \[#{10}-{10}\]/);
  });

  it('throws on an error line', async () => {
    await assert.rejects(
      pullModel('http://localhost:11434', 'nope:1b', () => {}, { fetch: streamingFetch(['{"error":"pull model manifest: file does not exist"}']) }),
      /file does not exist/,
    );
  });
});
