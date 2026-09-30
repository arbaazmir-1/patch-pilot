import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { loadConfig } from '../../src/config.ts';
import { MockProvider, parseMockScript, type MockScript } from '../../src/llm/mock.ts';
import { createCodemodProvider, createProvider, LlmError } from '../../src/llm/provider.ts';
import { VERDICT_SCHEMA, DOSSIER_SCHEMA } from '../../src/investigation/prompts.ts';
import type { ChatRequest } from '../../src/types.ts';
import { validateJson } from '../../src/util/schema.ts';

let tmp: string;
before(async () => {
  tmp = await mkdtemp(path.join(os.tmpdir(), 'pp-mock-'));
});
after(async () => {
  await rm(tmp, { recursive: true, force: true });
});

const tools: ChatRequest['tools'] = [
  { type: 'function', function: { name: 'get_usage', description: 'usage', parameters: { type: 'object', properties: { package: { type: 'string' } } } } },
];

const script: MockScript = {
  rules: [
    {
      id: 'minimist-loop',
      match: { purpose: 'verdict-loop', lastUserIncludes: 'GHSA-xvch', hasTools: true },
      replies: [
        { toolCalls: [{ name: 'get_usage', arguments: { package: 'minimist' } }] },
        { content: 'minimist parses process.argv directly.' },
      ],
    },
    {
      id: 'after-tool',
      match: { lastToolName: 'read_file' },
      replies: [{ content: 'read it' }],
    },
    {
      id: 'verdict',
      match: { purpose: 'verdict', hasFormat: true },
      replies: [{ json: { risk: 'High', reachable: 'yes', confidence: 0.8, reasoning: 'CLI input', evidence: ['src/cli.js:9'], recommendationAction: 'upgrade' } }],
      repeat: true,
    },
    { id: 'boom', match: { pattern: 'EXPLODE\\s+NOW' }, replies: [{ error: { message: 'model runner crashed', kind: 'out-of-memory', status: 500 } }] },
  ],
};

describe('MockProvider', () => {
  it('replays rule replies in order and records every request', async () => {
    const p = new MockProvider(script, { model: 'mock' });
    const req: ChatRequest = { purpose: 'verdict-loop', tools, messages: [{ role: 'user', content: 'Investigate GHSA-xvch-5gv4-984h' }] };
    const first = await p.chat(req);
    assert.equal(first.message.role, 'assistant');
    assert.deepEqual(first.message.tool_calls, [{ function: { name: 'get_usage', arguments: { package: 'minimist' }, index: 0 }, source: 'native' }]);
    const second = await p.chat(req);
    assert.equal(second.message.content, 'minimist parses process.argv directly.');
    assert.equal(second.message.tool_calls, undefined);
    assert.equal(p.calls.length, 2);
    assert.equal(p.calls[0]?.purpose, 'verdict-loop');
    assert.equal(first.model, 'mock');
  });

  it('matches tool results, repeats a rule and synthesizes when nothing matches', async () => {
    const p = new MockProvider(script);
    const afterTool = await p.chat({ messages: [{ role: 'user', content: 'x' }, { role: 'tool', tool_name: 'read_file', content: '1: code' }] });
    assert.equal(afterTool.message.content, 'read it');
    for (let i = 0; i < 3; i += 1) {
      const v = await p.chat({ purpose: 'verdict', format: VERDICT_SCHEMA, messages: [{ role: 'user', content: 'verdict please' }] });
      assert.equal(JSON.parse(v.message.content).risk, 'High');
    }
    const dossier = await p.chat({ purpose: 'dossier', format: DOSSIER_SCHEMA, messages: [{ role: 'user', content: 'facts' }] });
    assert.deepEqual(validateJson(JSON.parse(dossier.message.content), DOSSIER_SCHEMA), []);
    const unmatchedVerdict = await new MockProvider().chat({ format: VERDICT_SCHEMA, messages: [{ role: 'user', content: 'x' }] });
    assert.deepEqual(validateJson(JSON.parse(unmatchedVerdict.message.content), VERDICT_SCHEMA), [], 'synthesized verdicts are schema-valid');
    assert.equal((await new MockProvider().chat({ format: 'json', messages: [] })).message.content, '{}');
    const text = await new MockProvider().chat({ tools, messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(text.message.tool_calls, undefined);
  });

  it('throws LlmError for scripted errors and for unmatched requests with fallback "error"', async () => {
    const p = new MockProvider(script);
    await assert.rejects(p.chat({ messages: [{ role: 'user', content: 'please EXPLODE   NOW' }] }), (err: unknown) => {
      assert.ok(err instanceof LlmError);
      assert.equal(err.kind, 'out-of-memory');
      assert.equal(err.status, 500);
      return true;
    });
    const strict = new MockProvider({ rules: [], fallback: 'error' });
    await assert.rejects(strict.chat({ purpose: 'recon', messages: [] }), /no reply for this request \(purpose: recon\)/);
  });

  it('reports unused replies and a positive model check', async () => {
    const p = new MockProvider(script);
    assert.ok(p.pending().some((r) => r.rule === 'minimist-loop' && r.remaining === 2));
    assert.deepEqual(await p.checkModel(), { ok: true, model: 'mock', installed: true, tools: true, resolvedModel: 'mock' });
  });

  it('validates scripts', () => {
    assert.throws(() => parseMockScript([]), /object/);
    assert.throws(() => parseMockScript({}), /rules/);
    assert.throws(() => parseMockScript({ rules: [{ replies: [] }] }), /non-empty/);
    assert.throws(() => parseMockScript({ rules: [{ replies: [{ toolCalls: [{}] }] }] }), /toolCalls/);
    assert.throws(() => parseMockScript({ rules: [{ match: { pattern: '(' }, replies: [{}] }] }), /regex/);
    assert.throws(() => parseMockScript({ rules: [], fallback: 'maybe' }), /fallback/);
  });
});

describe('createProvider', () => {
  it('returns the mock provider (model "mock") and loads the script from --mock-script', async () => {
    const file = path.join(tmp, 'script.json');
    await writeFile(file, JSON.stringify({ rules: [{ match: { purpose: 'recon' }, replies: [{ content: 'from file' }] }] }));
    const config = await loadConfig({ dir: tmp, homeDir: tmp, env: {}, flags: { provider: 'mock', mockScript: file }, stdinIsTTY: false, stdoutIsTTY: false });
    const provider = createProvider(config);
    assert.equal(provider.name, 'mock');
    assert.equal(provider.model, 'mock');
    assert.equal((await provider.chat({ purpose: 'recon', messages: [] })).message.content, 'from file');
    assert.equal(createCodemodProvider({ ...config, codemodModel: 'coder' }).model, 'coder');
  });

  it('returns the Ollama provider configured from the config', async () => {
    const config = await loadConfig({ dir: tmp, homeDir: tmp, env: {}, flags: { numCtx: 8192, seed: 7 }, stdinIsTTY: false, stdoutIsTTY: false });
    const provider = createProvider(config);
    assert.equal(provider.name, 'ollama');
    assert.equal(provider.model, 'qwen3:8b');
    const options = (provider as unknown as { options: Record<string, unknown> }).options;
    assert.equal(options.numCtx, 8192);
    assert.equal(options.seed, 7);
    assert.equal(options.keepAlive, '30m');
    assert.equal(options.temperature, 0);
    assert.equal(options.timeoutMs, 180_000);
  });
});
