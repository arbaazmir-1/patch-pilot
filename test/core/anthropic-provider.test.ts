import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { MemoryAudit } from '../../src/audit.ts';
import { runPhase2 } from '../../src/investigation/agent.ts';
import { DOSSIER_SCHEMA, VERDICT_SCHEMA } from '../../src/investigation/prompts.ts';
import {
  adaptationFor,
  AnthropicProvider,
  claudeModelTraits,
  estimateClaudeCostUsd,
  historyKey,
  mapMessages,
  resolveClaudeModel,
  retryAfterMs,
  type AnthropicChatUsage,
} from '../../src/llm/anthropic.ts';
import { createCodemodProvider, createProvider, formatUsageSummary, LlmError, resolveProviderModel } from '../../src/llm/provider.ts';
import type { ChatMessage, ChatRequest, Config, ToolSchema } from '../../src/types.ts';
import { EnvironmentError } from '../../src/util/errors.ts';
import { captureUi, caseFileOf, fakeRegistry, minimistFixture, tempDir, testConfig, usageResult } from '../investigation/helpers.ts';

let dir: string;
let cleanup: () => Promise<void>;

before(async () => {
  ({ dir, cleanup } = await tempDir('pp-anthropic-'));
});
after(async () => {
  await cleanup();
});

type Body = Record<string, unknown> & { messages: { role: string; content: Record<string, unknown>[] }[] };

interface FakeCall {
  url: string;
  headers: Record<string, string>;
  body: Body;
}

// records requests, scripted replies
function fakeFetch(replies: ((body: Body, n: number) => { status?: number; json: unknown; headers?: Record<string, string> })[]): { fetch: typeof fetch; calls: FakeCall[] } {
  const calls: FakeCall[] = [];
  const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as Body;
    calls.push({ url: String(url), headers: init?.headers as Record<string, string>, body });
    const reply = replies[Math.min(calls.length - 1, replies.length - 1)] as (typeof replies)[number];
    const r = reply(body, calls.length);
    return new Response(JSON.stringify(r.json), { status: r.status ?? 200, headers: { 'content-type': 'application/json', ...(r.headers ?? {}) } });
  }) as typeof fetch;
  return { fetch: fetchImpl, calls };
}

function message(content: Record<string, unknown>[], extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'msg_1',
    type: 'message',
    role: 'assistant',
    model: 'claude-sonnet-5',
    stop_reason: content.some((c) => c.type === 'tool_use') ? 'tool_use' : 'end_turn',
    content,
    usage: { input_tokens: 1000, output_tokens: 500 },
    ...extra,
  };
}

function provider(fetchImpl: typeof fetch, model = 'sonnet', extra: Partial<ConstructorParameters<typeof AnthropicProvider>[0]> = {}): AnthropicProvider {
  return new AnthropicProvider({ apiKey: 'sk-ant-test-secret-key', model, timeoutMs: 5_000, fetch: fetchImpl, retryDelayMs: 1, ...extra });
}

const TOOLS: ToolSchema[] = [
  { type: 'function', function: { name: 'get_usage', description: 'How the project uses a package', parameters: { type: 'object', properties: { package: { type: 'string' } }, required: ['package'] } } },
];

describe('Anthropic request mapping', () => {
  it('maps system, user, assistant tool calls and tool results with matching tool_use ids', () => {
    const history: ChatMessage[] = [
      { role: 'system', content: 'You are PatchPilot.' },
      { role: 'user', content: 'Investigate minimist.' },
      { role: 'assistant', content: '', tool_calls: [{ function: { name: 'get_usage', arguments: { package: 'minimist' } } }, { function: { name: 'read_file', arguments: { path: 'src/cli.js' } } }] },
      { role: 'tool', tool_name: 'get_usage', content: '1 call to minimist' },
      { role: 'tool', tool_name: 'read_file', content: '7: const parseArgs = require("minimist")' },
      { role: 'user', content: '2 of 3 tool calls left.' },
    ];
    const { system, messages } = mapMessages(history);
    assert.equal(system, 'You are PatchPilot.');
    assert.deepEqual(
      messages.map((m) => m.role),
      ['user', 'assistant', 'user'],
    );
    const uses = messages[1]?.content ?? [];
    assert.equal(uses.length, 2);
    assert.equal(uses[0]?.type, 'tool_use');
    assert.equal(uses[0]?.name, 'get_usage');
    assert.deepEqual(uses[0]?.input, { package: 'minimist' });
    const results = messages[2]?.content ?? [];
    assert.equal(results[0]?.type, 'tool_result');
    assert.equal(results[0]?.tool_use_id, uses[0]?.id);
    assert.equal(results[1]?.tool_use_id, uses[1]?.id);
    assert.equal(results[1]?.content, '7: const parseArgs = require("minimist")');
    assert.deepEqual(results[2], { type: 'text', text: '2 of 3 tool calls left.' }, 'the budget note follows the results in the same user turn');
    assert.notEqual(uses[0]?.id, uses[1]?.id);
  });

  it('closes unanswered tool calls, never sends empty text and always starts and ends with a user turn', () => {
    const { messages } = mapMessages([
      { role: 'assistant', content: '', tool_calls: [{ function: { name: 'get_usage', arguments: {} } }] },
      { role: 'assistant', content: '' },
      { role: 'user', content: '' },
    ]);
    assert.equal(messages[0]?.role, 'user');
    assert.equal(messages[messages.length - 1]?.role, 'user');
    const synthetic = messages.flatMap((m) => m.content).find((b) => b.type === 'tool_result');
    assert.match(String(synthetic?.content), /no result/);
    assert.ok(messages.flatMap((m) => m.content).every((b) => b.type !== 'text' || String(b.text).trim() !== ''));
  });

  it('flattens tool history into text on request', () => {
    const { messages } = mapMessages(
      [
        { role: 'user', content: 'go' },
        { role: 'assistant', content: 'Checking.', tool_calls: [{ function: { name: 'get_usage', arguments: { package: 'lodash' } } }] },
        { role: 'tool', tool_name: 'get_usage', content: '3 calls' },
      ],
      { flattenTools: true },
    );
    const blocks = messages.flatMap((m) => m.content);
    assert.ok(blocks.every((b) => b.type === 'text'));
    assert.ok(blocks.some((b) => String(b.text).includes('[called get_usage {"package":"lodash"}]')));
    assert.ok(blocks.some((b) => String(b.text).startsWith('Result of get_usage:')));
  });

  it('knows each model family: sampling, thinking and forced tool use', () => {
    assert.equal(resolveClaudeModel('sonnet'), 'claude-sonnet-5');
    assert.equal(resolveClaudeModel('opus'), 'claude-opus-5-5');
    assert.equal(resolveClaudeModel('haiku'), 'claude-haiku-4-5');
    assert.equal(resolveClaudeModel('claude-opus-4-8'), 'claude-opus-4-8');
    const sonnet = claudeModelTraits('claude-sonnet-5');
    assert.equal(sonnet.sampling, false);
    assert.equal(sonnet.canDisableThinking, true);
    assert.equal(sonnet.forcedToolChoice, true);
    const opus = claudeModelTraits('claude-opus-5-5');
    assert.equal(opus.forcedToolChoice, false);
    assert.equal(opus.canDisableThinking, false);
    const haiku = claudeModelTraits('claude-haiku-4-5');
    assert.equal(haiku.sampling, true);
    assert.equal(claudeModelTraits('claude-future-9').sampling, false, 'unknown ids get the newest request surface');
  });

  it('estimates cost from usage and formats it for the footer', () => {
    assert.equal(estimateClaudeCostUsd('claude-sonnet-5', { input_tokens: 1_000_000, output_tokens: 100_000 }), 3);
    assert.equal(estimateClaudeCostUsd('claude-opus-5-5', { input_tokens: 1_000_000, output_tokens: 0 }), 4);
    assert.equal(estimateClaudeCostUsd('claude-haiku-4-5', { input_tokens: 0, output_tokens: 1_000_000 }), 5);
    assert.equal(estimateClaudeCostUsd('claude-unknown-1', { input_tokens: 10, output_tokens: 10 }), null);
    assert.equal(formatUsageSummary({ requests: 2, inputTokens: 12_300, outputTokens: 2_100, costUsd: 0.0456 }), 'est. $0.05 · 12.3k in / 2.1k out tokens');
    assert.equal(retryAfterMs('2'), 2000);
    assert.equal(retryAfterMs(null), null);
  });
});

describe('AnthropicProvider.chat', () => {
  it('sends the key only as x-api-key with the API version, and no temperature or thinking for claude-sonnet-5', async () => {
    const { fetch, calls } = fakeFetch([() => ({ json: message([{ type: 'text', text: 'minimist parses process.argv.' }]) })]);
    const p = provider(fetch);
    assert.equal(p.name, 'claude');
    assert.equal(p.model, 'claude-sonnet-5');
    const res = await p.chat({ messages: [{ role: 'system', content: 'sys' }, { role: 'user', content: 'hi' }], tools: TOOLS, options: { num_predict: 1536 }, purpose: 'verdict-loop' });
    assert.equal(res.message.content, 'minimist parses process.argv.');
    const call = calls[0] as FakeCall;
    assert.equal(call.url, 'https://api.anthropic.com/v1/messages');
    assert.equal(call.headers['x-api-key'], 'sk-ant-test-secret-key');
    assert.equal(call.headers['anthropic-version'], '2023-06-01');
    assert.equal(call.body.model, 'claude-sonnet-5');
    assert.equal(call.body.system, 'sys');
    assert.equal(call.body.max_tokens, 1536);
    assert.equal('temperature' in call.body, false, 'Claude Sonnet 5 rejects sampling parameters');
    assert.deepEqual(call.body.thinking, { type: 'disabled' }, '--think off disables adaptive thinking');
    assert.deepEqual((call.body.tools as Record<string, unknown>[])[0], { name: 'get_usage', description: 'How the project uses a package', input_schema: TOOLS[0]?.function.parameters });
  });

  it('sends temperature 0 to claude-haiku-4-5, and effort instead of disabled thinking to claude-opus-5-5', async () => {
    const haiku = fakeFetch([() => ({ json: message([{ type: 'text', text: 'ok' }]) })]);
    await provider(haiku.fetch, 'haiku').chat({ messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(haiku.calls[0]?.body.temperature, 0);
    assert.equal('thinking' in (haiku.calls[0]?.body ?? {}), false);
    const opus = fakeFetch([() => ({ json: message([{ type: 'thinking', thinking: '', signature: 'sig' }, { type: 'text', text: 'ok' }]) })]);
    const res = await provider(opus.fetch, 'opus').chat({ messages: [{ role: 'user', content: 'hi' }], options: { num_predict: 1024 } });
    assert.equal(res.message.content, 'ok');
    const body = opus.calls[0]?.body ?? ({} as Body);
    assert.equal('thinking' in body, false, 'thinking cannot be disabled on Claude Opus 5.5');
    assert.deepEqual(body.output_config, { effort: 'low' });
    assert.equal('temperature' in body, false);
    assert.ok((body.max_tokens as number) > 1024, 'thinking gets max_tokens headroom');
  });

  it('turns tool_use blocks into native tool calls and records usage with an estimated cost', async () => {
    const { fetch } = fakeFetch([() => ({ json: message([{ type: 'text', text: 'Let me check.' }, { type: 'tool_use', id: 'toolu_01', name: 'get_usage', input: { package: 'minimist' } }]) })]);
    const p = provider(fetch);
    const res = await p.chat({ messages: [{ role: 'user', content: 'go' }], tools: TOOLS });
    assert.equal(res.message.tool_calls?.[0]?.function.name, 'get_usage');
    assert.deepEqual(res.message.tool_calls?.[0]?.function.arguments, { package: 'minimist' });
    assert.equal(res.message.tool_calls?.[0]?.id, 'toolu_01');
    assert.equal(res.doneReason, 'tool_use');
    const usage = res.usage as AnthropicChatUsage;
    assert.equal(usage.promptTokens, 1000);
    assert.equal(usage.completionTokens, 500);
    assert.equal(usage.costUsd, (1000 * 2 + 500 * 10) / 1_000_000);
    assert.deepEqual(p.usageSummary(), { requests: 1, inputTokens: 1000, outputTokens: 500, costUsd: 0.007 });
  });

  it('implements format with a forced submit tool and returns its input as JSON content', async () => {
    const verdict = { risk: 'High', reachable: 'yes', confidence: 0.8, reasoning: 'argv reaches minimist.', evidence: ['src/cli.js:9'], recommendationAction: 'upgrade' };
    const { fetch, calls } = fakeFetch([() => ({ json: message([{ type: 'tool_use', id: 'toolu_9', name: 'submit', input: verdict }]) })]);
    const res = await provider(fetch).chat({
      messages: [
        { role: 'user', content: 'case' },
        { role: 'assistant', content: '', tool_calls: [{ function: { name: 'get_usage', arguments: { package: 'minimist' } } }] },
        { role: 'tool', tool_name: 'get_usage', content: '1 call' },
        { role: 'user', content: 'Now give your verdict as JSON.' },
      ],
      format: VERDICT_SCHEMA,
      purpose: 'verdict',
    });
    assert.deepEqual(JSON.parse(res.message.content), verdict);
    assert.equal(res.message.tool_calls, undefined, 'the submit call is not a tool call for the loop');
    const body = calls[0]?.body as Body;
    const tools = body.tools as Record<string, unknown>[];
    assert.equal(tools.length, 1);
    assert.equal(tools[0]?.name, 'submit');
    assert.deepEqual(tools[0]?.input_schema, VERDICT_SCHEMA);
    assert.deepEqual(body.tool_choice, { type: 'tool', name: 'submit' });
    const blocks = body.messages.flatMap((m) => m.content);
    const use = blocks.find((b) => b.type === 'tool_use');
    const result = blocks.find((b) => b.type === 'tool_result');
    assert.equal(result?.tool_use_id, use?.id, 'history tool blocks keep matching ids');
  });

  it('uses auto tool choice with an instruction where forced tool use is rejected (claude-opus-5-5)', async () => {
    const { fetch, calls } = fakeFetch([() => ({ json: message([{ type: 'text', text: '{"risk":"Low"}' }]) })]);
    const res = await provider(fetch, 'opus').chat({ messages: [{ role: 'user', content: 'verdict?' }], format: VERDICT_SCHEMA });
    assert.equal(res.message.content, '{"risk":"Low"}', 'a text answer is passed through for the loop to parse');
    assert.deepEqual(calls[0]?.body.tool_choice, { type: 'auto' });
    assert.match(String(calls[0]?.body.system), /call the submit tool/);
  });

  it('adapts once to a 400 that rejects forced tool use and remembers it for the model', async () => {
    const reject = { status: 400, json: { type: 'error', error: { type: 'invalid_request_error', message: 'tool_choice: type "tool" and "any" are not supported for this model.' } } };
    const ok = { json: message([{ type: 'tool_use', id: 'toolu_1', name: 'submit', input: { inputSources: [] } }]) };
    const { fetch, calls } = fakeFetch([() => reject, () => ok, () => ok]);
    const p = provider(fetch, 'claude-new-model-1');
    await p.chat({ messages: [{ role: 'user', content: 'dossier' }], format: DOSSIER_SCHEMA });
    assert.equal(calls.length, 2);
    assert.deepEqual(calls[0]?.body.tool_choice, { type: 'tool', name: 'submit' });
    assert.deepEqual(calls[1]?.body.tool_choice, { type: 'auto' });
    await p.chat({ messages: [{ role: 'user', content: 'dossier again' }], format: DOSSIER_SCHEMA });
    assert.equal(calls.length, 3);
    assert.deepEqual(calls[2]?.body.tool_choice, { type: 'auto' }, 'the adaptation persists for the run');
    assert.equal(adaptationFor('temperature: not supported on this model', { traits: claudeModelTraits('claude-haiku-4-5'), flattenTools: false, stripThinking: false }), 'sampling');
    assert.equal(adaptationFor('something else entirely', { traits: claudeModelTraits('claude-haiku-4-5'), flattenTools: false, stripThinking: false }), null);
  });

  it('replays its own assistant turn (thinking, text, original tool_use ids) when the history reaches it again', async () => {
    const first = message([
      { type: 'thinking', thinking: '', signature: 'sig-abc' },
      { type: 'tool_use', id: 'toolu_orig', name: 'get_usage', input: { pkg: 'minimist' } },
    ]);
    const { fetch, calls } = fakeFetch([() => ({ json: first }), () => ({ json: message([{ type: 'text', text: 'done' }]) })]);
    const p = provider(fetch, 'sonnet', { think: 'on' });
    const history: ChatMessage[] = [
      { role: 'system', content: 's' },
      { role: 'user', content: 'go' },
    ];
    const res = await p.chat({ messages: history, tools: TOOLS });
    // matches how the agent loop stores it
    history.push({ role: 'assistant', content: '', tool_calls: [{ function: { name: 'get_usage', arguments: { package: 'minimist' } } }] });
    history.push({ role: 'tool', tool_name: 'get_usage', content: '1 call' });
    history.push({ role: 'user', content: 'continue' });
    assert.equal(res.message.tool_calls?.length, 1);
    await p.chat({ messages: history, tools: TOOLS });
    const replayed = calls[1]?.body.messages[1]?.content ?? [];
    assert.deepEqual(replayed[0], { type: 'thinking', thinking: '', signature: 'sig-abc' });
    assert.equal(replayed[1]?.id, 'toolu_orig');
    assert.deepEqual(replayed[1]?.input, { pkg: 'minimist' }, 'replayed exactly as produced');
    assert.equal(calls[1]?.body.messages[2]?.content[0]?.tool_use_id, 'toolu_orig');
    assert.equal(historyKey(history.slice(0, 2)), historyKey([{ role: 'system', content: 's' }, { role: 'user', content: 'go' }]));
  });

  it('stops the run on a rejected key (fatal kind, no retry) with both ways to fix it', async () => {
    const { fetch, calls } = fakeFetch([() => ({ status: 401, json: { type: 'error', error: { type: 'authentication_error', message: 'invalid x-api-key' } } })]);
    await assert.rejects(
      () => provider(fetch).chat({ messages: [{ role: 'user', content: 'hi' }] }),
      (err: unknown) => {
        assert.ok(err instanceof LlmError);
        assert.equal(err.kind, 'unreachable', 'agent.ts treats it as fatal');
        assert.equal(err.status, 401);
        assert.match(err.message, /rejected the API key/);
        assert.match(String(err.hint), /patch-pilot config set anthropic-api-key/);
        assert.match(String(err.hint), /ANTHROPIC_API_KEY/);
        assert.ok(!err.message.includes('sk-ant-test-secret-key'));
        return true;
      },
    );
    assert.equal(calls.length, 1);
  });

  it('retries 429 (honouring retry-after) and 529, then gives up with a clear message', async () => {
    const limited = { status: 429, json: { type: 'error', error: { type: 'rate_limit_error', message: 'slow down' } }, headers: { 'retry-after': '0' } };
    const overloaded = { status: 529, json: { type: 'error', error: { type: 'overloaded_error', message: 'Overloaded' } } };
    const ok = { json: message([{ type: 'text', text: 'fine' }]) };
    const retried = fakeFetch([() => limited, () => overloaded, () => ok]);
    const res = await provider(retried.fetch).chat({ messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(res.message.content, 'fine');
    assert.equal(retried.calls.length, 3);
    const always = fakeFetch([() => overloaded]);
    await assert.rejects(
      () => provider(always.fetch, 'sonnet', { maxRetries: 2 }).chat({ messages: [{ role: 'user', content: 'hi' }] }),
      (err: unknown) => err instanceof LlmError && err.kind === 'http' && err.status === 529 && /overloaded/i.test(err.message) && /haiku/.test(String(err.hint)),
    );
    assert.equal(always.calls.length, 3, 'one attempt plus two retries');
  });

  it('maps an unknown model to model-missing and a refusal to invalid-response', async () => {
    const missing = fakeFetch([() => ({ status: 404, json: { type: 'error', error: { type: 'not_found_error', message: 'model: claude-nope' } } })]);
    await assert.rejects(() => provider(missing.fetch, 'claude-nope').chat({ messages: [{ role: 'user', content: 'hi' }] }), (err: unknown) => err instanceof LlmError && err.kind === 'model-missing');
    const refused = fakeFetch([() => ({ json: message([], { stop_reason: 'refusal', stop_details: { type: 'refusal', category: 'cyber' } }) })]);
    await assert.rejects(() => provider(refused.fetch).chat({ messages: [{ role: 'user', content: 'hi' }] }), (err: unknown) => err instanceof LlmError && err.kind === 'invalid-response' && /cyber/.test(err.message));
  });

  it('accepts aliases and claude ids in checkModel without a network call, and never logs the key', async () => {
    const { fetch, calls } = fakeFetch([() => ({ json: message([{ type: 'text', text: 'ok' }]) })]);
    const debugLog = path.join(dir, 'debug.log');
    const p = provider(fetch, 'sonnet', { debugLog });
    assert.equal((await p.checkModel('opus')).ok, true);
    assert.equal((await p.checkModel('opus')).resolvedModel, 'claude-opus-5-5');
    assert.equal((await p.checkModel('qwen3:8b')).ok, false);
    await p.warmup();
    assert.equal(calls.length, 0);
    await p.chat({ messages: [{ role: 'user', content: 'hi' }], purpose: 'verdict' });
    const log = await readFile(debugLog, 'utf8');
    assert.match(log, /"dir":"request"/);
    assert.match(log, /"provider":"claude"/);
    assert.ok(!log.includes('sk-ant-test-secret-key'));
  });
});

describe('createProvider for claude', () => {
  it('needs a key, and explains both ways to set it plus the subscriber route', async () => {
    const config = await testConfig(dir, { provider: 'claude' });
    assert.throws(
      () => createProvider(config),
      (err: unknown) => err instanceof EnvironmentError && /patch-pilot config set anthropic-api-key/.test(String(err.hint)) && /ANTHROPIC_API_KEY/.test(String(err.hint)) && /mcp --print-config/.test(String(err.hint)),
    );
  });

  it('defaults --model to sonnet for claude and keeps an explicit id', async () => {
    const config: Config = { ...(await testConfig(dir, { provider: 'claude' })), anthropicApiKey: 'sk-ant-x' };
    assert.equal(config.model, 'qwen3:8b');
    const p = createProvider(config);
    assert.equal(p.name, 'claude');
    assert.equal(p.model, 'claude-sonnet-5');
    assert.equal(createCodemodProvider({ ...config, codemodModel: 'qwen2.5-coder:7b' }).model, 'claude-sonnet-5', 'a local codemod model is not sent to Anthropic');
    const explicit: Config = { ...(await testConfig(dir, { provider: 'claude', model: 'claude-opus-4-8' })), anthropicApiKey: 'sk-ant-x' };
    assert.equal(createProvider(explicit).model, 'claude-opus-4-8');
    assert.deepEqual(resolveProviderModel({ provider: 'claude', model: 'haiku', sources: { model: 'user' } }), { model: 'claude-haiku-4-5', fallback: false });
    assert.deepEqual(resolveProviderModel({ provider: 'ollama', model: 'sonnet', sources: { model: 'user' } }), { model: 'qwen3:8b', fallback: true });
    assert.deepEqual(resolveProviderModel({ provider: 'claude', model: 'qwen3:8b', sources: { model: 'user' } }), { model: 'claude-sonnet-5', fallback: true });
  });
});

describe('the investigation loop on Claude', () => {
  it('runs recon, the gate, the verdict turn and the cache with provider claude', async () => {
    const { pkg, vuln } = minimistFixture();
    const caseFile = caseFileOf([pkg], [vuln], dir);
    const config = await testConfig(dir, { provider: 'claude' });
    const { registry, calls: toolCalls } = fakeRegistry({
      get_usage: () => usageResult('minimist', null, 1, [{ path: 'src/cli.js', line: 9, member: null }]),
      read_file: () => ({ ok: true, hint: 'src/cli.js:1-30', text: '9: const argv = parseArgs(process.argv.slice(2));' }),
    });
    const verdict = { risk: 'High', reachable: 'yes', confidence: 0.85, reasoning: 'minimist parses process.argv, which the user controls.', evidence: ['src/cli.js:9'], recommendationAction: 'upgrade' };
    const dossier = { inputSources: ['process.argv (CLI arguments)'], callSiteNotes: ['src/cli.js:9 parseArgs(argv)'], dependentsSummary: 'direct', fixCost: '1.2.6 patch', openQuestions: [] };
    const requests: ChatRequest[] = [];
    const { fetch } = fakeFetch([
      (body) => {
        const tools = ((body.tools as { name: string; input_schema: { required?: string[] } }[] | undefined) ?? []).map((t) => t);
        const submit = tools.find((t) => t.name === 'submit');
        if (submit) {
          const isVerdict = submit.input_schema.required?.includes('risk');
          return { json: message([{ type: 'tool_use', id: `toolu_s${requests.length}`, name: 'submit', input: isVerdict ? verdict : dossier }]) };
        }
        const names = tools.map((t) => t.name);
        const blocks = body.messages.flatMap((m) => m.content);
        const lastText = [...blocks].reverse().find((b) => b.type === 'text');
        if (names.includes('get_usage')) {
          const used = blocks.filter((b) => b.type === 'tool_use').map((b) => b.name);
          const coach = /"name":"read_file","arguments":(\{[^\n]*\})\}/.exec(String(lastText?.text ?? ''));
          if (coach) return { json: message([{ type: 'tool_use', id: 'toolu_r', name: 'read_file', input: JSON.parse(coach[1] as string) }]) };
          if (!used.includes('get_usage')) return { json: message([{ type: 'tool_use', id: 'toolu_u', name: 'get_usage', input: { package: 'minimist' } }]) };
          return { json: message([{ type: 'text', text: 'minimist is called with process.argv in src/cli.js.' }]) };
        }
        return { json: message([{ type: 'text', text: 'The package parses CLI arguments.' }]) };
      },
    ]);
    const p = new AnthropicProvider({ apiKey: 'sk-ant-loop', model: 'sonnet', timeoutMs: 5_000, fetch, retryDelayMs: 1 });
    const recording: typeof p.chat = async (req) => {
      requests.push(req);
      return AnthropicProvider.prototype.chat.call(p, req);
    };
    const wrapped = Object.assign(Object.create(p) as AnthropicProvider, { chat: recording });
    const { ui, out } = captureUi();
    const audit = new MemoryAudit();
    const assessment = await runPhase2(caseFile, config, { provider: wrapped, ui, audit, registry, graph: null, scanImports: async () => new Map() });
    const v = assessment.verdicts[0];
    assert.ok(v);
    assert.equal(v.investigation.provider, 'claude');
    assert.equal(v.investigation.model, 'claude-sonnet-5');
    assert.equal(v.risk, 'High');
    assert.equal(v.investigation.forced, false);
    assert.equal(v.recommendation.targetVersion, '1.2.6');
    assert.ok(toolCalls.some((c) => c.tool === 'read_file'), 'the evidence gate asked for a call-site read');
    assert.ok(audit.events('gate.evidence').some((e) => e.action === 'coached'));
    assert.match(out(), /\[evidence gate\]/);
    const cache = JSON.parse(await readFile(config.paths.verdictCacheFile, 'utf8')) as { entries: Record<string, unknown> };
    assert.ok(Object.keys(cache.entries).every((k) => k.startsWith('claude:')));
    assert.ok(requests.some((r) => r.format !== undefined));
  });
});
