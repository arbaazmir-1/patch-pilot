import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { LlmError } from '../../src/llm/errors.ts';
import { buildChatBody, classifyNetworkError, classifyOllamaError, OllamaProvider, parseChatResponse, type OllamaProviderOptions } from '../../src/llm/ollama.ts';
import { VERDICT_SCHEMA } from '../../src/investigation/prompts.ts';
import type { ChatRequest, ToolSchema } from '../../src/types.ts';
import { tempDir } from './helpers.ts';

const OPTIONS: OllamaProviderOptions = {
  host: 'http://localhost:11434',
  model: 'mistral:7b',
  numCtx: 16384,
  seed: 42,
  temperature: 0,
  timeoutMs: 1000,
  keepAlive: '30m',
  debugLog: null,
  retryDelayMs: 1,
};

const TOOLS: ToolSchema[] = [
  { type: 'function', function: { name: 'get_usage', description: 'usage', parameters: { type: 'object', properties: { package: { type: 'string' } }, required: ['package'] } } },
];

interface Captured {
  url: string;
  method: string;
  body: Record<string, unknown> | null;
}

// queued answers, records requests
function fakeFetch(replies: (Response | Error | ((c: Captured) => Response))[]): { fetch: typeof fetch; requests: Captured[] } {
  const requests: Captured[] = [];
  const queue = [...replies];
  const impl = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const captured: Captured = { url: String(input), method: init?.method ?? 'GET', body: typeof init?.body === 'string' ? (JSON.parse(init.body) as Record<string, unknown>) : null };
    requests.push(captured);
    const next = queue.shift();
    if (!next) throw new Error('no more fake replies');
    if (next instanceof Error) throw next;
    return typeof next === 'function' ? next(captured) : next;
  };
  return { fetch: impl as typeof fetch, requests };
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
}

function refused(): Error {
  return Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } });
}

describe('buildChatBody', () => {
  it('sends stream false, the defaults in options, keep_alive, and tools/format only when given', () => {
    const body = buildChatBody({ messages: [{ role: 'user', content: 'hi' }] }, OPTIONS);
    assert.deepEqual(body, {
      model: 'mistral:7b',
      messages: [{ role: 'user', content: 'hi' }],
      stream: false,
      options: { temperature: 0, num_ctx: 16384, seed: 42 },
      keep_alive: '30m',
    });
    assert.equal('tools' in body, false);
    assert.equal('format' in body, false);
    assert.equal('think' in body, false);
  });

  it('merges request options over the defaults and passes tools, format, think and model', () => {
    const req: ChatRequest = {
      model: 'qwen3:8b',
      messages: [{ role: 'user', content: 'x' }],
      tools: TOOLS,
      format: VERDICT_SCHEMA,
      options: { num_ctx: 8192, temperature: undefined, num_predict: 256 },
      keepAlive: '5m',
      think: false,
    };
    const body = buildChatBody(req, OPTIONS);
    assert.equal(body.model, 'qwen3:8b');
    assert.deepEqual(body.options, { temperature: 0, num_ctx: 8192, seed: 42, num_predict: 256 });
    assert.equal(body.keep_alive, '5m');
    assert.deepEqual(body.tools, TOOLS);
    assert.deepEqual(body.format, VERDICT_SCHEMA);
    assert.equal(body.think, false);
    assert.equal(buildChatBody({ messages: [], format: 'json', tools: [] }, OPTIONS).format, 'json');
    assert.equal('tools' in buildChatBody({ messages: [], tools: [] }, OPTIONS), false);
  });

  it('sends messages in wire shape: tool_calls without source/id, tool_name on tool results, no thinking', () => {
    const body = buildChatBody(
      {
        messages: [
          { role: 'assistant', content: '', thinking: 'secret thoughts', tool_calls: [{ function: { name: 'get_usage', arguments: { package: 'lodash' }, index: 0 }, source: 'text', id: 'c1' }] },
          { role: 'tool', tool_name: 'get_usage', content: 'result' },
        ],
      },
      OPTIONS,
    );
    assert.deepEqual(body.messages, [
      { role: 'assistant', content: '', tool_calls: [{ function: { name: 'get_usage', arguments: { package: 'lodash' } } }] },
      { role: 'tool', content: 'result', tool_name: 'get_usage' },
    ]);
  });
});

describe('parseChatResponse', () => {
  it('normalises tool calls (string arguments become objects) and converts durations to ms', () => {
    const r = parseChatResponse(
      {
        model: 'mistral:7b',
        message: {
          role: 'assistant',
          content: '',
          tool_calls: [
            { id: 'call_1', function: { name: 'get_usage', arguments: { package: 'lodash' } } },
            { function: { name: 'read_file', arguments: '{"path": "src/cli.js"}' } },
            { function: { name: '', arguments: {} } },
          ],
        },
        done: true,
        done_reason: 'stop',
        prompt_eval_count: 433,
        eval_count: 20,
        total_duration: 7_800_000_000,
        load_duration: 2_000_000_000,
        prompt_eval_duration: 5_000_000_000,
        eval_duration: 800_000_000,
      },
      'mistral:7b',
    );
    assert.deepEqual(r.message.tool_calls, [
      { function: { name: 'get_usage', arguments: { package: 'lodash' }, index: 0 }, source: 'native', id: 'call_1' },
      { function: { name: 'read_file', arguments: { path: 'src/cli.js' }, index: 1 }, source: 'native' },
    ]);
    assert.deepEqual(r.usage, { promptTokens: 433, completionTokens: 20, totalMs: 7800, loadMs: 2000, promptEvalMs: 5000, evalMs: 800 });
    assert.equal(r.doneReason, 'stop');
    assert.equal(r.done, true);
  });

  it('rejects bodies without a message and error bodies', () => {
    assert.throws(() => parseChatResponse({ done: true }, 'm'), (e: unknown) => e instanceof LlmError && e.kind === 'invalid-response');
    assert.throws(() => parseChatResponse(null, 'm'), (e: unknown) => e instanceof LlmError && e.kind === 'invalid-response');
    assert.throws(() => parseChatResponse({ error: "model 'x' not found" }, 'x'), (e: unknown) => e instanceof LlmError && e.kind === 'model-missing');
  });
});

describe('classifyOllamaError', () => {
  it('recognises a missing model with the ollama pull fix', () => {
    const e = classifyOllamaError(404, '{"error":"model \\"mistral:7b\\" not found, try pulling it first"}', 'mistral:7b');
    assert.equal(e.kind, 'model-missing');
    assert.equal(e.hint, 'ollama pull mistral');
    assert.equal(classifyOllamaError(404, '{"error":"model \'qwen3:8b\' not found"}', 'qwen3:8b').hint, 'ollama pull qwen3:8b');
  });

  it('recognises a model without tool support', () => {
    const e = classifyOllamaError(400, '{"error":"registry.ollama.ai/library/gemma:2b does not support tools"}', 'gemma:2b');
    assert.equal(e.kind, 'no-tools');
    assert.match(e.hint ?? '', /--model/);
    assert.match(e.hint ?? '', /ollama\.com\/search\?c=tools/);
  });

  it('maps out-of-memory, context overflow and runner crashes to out-of-memory with a --num-ctx hint', () => {
    const oom = classifyOllamaError(500, '{"error":"model requires more system memory (9.1 GiB) than is available (6.0 GiB)"}', 'mistral:7b');
    assert.equal(oom.kind, 'out-of-memory');
    assert.match(oom.hint ?? '', /--num-ctx 8192/);
    const ctx = classifyOllamaError(400, '{"error":"input length exceeds the context length"}', 'mistral:7b');
    assert.equal(ctx.kind, 'out-of-memory');
    assert.match(ctx.hint ?? '', /--num-ctx/);
    assert.equal(classifyOllamaError(500, '{"error":"llama runner process has terminated: signal: killed"}', 'm').kind, 'out-of-memory');
  });

  it('falls back to http with the status', () => {
    const e = classifyOllamaError(500, 'boom', 'm');
    assert.equal(e.kind, 'http');
    assert.equal(e.status, 500);
    assert.match(classifyOllamaError(404, '404 page not found', 'm').hint ?? '', /--ollama-host/);
  });

  it('classifies network failures', () => {
    assert.equal(classifyNetworkError(refused(), OPTIONS.host, 1000, false).kind, 'unreachable');
    assert.match(classifyNetworkError(refused(), OPTIONS.host, 1000, false).hint ?? '', /ollama serve/);
    const timeout = Object.assign(new Error('timed out'), { name: 'TimeoutError' });
    assert.equal(classifyNetworkError(timeout, OPTIONS.host, 180_000, false).kind, 'timeout');
    assert.equal(classifyNetworkError(refused(), OPTIONS.host, 1000, true).kind, 'aborted');
  });
});

describe('OllamaProvider.chat', () => {
  let tmp: Awaited<ReturnType<typeof tempDir>>;
  before(async () => {
    tmp = await tempDir('pp-ollama-');
  });
  after(async () => {
    await tmp.cleanup();
  });

  it('posts to /api/chat and returns the parsed message', async () => {
    const { fetch, requests } = fakeFetch([json({ model: 'mistral:7b', message: { role: 'assistant', content: 'hello' }, done: true })]);
    const p = new OllamaProvider({ ...OPTIONS, fetch });
    const r = await p.chat({ purpose: 'verdict', messages: [{ role: 'user', content: 'x' }], format: VERDICT_SCHEMA });
    assert.equal(r.message.content, 'hello');
    assert.equal(requests[0]?.url, 'http://localhost:11434/api/chat');
    assert.equal(requests[0]?.method, 'POST');
    assert.deepEqual(requests[0]?.body?.format, VERDICT_SCHEMA);
  });

  it('recovers tool calls written as text when the request has tools', async () => {
    const content = 'I need the usage first.\n```json\n{"name": "get_usage", "arguments": {"package": "lodash"}}\n```';
    const { fetch } = fakeFetch([json({ message: { role: 'assistant', content }, done: true })]);
    const r = await new OllamaProvider({ ...OPTIONS, fetch }).chat({ messages: [{ role: 'user', content: 'x' }], tools: TOOLS });
    assert.deepEqual(r.message.tool_calls, [{ function: { name: 'get_usage', arguments: { package: 'lodash' }, index: 0 }, source: 'text' }]);
    assert.equal(r.message.content, 'I need the usage first.');
    const noTools = await new OllamaProvider({ ...OPTIONS, fetch: fakeFetch([json({ message: { role: 'assistant', content }, done: true })]).fetch }).chat({ messages: [] });
    assert.equal(noTools.message.tool_calls, undefined);
  });

  it('throws classified LlmErrors for HTTP failures', async () => {
    const { fetch } = fakeFetch([json({ error: 'gemma does not support tools' }, 400)]);
    await assert.rejects(new OllamaProvider({ ...OPTIONS, fetch }).chat({ messages: [], tools: TOOLS }), (e: unknown) => e instanceof LlmError && e.kind === 'no-tools' && e.status === 400);
  });

  it('retries once after a network error or a busy status, then gives up with unreachable', async () => {
    const ok = json({ message: { role: 'assistant', content: 'ok' }, done: true });
    const retried = fakeFetch([refused(), ok]);
    assert.equal((await new OllamaProvider({ ...OPTIONS, fetch: retried.fetch }).chat({ messages: [] })).message.content, 'ok');
    assert.equal(retried.requests.length, 2);
    const busy = fakeFetch([json({ error: 'server busy' }, 503), json({ message: { role: 'assistant', content: 'later' }, done: true })]);
    assert.equal((await new OllamaProvider({ ...OPTIONS, fetch: busy.fetch }).chat({ messages: [] })).message.content, 'later');
    const down = fakeFetch([refused(), refused()]);
    await assert.rejects(new OllamaProvider({ ...OPTIONS, fetch: down.fetch }).chat({ messages: [] }), (e: unknown) => e instanceof LlmError && e.kind === 'unreachable' && /ollama serve/.test(e.hint ?? ''));
    assert.equal(down.requests.length, 2);
  });

  it('reports a timeout when no answer arrives in time', async () => {
    const hang = (async (_input: unknown, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(init.signal?.reason));
      })) as typeof fetch;
    await assert.rejects(new OllamaProvider({ ...OPTIONS, fetch: hang, timeoutMs: 30 }).chat({ messages: [] }), (e: unknown) => e instanceof LlmError && e.kind === 'timeout');
  });

  it('rejects invalid JSON bodies', async () => {
    const { fetch } = fakeFetch([new Response('not json', { status: 200 })]);
    await assert.rejects(new OllamaProvider({ ...OPTIONS, fetch }).chat({ messages: [] }), (e: unknown) => e instanceof LlmError && e.kind === 'invalid-response');
  });

  it('writes every request and response to the debug log when enabled', async () => {
    const debugLog = path.join(tmp.dir, 'state', 'debug.log');
    const { fetch } = fakeFetch([json({ message: { role: 'assistant', content: 'logged' }, done: true }), json({ error: 'boom' }, 500)]);
    const p = new OllamaProvider({ ...OPTIONS, fetch, debugLog });
    await p.chat({ purpose: 'recon', messages: [{ role: 'user', content: 'x' }] });
    await assert.rejects(p.chat({ purpose: 'verdict', messages: [] }));
    const lines = (await readFile(debugLog, 'utf8')).trim().split('\n').map((l) => JSON.parse(l) as Record<string, unknown>);
    assert.deepEqual(lines.map((l) => l.dir), ['request', 'response', 'request', 'error']);
    assert.equal(lines[0]?.purpose, 'recon');
    assert.equal((lines[0]?.body as { model?: string }).model, 'mistral:7b');
  });
});

describe('OllamaProvider.checkModel and warmup', () => {
  const tags = { models: [{ name: 'mistral:7b', model: 'mistral:7b', details: { parameter_size: '7.2B' } }, { name: 'gemma:2b', details: { parameter_size: '2B' } }] };

  it('accepts mistral and mistral:latest for an installed mistral:7b and reads capabilities from /api/show', async () => {
    for (const want of ['mistral', 'mistral:latest', 'mistral:7b']) {
      const { fetch, requests } = fakeFetch([json(tags), json({ capabilities: ['completion', 'tools'] })]);
      const check = await new OllamaProvider({ ...OPTIONS, fetch }).checkModel(want);
      assert.deepEqual(check, { ok: true, model: want, installed: true, tools: true, resolvedModel: 'mistral:7b' });
      assert.equal(requests[0]?.url, 'http://localhost:11434/api/tags');
      assert.deepEqual(requests[1]?.body, { model: 'mistral:7b' });
    }
  });

  it('reports a missing model with the pull command and a model without tools', async () => {
    const missing = await new OllamaProvider({ ...OPTIONS, fetch: fakeFetch([json(tags)]).fetch }).checkModel('qwen3:8b');
    assert.equal(missing.ok, false);
    assert.equal(missing.installed, false);
    assert.deepEqual(missing.fix, ['ollama pull qwen3:8b', 'https://ollama.com/library/qwen3']);
    const noTools = await new OllamaProvider({ ...OPTIONS, fetch: fakeFetch([json(tags), json({ capabilities: ['completion'] })]).fetch }).checkModel('gemma:2b');
    assert.equal(noTools.ok, false);
    assert.equal(noTools.tools, false);
    assert.equal(noTools.resolvedModel, 'gemma:2b');
    assert.match(noTools.message ?? '', /does not support tool calling/);
  });

  it('reports an unreachable server without throwing', async () => {
    const check = await new OllamaProvider({ ...OPTIONS, fetch: fakeFetch([refused()]).fetch }).checkModel();
    assert.equal(check.ok, false);
    assert.match(check.message ?? '', /not reachable/);
  });

  it('warms up with empty messages, the run num_ctx and keep_alive, and never throws', async () => {
    const { fetch, requests } = fakeFetch([json({ message: { role: 'assistant', content: '' }, done: true, done_reason: 'load' })]);
    await new OllamaProvider({ ...OPTIONS, fetch }).warmup();
    assert.deepEqual(requests[0]?.body, { model: 'mistral:7b', messages: [], stream: false, keep_alive: '30m', options: { num_ctx: 16384 } });
    await new OllamaProvider({ ...OPTIONS, fetch: fakeFetch([refused()]).fetch }).warmup();
  });
});
