// /api/chat adapter and model check
import { appendFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { redactSecrets } from '../audit.ts';
import { LINKS, pullCommandFor, resolveModelName, splitModelName } from '../preflight.ts';
import type { ChatMessage, ChatOptions, ChatRequest, ChatResponse, ChatUsage, InstalledModel, ModelCheck, ToolCall } from '../types.ts';
import { USER_AGENT } from '../version.ts';
import { LlmError } from './errors.ts';
import type { ChatProvider } from './provider.ts';
import { normalizeToolArguments, parseTextToolCalls } from './textToolCalls.ts';

export interface OllamaProviderOptions {
  // normalised base URL, e.g. "http://localhost:11434"
  host: string;
  model: string;
  numCtx: number;
  // auto keeps model default
  think?: 'auto' | 'on' | 'off';
  seed: number;
  temperature: number;
  // per turn
  timeoutMs: number;
  // e.g. "30m" keeps the model loaded across the run
  keepAlive: string;
  // .patch-pilot/debug.log when PATCHPILOT_DEBUG=1, else null
  debugLog: string | null;
  // tests inject this
  fetch?: typeof fetch;
  // before the one retry, default 500 ms
  retryDelayMs?: number;
}

// busy or restarting, 500 is a model error
const RETRY_STATUSES: ReadonlySet<number> = new Set([429, 502, 503, 504]);
const PROBE_TIMEOUT_MS = 5_000;

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new LlmError('aborted', 'Request aborted'));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(new LlmError('aborted', 'Request aborted'));
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

// undefined must not override defaults
function definedOptions(options: ChatOptions | undefined): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(options ?? {})) if (value !== undefined) out[key] = value;
  return out;
}

// no thinking, no tool call source/id
function toWireMessage(message: ChatMessage): Record<string, unknown> {
  const out: Record<string, unknown> = { role: message.role, content: message.content ?? '' };
  if (message.tool_calls && message.tool_calls.length > 0) {
    out.tool_calls = message.tool_calls.map((call) => ({
      function: { name: call.function.name, arguments: call.function.arguments ?? {} },
    }));
  }
  if (message.role === 'tool' && message.tool_name) out.tool_name = message.tool_name;
  return out;
}

export function buildChatBody(req: ChatRequest, options: OllamaProviderOptions): Record<string, unknown> {
  const body: Record<string, unknown> = {
    model: req.model ?? options.model,
    messages: (req.messages ?? []).map(toWireMessage),
    stream: false,
    options: { temperature: options.temperature, num_ctx: options.numCtx, seed: options.seed, ...definedOptions(req.options) },
    keep_alive: req.keepAlive ?? options.keepAlive,
  };
  if (req.tools && req.tools.length > 0) body.tools = req.tools;
  if (req.format !== undefined) body.format = req.format;
  if (req.think !== undefined) body.think = req.think;
  return body;
}

const nsToMs = (value: unknown): number | undefined => (typeof value === 'number' && Number.isFinite(value) ? Math.round(value / 1e6) : undefined);
const count = (value: unknown): number | undefined => (typeof value === 'number' && Number.isFinite(value) ? value : undefined);

// tool args normalised to objects
export function parseChatResponse(raw: unknown, model: string): ChatResponse {
  if (!isRecord(raw)) throw new LlmError('invalid-response', `Ollama returned an unexpected response for ${model}`);
  if (typeof raw.error === 'string') throw classifyOllamaError(200, JSON.stringify({ error: raw.error }), model);
  const m = raw.message;
  if (!isRecord(m)) throw new LlmError('invalid-response', `Ollama returned no message for ${model}`);
  const message: ChatMessage = { role: 'assistant', content: typeof m.content === 'string' ? m.content : '' };
  if (Array.isArray(m.tool_calls)) {
    const calls: ToolCall[] = [];
    m.tool_calls.forEach((entry, i) => {
      if (!isRecord(entry)) return;
      const fn = isRecord(entry.function) ? entry.function : entry;
      const name = typeof fn.name === 'string' ? fn.name.trim() : '';
      if (name === '') return;
      const call: ToolCall = {
        function: { name, arguments: normalizeToolArguments(fn.arguments), index: typeof fn.index === 'number' ? fn.index : i },
        source: 'native',
      };
      if (typeof entry.id === 'string') call.id = entry.id;
      calls.push(call);
    });
    if (calls.length > 0) message.tool_calls = calls;
  }
  if (typeof m.thinking === 'string' && m.thinking !== '') message.thinking = m.thinking;
  const usage: ChatUsage = {};
  const assign = <K extends keyof ChatUsage>(key: K, value: number | undefined): void => {
    if (value !== undefined) usage[key] = value;
  };
  assign('promptTokens', count(raw.prompt_eval_count));
  assign('completionTokens', count(raw.eval_count));
  assign('totalMs', nsToMs(raw.total_duration));
  assign('loadMs', nsToMs(raw.load_duration));
  assign('promptEvalMs', nsToMs(raw.prompt_eval_duration));
  assign('evalMs', nsToMs(raw.eval_duration));
  const response: ChatResponse = {
    message,
    model: typeof raw.model === 'string' && raw.model !== '' ? raw.model : model,
    done: raw.done !== false,
  };
  if (typeof raw.done_reason === 'string') response.doneReason = raw.done_reason;
  if (Object.keys(usage).length > 0) response.usage = usage;
  return response;
}

// with a hint
export function classifyOllamaError(status: number, body: string, model: string): LlmError {
  let detail = (body ?? '').trim();
  try {
    const parsed = JSON.parse(detail) as unknown;
    if (isRecord(parsed) && typeof parsed.error === 'string') detail = parsed.error.trim();
  } catch {
    // plain-text body
  }
  detail = detail.slice(0, 300) || `HTTP ${status}`;
  const lower = detail.toLowerCase();
  if (/does not support tools/.test(lower)) {
    return new LlmError('no-tools', `${model} does not support tool calling (${detail})`, {
      status,
      hint: `Pick a tool-capable model with --model <name> (list: ${LINKS.toolModels}), for example: ollama pull qwen3:8b`,
    });
  }
  if (/model ['"]?[^'"]*['"]? not found|not found, try pulling|try pulling it first|pull (it|the model) first|no such model|model not found/.test(lower) || (status === 404 && /model/.test(lower))) {
    return new LlmError('model-missing', `Model ${model} is not installed in Ollama`, { status, hint: pullCommandFor(model) });
  }
  if (/out of memory|insufficient memory|requires more system memory|not enough memory|cudamalloc|failed to allocate|unable to allocate|memory layout cannot be allocated|\boom\b|oom-kill/.test(lower)) {
    return new LlmError('out-of-memory', `Ollama ran out of memory running ${model}: ${detail}`, {
      status,
      hint: 'Try a smaller context window, for example --num-ctx 8192, or close other applications.',
    });
  }
  if (/context (length|window|size)|exceeds (the )?(maximum )?context|too many tokens|input (is )?too long|prompt is too long|n_ctx/.test(lower)) {
    return new LlmError('out-of-memory', `The prompt does not fit the context window of ${model}: ${detail}`, {
      status,
      hint: 'Raise the context with --num-ctx 32768 if memory allows, or narrow the run with --only.',
    });
  }
  if (/runner (process )?(has )?(terminated|unexpectedly stopped|stopped unexpectedly)|signal: killed|exit status/.test(lower)) {
    return new LlmError('out-of-memory', `The Ollama model runner stopped while running ${model}: ${detail}`, {
      status,
      hint: 'This is usually memory pressure: try --num-ctx 8192 or close other applications, then run again.',
    });
  }
  if (status === 404) {
    return new LlmError('http', `Ollama returned HTTP 404: ${detail}`, { status, hint: 'Check --ollama-host: it must point at an Ollama server (default http://localhost:11434).' });
  }
  return new LlmError('http', `Ollama returned HTTP ${status}: ${detail}`, { status });
}

// unreachable, timeout, aborted
export function classifyNetworkError(err: unknown, host: string, timeoutMs: number, callerAborted: boolean): LlmError {
  if (err instanceof LlmError) return err;
  if (callerAborted) return new LlmError('aborted', 'Request aborted', { cause: err });
  const e = err as { name?: string; message?: string; cause?: { code?: string; message?: string; errors?: { code?: string }[] } };
  const code = e?.cause?.code ?? e?.cause?.errors?.find((x) => x?.code)?.code ?? null;
  if (e?.name === 'TimeoutError' || code === 'UND_ERR_HEADERS_TIMEOUT' || code === 'UND_ERR_BODY_TIMEOUT' || code === 'ETIMEDOUT') {
    return new LlmError('timeout', `Ollama did not answer within ${Math.round(timeoutMs / 1000)} s`, {
      cause: err,
      hint: 'The model may still be loading or the prompt is large: try again, use a smaller --num-ctx, or a smaller model.',
    });
  }
  if (e?.name === 'AbortError') return new LlmError('aborted', 'Request aborted', { cause: err });
  const reason = code ?? e?.cause?.message ?? e?.message ?? String(err);
  return new LlmError('unreachable', `Ollama is not reachable at ${host} (${reason})`, {
    cause: err,
    hint: `Start it with: ollama serve (or open the Ollama app). Install: ${LINKS.ollamaDownload}`,
  });
}

interface RawReply {
  status: number;
  text: string;
}

export class OllamaProvider implements ChatProvider {
  readonly name = 'ollama' as const;
  readonly model: string;
  readonly options: OllamaProviderOptions;
  private readonly fetchImpl: typeof fetch;

  constructor(options: OllamaProviderOptions) {
    this.options = options;
    this.model = options.model;
    this.fetchImpl = options.fetch ?? ((input, init) => fetch(input, init));
  }

  // filled by checkModel
  private readonly capabilities = new Map<string, string[] | null>();

  // undefined for auto or non-thinkers
  private async thinkFor(model: string): Promise<boolean | undefined> {
    const mode = this.options.think ?? 'auto';
    if (mode === 'auto') return undefined;
    if (!this.capabilities.has(model)) await this.checkModel(model);
    const caps = this.capabilities.get(model);
    if (!caps || !caps.includes('thinking')) return undefined;
    return mode === 'on';
  }

  async chat(req: ChatRequest): Promise<ChatResponse> {
    const model = req.model ?? this.model;
    const think = req.think ?? (await this.thinkFor(model));
    const body = buildChatBody(think === undefined ? req : { ...req, think }, this.options);
    const timeoutMs = req.timeoutMs ?? this.options.timeoutMs;
    const started = Date.now();
    await this.debug({ dir: 'request', purpose: req.purpose ?? 'other', body });
    let reply: RawReply;
    try {
      reply = await this.request('/api/chat', { method: 'POST', body, timeoutMs, signal: req.signal, retries: 1 });
    } catch (err) {
      const error = classifyNetworkError(err, this.options.host, timeoutMs, Boolean(req.signal?.aborted));
      await this.debug({ dir: 'error', purpose: req.purpose ?? 'other', kind: error.kind, message: error.message, durationMs: Date.now() - started });
      throw error;
    }
    if (reply.status < 200 || reply.status >= 300) {
      const error = classifyOllamaError(reply.status, reply.text, model);
      await this.debug({ dir: 'error', purpose: req.purpose ?? 'other', status: reply.status, kind: error.kind, message: error.message, durationMs: Date.now() - started });
      throw error;
    }
    let raw: unknown;
    try {
      raw = JSON.parse(reply.text);
    } catch (err) {
      await this.debug({ dir: 'error', purpose: req.purpose ?? 'other', kind: 'invalid-response', text: reply.text.slice(0, 2000) });
      throw new LlmError('invalid-response', `Ollama returned invalid JSON for ${model}`, { cause: err });
    }
    const response = parseChatResponse(raw, model);
    if (req.tools && req.tools.length > 0 && !(response.message.tool_calls && response.message.tool_calls.length > 0)) {
      const recovered = parseTextToolCalls(response.message.content, req.tools.map((t) => t.function.name));
      if (recovered.calls.length > 0) {
        response.message.tool_calls = recovered.calls;
        response.message.content = recovered.text;
      }
    }
    await this.debug({ dir: 'response', purpose: req.purpose ?? 'other', durationMs: Date.now() - started, response: raw });
    return response;
  }

  // never throws
  async checkModel(model?: string): Promise<ModelCheck> {
    const want = (model ?? this.model).trim();
    const host = this.options.host;
    let installed: InstalledModel[];
    try {
      const reply = await this.request('/api/tags', { method: 'GET', timeoutMs: PROBE_TIMEOUT_MS, retries: 0 });
      if (reply.status !== 200) {
        return { ok: false, model: want, installed: false, tools: null, resolvedModel: null, message: `Ollama at ${host} answered HTTP ${reply.status} for /api/tags`, fix: ['patch-pilot doctor'] };
      }
      const tags = JSON.parse(reply.text) as { models?: { name?: string; model?: string; digest?: string; size?: number; details?: { parameter_size?: string }; capabilities?: string[] }[] };
      installed = (tags.models ?? [])
        .map((m): InstalledModel => ({
          name: m.name ?? m.model ?? '',
          digest: m.digest ?? null,
          sizeBytes: typeof m.size === 'number' ? m.size : null,
          parameterSize: m.details?.parameter_size ?? null,
          capabilities: Array.isArray(m.capabilities) ? m.capabilities : null,
        }))
        .filter((m) => m.name !== '');
    } catch (err) {
      const error = classifyNetworkError(err, host, PROBE_TIMEOUT_MS, false);
      return { ok: false, model: want, installed: false, tools: null, resolvedModel: null, message: error.message, fix: error.hint ? [error.hint] : [] };
    }
    const resolved = resolveModelName(want, installed);
    if (!resolved) {
      const [base] = splitModelName(want);
      return {
        ok: false,
        model: want,
        installed: false,
        tools: null,
        resolvedModel: null,
        message: `Model ${want} is not installed in Ollama at ${host}`,
        fix: [pullCommandFor(want), `${LINKS.ollamaLibrary}${base}`],
      };
    }
    let capabilities = installed.find((m) => m.name === resolved)?.capabilities ?? null;
    try {
      const reply = await this.request('/api/show', { method: 'POST', body: { model: resolved }, timeoutMs: PROBE_TIMEOUT_MS * 2, retries: 0 });
      if (reply.status === 200) {
        const show = JSON.parse(reply.text) as { capabilities?: unknown };
        if (Array.isArray(show.capabilities)) capabilities = show.capabilities.filter((c): c is string => typeof c === 'string');
      }
    } catch {
      // keep /api/tags capabilities
    }
    this.capabilities.set(want, capabilities);
    this.capabilities.set(resolved, capabilities);
    const tools = capabilities ? capabilities.includes('tools') : null;
    if (tools === false) {
      const others = installed.filter((m) => m.name !== resolved && m.capabilities?.includes('tools')).map((m) => m.name);
      return {
        ok: false,
        model: want,
        installed: true,
        tools: false,
        resolvedModel: resolved,
        message: `${resolved} does not support tool calling`,
        fix: [others.length > 0 ? `Use a tool-capable model: --model ${others[0]}` : 'Pull a tool-capable model, for example: ollama pull qwen3:8b', LINKS.toolModels],
      };
    }
    const check: ModelCheck = { ok: true, model: want, installed: true, tools, resolvedModel: resolved };
    if (tools === null) check.message = `Could not read the capabilities of ${resolved}; assuming it supports tools`;
    return check;
  }

  // empty messages load without generating
  async warmup(): Promise<void> {
    const body = {
      model: this.model,
      messages: [],
      stream: false,
      keep_alive: this.options.keepAlive,
      options: { num_ctx: this.options.numCtx },
    };
    const started = Date.now();
    await this.debug({ dir: 'request', purpose: 'warmup', body });
    try {
      const reply = await this.request('/api/chat', { method: 'POST', body, timeoutMs: this.options.timeoutMs, retries: 0 });
      await this.debug({ dir: 'response', purpose: 'warmup', status: reply.status, durationMs: Date.now() - started, text: reply.text.slice(0, 500) });
    } catch (err) {
      await this.debug({ dir: 'error', purpose: 'warmup', message: err instanceof Error ? err.message : String(err), durationMs: Date.now() - started });
    }
  }

  // retry on connection errors and busy
  private async request(
    pathname: string,
    init: { method: 'GET' | 'POST'; body?: unknown; timeoutMs: number; signal?: AbortSignal; retries: number },
  ): Promise<RawReply> {
    const url = `${this.options.host}${pathname}`;
    const delay = this.options.retryDelayMs ?? 500;
    for (let attempt = 0; ; attempt += 1) {
      const timeout = AbortSignal.timeout(init.timeoutMs);
      const signal = init.signal ? AbortSignal.any([timeout, init.signal]) : timeout;
      try {
        const res = await this.fetchImpl(url, {
          method: init.method,
          headers: { 'user-agent': USER_AGENT, accept: 'application/json', ...(init.body === undefined ? {} : { 'content-type': 'application/json' }) },
          body: init.body === undefined ? undefined : JSON.stringify(init.body),
          signal,
        });
        const text = await res.text();
        if (attempt < init.retries && RETRY_STATUSES.has(res.status)) {
          await sleep(delay * 2 ** attempt, init.signal);
          continue;
        }
        return { status: res.status, text };
      } catch (err) {
        if (err instanceof LlmError) throw err;
        // a timeout or caller abort is final
        const timedOut = timeout.aborted || (err as { name?: unknown } | null)?.name === 'TimeoutError';
        if (timedOut || init.signal?.aborted || attempt >= init.retries) throw err;
        await sleep(delay * 2 ** attempt, init.signal);
      }
    }
  }

  // never throws
  private async debug(entry: Record<string, unknown>): Promise<void> {
    const file = this.options.debugLog;
    if (!file) return;
    try {
      await mkdir(path.dirname(file), { recursive: true });
      const record = redactSecrets({ ts: new Date().toISOString(), host: this.options.host, model: this.model, ...entry });
      await appendFile(file, `${JSON.stringify(record)}\n`, 'utf8');
    } catch {
      // debugging must never break a run
    }
  }
}
