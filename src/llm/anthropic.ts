// claude via api key only
import { createHash } from 'node:crypto';
import { appendFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { redactSecrets } from '../audit.ts';
import type { ChatMessage, ChatRequest, ChatResponse, ChatUsage, JsonSchema, ModelCheck, ThinkMode, ToolCall } from '../types.ts';
import { stableStringify } from '../util/fs.ts';
import { USER_AGENT } from '../version.ts';
import { LlmError } from './errors.ts';
import type { ChatProvider, ProviderUsageSummary } from './provider.ts';
import { normalizeToolArguments } from './textToolCalls.ts';

export const ANTHROPIC_MESSAGES_URL = 'https://api.anthropic.com/v1/messages';
export const ANTHROPIC_VERSION = '2023-06-01';
export const ANTHROPIC_KEYS_URL = 'https://console.anthropic.com/settings/keys';
// carries structured output
export const SUBMIT_TOOL = 'submit';
export const DEFAULT_CLAUDE_MODEL = 'sonnet';

// full ids pass through
export const CLAUDE_MODEL_ALIASES: Readonly<Record<string, string>> = {
  sonnet: 'claude-sonnet-5',
  opus: 'claude-opus-5-5',
  haiku: 'claude-haiku-4-5',
};

const RETRY_STATUSES: ReadonlySet<number> = new Set([429, 500, 502, 503, 504, 529]);
const DEFAULT_MAX_TOKENS = 4096;
// thinking counts toward max_tokens
const THINKING_HEADROOM = 16_000;
const MAX_TOKENS_CAP = 64_000;
const MAX_ADAPTATIONS = 3;
const REPLAY_LIMIT = 256;
const MAX_RETRY_WAIT_MS = 30_000;
// thinking turns are slower
const THINKING_TIMEOUT_MS = 300_000;

const SUBMIT_DESCRIPTION = 'Submit the final answer. The input must follow the schema exactly; it is the whole answer, so do not also write it as text.';
const SUBMIT_INSTRUCTION = 'When you have the answer, call the submit tool with it (its input is the whole answer) instead of writing the answer as text.';

export function resolveClaudeModel(name: string): string {
  const trimmed = name.trim();
  return CLAUDE_MODEL_ALIASES[trimmed.toLowerCase()] ?? trimmed;
}

export function isClaudeModelName(name: string | null | undefined): boolean {
  if (!name) return false;
  const key = name.trim().toLowerCase();
  return Object.hasOwn(CLAUDE_MODEL_ALIASES, key) || /^claude-[a-z0-9][a-z0-9.-]*$/.test(key);
}

export interface ClaudeModelTraits {
  // 4.7+ and 5 series reject sampling
  sampling: boolean;
  adaptiveByDefault: boolean;
  canDisableThinking: boolean;
  adaptive: boolean;
  forcedToolChoice: boolean;
  // output_config.effort
  effort: boolean;
  // bound to the exact prompt prefix
  boundThinking: boolean;
}

const NEW_GENERATION: ClaudeModelTraits = {
  sampling: false,
  adaptiveByDefault: true,
  canDisableThinking: false,
  adaptive: true,
  forcedToolChoice: true,
  effort: false,
  boundThinking: true,
};

// unknown ids get newest traits
export function claudeModelTraits(model: string): ClaudeModelTraits {
  const id = model.trim().toLowerCase();
  const dated = (base: string): boolean => id === base || new RegExp(`^${base}-\\d{8}$`).test(id);
  if (/^claude-(opus-5-5|fable-5-1|mythos-5-1)(\b|-)/.test(id)) {
    return { sampling: false, adaptiveByDefault: true, canDisableThinking: false, adaptive: true, forcedToolChoice: false, effort: true, boundThinking: true };
  }
  if (dated('claude-fable-5') || dated('claude-mythos-5')) {
    return { sampling: false, adaptiveByDefault: true, canDisableThinking: false, adaptive: true, forcedToolChoice: true, effort: true, boundThinking: false };
  }
  if (dated('claude-opus-5') || /^claude-sonnet-5(\b|-)/.test(id)) {
    return { sampling: false, adaptiveByDefault: true, canDisableThinking: true, adaptive: true, forcedToolChoice: true, effort: true, boundThinking: false };
  }
  if (/^claude-opus-4-[78](\b|-)/.test(id)) {
    return { sampling: false, adaptiveByDefault: false, canDisableThinking: true, adaptive: true, forcedToolChoice: true, effort: true, boundThinking: false };
  }
  if (/^claude-(opus|sonnet)-4-6(\b|-)/.test(id)) {
    return { sampling: true, adaptiveByDefault: false, canDisableThinking: true, adaptive: true, forcedToolChoice: true, effort: true, boundThinking: false };
  }
  if (/^claude-(haiku-4-5|opus-4|sonnet-4|3)/.test(id)) {
    return { sampling: true, adaptiveByDefault: false, canDisableThinking: true, adaptive: false, forcedToolChoice: true, effort: false, boundThinking: false };
  }
  return { ...NEW_GENERATION };
}

// usd per million tokens, in/out
const PRICING: readonly [RegExp, number, number][] = [
  [/^claude-opus-5-5/, 4, 20],
  [/^claude-(fable|mythos)-5/, 10, 50],
  [/^claude-opus-5/, 5, 25],
  [/^claude-opus-4-[5-9]/, 5, 25],
  [/^claude-opus-4/, 15, 75],
  [/^claude-sonnet-5/, 2, 10],
  [/^claude-sonnet-4/, 3, 15],
  [/^claude-3-7-sonnet|^claude-3-5-sonnet/, 3, 15],
  [/^claude-haiku-4-5/, 1, 5],
  [/^claude-3-5-haiku/, 0.8, 4],
  [/^claude-3-haiku/, 0.25, 1.25],
];

export function claudePricing(model: string): { inputPerMTok: number; outputPerMTok: number } | null {
  const id = model.trim().toLowerCase();
  const row = PRICING.find(([re]) => re.test(id));
  return row ? { inputPerMTok: row[1], outputPerMTok: row[2] } : null;
}

export interface AnthropicUsageCounts {
  input_tokens?: number;
  output_tokens?: number;
  cache_creation_input_tokens?: number;
  cache_read_input_tokens?: number;
}

// null for unknown models
export function estimateClaudeCostUsd(model: string, usage: AnthropicUsageCounts): number | null {
  const price = claudePricing(model);
  if (!price) return null;
  const n = (v: number | undefined): number => (typeof v === 'number' && Number.isFinite(v) ? v : 0);
  const input = n(usage.input_tokens) + n(usage.cache_creation_input_tokens) * 1.25 + n(usage.cache_read_input_tokens) * 0.1;
  return (input * price.inputPerMTok + n(usage.output_tokens) * price.outputPerMTok) / 1_000_000;
}

export interface AnthropicChatUsage extends ChatUsage {
  costUsd?: number;
  cacheReadTokens?: number;
  cacheWriteTokens?: number;
}

type Block = Record<string, unknown>;

export interface WireMessage {
  role: 'user' | 'assistant';
  content: Block[];
}

// replayed verbatim
export interface ReplayEntry {
  blocks: Block[];
  toolIds: string[];
  toolNames: string[];
}

export interface MapOptions {
  // by history key
  replay?: (key: string) => ReplayEntry | undefined;
  // tools as text, no tool blocks
  flattenTools?: boolean;
  stripThinking?: boolean;
}

// hash of what the model saw
export function historyKey(messages: readonly ChatMessage[]): string {
  const shape = messages.map((m) => [
    m.role,
    m.content ?? '',
    m.tool_name ?? null,
    (m.tool_calls ?? []).map((c) => [c.function?.name ?? '', c.function?.arguments ?? {}]),
  ]);
  return createHash('sha256').update(stableStringify(shape)).digest('hex');
}

function toolInput(args: unknown): Record<string, unknown> {
  return args && typeof args === 'object' && !Array.isArray(args) ? (args as Record<string, unknown>) : {};
}

export function mapMessages(input: readonly ChatMessage[], options: MapOptions = {}): { system: string; messages: WireMessage[] } {
  const systemParts: string[] = [];
  const out: WireMessage[] = [];
  let pending: { id: string; name: string }[] = [];
  let seq = 0;
  const newId = (): string => {
    seq += 1;
    return `toolu_pp_${String(seq).padStart(4, '0')}`;
  };
  const push = (role: WireMessage['role'], blocks: Block[]): void => {
    if (blocks.length === 0) return;
    const last = out[out.length - 1];
    if (last && last.role === role) last.content.push(...blocks);
    else out.push({ role, content: [...blocks] });
  };
  // tool_use needs a tool_result
  const closePending = (): void => {
    if (pending.length === 0) return;
    push(
      'user',
      pending.map((p) => ({ type: 'tool_result', tool_use_id: p.id, content: '(no result was returned for this call)' })),
    );
    pending = [];
  };
  input.forEach((m, index) => {
    const content = typeof m.content === 'string' ? m.content : '';
    if (m.role === 'system') {
      if (content.trim() !== '') systemParts.push(content);
      return;
    }
    if (m.role === 'tool') {
      const text = content === '' ? '(no output)' : content;
      if (options.flattenTools || pending.length === 0) {
        push('user', [{ type: 'text', text: `Result of ${m.tool_name ?? 'the tool call'}:\n${text}` }]);
        return;
      }
      let at = pending.findIndex((p) => p.name === m.tool_name);
      if (at === -1) at = 0;
      const [slot] = pending.splice(at, 1);
      push('user', [{ type: 'tool_result', tool_use_id: (slot as { id: string }).id, content: text }]);
      return;
    }
    if (m.role === 'user') {
      closePending();
      push('user', [{ type: 'text', text: content.trim() === '' ? '(empty message)' : content }]);
      return;
    }
    closePending();
    const calls = (m.tool_calls ?? []).filter((c) => typeof c?.function?.name === 'string' && c.function.name !== '');
    if (calls.length === 0) {
      if (content.trim() !== '') push('assistant', [{ type: 'text', text: content }]);
      return;
    }
    if (options.flattenTools) {
      const lines = calls.map((c) => `[called ${c.function.name} ${JSON.stringify(toolInput(c.function.arguments))}]`);
      push('assistant', [{ type: 'text', text: [content.trim(), ...lines].filter(Boolean).join('\n') }]);
      return;
    }
    const replay = options.replay?.(historyKey(input.slice(0, index)));
    if (replay && replay.toolNames.length === calls.length && replay.toolNames.every((name, i) => name === calls[i]?.function.name)) {
      const blocks = options.stripThinking ? replay.blocks.filter((b) => b.type !== 'thinking' && b.type !== 'redacted_thinking') : replay.blocks;
      push('assistant', structuredClone(blocks));
      pending = replay.toolIds.map((id, i) => ({ id, name: replay.toolNames[i] ?? '' }));
      return;
    }
    const blocks: Block[] = [];
    if (content.trim() !== '') blocks.push({ type: 'text', text: content });
    for (const call of calls) {
      const id = newId();
      blocks.push({ type: 'tool_use', id, name: call.function.name, input: toolInput(call.function.arguments) });
      pending.push({ id, name: call.function.name });
    }
    push('assistant', blocks);
  });
  closePending();
  if (out.length === 0 || out[0]?.role !== 'user') out.unshift({ role: 'user', content: [{ type: 'text', text: '(start)' }] });
  // no prefill on current models
  if (out[out.length - 1]?.role === 'assistant') out.push({ role: 'user', content: [{ type: 'text', text: 'Continue.' }] });
  return { system: systemParts.join('\n\n'), messages: out };
}

// thinkingOn adds max_tokens headroom
export function thinkingSettings(traits: ClaudeModelTraits, think: ThinkMode): { thinking?: Record<string, unknown>; effort?: string; thinkingOn: boolean } {
  if (think === 'off') {
    if (!traits.adaptiveByDefault) return { thinkingOn: false };
    if (traits.canDisableThinking) return { thinking: { type: 'disabled' }, thinkingOn: false };
    // cannot disable (opus 5.5, fable), go low
    return traits.effort ? { effort: 'low', thinkingOn: true } : { thinkingOn: true };
  }
  if (think === 'on') {
    if (!traits.adaptive) return { thinkingOn: false };
    return traits.effort ? { thinking: { type: 'adaptive' }, effort: 'high', thinkingOn: true } : { thinking: { type: 'adaptive' }, thinkingOn: true };
  }
  return { thinkingOn: traits.adaptiveByDefault };
}

export interface BuildOptions extends MapOptions {
  model: string;
  traits: ClaudeModelTraits;
  think: ThinkMode;
}

export function buildAnthropicRequest(req: ChatRequest, options: BuildOptions): Record<string, unknown> {
  const format = req.format;
  const { system: mappedSystem, messages } = mapMessages(req.messages ?? [], options);
  const settings = thinkingSettings(options.traits, options.think);
  const tools: Block[] = (req.tools ?? []).map((t) => ({
    name: t.function.name,
    description: t.function.description,
    input_schema: t.function.parameters,
  }));
  let system = mappedSystem;
  let toolChoice: Record<string, unknown> | undefined;
  if (format !== undefined) {
    const schema: JsonSchema = format === 'json' ? { type: 'object' } : format;
    tools.push({ name: SUBMIT_TOOL, description: SUBMIT_DESCRIPTION, input_schema: schema });
    if (options.traits.forcedToolChoice) toolChoice = { type: 'tool', name: SUBMIT_TOOL };
    else {
      toolChoice = { type: 'auto' };
      system = system ? `${system}\n\n${SUBMIT_INSTRUCTION}` : SUBMIT_INSTRUCTION;
    }
  }
  const requested = req.options?.num_predict;
  const base = typeof requested === 'number' && Number.isFinite(requested) && requested > 0 ? Math.max(256, Math.floor(requested)) : DEFAULT_MAX_TOKENS;
  const body: Record<string, unknown> = {
    model: options.model,
    max_tokens: Math.min(MAX_TOKENS_CAP, base + (settings.thinkingOn ? THINKING_HEADROOM : 0)),
  };
  if (system) body.system = system;
  body.messages = messages;
  if (tools.length > 0) body.tools = tools;
  if (toolChoice) body.tool_choice = toolChoice;
  if (options.traits.sampling) body.temperature = 0;
  if (settings.thinking) body.thinking = settings.thinking;
  if (settings.effort) body.output_config = { effort: settings.effort };
  if (req.options?.stop && req.options.stop.length > 0) body.stop_sequences = req.options.stop;
  return body;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

const count = (value: unknown): number | undefined => (typeof value === 'number' && Number.isFinite(value) ? value : undefined);

export interface ParsedAnthropicResponse {
  response: ChatResponse;
  // kept for replay
  blocks: Block[];
  toolIds: string[];
  toolNames: string[];
  inputTokens: number;
  outputTokens: number;
  costUsd: number | null;
}

// submit tool input becomes content
export function parseAnthropicResponse(raw: unknown, options: { model: string; format: boolean; durationMs?: number }): ParsedAnthropicResponse {
  if (!isRecord(raw) || !Array.isArray(raw.content)) throw new LlmError('invalid-response', `The Anthropic API returned an unexpected response for ${options.model}`);
  const blocks = raw.content.filter(isRecord);
  const stopReason = typeof raw.stop_reason === 'string' ? raw.stop_reason : undefined;
  const model = typeof raw.model === 'string' && raw.model !== '' ? raw.model : options.model;
  if (stopReason === 'refusal') {
    const details = isRecord(raw.stop_details) ? raw.stop_details : {};
    const category = typeof details.category === 'string' ? ` (${details.category})` : '';
    throw new LlmError('invalid-response', `Claude declined to answer this request${category}`, {
      hint: 'The verdict for this vulnerability is derived from the evidence instead; try another model with --model if it keeps happening.',
    });
  }
  const text = blocks
    .filter((b) => b.type === 'text' && typeof b.text === 'string')
    .map((b) => b.text as string)
    .join('');
  const thinking = blocks
    .filter((b) => b.type === 'thinking' && typeof b.thinking === 'string' && b.thinking !== '')
    .map((b) => b.thinking as string)
    .join('\n');
  const uses = blocks.filter((b) => b.type === 'tool_use' && typeof b.name === 'string');
  const message: ChatMessage = { role: 'assistant', content: text };
  const toolIds: string[] = [];
  const toolNames: string[] = [];
  if (options.format) {
    const submit = uses.find((b) => b.name === SUBMIT_TOOL);
    if (submit) message.content = JSON.stringify(isRecord(submit.input) ? submit.input : normalizeToolArguments(submit.input));
  } else if (uses.length > 0) {
    message.tool_calls = uses.map((b, index): ToolCall => {
      const call: ToolCall = { function: { name: String(b.name), arguments: normalizeToolArguments(b.input), index }, source: 'native' };
      if (typeof b.id === 'string') call.id = b.id;
      return call;
    });
    for (const b of uses) {
      toolIds.push(typeof b.id === 'string' ? b.id : '');
      toolNames.push(String(b.name));
    }
  }
  if (thinking) message.thinking = thinking;
  const u = isRecord(raw.usage) ? (raw.usage as AnthropicUsageCounts) : {};
  const inputTokens = (count(u.input_tokens) ?? 0) + (count(u.cache_creation_input_tokens) ?? 0) + (count(u.cache_read_input_tokens) ?? 0);
  const outputTokens = count(u.output_tokens) ?? 0;
  const costUsd = estimateClaudeCostUsd(model, u);
  const usage: AnthropicChatUsage = { promptTokens: inputTokens, completionTokens: outputTokens };
  if (options.durationMs !== undefined) usage.totalMs = options.durationMs;
  if (costUsd !== null) usage.costUsd = costUsd;
  if (count(u.cache_read_input_tokens)) usage.cacheReadTokens = count(u.cache_read_input_tokens) as number;
  if (count(u.cache_creation_input_tokens)) usage.cacheWriteTokens = count(u.cache_creation_input_tokens) as number;
  const response: ChatResponse = { message, model, done: true, usage };
  if (stopReason) response.doneReason = stopReason;
  return { response, blocks, toolIds, toolNames, inputTokens, outputTokens, costUsd };
}

export function parseAnthropicError(body: string): { type: string | null; message: string } {
  const text = (body ?? '').trim();
  try {
    const parsed = JSON.parse(text) as unknown;
    if (isRecord(parsed) && isRecord(parsed.error)) {
      return { type: typeof parsed.error.type === 'string' ? parsed.error.type : null, message: typeof parsed.error.message === 'string' ? parsed.error.message : text.slice(0, 300) };
    }
  } catch {
    // plain-text body
  }
  return { type: null, message: text.slice(0, 300) };
}

const KEY_HINT = `Check the key: patch-pilot config set anthropic-api-key (asks without echo), or export ANTHROPIC_API_KEY. Keys: ${ANTHROPIC_KEYS_URL}`;

// key, billing, model errors stop the run
export function classifyAnthropicError(status: number, body: string, model: string): LlmError {
  const { type, message } = parseAnthropicError(body);
  const detail = message || `HTTP ${status}`;
  const lower = detail.toLowerCase();
  const label = `${status}${type ? ` ${type}` : ''}`;
  if (status === 401 || type === 'authentication_error') {
    return new LlmError('unreachable', `The Anthropic API rejected the API key (${label}: ${detail})`, { status, hint: KEY_HINT });
  }
  if (status === 402 || type === 'billing_error') {
    return new LlmError('unreachable', `The Anthropic API refused the request for a billing reason (${label}: ${detail})`, {
      status,
      hint: 'Check the plan and credit balance of the organisation that owns the key: https://console.anthropic.com/settings/billing',
    });
  }
  if (status === 403 || type === 'permission_error') {
    return new LlmError('unreachable', `The API key is not allowed to use ${model} (${label}: ${detail})`, { status, hint: `${KEY_HINT}. Or pick another model: --model sonnet, opus or haiku.` });
  }
  if (status === 404 || type === 'not_found_error') {
    return new LlmError('model-missing', `Model ${model} is not available to this Anthropic API key (${label}: ${detail})`, {
      status,
      hint: 'Use --model sonnet, opus or haiku, or a full model id (https://docs.anthropic.com/en/docs/about-claude/models).',
    });
  }
  if (status === 413 || type === 'request_too_large' || /prompt is too long|too many tokens|context (window|length)/.test(lower)) {
    return new LlmError('out-of-memory', `The request is too large for ${model} (${label}: ${detail})`, { status, hint: 'Narrow the run with --only <package>, or lower --max-steps.' });
  }
  if (status === 429 || type === 'rate_limit_error') {
    return new LlmError('http', `The Anthropic API rate limit was reached (${label}: ${detail})`, {
      status,
      hint: 'Wait a minute, then continue with patch-pilot investigate --resume (or narrow the run with --only / --limit).',
    });
  }
  if (status === 529 || type === 'overloaded_error') {
    return new LlmError('http', `The Anthropic API is overloaded (${label}: ${detail})`, { status, hint: 'Try again shortly, or use a lighter model: --model haiku.' });
  }
  return new LlmError('http', `The Anthropic API returned HTTP ${label}: ${detail}`, { status });
}

// 400 naming a rejected feature
export function adaptationFor(
  message: string,
  state: { traits: ClaudeModelTraits; flattenTools: boolean; stripThinking: boolean },
): 'tool_choice' | 'sampling' | 'thinking-disabled' | 'thinking-adaptive' | 'effort' | 'strip-thinking' | 'flatten-tools' | null {
  const m = message.toLowerCase();
  if (/tool_choice/.test(m) && state.traits.forcedToolChoice) return 'tool_choice';
  if (/\b(temperature|top_p|top_k)\b/.test(m) && state.traits.sampling) return 'sampling';
  if (/signature|thinking block|different conversation/.test(m) && !state.stripThinking) return 'strip-thinking';
  if (/thinking\.type\.disabled|"disabled"|thinking.*disabled/.test(m) && state.traits.canDisableThinking) return 'thinking-disabled';
  if (/thinking\.type\.adaptive|adaptive/.test(m) && state.traits.adaptive) return 'thinking-adaptive';
  if (/effort|output_config/.test(m) && state.traits.effort) return 'effort';
  if (/tool_use|tool_result/.test(m) && !state.flattenTools) return 'flatten-tools';
  return null;
}

function applyAdaptation(kind: NonNullable<ReturnType<typeof adaptationFor>>, state: { traits: ClaudeModelTraits; flattenTools: boolean; stripThinking: boolean }): void {
  switch (kind) {
    case 'tool_choice':
      state.traits.forcedToolChoice = false;
      break;
    case 'sampling':
      state.traits.sampling = false;
      break;
    case 'thinking-disabled':
      state.traits.canDisableThinking = false;
      break;
    case 'thinking-adaptive':
      state.traits.adaptive = false;
      break;
    case 'effort':
      state.traits.effort = false;
      break;
    case 'strip-thinking':
      state.stripThinking = true;
      break;
    default:
      state.flattenTools = true;
  }
}

export interface AnthropicProviderOptions {
  apiKey: string;
  // alias or id
  model: string;
  // per attempt
  timeoutMs: number;
  // off disables thinking where allowed
  think?: ThinkMode;
  // only with PATCHPILOT_DEBUG=1
  debugLog?: string | null;
  // for tests
  fetch?: typeof fetch;
  // 429, 5xx, 529, network (default 3)
  maxRetries?: number;
  // doubled per attempt unless retry-after
  retryDelayMs?: number;
  // for tests
  url?: string;
}

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

// seconds or http date
export function retryAfterMs(value: string | null | undefined, now = Date.now()): number | null {
  if (!value) return null;
  const seconds = Number(value.trim());
  if (Number.isFinite(seconds) && seconds >= 0) return seconds * 1000;
  const at = Date.parse(value);
  return Number.isNaN(at) ? null : Math.max(0, at - now);
}

function networkError(err: unknown, timeoutMs: number, callerAborted: boolean): LlmError {
  if (err instanceof LlmError) return err;
  if (callerAborted) return new LlmError('aborted', 'Request aborted', { cause: err });
  const e = err as { name?: string; message?: string; cause?: { code?: string; message?: string } };
  if (e?.name === 'TimeoutError') {
    return new LlmError('timeout', `The Anthropic API did not answer within ${Math.round(timeoutMs / 1000)} s`, {
      cause: err,
      hint: 'Try again; narrow the run with --only if large prompts keep timing out.',
    });
  }
  if (e?.name === 'AbortError') return new LlmError('aborted', 'Request aborted', { cause: err });
  const reason = e?.cause?.code ?? e?.cause?.message ?? e?.message ?? String(err);
  return new LlmError('unreachable', `The Anthropic API is not reachable (${reason})`, {
    cause: err,
    hint: 'Check the network connection (PatchPilot needs https://api.anthropic.com for --provider claude).',
  });
}

interface RawReply {
  status: number;
  text: string;
}

export class AnthropicProvider implements ChatProvider {
  readonly name = 'claude' as const;
  // aliases expanded
  readonly model: string;
  readonly options: AnthropicProviderOptions;
  private readonly fetchImpl: typeof fetch;
  private readonly traits = new Map<string, ClaudeModelTraits>();
  private readonly flags = new Map<string, { flattenTools: boolean; stripThinking: boolean }>();
  private readonly replays = new Map<string, ReplayEntry>();
  private readonly totals = { requests: 0, inputTokens: 0, outputTokens: 0, costUsd: 0, costKnown: true };

  constructor(options: AnthropicProviderOptions) {
    this.options = options;
    this.model = resolveClaudeModel(options.model);
    this.fetchImpl = options.fetch ?? ((input, init) => fetch(input, init));
  }

  // adaptations persist for the run
  traitsFor(model: string): ClaudeModelTraits {
    let traits = this.traits.get(model);
    if (!traits) {
      traits = claudeModelTraits(model);
      this.traits.set(model, traits);
    }
    return traits;
  }

  async chat(req: ChatRequest): Promise<ChatResponse> {
    const model = resolveClaudeModel(req.model ?? this.model);
    const traits = this.traitsFor(model);
    const flags = this.flags.get(model) ?? { flattenTools: false, stripThinking: false };
    this.flags.set(model, flags);
    const format = req.format !== undefined;
    const purpose = req.purpose ?? 'other';
    // higher timeout floor for thinking
    const thinking = thinkingSettings(traits, this.options.think ?? 'off').thinkingOn;
    const timeoutMs = req.timeoutMs ?? (thinking ? Math.max(this.options.timeoutMs, THINKING_TIMEOUT_MS) : this.options.timeoutMs);
    const key = historyKey(req.messages ?? []);
    for (let adaptations = 0; ; adaptations += 1) {
      const state = { traits, flattenTools: flags.flattenTools, stripThinking: flags.stripThinking || (format && traits.boundThinking) };
      const body = buildAnthropicRequest(req, {
        model,
        traits,
        think: this.options.think ?? 'off',
        replay: (k) => this.replays.get(k),
        flattenTools: state.flattenTools,
        stripThinking: state.stripThinking,
      });
      const started = Date.now();
      await this.debug({ dir: 'request', purpose, body });
      let reply: RawReply;
      try {
        reply = await this.send(body, timeoutMs, req.signal);
      } catch (err) {
        const error = networkError(err, timeoutMs, Boolean(req.signal?.aborted));
        await this.debug({ dir: 'error', purpose, kind: error.kind, message: error.message, durationMs: Date.now() - started });
        throw error;
      }
      if (reply.status >= 200 && reply.status < 300) {
        let raw: unknown;
        try {
          raw = JSON.parse(reply.text);
        } catch (err) {
          await this.debug({ dir: 'error', purpose, kind: 'invalid-response', text: reply.text.slice(0, 2000) });
          throw new LlmError('invalid-response', `The Anthropic API returned invalid JSON for ${model}`, { cause: err });
        }
        let parsed: ParsedAnthropicResponse;
        try {
          parsed = parseAnthropicResponse(raw, { model, format, durationMs: Date.now() - started });
        } catch (err) {
          await this.debug({ dir: 'error', purpose, kind: err instanceof LlmError ? err.kind : 'invalid-response', message: (err as Error).message, response: raw });
          throw err;
        }
        this.record(parsed);
        if (!format && parsed.toolIds.length > 0 && parsed.toolIds.every((id) => id !== '')) this.remember(key, parsed);
        await this.debug({ dir: 'response', purpose, durationMs: Date.now() - started, response: raw });
        return parsed.response;
      }
      const { message } = parseAnthropicError(reply.text);
      if (reply.status === 400 && adaptations < MAX_ADAPTATIONS) {
        const kind = adaptationFor(message, state);
        if (kind) {
          applyAdaptation(kind, state);
          flags.flattenTools = state.flattenTools;
          if (kind === 'strip-thinking') flags.stripThinking = true;
          await this.debug({ dir: 'adapt', purpose, adaptation: kind, message });
          continue;
        }
      }
      const error = classifyAnthropicError(reply.status, reply.text, model);
      await this.debug({ dir: 'error', purpose, status: reply.status, kind: error.kind, message: error.message, durationMs: Date.now() - started });
      throw error;
    }
  }

  // no network call
  async checkModel(model?: string): Promise<ModelCheck> {
    const want = (model ?? this.model).trim();
    if (isClaudeModelName(want)) {
      const resolved = resolveClaudeModel(want);
      return { ok: true, model: want, installed: true, tools: true, resolvedModel: resolved };
    }
    return {
      ok: false,
      model: want,
      installed: false,
      tools: null,
      resolvedModel: null,
      message: `${want} is not a Claude model`,
      fix: ['Use --model sonnet, opus or haiku, or a full model id such as claude-sonnet-5'],
    };
  }

  // api is always warm
  async warmup(): Promise<void> {}

  usageSummary(): ProviderUsageSummary {
    return {
      requests: this.totals.requests,
      inputTokens: this.totals.inputTokens,
      outputTokens: this.totals.outputTokens,
      costUsd: this.totals.costKnown ? this.totals.costUsd : null,
    };
  }

  private record(parsed: ParsedAnthropicResponse): void {
    this.totals.requests += 1;
    this.totals.inputTokens += parsed.inputTokens;
    this.totals.outputTokens += parsed.outputTokens;
    if (parsed.costUsd === null) this.totals.costKnown = false;
    else this.totals.costUsd += parsed.costUsd;
  }

  private remember(key: string, parsed: ParsedAnthropicResponse): void {
    this.replays.set(key, { blocks: structuredClone(parsed.blocks), toolIds: [...parsed.toolIds], toolNames: [...parsed.toolNames] });
    if (this.replays.size > REPLAY_LIMIT) {
      const oldest = this.replays.keys().next().value;
      if (oldest !== undefined) this.replays.delete(oldest);
    }
  }

  private async send(body: Record<string, unknown>, timeoutMs: number, callerSignal?: AbortSignal): Promise<RawReply> {
    const retries = this.options.maxRetries ?? 3;
    const base = this.options.retryDelayMs ?? 1000;
    for (let attempt = 0; ; attempt += 1) {
      const timeout = AbortSignal.timeout(timeoutMs);
      const signal = callerSignal ? AbortSignal.any([timeout, callerSignal]) : timeout;
      try {
        const res = await this.fetchImpl(this.options.url ?? ANTHROPIC_MESSAGES_URL, {
          method: 'POST',
          headers: {
            'x-api-key': this.options.apiKey,
            'anthropic-version': ANTHROPIC_VERSION,
            'content-type': 'application/json',
            accept: 'application/json',
            'user-agent': USER_AGENT,
          },
          body: JSON.stringify(body),
          signal,
        });
        const text = await res.text();
        if (attempt < retries && RETRY_STATUSES.has(res.status)) {
          const after = retryAfterMs(res.headers?.get?.('retry-after'));
          await sleep(Math.min(MAX_RETRY_WAIT_MS, after ?? base * 2 ** attempt), callerSignal);
          continue;
        }
        return { status: res.status, text };
      } catch (err) {
        if (err instanceof LlmError) throw err;
        const name = (err as { name?: string })?.name;
        if (callerSignal?.aborted || name === 'TimeoutError' || attempt >= retries) throw err;
        await sleep(Math.min(MAX_RETRY_WAIT_MS, base * 2 ** attempt), callerSignal);
      }
    }
  }

  // never throws, never logs the key
  private async debug(entry: Record<string, unknown>): Promise<void> {
    const file = this.options.debugLog;
    if (!file) return;
    try {
      await mkdir(path.dirname(file), { recursive: true });
      const record = redactSecrets({ ts: new Date().toISOString(), provider: 'claude', model: this.model, ...entry });
      await appendFile(file, `${JSON.stringify(record)}\n`, 'utf8');
    } catch {
      // debug must not break a run
    }
  }
}
