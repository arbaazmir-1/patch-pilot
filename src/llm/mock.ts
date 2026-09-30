// scripted, for tests and --provider mock
import type { ChatMessage, ChatPurpose, ChatRequest, ChatResponse, ChatRole, ModelCheck, ToolCall } from '../types.ts';
import { synthesizeFromSchema } from '../util/schema.ts';
import { LlmError, type LlmErrorKind } from './errors.ts';
import type { ChatProvider } from './provider.ts';

export interface MockToolCallSpec {
  name: string;
  arguments?: Record<string, unknown>;
}

export interface MockReply {
  content?: string;
  toolCalls?: MockToolCallSpec[];
  // for format requests
  json?: unknown;
  thinking?: string;
  // throws an LlmError
  error?: { message: string; kind?: LlmErrorKind; status?: number };
  delayMs?: number;
}

// all must hold, case-sensitive
export interface MockMatcher {
  purpose?: ChatPurpose | ChatPurpose[];
  model?: string;
  hasTools?: boolean;
  // tools include all of these
  toolNames?: string[];
  hasFormat?: boolean;
  lastRole?: ChatRole;
  // last message is this tool's result
  lastToolName?: string;
  lastUserIncludes?: string;
  lastMessageIncludes?: string;
  anyMessageIncludes?: string;
  systemIncludes?: string;
  // against all contents, newline-joined
  pattern?: string;
}

export interface MockRule {
  id?: string;
  match?: MockMatcher;
  replies: MockReply[];
  // repeat last reply when out
  repeat?: boolean;
}

export interface MockScript {
  rules: MockRule[];
  // unmatched: synthesize or throw
  fallback?: 'synthesize' | 'error';
}

interface RuleState {
  rule: MockRule;
  used: number;
}

function asArray<T>(v: T | T[] | undefined): T[] {
  if (v === undefined) return [];
  return Array.isArray(v) ? v : [v];
}

function lastOf(messages: ChatMessage[], role?: ChatRole): ChatMessage | undefined {
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    const m = messages[i];
    if (m && (role === undefined || m.role === role)) return m;
  }
  return undefined;
}

export function matchesRequest(matcher: MockMatcher | undefined, req: ChatRequest, defaultModel: string): boolean {
  if (!matcher) return true;
  const messages = req.messages ?? [];
  if (matcher.purpose !== undefined && !asArray(matcher.purpose).includes(req.purpose ?? 'other')) return false;
  if (matcher.model !== undefined && (req.model ?? defaultModel) !== matcher.model) return false;
  const tools = req.tools ?? [];
  if (matcher.hasTools !== undefined && (tools.length > 0) !== matcher.hasTools) return false;
  if (matcher.toolNames && !matcher.toolNames.every((n) => tools.some((t) => t.function.name === n))) return false;
  if (matcher.hasFormat !== undefined && (req.format !== undefined) !== matcher.hasFormat) return false;
  const last = messages[messages.length - 1];
  if (matcher.lastRole !== undefined && last?.role !== matcher.lastRole) return false;
  if (matcher.lastToolName !== undefined && !(last?.role === 'tool' && last.tool_name === matcher.lastToolName)) return false;
  if (matcher.lastUserIncludes !== undefined && !(lastOf(messages, 'user')?.content ?? '').includes(matcher.lastUserIncludes)) return false;
  if (matcher.lastMessageIncludes !== undefined && !(last?.content ?? '').includes(matcher.lastMessageIncludes)) return false;
  if (matcher.anyMessageIncludes !== undefined && !messages.some((m) => m.content.includes(matcher.anyMessageIncludes as string))) {
    return false;
  }
  if (matcher.systemIncludes !== undefined && !messages.some((m) => m.role === 'system' && m.content.includes(matcher.systemIncludes as string))) {
    return false;
  }
  if (matcher.pattern !== undefined) {
    const all = messages.map((m) => m.content).join('\n');
    if (!new RegExp(matcher.pattern, 'm').test(all)) return false;
  }
  return true;
}

// throws on the first problem
export function parseMockScript(raw: unknown): MockScript {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('Mock script must be an object with "rules"');
  const obj = raw as Record<string, unknown>;
  if (!Array.isArray(obj.rules)) throw new Error('Mock script needs a "rules" array');
  if (obj.fallback !== undefined && obj.fallback !== 'synthesize' && obj.fallback !== 'error') {
    throw new Error('Mock script "fallback" must be "synthesize" or "error"');
  }
  obj.rules.forEach((rule, i) => {
    if (!rule || typeof rule !== 'object') throw new Error(`rules[${i}] must be an object`);
    const r = rule as Record<string, unknown>;
    if (!Array.isArray(r.replies) || r.replies.length === 0) throw new Error(`rules[${i}].replies must be a non-empty array`);
    r.replies.forEach((reply, j) => {
      if (!reply || typeof reply !== 'object') throw new Error(`rules[${i}].replies[${j}] must be an object`);
      const calls = (reply as Record<string, unknown>).toolCalls;
      if (calls !== undefined && (!Array.isArray(calls) || !calls.every((c) => c && typeof (c as MockToolCallSpec).name === 'string'))) {
        throw new Error(`rules[${i}].replies[${j}].toolCalls must be [{ name, arguments }]`);
      }
    });
    if (r.match !== undefined && (typeof r.match !== 'object' || r.match === null)) throw new Error(`rules[${i}].match must be an object`);
    if (typeof (r.match as MockMatcher | undefined)?.pattern === 'string') {
      try {
        new RegExp((r.match as MockMatcher).pattern as string);
      } catch (err) {
        throw new Error(`rules[${i}].match.pattern is not a valid regex: ${(err as Error).message}`, { cause: err });
      }
    }
  });
  return obj as unknown as MockScript;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export interface MockProviderOptions {
  model?: string;
}

export class MockProvider implements ChatProvider {
  readonly name = 'mock' as const;
  readonly model: string;
  // deep copies, in order
  readonly calls: ChatRequest[] = [];
  private readonly script: MockScript;
  private readonly states: RuleState[];

  constructor(script: MockScript = { rules: [] }, options: MockProviderOptions = {}) {
    this.script = parseMockScript(script);
    this.model = options.model ?? 'mock';
    this.states = this.script.rules.map((rule) => ({ rule, used: 0 }));
  }

  async chat(req: ChatRequest): Promise<ChatResponse> {
    const { signal, ...rest } = req;
    this.calls.push(structuredClone(rest));
    if (signal?.aborted) throw new LlmError('aborted', 'Request aborted');
    const reply = this.nextReply(req);
    if (reply?.delayMs) await delay(reply.delayMs);
    if (reply?.error) {
      throw new LlmError(reply.error.kind ?? 'http', reply.error.message, reply.error.status === undefined ? {} : { status: reply.error.status });
    }
    const message = reply ? this.toMessage(reply) : this.synthesize(req);
    return { message, model: req.model ?? this.model, done: true, doneReason: 'stop' };
  }

  async checkModel(model?: string): Promise<ModelCheck> {
    const name = model ?? this.model;
    return { ok: true, model: name, installed: true, tools: true, resolvedModel: name };
  }

  async warmup(): Promise<void> {}

  // for script-consumed checks
  pending(): { rule: string; remaining: number }[] {
    return this.states
      .filter((s) => !s.rule.repeat && s.used < s.rule.replies.length)
      .map((s, i) => ({ rule: s.rule.id ?? `rules[${i}]`, remaining: s.rule.replies.length - s.used }));
  }

  private nextReply(req: ChatRequest): MockReply | null {
    for (const state of this.states) {
      const { rule } = state;
      const exhausted = state.used >= rule.replies.length;
      if (exhausted && !rule.repeat) continue;
      if (!matchesRequest(rule.match, req, this.model)) continue;
      const index = Math.min(state.used, rule.replies.length - 1);
      state.used += 1;
      return rule.replies[index] ?? null;
    }
    if (this.script.fallback === 'error') {
      throw new LlmError('invalid-response', `Mock script has no reply for this request (purpose: ${req.purpose ?? 'other'})`);
    }
    return null;
  }

  private toMessage(reply: MockReply): ChatMessage {
    const content = reply.json !== undefined ? JSON.stringify(reply.json) : (reply.content ?? '');
    const message: ChatMessage = { role: 'assistant', content };
    if (reply.toolCalls && reply.toolCalls.length > 0) {
      message.tool_calls = reply.toolCalls.map(
        (call, index): ToolCall => ({ function: { name: call.name, arguments: call.arguments ?? {}, index }, source: 'native' }),
      );
    }
    if (reply.thinking) message.thinking = reply.thinking;
    return message;
  }

  private synthesize(req: ChatRequest): ChatMessage {
    if (req.format && req.format !== 'json') {
      return { role: 'assistant', content: JSON.stringify(synthesizeFromSchema(req.format)) };
    }
    if (req.format === 'json') return { role: 'assistant', content: '{}' };
    return { role: 'assistant', content: 'Mock provider: no scripted reply, so no further tool calls.' };
  }
}
