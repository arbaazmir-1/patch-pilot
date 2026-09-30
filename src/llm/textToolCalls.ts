// small models emit tool calls as text
import type { ToolCall } from '../types.ts';

export interface TextToolCallParse {
  calls: ToolCall[];
  // recovered calls removed
  text: string;
}

// non-JSON string args land here
export const RAW_ARGUMENTS_KEY = '__raw';

// object, JSON string or other
export function normalizeToolArguments(value: unknown): Record<string, unknown> {
  if (value === undefined || value === null) return {};
  if (typeof value === 'object' && !Array.isArray(value)) return value as Record<string, unknown>;
  if (typeof value === 'string') {
    const text = value.trim();
    if (text === '') return {};
    const parsed = parseLenientJson(text);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed as Record<string, unknown>;
    return { [RAW_ARGUMENTS_KEY]: value };
  }
  return { [RAW_ARGUMENTS_KEY]: JSON.stringify(value) };
}

// for ToolRegistry.execute
export function unwrapRawArguments(args: Record<string, unknown> | undefined | null): unknown {
  if (!args) return {};
  const keys = Object.keys(args);
  if (keys.length === 1 && keys[0] === RAW_ARGUMENTS_KEY && typeof args[RAW_ARGUMENTS_KEY] === 'string') return args[RAW_ARGUMENTS_KEY];
  return args;
}

function endOfString(text: string, start: number): number {
  const quote = text[start];
  for (let i = start + 1; i < text.length; i += 1) {
    const ch = text[i];
    if (ch === '\\') {
      i += 1;
      continue;
    }
    if (ch === quote) return i + 1;
  }
  return text.length;
}

function lastSignificant(text: string): string {
  for (let i = text.length - 1; i >= 0; i -= 1) {
    const ch = text[i] ?? '';
    if (!/\s/.test(ch)) return ch;
  }
  return '';
}

// JS/Python-ish object text, best effort
function repairJson(text: string): string {
  let out = '';
  let i = 0;
  while (i < text.length) {
    const ch = text[i] ?? '';
    if (ch === '"') {
      const end = endOfString(text, i);
      out += text.slice(i, end);
      i = end;
      continue;
    }
    if (ch === "'") {
      const end = endOfString(text, i);
      const inner = text.slice(i + 1, Math.max(i + 1, end - 1)).replace(/\\'/g, "'");
      let value = inner;
      try {
        value = JSON.parse(`"${inner.replace(/"/g, '\\"')}"`) as string;
      } catch {
        // keep raw inner text
      }
      out += JSON.stringify(value);
      i = end;
      continue;
    }
    if (/[A-Za-z_$]/.test(ch)) {
      let j = i;
      while (j < text.length && /[\w$-]/.test(text[j] ?? '')) j += 1;
      const word = text.slice(i, j);
      const isKey = /^\s*:/.test(text.slice(j)) && '{,'.includes(lastSignificant(out) || '{');
      if (isKey) out += JSON.stringify(word);
      else if (word === 'True') out += 'true';
      else if (word === 'False') out += 'false';
      else if (word === 'None') out += 'null';
      else out += word;
      i = j;
      continue;
    }
    if (ch === ',' && /^\s*[}\]]/.test(text.slice(i + 1))) {
      i += 1;
      continue;
    }
    out += ch;
    i += 1;
  }
  return out;
}

// one repair pass, else undefined
export function parseLenientJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    // try repaired
  }
  const repaired = repairJson(text);
  if (repaired !== text) {
    try {
      return JSON.parse(repaired);
    } catch {
      // not json
    }
  }
  return undefined;
}

// exclusive end, -1 if unbalanced
function balancedEnd(text: string, start: number): number {
  const pairs: Record<string, string> = { '{': '}', '[': ']', '(': ')' };
  const first = text[start] ?? '';
  if (!(first in pairs)) return -1;
  const stack: string[] = [];
  for (let i = start; i < text.length; i += 1) {
    const ch = text[i] ?? '';
    if (ch === '"' || (ch === "'" && stack.length > 0 && /[\s{[(:,=]/.test(text[i - 1] ?? ''))) {
      i = endOfString(text, i) - 1;
      continue;
    }
    const close = pairs[ch];
    if (close) stack.push(close);
    else if (ch === '}' || ch === ']' || ch === ')') {
      if (stack.pop() !== ch) return -1;
      if (stack.length === 0) return i + 1;
    }
  }
  return -1;
}

// matches the registry's canonicalToolName
function canonicalName(name: string): string {
  return name
    .trim()
    .replace(/^(functions|tools?)\./i, '')
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/[-\s]+/g, '_')
    .toLowerCase();
}

type NameIndex = Map<string, string>;

function resolveName(name: unknown, index: NameIndex): string | null {
  if (typeof name !== 'string' || name.trim() === '' || name.length > 80) return null;
  return index.get(canonicalName(name)) ?? null;
}

function makeCall(name: string, args: unknown): ToolCall {
  return { function: { name, arguments: normalizeToolArguments(args) }, source: 'text' };
}

const NAME_KEYS = ['name', 'tool', 'tool_name', 'toolName', 'function_name', 'action', 'recipient_name', 'command'];
const ARG_KEYS = ['arguments', 'parameters', 'args', 'input', 'tool_input', 'action_input', 'params', 'kwargs'];

function firstDefined(obj: Record<string, unknown>, keys: readonly string[]): unknown {
  for (const key of keys) if (obj[key] !== undefined) return obj[key];
  return undefined;
}

// object, array or wrapper
function callsFromValue(value: unknown, index: NameIndex, depth = 0): ToolCall[] {
  if (depth > 4 || value === null || typeof value !== 'object') return [];
  if (Array.isArray(value)) return value.flatMap((item) => callsFromValue(item, index, depth + 1));
  const obj = value as Record<string, unknown>;
  if (Array.isArray(obj.tool_calls)) return callsFromValue(obj.tool_calls, index, depth + 1);
  let name = firstDefined(obj, NAME_KEYS);
  let args = firstDefined(obj, ARG_KEYS);
  const fn = obj.function;
  if (fn && typeof fn === 'object' && !Array.isArray(fn)) {
    const f = fn as Record<string, unknown>;
    name ??= f.name;
    args ??= f.arguments ?? f.parameters;
  } else if (typeof fn === 'string') {
    name ??= fn;
  }
  const resolved = resolveName(name, index);
  if (resolved) return [makeCall(resolved, args)];
  const keys = Object.keys(obj);
  if (keys.length === 1) {
    const key = keys[0] as string;
    const inner = obj[key];
    const single = resolveName(key, index);
    if (single && (inner === null || (typeof inner === 'object' && !Array.isArray(inner)))) return [makeCall(single, inner)];
  }
  for (const inner of Object.values(obj)) {
    if (inner && typeof inner === 'object') {
      const found = callsFromValue(inner, index, depth + 1);
      if (found.length > 0) return found;
    }
  }
  return [];
}

function parseKwargs(inner: string): Record<string, unknown> | null {
  const out: Record<string, unknown> = {};
  const re = /\s*([A-Za-z_][\w]*)\s*[=:]\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|-?\d+(?:\.\d+)?|true|false|True|False|null|None|[^,)]+?)\s*(?:,|$)/y;
  let pos = 0;
  const text = inner.trim();
  while (pos < text.length) {
    re.lastIndex = pos;
    const m = re.exec(text);
    if (!m || m[1] === undefined || m[2] === undefined) return null;
    const raw = m[2].trim();
    const parsed = parseLenientJson(raw);
    out[m[1]] = parsed === undefined ? raw.replace(/^['"]|['"]$/g, '') : parsed;
    pos = re.lastIndex;
  }
  return out;
}

// JSON, key=value, one string or nothing
function parseCallArgs(inner: string): { ok: boolean; args: unknown; empty: boolean } {
  const text = inner.trim();
  if (text === '') return { ok: true, args: {}, empty: true };
  if (text.startsWith('{')) {
    const parsed = parseLenientJson(text);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? { ok: true, args: parsed, empty: false } : { ok: false, args: null, empty: false };
  }
  const kwargs = parseKwargs(text);
  if (kwargs && Object.keys(kwargs).length > 0) return { ok: true, args: kwargs, empty: false };
  if (/^("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')$/.test(text)) {
    const value = parseLenientJson(text);
    if (typeof value === 'string') return { ok: true, args: value, empty: false };
  }
  return { ok: false, args: null, empty: false };
}

interface Span {
  start: number;
  end: number;
  calls: ToolCall[];
}

class SpanSet {
  readonly spans: Span[] = [];
  overlaps(start: number, end: number): boolean {
    return this.spans.some((s) => start < s.end && end > s.start);
  }
  add(start: number, end: number, calls: ToolCall[]): boolean {
    if (calls.length === 0 || this.overlaps(start, end)) return false;
    this.spans.push({ start, end, calls });
    return true;
  }
}

function scan(text: string, index: NameIndex): SpanSet {
  const set = new SpanSet();

  for (const m of text.matchAll(/```[^\n`]*\n?([\s\S]*?)```/g)) {
    const start = m.index ?? 0;
    const inner = scan(m[1] ?? '', index);
    set.add(start, start + m[0].length, inner.spans.sort((a, b) => a.start - b.start).flatMap((s) => s.calls));
  }

  // <tool_call>{...}</tool_call>
  for (const m of text.matchAll(/<tool_call>\s*([\s\S]*?)\s*<\/tool_call>/g)) {
    const start = m.index ?? 0;
    set.add(start, start + m[0].length, callsFromValue(parseLenientJson(m[1] ?? ''), index));
  }

  // <function=name>{...}</function>
  for (const m of text.matchAll(/<function=([\w.-]+)>/g)) {
    const start = m.index ?? 0;
    const name = resolveName(m[1], index);
    if (!name) continue;
    let pos = start + m[0].length;
    while (/\s/.test(text[pos] ?? '')) pos += 1;
    let args: unknown = {};
    if (text[pos] === '{') {
      const end = balancedEnd(text, pos);
      if (end < 0) continue;
      args = parseLenientJson(text.slice(pos, end));
      if (args === undefined) continue;
      pos = end;
    }
    const close = /^\s*<\/function>/.exec(text.slice(pos));
    if (close) pos += close[0].length;
    set.add(start, pos, [makeCall(name, args)]);
  }

  // [TOOL_CALLS] [...] or name[ARGS]{...}
  for (const m of text.matchAll(/\[TOOL_CALLS\]\s*/g)) {
    const start = m.index ?? 0;
    let pos = start + m[0].length;
    const calls: ToolCall[] = [];
    let end = -1;
    if (text[pos] === '[' || text[pos] === '{') {
      end = balancedEnd(text, pos);
      if (end > 0) calls.push(...callsFromValue(parseLenientJson(text.slice(pos, end)), index));
    } else {
      for (;;) {
        const named = /^([A-Za-z_][\w.-]*)\s*(\[ARGS\]|\[CALL_ID\][^[]*\[ARGS\])\s*/.exec(text.slice(pos));
        if (!named || named[1] === undefined) break;
        const name = resolveName(named[1], index);
        const argsAt = pos + named[0].length;
        const argsEnd = text[argsAt] === '{' ? balancedEnd(text, argsAt) : -1;
        if (!name || argsEnd < 0) break;
        const args = parseLenientJson(text.slice(argsAt, argsEnd));
        if (args === undefined) break;
        calls.push(makeCall(name, args));
        end = argsEnd;
        pos = argsEnd;
        const next = /^\s*(\[TOOL_CALLS\])?\s*/.exec(text.slice(pos));
        pos += next ? next[0].length : 0;
      }
    }
    if (end > 0) set.add(start, end, calls);
  }

  // bare or prose-wrapped JSON
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (ch !== '{' && ch !== '[') continue;
    if (set.overlaps(i, i + 1)) continue;
    const end = balancedEnd(text, i);
    if (end < 0) continue;
    const value = parseLenientJson(text.slice(i, end));
    if (value === undefined) continue;
    const calls = callsFromValue(value, index);
    if (calls.length > 0) set.add(i, end, calls);
    i = end - 1;
  }

  // name({...}), name(key="v"), name("v")
  for (const m of text.matchAll(/(?<![\w$.])((?:functions\.|tools?\.)?[A-Za-z_][\w-]*)\s*\(/g)) {
    const start = m.index ?? 0;
    const name = resolveName(m[1], index);
    if (!name) continue;
    const open = start + m[0].length - 1;
    const end = balancedEnd(text, open);
    if (end < 0 || set.overlaps(start, end)) continue;
    const parsed = parseCallArgs(text.slice(open + 1, end - 1));
    if (!parsed.ok) continue;
    if (parsed.empty) {
      // bare name() only alone on its line
      const lineStart = text.lastIndexOf('\n', start - 1) + 1;
      const lineEndIdx = text.indexOf('\n', end);
      const line = text.slice(lineStart, lineEndIdx === -1 ? text.length : lineEndIdx).trim().replace(/^`+|`+$/g, '').replace(/[.;]$/, '');
      if (line !== text.slice(start, end).trim()) continue;
    }
    let spanStart = start;
    let spanEnd = end;
    if (text[spanStart - 1] === '`' && text[spanEnd] === '`') {
      spanStart -= 1;
      spanEnd += 1;
    }
    set.add(spanStart, spanEnd, [makeCall(name, parsed.args)]);
  }
  return set;
}

function sortedStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(sortedStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    return `{${Object.keys(obj)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${sortedStringify(obj[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

function tidy(text: string): string {
  return text
    .replace(/\[TOOL_CALLS\]|\[\/?TOOL_RESULTS\]|<\|python_tag\|>|<\|eom_id\|>|<\|eot_id\|>/g, '')
    .split('\n')
    .map((line) => line.replace(/(\S)[ \t]{2,}/g, '$1 ').replace(/\s+$/, ''))
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

export function parseTextToolCalls(content: string, toolNames: readonly string[]): TextToolCallParse {
  const source = typeof content === 'string' ? content : '';
  if (source.trim() === '' || toolNames.length === 0) return { calls: [], text: tidy(source) };
  const index: NameIndex = new Map(toolNames.map((name) => [canonicalName(name), name]));
  const spans = scan(source, index).spans.sort((a, b) => a.start - b.start);
  if (spans.length === 0) return { calls: [], text: tidy(source) };
  const calls: ToolCall[] = [];
  const seen = new Set<string>();
  for (const span of spans) {
    for (const call of span.calls) {
      const key = `${call.function.name}:${sortedStringify(call.function.arguments)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      calls.push({ ...call, function: { ...call.function, index: calls.length } });
    }
  }
  let text = '';
  let pos = 0;
  for (const span of spans) {
    text += source.slice(pos, span.start);
    pos = span.end;
  }
  text += source.slice(pos);
  return { calls, text: tidy(text) };
}

// bare, fenced or in prose
export function extractJsonObject(content: string): Record<string, unknown> | undefined {
  const text = String(content ?? '').trim();
  if (text === '') return undefined;
  const direct = parseLenientJson(text);
  if (direct && typeof direct === 'object' && !Array.isArray(direct)) return direct as Record<string, unknown>;
  for (let i = text.indexOf('{'); i !== -1; i = text.indexOf('{', i + 1)) {
    const end = balancedEnd(text, i);
    if (end < 0) continue;
    const value = parseLenientJson(text.slice(i, end));
    if (value && typeof value === 'object' && !Array.isArray(value)) return value as Record<string, unknown>;
  }
  return undefined;
}

// leaves prose for display
export function stripJsonBlocks(content: string): string {
  const text = String(content ?? '').replace(/```[\s\S]*?(```|$)/g, ' ');
  let out = '';
  let i = 0;
  while (i < text.length) {
    const ch = text[i] ?? '';
    if (ch === '{' || ch === '[') {
      const end = balancedEnd(text, i);
      if (end > i && parseLenientJson(text.slice(i, end)) !== undefined) {
        out += ' ';
        i = end;
        continue;
      }
    }
    out += ch;
    i += 1;
  }
  return out;
}
