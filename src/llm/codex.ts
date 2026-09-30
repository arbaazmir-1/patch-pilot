// codex exec runner, login check, chat provider
import { execFile } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, writeFile, appendFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { redactSecrets } from '../audit.ts';
import type { ChatRequest, ChatResponse, JsonSchema, ModelCheck } from '../types.ts';
import { EnvironmentError } from '../util/errors.ts';
import { run as runCommand, which as whichCommand, type RunOptions, type RunResult } from '../util/proc.ts';
import { LlmError } from './errors.ts';
import type { ChatProvider, ProviderUsageSummary } from './provider.ts';

export const CODEX_INSTALL = 'npm install -g @openai/codex';
export const CODEX_DOCS = 'https://developers.openai.com/codex';
export const CODEX_LOGIN = 'codex login';
// no --model and no config.toml model
export const CODEX_DEFAULT_LABEL = 'codex-default';

const MAX_STDOUT_BUFFER = 256 * 1024 * 1024;
const STDERR_TAIL = 8 * 1024;
const KILL_GRACE_MS = 5_000;

// json escapes are valid toml
export function tomlString(value: string): string {
  return JSON.stringify(value);
}

export function tomlArray(values: readonly string[]): string {
  return `[${values.map(tomlString).join(',')}]`;
}

export interface CodexMcpServerSpec {
  // mcp_servers key, no dots
  name: string;
  command: string;
  args: readonly string[];
}

export interface CodexExecSpec {
  prompt: string;
  projectRoot: string;
  // -m, null uses codex config
  model?: string | null;
  outputSchemaFile?: string | null;
  outputFile?: string | null;
  mcpServer?: CodexMcpServerSpec | null;
  // -a never, or approval_policy if -a rejected
  approval?: 'flag' | 'config';
}

// codex defaults 10 s startup, 60 s per call
export const MCP_STARTUP_TIMEOUT_SEC = 30;
export const MCP_TOOL_TIMEOUT_SEC = 180;

// exec, prompt, then flags
export function buildCodexExecArgs(spec: CodexExecSpec): string[] {
  const prompt = spec.prompt.startsWith('-') ? ` ${spec.prompt}` : spec.prompt;
  const approval = spec.approval === 'config' ? ['-c', 'approval_policy="never"'] : ['-a', 'never'];
  const args = ['exec', prompt, '--json', '--sandbox', 'read-only', ...approval, '-C', spec.projectRoot, '--skip-git-repo-check'];
  if (spec.outputSchemaFile) args.push('--output-schema', spec.outputSchemaFile);
  if (spec.outputFile) args.push('-o', spec.outputFile);
  if (spec.model) args.push('-m', spec.model);
  if (spec.mcpServer) {
    const key = `mcp_servers.${spec.mcpServer.name}`;
    args.push('-c', `${key}.command=${tomlString(spec.mcpServer.command)}`);
    args.push('-c', `${key}.args=${tomlArray(spec.mcpServer.args)}`);
    args.push('-c', `${key}.startup_timeout_sec=${MCP_STARTUP_TIMEOUT_SEC}`);
    args.push('-c', `${key}.tool_timeout_sec=${MCP_TOOL_TIMEOUT_SEC}`);
  }
  return args;
}

// this build rejected -a after exec
export function rejectedApprovalFlag(result: Pick<CodexRunResult, 'exitCode' | 'events' | 'stderr'>): boolean {
  return result.exitCode === 2 && result.events === 0 && /(unexpected|unrecognized|unknown|wasn't expected)[^\n]*('-a'|-a\b|ask-for-approval)/i.test(result.stderr);
}

// sticky 'config' once -a is rejected
let approvalMode: 'flag' | 'config' = 'flag';

// prompt replaced by a placeholder
export function displayCodexCommand(command: string, args: readonly string[]): string[] {
  return [command, ...args.map((a, i) => (i === 1 && args[0] === 'exec' ? '<prompt>' : a))];
}

export interface CodexUsage {
  inputTokens: number;
  cachedInputTokens: number;
  outputTokens: number;
  reasoningOutputTokens: number;
}

export interface CodexItem {
  id: string;
  // e.g. agent_message, reasoning, mcp_tool_call, file_change, error
  type: string;
  text?: string;
  server?: string;
  tool?: string;
  arguments?: unknown;
  result?: unknown;
  error?: string | null;
  status?: string;
  command?: string;
  exitCode?: number | null;
  output?: string;
}

export type CodexEvent =
  | { type: 'thread.started'; threadId: string | null }
  | { type: 'turn.started' }
  | { type: 'turn.completed'; usage: CodexUsage }
  | { type: 'turn.failed'; message: string }
  | { type: 'error'; message: string }
  | { type: 'item.started' | 'item.updated' | 'item.completed'; item: CodexItem }
  | { type: 'other'; raw: Record<string, unknown> };

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function num(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function errorText(value: unknown): string | null {
  if (typeof value === 'string') return value;
  if (isRecord(value) && typeof value.message === 'string') return value.message;
  return null;
}

export function emptyCodexUsage(): CodexUsage {
  return { inputTokens: 0, cachedInputTokens: 0, outputTokens: 0, reasoningOutputTokens: 0 };
}

function parseItem(raw: unknown): CodexItem | null {
  if (!isRecord(raw)) return null;
  const type = str(raw.type) ?? str(raw.item_type) ?? 'unknown';
  const item: CodexItem = { id: str(raw.id) ?? '', type };
  const text = str(raw.text);
  if (text !== undefined) item.text = text;
  if (str(raw.server) !== undefined) item.server = raw.server as string;
  if (str(raw.tool) !== undefined) item.tool = raw.tool as string;
  if (raw.arguments !== undefined) item.arguments = raw.arguments;
  if (raw.result !== undefined && raw.result !== null) item.result = raw.result;
  const error = errorText(raw.error);
  if (error !== null) item.error = error;
  if (str(raw.status) !== undefined) item.status = raw.status as string;
  if (str(raw.command) !== undefined) item.command = raw.command as string;
  if (typeof raw.exit_code === 'number') item.exitCode = raw.exit_code;
  const output = str(raw.aggregated_output) ?? str(raw.output);
  if (output !== undefined) item.output = output;
  if (type === 'error' && item.text === undefined && str(raw.message) !== undefined) item.text = raw.message as string;
  return item;
}

// null for blank or non-json
export function parseCodexEvent(line: string): CodexEvent | null {
  const text = line.trim();
  if (text === '' || !text.startsWith('{')) return null;
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isRecord(raw)) return null;
  switch (raw.type) {
    case 'thread.started':
      return { type: 'thread.started', threadId: str(raw.thread_id) ?? null };
    case 'turn.started':
      return { type: 'turn.started' };
    case 'turn.completed': {
      const u = isRecord(raw.usage) ? raw.usage : {};
      return {
        type: 'turn.completed',
        usage: {
          inputTokens: num(u.input_tokens),
          cachedInputTokens: num(u.cached_input_tokens),
          outputTokens: num(u.output_tokens),
          reasoningOutputTokens: num(u.reasoning_output_tokens),
        },
      };
    }
    case 'turn.failed':
      return { type: 'turn.failed', message: errorText(raw.error) ?? str(raw.message) ?? 'the Codex turn failed' };
    case 'error':
      return { type: 'error', message: str(raw.message) ?? errorText(raw.error) ?? 'Codex reported an error' };
    case 'item.started':
    case 'item.updated':
    case 'item.completed': {
      const item = parseItem(raw.item);
      return item ? { type: raw.type, item } : null;
    }
    default:
      return { type: 'other', raw };
  }
}

// incremental, for stdout chunks
export class CodexJsonlParser {
  private buffer = '';

  push(chunk: string): CodexEvent[] {
    this.buffer += chunk;
    const out: CodexEvent[] = [];
    let nl = this.buffer.indexOf('\n');
    while (nl !== -1) {
      const event = parseCodexEvent(this.buffer.slice(0, nl));
      if (event) out.push(event);
      this.buffer = this.buffer.slice(nl + 1);
      nl = this.buffer.indexOf('\n');
    }
    return out;
  }

  end(): CodexEvent[] {
    const rest = this.buffer;
    this.buffer = '';
    const event = parseCodexEvent(rest);
    return event ? [event] : [];
  }
}

// as codex reports it
export function mcpResultText(result: unknown): string {
  if (typeof result === 'string') return result;
  if (!isRecord(result)) return '';
  const content = Array.isArray(result.content) ? result.content : [];
  const texts = content.filter(isRecord).map((c) => (typeof c.text === 'string' ? c.text : '')).filter(Boolean);
  if (texts.length > 0) return texts.join('\n');
  const structured = result.structured_content ?? result.structuredContent;
  return structured === undefined ? '' : JSON.stringify(structured);
}

export interface CodexRunOptions extends CodexExecSpec {
  // default "codex" on PATH
  codexCommand?: string;
  env?: NodeJS.ProcessEnv;
  // child env only, never argv
  apiKey?: string | null;
  timeoutMs: number;
  signal?: AbortSignal;
  onEvent?: (event: CodexEvent) => void;
}

export interface CodexRunResult {
  exitCode: number | null;
  signal: string | null;
  durationMs: number;
  timedOut: boolean;
  aborted: boolean;
  // last agent_message text
  finalMessage: string | null;
  // last turn.failed or error message
  lastError: string | null;
  usage: CodexUsage;
  // completed only
  toolCalls: number;
  events: number;
  stderr: string;
  // prompt elided
  command: string[];
}

// codex not installed or not on PATH
export function codexNotInstalled(): EnvironmentError {
  return new EnvironmentError('The Codex CLI (codex) is not installed or not on PATH', {
    hint: `Install it: ${CODEX_INSTALL}, then sign in: ${CODEX_LOGIN} (or export CODEX_API_KEY). Docs: ${CODEX_DOCS}`,
  });
}

// retries with approval_policy if -a rejected
export async function runCodexExec(options: CodexRunOptions): Promise<CodexRunResult> {
  const approval = options.approval ?? approvalMode;
  const result = await runCodexOnce({ ...options, approval });
  if (approval === 'flag' && rejectedApprovalFlag(result)) {
    approvalMode = 'config';
    return runCodexOnce({ ...options, approval: 'config' });
  }
  return result;
}

function runCodexOnce(options: CodexRunOptions): Promise<CodexRunResult> {
  const command = options.codexCommand ?? 'codex';
  const args = buildCodexExecArgs(options);
  const env: NodeJS.ProcessEnv = { ...(options.env ?? process.env) };
  if (options.apiKey) env.CODEX_API_KEY = options.apiKey;
  const started = Date.now();
  const controller = new AbortController();
  let timedOut = false;
  let aborted = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, Math.max(1, options.timeoutMs));
  const onCallerAbort = (): void => {
    aborted = true;
    controller.abort();
  };
  if (options.signal?.aborted) onCallerAbort();
  else options.signal?.addEventListener('abort', onCallerAbort, { once: true });

  const parser = new CodexJsonlParser();
  const result: CodexRunResult = {
    exitCode: null,
    signal: null,
    durationMs: 0,
    timedOut: false,
    aborted: false,
    finalMessage: null,
    lastError: null,
    usage: emptyCodexUsage(),
    toolCalls: 0,
    events: 0,
    stderr: '',
    command: displayCodexCommand(command, args),
  };
  const handle = (event: CodexEvent): void => {
    result.events += 1;
    if (event.type === 'turn.completed') {
      result.usage.inputTokens += event.usage.inputTokens;
      result.usage.cachedInputTokens += event.usage.cachedInputTokens;
      result.usage.outputTokens += event.usage.outputTokens;
      result.usage.reasoningOutputTokens += event.usage.reasoningOutputTokens;
    } else if (event.type === 'turn.failed' || event.type === 'error') {
      result.lastError = event.message;
    } else if (event.type === 'item.completed') {
      if (event.item.type === 'agent_message' && typeof event.item.text === 'string') result.finalMessage = event.item.text;
      if (event.item.type === 'mcp_tool_call') result.toolCalls += 1;
      if (event.item.type === 'error' && event.item.text) result.lastError = event.item.text;
    }
    try {
      options.onEvent?.(event);
    } catch {
      // rendering must never break the run
    }
  };

  return new Promise<CodexRunResult>((resolve, reject) => {
    let killTimer: NodeJS.Timeout | null = null;
    let settled = false;
    const child = execFile(
      command,
      args,
      {
        cwd: options.projectRoot,
        env,
        encoding: 'utf8',
        maxBuffer: MAX_STDOUT_BUFFER,
        shell: false,
        windowsHide: true,
        signal: controller.signal,
        killSignal: 'SIGTERM',
      },
      (error) => {
        settled = true;
        clearTimeout(timer);
        if (killTimer) clearTimeout(killTimer);
        options.signal?.removeEventListener('abort', onCallerAbort);
        for (const event of parser.end()) handle(event);
        const err = error as (NodeJS.ErrnoException & { code?: number | string; signal?: string }) | null;
        if (err && err.code === 'ENOENT' && !timedOut && !aborted) {
          reject(codexNotInstalled());
          return;
        }
        result.exitCode = err ? (typeof err.code === 'number' ? err.code : null) : 0;
        result.signal = err?.signal ?? null;
        result.timedOut = timedOut;
        result.aborted = aborted;
        result.durationMs = Date.now() - started;
        resolve(result);
      },
    );
    // sigterm, then sigkill after grace
    controller.signal.addEventListener(
      'abort',
      () => {
        if (settled) return;
        killTimer = setTimeout(() => child.kill('SIGKILL'), KILL_GRACE_MS);
        killTimer.unref();
      },
      { once: true },
    );
    child.stdin?.end();
    child.stdout?.on('data', (chunk: string | Buffer) => {
      for (const event of parser.push(String(chunk))) handle(event);
    });
    child.stderr?.on('data', (chunk: string | Buffer) => {
      result.stderr = `${result.stderr}${String(chunk)}`.slice(-STDERR_TAIL);
    });
  });
}

// reason plus the fix
export function describeCodexFailure(result: CodexRunResult, timeoutMs: number): { message: string; hint: string; auth: boolean } {
  if (result.timedOut) {
    return {
      message: `Codex did not finish within ${Math.round(timeoutMs / 60_000)} min`,
      hint: 'Narrow the run with --only <package>, then continue with patch-pilot investigate --resume.',
      auth: false,
    };
  }
  const detail = (result.lastError ?? result.stderr.trim().split('\n').filter(Boolean).slice(-3).join(' ')).slice(0, 400) || 'no error message';
  const code = result.exitCode === null ? `signal ${result.signal ?? 'unknown'}` : `code ${result.exitCode}`;
  const message = `codex exec exited with ${code}: ${detail}`;
  if (/not logged in|log in|login|unauthori[sz]ed|\b401\b|api key|authenticat|credential/i.test(detail)) {
    return { message, hint: `Sign in with: ${CODEX_LOGIN} (ChatGPT), or export CODEX_API_KEY=... (OpenAI recommends an API key for automation). Docs: ${CODEX_DOCS}`, auth: true };
  }
  if (/rate limit|\b429\b|quota|usage limit|too many requests/i.test(detail)) {
    return { message, hint: 'Wait for the limit to reset, then continue with patch-pilot investigate --resume.', auth: false };
  }
  if (/unexpected argument|unrecognized|unknown option|usage:/i.test(detail)) {
    return { message, hint: `Update the Codex CLI: ${CODEX_INSTALL}@latest. Docs: ${CODEX_DOCS}`, auth: false };
  }
  return { message, hint: `Check codex login status and try again. Docs: ${CODEX_DOCS}`, auth: false };
}

export interface CodexStatus {
  installed: boolean;
  path: string | null;
  loggedIn: boolean;
  method: 'chatgpt' | 'api-key' | null;
  // e.g. "Logged in using ChatGPT", "CODEX_API_KEY", "not logged in"
  detail: string;
}

export interface CodexStatusDeps {
  which?: (cmd: string, env?: NodeJS.ProcessEnv) => Promise<string | null>;
  run?: (cmd: string, args: readonly string[], options?: RunOptions) => Promise<RunResult>;
  env?: NodeJS.ProcessEnv;
  apiKey?: string | null;
}

// installed and logged in or keyed, never throws
export async function codexStatus(deps: CodexStatusDeps = {}): Promise<CodexStatus> {
  const env = deps.env ?? process.env;
  const find = deps.which ?? whichCommand;
  const exec = deps.run ?? runCommand;
  const found = await find('codex', env).catch(() => null);
  if (!found) {
    return deps.apiKey
      ? { installed: false, path: null, loggedIn: false, method: 'api-key', detail: 'CODEX_API_KEY set, but the codex CLI is not installed' }
      : { installed: false, path: null, loggedIn: false, method: null, detail: 'not installed' };
  }
  const res = await exec('codex', ['login', 'status'], { env, timeoutMs: 15_000 }).catch(() => null);
  const text = `${res?.stderr ?? ''}\n${res?.stdout ?? ''}`.trim();
  const line = text.split('\n').map((l) => l.trim()).find((l) => /logged in/i.test(l)) ?? text.split('\n')[0]?.trim() ?? '';
  if (res?.ok) {
    const method = /api key/i.test(text) ? 'api-key' : /chatgpt/i.test(text) ? 'chatgpt' : null;
    return { installed: true, path: found, loggedIn: true, method, detail: line || 'logged in' };
  }
  if (deps.apiKey) return { installed: true, path: found, loggedIn: true, method: 'api-key', detail: 'CODEX_API_KEY' };
  return { installed: true, path: found, loggedIn: false, method: null, detail: 'not logged in' };
}

// $CODEX_HOME/config.toml, default ~/.codex
export function readCodexConfigModel(env: NodeJS.ProcessEnv = process.env, homeDir: string = os.homedir()): string | null {
  const dir = env.CODEX_HOME && env.CODEX_HOME.trim() !== '' ? env.CODEX_HOME : path.join(homeDir, '.codex');
  let text: string;
  try {
    text = readFileSync(path.join(dir, 'config.toml'), 'utf8');
  } catch {
    return null;
  }
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (line.startsWith('[')) break;
    const m = /^model\s*=\s*["']([^"']+)["']/.exec(line);
    if (m && m[1]) return m[1];
  }
  return null;
}

// --model, config model, else "codex-default"
export function codexModelLabel(explicit: string | null | undefined, env: NodeJS.ProcessEnv = process.env): string {
  if (explicit && explicit.trim() !== '') return explicit.trim();
  return readCodexConfigModel(env) ?? CODEX_DEFAULT_LABEL;
}

// strict mode: all required, no extras
export function strictSchema(schema: JsonSchema): JsonSchema {
  const copy: JsonSchema = { ...schema };
  if (copy.type === 'object' || copy.properties) {
    const props: Record<string, JsonSchema> = {};
    for (const [key, value] of Object.entries(copy.properties ?? {})) props[key] = strictSchema(value);
    copy.properties = props;
    copy.required = Object.keys(props);
    copy.additionalProperties = false;
  }
  if (copy.items) copy.items = strictSchema(copy.items);
  if (copy.anyOf) copy.anyOf = copy.anyOf.map(strictSchema);
  if (copy.oneOf) copy.oneOf = copy.oneOf.map(strictSchema);
  return copy;
}

// whole transcript in one prompt
export function transcriptPrompt(req: ChatRequest): string {
  const lines: string[] = [
    'You are helping PatchPilot, a dependency security tool, with one step of its work. Answer the last message of the conversation below.',
    'Do not edit files and do not run commands: everything you need is in the conversation.',
  ];
  if (req.tools && req.tools.length > 0) lines.push('No tools are available in this step: answer from the conversation.');
  const system = (req.messages ?? []).filter((m) => m.role === 'system').map((m) => m.content.trim()).filter(Boolean);
  if (system.length > 0) lines.push('', '## Instructions', ...system);
  lines.push('', '## Conversation');
  for (const m of req.messages ?? []) {
    if (m.role === 'system') continue;
    if (m.role === 'tool') lines.push('', `### Tool result (${m.tool_name ?? 'tool'})`, m.content);
    else if (m.role === 'assistant') {
      const calls = (m.tool_calls ?? []).map((c) => `[called ${c.function.name} ${JSON.stringify(c.function.arguments ?? {})}]`);
      lines.push('', '### Assistant', [m.content, ...calls].filter((s) => s && s.trim() !== '').join('\n') || '(no text)');
    } else lines.push('', '### User', m.content);
  }
  if (req.format !== undefined) lines.push('', 'Reply with only a JSON object that matches the output schema.');
  return lines.join('\n');
}

export interface CodexChatProviderOptions {
  projectRoot: string;
  // -m, null for codex config
  model: string | null;
  // label for verdicts and logs
  label: string;
  apiKey: string | null;
  // schema and output files, .patch-pilot/tmp
  tmpDir: string;
  timeoutMs: number;
  debugLog?: string | null;
  codexCommand?: string;
  env?: NodeJS.ProcessEnv;
}

export class CodexChatProvider implements ChatProvider {
  readonly name = 'codex' as const;
  readonly model: string;
  readonly options: CodexChatProviderOptions;
  private readonly totals = { requests: 0, inputTokens: 0, outputTokens: 0 };

  constructor(options: CodexChatProviderOptions) {
    this.options = options;
    this.model = options.label;
  }

  async chat(req: ChatRequest): Promise<ChatResponse> {
    await mkdir(this.options.tmpDir, { recursive: true });
    const dir = await mkdtemp(path.join(this.options.tmpDir, 'codex-'));
    const started = Date.now();
    try {
      let schemaFile: string | null = null;
      if (req.format !== undefined && req.format !== 'json') {
        schemaFile = path.join(dir, 'schema.json');
        await writeFile(schemaFile, JSON.stringify(strictSchema(req.format), null, 2), 'utf8');
      }
      const outputFile = path.join(dir, 'answer.txt');
      const timeoutMs = req.timeoutMs ?? this.options.timeoutMs;
      await this.debug({ dir: 'request', purpose: req.purpose ?? 'other', messages: req.messages?.length ?? 0, format: req.format !== undefined });
      const result = await runCodexExec({
        prompt: transcriptPrompt(req),
        projectRoot: this.options.projectRoot,
        model: this.options.model,
        outputSchemaFile: schemaFile,
        outputFile,
        apiKey: this.options.apiKey,
        timeoutMs,
        ...(req.signal ? { signal: req.signal } : {}),
        ...(this.options.codexCommand ? { codexCommand: this.options.codexCommand } : {}),
        ...(this.options.env ? { env: this.options.env } : {}),
      }).catch((err: unknown) => {
        if (err instanceof EnvironmentError) throw new LlmError('unreachable', err.message, { hint: err.hint ?? `Install it: ${CODEX_INSTALL}` });
        throw err;
      });
      this.totals.requests += 1;
      this.totals.inputTokens += result.usage.inputTokens;
      this.totals.outputTokens += result.usage.outputTokens;
      if (result.aborted) throw new LlmError('aborted', 'Request aborted');
      if (result.timedOut) throw new LlmError('timeout', `Codex did not answer within ${Math.round(timeoutMs / 1000)} s`);
      if (result.exitCode !== 0) {
        const failure = describeCodexFailure(result, timeoutMs);
        await this.debug({ dir: 'error', purpose: req.purpose ?? 'other', message: failure.message, durationMs: Date.now() - started });
        throw new LlmError(failure.auth ? 'unreachable' : 'http', failure.message, { hint: failure.hint });
      }
      const written = await readFile(outputFile, 'utf8').catch(() => null);
      const content = (written ?? result.finalMessage ?? '').trim();
      await this.debug({ dir: 'response', purpose: req.purpose ?? 'other', durationMs: Date.now() - started, content: content.slice(0, 4000) });
      return {
        message: { role: 'assistant', content },
        model: this.model,
        done: true,
        doneReason: 'stop',
        usage: { promptTokens: result.usage.inputTokens, completionTokens: result.usage.outputTokens, totalMs: Date.now() - started },
      };
    } finally {
      await rm(dir, { recursive: true, force: true }).catch(() => {});
    }
  }

  async checkModel(model?: string): Promise<ModelCheck> {
    const name = model ?? this.model;
    return { ok: true, model: name, installed: true, tools: true, resolvedModel: name };
  }

  async warmup(): Promise<void> {}

  usageSummary(): ProviderUsageSummary {
    return { requests: this.totals.requests, inputTokens: this.totals.inputTokens, outputTokens: this.totals.outputTokens, costUsd: null };
  }

  private async debug(entry: Record<string, unknown>): Promise<void> {
    const file = this.options.debugLog;
    if (!file) return;
    try {
      await mkdir(path.dirname(file), { recursive: true });
      await appendFile(file, `${JSON.stringify(redactSecrets({ ts: new Date().toISOString(), provider: 'codex', model: this.model, ...entry }))}\n`, 'utf8');
    } catch {
      // debugging must never break a run
    }
  }
}
