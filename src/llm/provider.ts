import { readFileSync } from 'node:fs';
import { DEFAULT_MODEL } from '../config.ts';
import type { ChatRequest, ChatResponse, Config, ModelCheck, ProviderName } from '../types.ts';
import { EnvironmentError } from '../util/errors.ts';
import { ANTHROPIC_KEYS_URL, AnthropicProvider, DEFAULT_CLAUDE_MODEL, isClaudeModelName, resolveClaudeModel } from './anthropic.ts';
import { CodexChatProvider, codexModelLabel } from './codex.ts';
import { MockProvider, parseMockScript, type MockScript } from './mock.ts';
import { OllamaProvider } from './ollama.ts';

// cloud providers only
export interface ProviderUsageSummary {
  requests: number;
  inputTokens: number;
  outputTokens: number;
  // null for unknown prices
  costUsd: number | null;
}

export interface ChatProvider {
  readonly name: ProviderName;
  readonly model: string;
  // throws LlmError
  chat(req: ChatRequest): Promise<ChatResponse>;
  checkModel(model?: string): Promise<ModelCheck>;
  // warm up for a fast first turn
  warmup?(): Promise<void>;
  // cloud providers only
  usageSummary?(): ProviderUsageSummary | null;
}

export { LlmError, type LlmErrorKind } from './errors.ts';

export interface CreateProviderOptions {
  // e.g. config.codemodModel
  model?: string;
  // else an empty script
  script?: MockScript;
}

export function loadMockScriptFile(file: string): MockScript {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(file, 'utf8'));
  } catch (err) {
    throw new Error(`Cannot read mock script ${file}: ${(err as Error).message}`, { cause: err });
  }
  return parseMockScript(raw);
}

export function missingAnthropicKey(): EnvironmentError {
  return new EnvironmentError('No Anthropic API key for --provider claude', {
    hint: [
      'Store it with: patch-pilot config set anthropic-api-key (asks without echo), or export ANTHROPIC_API_KEY=...',
      `Create a key: ${ANTHROPIC_KEYS_URL}`,
      'Claude Pro or Max subscription instead of an API key? Use PatchPilot inside your own Claude Code: patch-pilot mcp --print-config',
    ].join('\n  '),
  });
}

// ollama by default
export function createProvider(config: Config, options: CreateProviderOptions = {}): ChatProvider {
  const model = options.model ?? config.model;
  if (config.provider === 'mock') {
    const script = options.script ?? (config.mockScript ? loadMockScriptFile(config.mockScript) : { rules: [] });
    return new MockProvider(script, { model });
  }
  if (config.provider === 'claude') {
    if (!config.anthropicApiKey) throw missingAnthropicKey();
    const chosen = options.model !== undefined && isClaudeModelName(options.model) ? options.model : resolveProviderModel(config).model;
    return new AnthropicProvider({
      apiKey: config.anthropicApiKey,
      model: chosen,
      timeoutMs: config.timeouts.llmMs,
      think: config.think,
      debugLog: config.debug ? config.paths.debugLog : null,
    });
  }
  if (config.provider === 'codex') {
    const explicit = config.sources.model === 'flag' ? model : null;
    return new CodexChatProvider({
      projectRoot: config.projectRoot,
      model: explicit,
      label: codexModelLabel(explicit),
      apiKey: config.codexApiKey,
      tmpDir: config.paths.tmpDir,
      timeoutMs: Math.max(config.timeouts.llmMs * 2, 300_000),
      debugLog: config.debug ? config.paths.debugLog : null,
    });
  }
  return new OllamaProvider({
    host: config.ollamaHost,
    model,
    numCtx: config.numCtx,
    think: config.think,
    seed: config.seed,
    temperature: 0,
    timeoutMs: config.timeouts.llmMs,
    keepAlive: '30m',
    debugLog: config.debug ? config.paths.debugLog : null,
  });
}

// --codemod-model or the main model
export function createCodemodProvider(config: Config, options: Omit<CreateProviderOptions, 'model'> = {}): ChatProvider {
  if (config.provider === 'claude') {
    const codemod = config.codemodModel && isClaudeModelName(config.codemodModel) ? config.codemodModel : config.model;
    return createProvider(config, { ...options, model: codemod });
  }
  if (config.provider === 'codex') return createProvider(config, { ...options, model: config.model });
  return createProvider(config, { ...options, model: config.codemodModel ?? config.model });
}

function isClaudeLike(model: string): boolean {
  return isClaudeModelName(model);
}

// saved models never cross providers
export function resolveProviderModel(config: Pick<Config, 'provider' | 'model' | 'sources'>): { model: string; fallback: boolean } {
  const explicit = config.sources.model === 'flag';
  switch (config.provider) {
    case 'claude':
      if (isClaudeLike(config.model)) return { model: resolveClaudeModel(config.model), fallback: false };
      return explicit ? { model: config.model, fallback: false } : { model: resolveClaudeModel(DEFAULT_CLAUDE_MODEL), fallback: true };
    case 'codex':
      return explicit ? { model: config.model, fallback: false } : { model: codexModelLabel(null), fallback: config.sources.model !== 'default' };
    case 'ollama':
      if (!explicit && isClaudeLike(config.model)) return { model: DEFAULT_MODEL, fallback: true };
      return { model: config.model, fallback: false };
    default:
      return { model: config.model, fallback: false };
  }
}

// e.g. "1.2k"
function kTokens(n: number): string {
  if (n < 1000) return String(n);
  if (n < 100_000) return `${(n / 1000).toFixed(1)}k`;
  return `${Math.round(n / 1000)}k`;
}

// empty when unused
export function formatUsageSummary(summary: ProviderUsageSummary | null | undefined, dot = '·'): string {
  if (!summary || summary.requests === 0) return '';
  const cost = summary.costUsd === null ? 'cost unknown' : `est. $${summary.costUsd < 0.01 ? summary.costUsd.toFixed(4) : summary.costUsd.toFixed(2)}`;
  return `${cost} ${dot} ${kTokens(summary.inputTokens)} in / ${kTokens(summary.outputTokens)} out tokens`;
}
