// detect ollama, claude, codex
import { select } from '@inquirer/prompts';
import { configSet } from './configCommand.ts';
import { DEFAULT_MODEL, isLocalHost } from './config.ts';
import { ANTHROPIC_KEYS_URL, CLAUDE_MODEL_ALIASES, claudePricing, DEFAULT_CLAUDE_MODEL, isClaudeModelName, resolveClaudeModel } from './llm/anthropic.ts';
import { CODEX_DOCS, CODEX_INSTALL, CODEX_LOGIN, codexModelLabel, codexStatus, type CodexStatus } from './llm/codex.ts';
import { resolveProviderModel } from './llm/provider.ts';
import type { Config, ProviderAvailability, ProviderName, ProviderSelection } from './types.ts';
import type { Ui } from './ui.ts';
import { USER_AGENT } from './version.ts';

export type ModelStrength = 'strong' | 'usable' | 'weak' | 'unknown';

export const SUBSCRIBER_NOTE = 'Claude Pro or Max subscription? Use PatchPilot inside your own Claude Code: patch-pilot mcp --print-config';

export const PROVIDER_LABELS: Readonly<Record<ProviderName, string>> = {
  ollama: 'Ollama',
  claude: 'Claude API',
  codex: 'Codex CLI',
  mock: 'Mock',
};

const OLLAMA_DOWNLOAD = 'https://ollama.com/download';
const OLLAMA_TOOL_MODELS = 'https://ollama.com/search?c=tools';
const STRENGTH_RANK: Record<ModelStrength, number> = { strong: 3, usable: 2, unknown: 1, weak: 0 };

export function isCloudProvider(provider: ProviderName): boolean {
  return provider === 'claude' || provider === 'codex';
}

export function privacyNote(provider: ProviderName, ollamaHost?: string): string {
  switch (provider) {
    case 'claude':
      return 'cloud: code snippets are sent to Anthropic';
    case 'codex':
      return 'cloud: code snippets are sent to OpenAI';
    case 'ollama':
      return ollamaHost && !isLocalHost(ollamaHost) ? `code snippets are sent to your Ollama server at ${ollamaHost}` : 'local, code stays on this machine';
    default:
      return 'scripted, no model';
  }
}

// from the tag or parameter_size
export function parameterBillions(name: string, parameterSize?: string | null): number | null {
  const colon = name.lastIndexOf(':');
  const tag = colon > name.lastIndexOf('/') ? name.slice(colon + 1) : '';
  const fromTag = /(\d+(?:\.\d+)?)b(?![a-z])/i.exec(tag);
  if (fromTag && fromTag[1] !== undefined) return Number(fromTag[1]);
  const fromSize = /^(\d+(?:\.\d+)?)\s*([BM])$/i.exec((parameterSize ?? '').trim());
  if (fromSize && fromSize[1] !== undefined) return fromSize[2]?.toUpperCase() === 'M' ? Number(fromSize[1]) / 1000 : Number(fromSize[1]);
  return null;
}

// guidance only, never blocks
export function modelStrength(name: string, sizeB: number | null, family?: string | null): ModelStrength {
  if (sizeB === null || !Number.isFinite(sizeB)) return 'unknown';
  const base = (name.split(':')[0] ?? name).split('/').pop()?.toLowerCase() ?? '';
  const qwen3 = /^qwen3/.test(base) || /^qwen3/.test((family ?? '').toLowerCase());
  if (qwen3) return sizeB >= 7.5 ? 'strong' : sizeB >= 3.5 ? 'usable' : 'weak';
  return sizeB >= 12 ? 'strong' : sizeB >= 6.5 ? 'usable' : 'weak';
}

export function strengthNote(strength: ModelStrength): string {
  switch (strength) {
    case 'strong':
      return 'strong: good judgement on most projects';
    case 'usable':
      return 'usable: fine for most projects, follows the protocol';
    case 'weak':
      return 'weak: expect shallow verdicts';
    default:
      return 'strength unknown';
  }
}

export interface OllamaModelInfo {
  name: string;
  parameterSize: string | null;
  sizeB: number | null;
  family: string | null;
  tools: boolean | null;
  strength: ModelStrength;
}

export interface OllamaModelsProbe {
  reachable: boolean;
  version: string | null;
  models: OllamaModelInfo[];
  error: string | null;
}

async function getJson(fetchImpl: typeof fetch, url: string, init: RequestInit, timeoutMs: number): Promise<unknown> {
  const res = await fetchImpl(url, { ...init, headers: { 'user-agent': USER_AGENT, ...(init.body ? { 'content-type': 'application/json' } : {}) }, signal: AbortSignal.timeout(timeoutMs) });
  const text = await res.text();
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return JSON.parse(text) as unknown;
}

function fetchErrorText(err: unknown): string {
  const e = err as { name?: string; message?: string; cause?: { code?: string } };
  if (e?.name === 'TimeoutError') return 'timed out';
  if (e?.cause?.code === 'ECONNREFUSED') return 'connection refused';
  return e?.cause?.code ?? e?.message ?? String(err);
}

// never throws
export async function probeOllamaModels(host: string, options: { fetch?: typeof fetch; timeoutMs?: number } = {}): Promise<OllamaModelsProbe> {
  const fetchImpl = options.fetch ?? ((input, init) => fetch(input, init));
  const timeoutMs = options.timeoutMs ?? 3_000;
  const out: OllamaModelsProbe = { reachable: false, version: null, models: [], error: null };
  try {
    const version = (await getJson(fetchImpl, `${host}/api/version`, { method: 'GET' }, timeoutMs)) as { version?: unknown };
    out.reachable = true;
    out.version = typeof version?.version === 'string' ? version.version : null;
  } catch (err) {
    out.error = fetchErrorText(err);
    return out;
  }
  let tags: { models?: { name?: string; model?: string; details?: { parameter_size?: string; family?: string }; capabilities?: unknown }[] };
  try {
    tags = (await getJson(fetchImpl, `${host}/api/tags`, { method: 'GET' }, timeoutMs)) as typeof tags;
  } catch (err) {
    out.error = `could not list models (${fetchErrorText(err)})`;
    return out;
  }
  const models = (tags.models ?? [])
    .map((m) => {
      const name = m.name ?? m.model ?? '';
      const caps = Array.isArray(m.capabilities) ? m.capabilities.filter((c): c is string => typeof c === 'string') : null;
      const parameterSize = m.details?.parameter_size ?? null;
      const sizeB = parameterBillions(name, parameterSize);
      const family = m.details?.family ?? null;
      return { name, parameterSize, sizeB, family, tools: caps ? caps.includes('tools') : null, strength: modelStrength(name, sizeB, family) };
    })
    .filter((m) => m.name !== '');
  await Promise.all(
    models
      .filter((m) => m.tools === null)
      .slice(0, 12)
      .map(async (m) => {
        try {
          const show = (await getJson(fetchImpl, `${host}/api/show`, { method: 'POST', body: JSON.stringify({ model: m.name }) }, timeoutMs * 2)) as { capabilities?: unknown };
          if (Array.isArray(show?.capabilities)) m.tools = show.capabilities.includes('tools');
        } catch {
        }
      }),
  );
  out.models = models;
  return out;
}

// strongest first, then smallest
export function rankToolModels(models: readonly OllamaModelInfo[]): OllamaModelInfo[] {
  return models
    .filter((m) => m.tools !== false)
    .sort((a, b) => STRENGTH_RANK[b.strength] - STRENGTH_RANK[a.strength] || (a.sizeB ?? 999) - (b.sizeB ?? 999) || a.name.localeCompare(b.name));
}

// matches base and size
function installedMatch(want: string, models: readonly OllamaModelInfo[]): OllamaModelInfo | undefined {
  const exact = models.find((m) => m.name === want);
  if (exact) return exact;
  const [base, tag] = want.includes(':') ? [want.slice(0, want.lastIndexOf(':')), want.slice(want.lastIndexOf(':') + 1)] : [want, null];
  const same = models.filter((m) => (m.name.includes(':') ? m.name.slice(0, m.name.lastIndexOf(':')) : m.name) === base);
  if (tag === null || tag === 'latest') return same[0];
  const wanted = parameterBillions(want);
  return same.find((m) => wanted !== null && m.sizeB !== null && Math.abs(m.sizeB - wanted) < 1);
}

export interface PickerDeps {
  fetch?: typeof fetch;
  // default: codex login status
  codexStatus?: () => Promise<CodexStatus>;
  // default: inquirer select
  select?: (message: string, choices: PickerChoice[], defaultValue?: string) => Promise<string>;
  // default: ui single-key prompt
  ask?: (question: string) => Promise<boolean>;
  // default: config set per key
  remember?: (values: { key: string; value: string }[]) => Promise<void>;
  env?: NodeJS.ProcessEnv;
}

export interface PickerChoice {
  value: string;
  name: string;
  description?: string;
  // disables the choice, shows why
  disabled?: string | false;
}

export interface ProviderDetection {
  options: ProviderAvailability[];
  ollama: OllamaModelsProbe;
  codex: CodexStatus;
}

function keySource(config: Pick<Config, 'sources'>, key: 'anthropicApiKey' | 'codexApiKey', env: string): string {
  return config.sources[key] === 'user' ? '~/.patch-pilot/config.json' : env;
}

// never throws
export async function detectProviders(config: Config, deps: PickerDeps = {}): Promise<ProviderDetection> {
  const env = deps.env ?? process.env;
  const [ollama, codex] = await Promise.all([
    probeOllamaModels(config.ollamaHost, { ...(deps.fetch ? { fetch: deps.fetch } : {}), timeoutMs: config.timeouts.ollamaProbeMs }),
    (deps.codexStatus ?? (() => codexStatus({ apiKey: config.codexApiKey, env })))().catch(
      (): CodexStatus => ({ installed: false, path: null, loggedIn: false, method: null, detail: 'not installed' }),
    ),
  ]);
  const options: ProviderAvailability[] = [];

  const ranked = rankToolModels(ollama.models.filter((m) => m.tools === true));
  const configured = config.provider === 'ollama' || !isClaudeModelName(config.model) ? installedMatch(config.model, ranked) : undefined;
  const suggested = configured ?? ranked[0];
  if (!ollama.reachable) {
    options.push({
      provider: 'ollama',
      available: false,
      detail: `not reachable at ${config.ollamaHost} (${ollama.error ?? 'no answer'})`,
      model: null,
      fix: ['Start it: ollama serve (or open the Ollama app)', `Install: ${OLLAMA_DOWNLOAD}`],
    });
  } else if (!suggested) {
    options.push({
      provider: 'ollama',
      available: false,
      detail: ollama.models.length > 0 ? 'no tool-capable model installed' : 'no model installed',
      model: null,
      fix: ['Pull one: ollama pull qwen3:8b (or ollama pull mistral)', `Tool-capable models: ${OLLAMA_TOOL_MODELS}`],
    });
  } else {
    options.push({
      provider: 'ollama',
      available: true,
      detail: `${suggested.name} (${suggested.strength}) ${'·'} ${ranked.length} tool-capable model${ranked.length === 1 ? '' : 's'} ${'·'} ${privacyNote('ollama', config.ollamaHost)}`,
      model: suggested.name,
      strength: suggested.strength,
    });
  }

  const claudeModel = isClaudeModelName(config.model) ? config.model : DEFAULT_CLAUDE_MODEL;
  if (config.anthropicApiKey) {
    options.push({
      provider: 'claude',
      available: true,
      detail: `${claudeModel} (API key from ${keySource(config, 'anthropicApiKey', 'ANTHROPIC_API_KEY')}) ${'·'} ${privacyNote('claude')}`,
      model: claudeModel,
    });
  } else {
    options.push({
      provider: 'claude',
      available: false,
      detail: 'no Anthropic API key',
      model: null,
      fix: ['patch-pilot config set anthropic-api-key (asks without echo), or export ANTHROPIC_API_KEY=...', `Keys: ${ANTHROPIC_KEYS_URL}`, SUBSCRIBER_NOTE],
    });
  }

  const label = codexModelLabel(null, env);
  if (codex.installed && codex.loggedIn) {
    const how = codex.method === 'api-key' ? (config.codexApiKey ? `API key from ${keySource(config, 'codexApiKey', 'CODEX_API_KEY')}` : 'API key login') : codex.method === 'chatgpt' ? 'ChatGPT login' : codex.detail;
    options.push({ provider: 'codex', available: true, detail: `${label} (${how}) ${'·'} ${privacyNote('codex')}`, model: label });
  } else if (!codex.installed) {
    options.push({ provider: 'codex', available: false, detail: 'Codex CLI not installed', model: null, fix: [`Install: ${CODEX_INSTALL}`, `Then: ${CODEX_LOGIN} (or export CODEX_API_KEY=...)`, `Docs: ${CODEX_DOCS}`] });
  } else {
    options.push({ provider: 'codex', available: false, detail: 'Codex CLI not logged in', model: null, fix: [`Sign in: ${CODEX_LOGIN} (ChatGPT), or export CODEX_API_KEY=... (recommended for automation)`, `Docs: ${CODEX_DOCS}`] });
  }
  return { options, ollama, codex };
}

export interface ProviderChoice {
  provider: ProviderName;
  model: string;
  selection: ProviderSelection;
  cloud: boolean;
  // empty when set by flag or config
  options: ProviderAvailability[];
  remembered: boolean;
  // e.g. cloud options without ollama
  notes: string[];
  // saved model was another provider's
  modelFallback: boolean;
}

function defaultSelect(ui: Ui): NonNullable<PickerDeps['select']> {
  return async (message, choices, defaultValue) =>
    select({
      message: ui.text(message),
      choices: choices.map((c) => ({
        value: c.value,
        name: ui.text(c.name),
        ...(c.description ? { description: ui.text(c.description) } : {}),
        ...(c.disabled ? { disabled: ui.text(c.disabled) } : {}),
      })),
      ...(defaultValue !== undefined ? { default: defaultValue } : {}),
      theme: { prefix: ui.blue(ui.glyphs.prompt), style: { description: (text: string) => ui.c.dim(text) } },
    });
}

function defaultRemember(ui: Ui, env: NodeJS.ProcessEnv): NonNullable<PickerDeps['remember']> {
  return async (values) => {
    for (const { key, value } of values) await configSet(key, value, ui, { interactive: false, env });
  };
}

const CLAUDE_CHOICES: readonly { alias: string; note: string }[] = [
  { alias: 'sonnet', note: 'balanced (the default)' },
  { alias: 'opus', note: 'most capable, slower' },
  { alias: 'haiku', note: 'fastest and cheapest' },
];

function claudeModelChoices(): PickerChoice[] {
  return CLAUDE_CHOICES.map(({ alias, note }) => {
    const id = CLAUDE_MODEL_ALIASES[alias] ?? alias;
    const price = claudePricing(id);
    return { value: alias, name: `${alias}  ${id}`, description: `${note}${price ? `, $${price.inputPerMTok} in / $${price.outputPerMTok} out per million tokens` : ''}` };
  });
}

// flag, config, then picker
export async function chooseProvider(config: Config, ui: Ui, deps: PickerDeps = {}): Promise<ProviderChoice> {
  const env = deps.env ?? process.env;
  if (config.provider === 'mock' || config.providerSelection === 'flag' || config.providerSelection === 'config') {
    const resolved = resolveProviderModel(config);
    return {
      provider: config.provider,
      model: resolved.model,
      selection: config.providerSelection === 'default' ? 'default' : config.providerSelection,
      cloud: isCloudProvider(config.provider),
      options: [],
      remembered: false,
      notes: [],
      modelFallback: resolved.fallback,
    };
  }
  const detection = await detectProviders(config, deps);
  const { options } = detection;
  const available = options.filter((o) => o.available);
  const interactive = config.interactive && ui.interactive;
  const ollama = options.find((o) => o.provider === 'ollama');
  const onlyOllama = available.length === 1 && available[0]?.provider === 'ollama';
  if (!interactive || available.length === 0 || onlyOllama) {
    const resolved = resolveProviderModel({ ...config, provider: 'ollama' });
    const notes: string[] = [];
    if (!ollama?.available) {
      const cloud = available.filter((o) => isCloudProvider(o.provider));
      if (cloud.length > 0) {
        notes.push(
          `Ollama is not available, but ${cloud.map((o) => PROVIDER_LABELS[o.provider]).join(' and ')} ${cloud.length === 1 ? 'is' : 'are'} ready: pass ${cloud.map((o) => `--provider ${o.provider}`).join(' or ')} to use ${cloud.length === 1 ? 'it' : 'one'} (code snippets are then sent to ${cloud.map((o) => (o.provider === 'claude' ? 'Anthropic' : 'OpenAI')).join(' or ')}).`,
        );
      } else {
        notes.push(`No model provider is ready. Start Ollama (ollama serve), or use --provider claude with an API key, or --provider codex with the Codex CLI. ${SUBSCRIBER_NOTE}`);
      }
    }
    return { provider: 'ollama', model: resolved.model, selection: 'default', cloud: false, options, remembered: false, notes, modelFallback: resolved.fallback };
  }

  const choose = deps.select ?? defaultSelect(ui);
  const providerChoices: PickerChoice[] = options.map((o) => ({
    value: o.provider,
    name: `${PROVIDER_LABELS[o.provider].padEnd(10)}  ${o.detail}`,
    description: o.available ? privacyNote(o.provider, config.ollamaHost) : (o.fix?.[0] ?? 'not available'),
    disabled: o.available ? false : o.detail,
  }));
  ui.info('');
  const firstAvailable = available.find((o) => o.provider === 'ollama') ?? available[0];
  const provider = (await choose('Which model should investigate this project?', providerChoices, firstAvailable?.provider)) as ProviderName;
  let model: string;
  let remembered = false;
  if (provider === 'claude') {
    const current = isClaudeModelName(config.model) ? config.model.toLowerCase() : DEFAULT_CLAUDE_MODEL;
    const alias = await choose('Which Claude model?', claudeModelChoices(), Object.hasOwn(CLAUDE_MODEL_ALIASES, current) ? current : DEFAULT_CLAUDE_MODEL);
    model = alias;
  } else if (provider === 'ollama') {
    const ranked = rankToolModels(detection.ollama.models.filter((m) => m.tools === true));
    const suggested = ollama?.model ?? ranked[0]?.name ?? DEFAULT_MODEL;
    model =
      ranked.length > 1
        ? await choose(
            'Which local model?',
            ranked.map((m) => ({ value: m.name, name: `${m.name}${m.parameterSize ? `  ${m.parameterSize}` : ''}`, description: strengthNote(m.strength) })),
            suggested,
          )
        : suggested;
  } else {
    model = codexModelLabel(config.sources.model === 'flag' ? config.model : null, env);
  }
  if (await (deps.ask ?? (async (q: string) => (await ui.singleKeyPrompt(q, 'y/n')) === 'y'))('Remember this choice for next time?')) {
    await (deps.remember ?? defaultRemember(ui, env))([{ key: 'provider', value: provider }, ...(provider === 'codex' ? [] : [{ key: 'model', value: model }])]);
    remembered = true;
  }
  return {
    provider,
    model: provider === 'claude' ? resolveClaudeModel(model) : model,
    selection: 'picker',
    cloud: isCloudProvider(provider),
    options,
    remembered,
    notes: [],
    modelFallback: false,
  };
}

// picker choice counts as a flag
export function applyProviderChoice(config: Config, choice: ProviderChoice): void {
  config.provider = choice.provider;
  config.providerSelection = choice.selection;
  if (choice.selection === 'picker') {
    config.model = choice.model;
    if (choice.provider !== 'codex') config.sources.model = 'flag';
    config.sources.provider = 'flag';
    return;
  }
  if (choice.model !== config.model) {
    config.model = choice.model;
    if (choice.modelFallback) config.sources.model = 'default';
  }
}

export function renderProviderLines(options: readonly ProviderAvailability[], ui: Ui, current: ProviderName): string {
  const width = Math.max(...options.map((o) => PROVIDER_LABELS[o.provider].length)) + 2;
  const lines = ['', ui.c.bold('Providers')];
  for (const o of options) {
    const label = `${PROVIDER_LABELS[o.provider]}${o.provider === current ? ' *' : ''}`.padEnd(width);
    if (o.available) lines.push(ui.formatCheck(label, o.detail, ui.c));
    else if (o.provider === current) lines.push(ui.formatFail(label, o.detail, ui.c));
    else lines.push(ui.formatInfoLine(label, o.detail, ui.c));
    if (!o.available && o.fix && o.fix.length > 0) lines.push(ui.formatDimLines(o.fix, width + 4, ui.c));
  }
  lines.push(ui.c.dim('  * the provider of this run'));
  const claude = options.find((o) => o.provider === 'claude');
  if (claude?.available) lines.push(ui.c.dim(`  ${SUBSCRIBER_NOTE}`));
  return lines.join('\n');
}
