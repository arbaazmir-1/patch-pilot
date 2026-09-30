// flags, env, config files, ignores, --fail-on
import { readFile, realpath, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type {
  Config,
  ConfigPaths,
  ConfigSource,
  ConfigTimeouts,
  FailOn,
  IgnoreEntry,
  ProjectConfigFile,
  ProviderName,
  ProviderSelection,
  RiskLevel,
  SearchMode,
  UserConfigFile,
  Verdict,
} from './types.ts';
import { ConfigError } from './util/errors.ts';
import { updateJsonFile } from './util/fs.ts';

// best benchmarked, ~35 s per cve, think off
export const DEFAULT_MODEL = 'qwen3:8b';
export const MOCK_MODEL = 'mock';
export const DEFAULT_OLLAMA_HOST = 'http://localhost:11434';
export const OLLAMA_DEFAULT_PORT = 11434;
export const DEFAULT_NUM_CTX = 16384;
export const DEFAULT_MAX_STEPS = 3;
export const DEFAULT_SEED = 42;
export const DEFAULT_SEARCH: SearchMode = 'auto';
export const DEFAULT_FAIL_ON: FailOn = 'high';
export const DEFAULT_PROVIDER: ProviderName = 'ollama';

export const CONFIG_FILE_NAME = 'patch-pilot.config.json';
// mode 0600
export const USER_CONFIG_FILE_NAME = 'config.json';
export const STATE_DIR_NAME = '.patch-pilot';
export const HOME_DIR_NAME = '.patch-pilot';

// plus the config's exclude list
export const DEFAULT_EXCLUDES: readonly string[] = [
  'node_modules/**',
  '**/node_modules/**',
  '.git/**',
  'dist/**',
  'build/**',
  'coverage/**',
  '.patch-pilot/**',
];

export const DEFAULT_TIMEOUTS: ConfigTimeouts = {
  osvMs: 20_000,
  registryMs: 15_000,
  llmMs: 180_000,
  webMs: 15_000,
  ollamaProbeMs: 3_000,
};

export const PROVIDERS: readonly ProviderName[] = ['ollama', 'claude', 'codex', 'mock'];
export const SEARCH_MODES: readonly SearchMode[] = ['auto', 'ollama', 'docs', 'brave', 'off'];
export const THINK_MODES = ['auto', 'on', 'off'] as const;
const DEFAULT_THINK: (typeof THINK_MODES)[number] = 'off';
export const FAIL_ON_VALUES: readonly FailOn[] = ['critical', 'high', 'medium', 'low', 'noise', 'never'];

// ascending
export const RISK_ORDER: readonly RiskLevel[] = ['Noise', 'Low', 'Medium', 'High', 'Critical'];

const NUM_CTX_RANGE = { min: 2048, max: 262_144 };
const MAX_STEPS_RANGE = { min: 1, max: 12 };

// numbers may arrive as strings
export interface CliFlags {
  provider?: string;
  model?: string;
  codemodModel?: string;
  ollamaHost?: string;
  numCtx?: number | string;
  think?: string;
  maxSteps?: number | string;
  limit?: number | string;
  only?: string | string[];
  maxCves?: number | string;
  offline?: boolean;
  dryRun?: boolean;
  cache?: boolean;
  fresh?: boolean;
  approveAll?: boolean;
  approveCodemods?: boolean;
  approve?: string | string[];
  trust?: boolean;
  json?: boolean;
  verbose?: boolean;
  quiet?: boolean;
  seed?: number | string;
  search?: string;
  ci?: boolean;
  failOn?: string;
  resume?: boolean;
  color?: boolean;
  mockScript?: string;
}

export interface LoadConfigInput {
  // resolved against cwd
  dir?: string;
  flags?: CliFlags;
  env?: NodeJS.ProcessEnv;
  cwd?: string;
  homeDir?: string;
  stdinIsTTY?: boolean;
  stdoutIsTTY?: boolean;
  // for db, trust
  skipProjectFile?: boolean;
}

function parseInteger(name: string, value: unknown, min: number, max: number): number {
  const n = typeof value === 'number' ? value : typeof value === 'string' && value.trim() !== '' ? Number(value) : Number.NaN;
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new ConfigError(`Invalid ${name}: ${String(value)} (expected an integer from ${min} to ${max})`);
  }
  return n;
}

function parseEnum<T extends string>(name: string, value: unknown, allowed: readonly T[]): T {
  if (typeof value === 'string' && (allowed as readonly string[]).includes(value.toLowerCase())) {
    return value.toLowerCase() as T;
  }
  throw new ConfigError(`Invalid ${name}: ${String(value)} (expected one of ${allowed.join(', ')})`);
}

function parseList(value: string | string[] | undefined): string[] {
  if (value === undefined) return [];
  const parts = Array.isArray(value) ? value : [value];
  return [...new Set(parts.flatMap((p) => p.split(',')).map((p) => p.trim()).filter(Boolean))];
}

function parseBoolEnv(value: string | undefined): boolean | undefined {
  if (value === undefined) return undefined;
  const v = value.trim().toLowerCase();
  if (v === '' || v === '0' || v === 'false' || v === 'no' || v === 'off') return false;
  return true;
}

function nonEmpty(value: string | undefined): string | undefined {
  return value !== undefined && value.trim() !== '' ? value.trim() : undefined;
}

// like the ollama cli, 0.0.0.0 -> 127.0.0.1
export function normalizeOllamaHost(raw: string): string {
  const input = raw.trim();
  if (input === '') throw new ConfigError('Invalid Ollama host: empty value');
  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(input);
  let url: URL;
  try {
    url = new URL(hasScheme ? input : `http://${input}`);
  } catch {
    throw new ConfigError(`Invalid Ollama host: ${raw}`, { hint: 'Use a URL such as http://localhost:11434' });
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new ConfigError(`Invalid Ollama host: ${raw} (only http and https are supported)`);
  }
  if (url.hostname === '0.0.0.0') url.hostname = '127.0.0.1';
  if (url.hostname === '[::]') url.hostname = '[::1]';
  if (!hasScheme && url.port === '') url.port = String(OLLAMA_DEFAULT_PORT);
  const pathname = url.pathname.replace(/\/+$/, '');
  return `${url.protocol}//${url.host}${pathname}`;
}

export function isLocalHost(host: string): boolean {
  try {
    const name = new URL(host).hostname.replace(/^\[|\]$/g, '');
    // loopback ipv4 only, not 127.evil.com
    const loopbackV4 = /^127(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(name);
    return name === 'localhost' || name === '::1' || loopbackV4 || name.endsWith('.localhost');
  } catch {
    return false;
  }
}

export function patchPilotHome(homeDir: string = os.homedir()): string {
  return path.join(homeDir, HOME_DIR_NAME);
}

export function projectPaths(projectRoot: string, homeDir: string = os.homedir()): ConfigPaths {
  const stateDir = path.join(projectRoot, STATE_DIR_NAME);
  const home = patchPilotHome(homeDir);
  return {
    projectRoot,
    stateDir,
    homeDir: home,
    userConfigFile: path.join(home, USER_CONFIG_FILE_NAME),
    dbFile: path.join(home, 'patch-pilot.db'),
    trustedFile: path.join(home, 'trusted.json'),
    configFile: path.join(projectRoot, CONFIG_FILE_NAME),
    caseFile: path.join(stateDir, 'case-file.json'),
    assessmentFile: path.join(stateDir, 'assessment.json'),
    verdictCacheFile: path.join(stateDir, 'verdict-cache.json'),
    auditLog: path.join(stateDir, 'audit.jsonl'),
    reportMd: path.join(stateDir, 'report.md'),
    reportJson: path.join(stateDir, 'report.json'),
    backupDir: path.join(stateDir, 'backup'),
    tmpDir: path.join(stateDir, 'tmp'),
    debugLog: path.join(stateDir, 'debug.log'),
  };
}

const KNOWN_FILE_KEYS = new Set([
  '$schema',
  'provider',
  'model',
  'codemodModel',
  'ollamaHost',
  'numCtx',
  'think',
  'maxSteps',
  'search',
  'failOn',
  'exclude',
  'ignore',
]);

function validateIgnoreEntries(raw: unknown, errors: string[]): IgnoreEntry[] {
  if (!Array.isArray(raw)) {
    errors.push('"ignore" must be an array of { id, reason, package?, until? }');
    return [];
  }
  const out: IgnoreEntry[] = [];
  raw.forEach((item, i) => {
    const where = `ignore[${i}]`;
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      errors.push(`${where} must be an object`);
      return;
    }
    const e = item as Record<string, unknown>;
    if (typeof e.id !== 'string' || e.id.trim() === '') errors.push(`${where}.id is required (an OSV or CVE id)`);
    if (typeof e.reason !== 'string' || e.reason.trim() === '') errors.push(`${where}.reason is required`);
    if (e.package !== undefined && typeof e.package !== 'string') errors.push(`${where}.package must be a string`);
    if (e.by !== undefined && typeof e.by !== 'string') errors.push(`${where}.by must be a string`);
    if (e.createdAt !== undefined && typeof e.createdAt !== 'string') errors.push(`${where}.createdAt must be a string`);
    if (e.until !== undefined && (typeof e.until !== 'string' || parseUntil(e.until) === null)) {
      errors.push(`${where}.until must be a date such as 2026-12-31`);
    }
    if (typeof e.id === 'string' && typeof e.reason === 'string') {
      const entry: IgnoreEntry = {
        id: e.id.trim(),
        reason: e.reason,
        by: typeof e.by === 'string' ? e.by : 'unknown',
        createdAt: typeof e.createdAt === 'string' ? e.createdAt : '',
      };
      if (typeof e.package === 'string' && e.package.trim() !== '') entry.package = e.package.trim();
      if (typeof e.until === 'string') entry.until = e.until;
      out.push(entry);
    }
  });
  return out;
}

// reports every problem at once
export function validateProjectConfig(raw: unknown, file: string): { data: ProjectConfigFile; warnings: string[] } {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new ConfigError(`${file} must contain a JSON object`);
  }
  const obj = raw as Record<string, unknown>;
  const errors: string[] = [];
  const warnings: string[] = [];
  const data: ProjectConfigFile = {};
  const tryField = (fn: () => void): void => {
    try {
      fn();
    } catch (err) {
      errors.push(err instanceof Error ? err.message : String(err));
    }
  };
  for (const key of Object.keys(obj)) {
    if (!KNOWN_FILE_KEYS.has(key)) warnings.push(`Unknown key "${key}" in ${path.basename(file)} (ignored)`);
  }
  if (obj.provider !== undefined) tryField(() => (data.provider = parseEnum('provider', obj.provider, PROVIDERS)));
  for (const key of ['model', 'codemodModel'] as const) {
    const v = obj[key];
    if (v === undefined) continue;
    if (typeof v !== 'string' || v.trim() === '') errors.push(`"${key}" must be a non-empty string`);
    else data[key] = v.trim();
  }
  if (obj.ollamaHost !== undefined) {
    if (typeof obj.ollamaHost !== 'string') errors.push('"ollamaHost" must be a string');
    else tryField(() => (data.ollamaHost = normalizeOllamaHost(obj.ollamaHost as string)));
  }
  if (obj.numCtx !== undefined) tryField(() => (data.numCtx = parseInteger('numCtx', obj.numCtx, NUM_CTX_RANGE.min, NUM_CTX_RANGE.max)));
  if (obj.maxSteps !== undefined) {
    tryField(() => (data.maxSteps = parseInteger('maxSteps', obj.maxSteps, MAX_STEPS_RANGE.min, MAX_STEPS_RANGE.max)));
  }
  if (obj.think !== undefined) tryField(() => (data.think = parseEnum('think', obj.think, THINK_MODES)));
  if (obj.search !== undefined) tryField(() => (data.search = parseEnum('search', obj.search, SEARCH_MODES)));
  if (obj.failOn !== undefined) tryField(() => (data.failOn = parseEnum('failOn', obj.failOn, FAIL_ON_VALUES)));
  if (obj.exclude !== undefined) {
    if (!Array.isArray(obj.exclude) || !obj.exclude.every((g) => typeof g === 'string')) {
      errors.push('"exclude" must be an array of glob strings');
    } else {
      data.exclude = obj.exclude.map((g) => g.trim()).filter(Boolean);
    }
  }
  if (obj.ignore !== undefined) data.ignore = validateIgnoreEntries(obj.ignore, errors);
  if (errors.length > 0) {
    throw new ConfigError(`Invalid ${path.basename(file)}:\n  - ${errors.join('\n  - ')}`, {
      hint: `Fix ${file} (or delete it to use the defaults).`,
    });
  }
  return { data, warnings };
}

// null when absent
export async function readProjectConfig(
  projectRoot: string,
): Promise<{ path: string; data: ProjectConfigFile; warnings: string[] } | null> {
  const file = path.join(projectRoot, CONFIG_FILE_NAME);
  let text: string;
  try {
    text = await readFile(file, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw new ConfigError(`Cannot read ${file}: ${(err as Error).message}`);
  }
  let raw: unknown;
  try {
    raw = text.trim() === '' ? {} : JSON.parse(text);
  } catch (err) {
    throw new ConfigError(`Invalid JSON in ${file}: ${describeJsonError(err)}`, {
      hint: `Fix ${file} (or delete it to use the defaults).`,
    });
  }
  const { data, warnings } = validateProjectConfig(raw, file);
  return { path: file, data, warnings };
}

export interface UserConfigKeySpec {
  field: keyof UserConfigFile;
  // masked by config get
  secret: boolean;
  env?: string;
  description: string;
}

// kebab-case on the command line
export const USER_CONFIG_KEYS: Readonly<Record<string, UserConfigKeySpec>> = {
  'ollama-api-key': { field: 'ollamaApiKey', secret: true, env: 'OLLAMA_API_KEY', description: 'Ollama Web Search key (https://ollama.com/settings/keys)' },
  'github-token': { field: 'githubToken', secret: true, env: 'GITHUB_TOKEN', description: 'GitHub token for a higher API rate limit' },
  'brave-search-api-key': { field: 'braveApiKey', secret: true, env: 'BRAVE_SEARCH_API_KEY', description: 'Brave Search key (optional backend)' },
  'anthropic-api-key': { field: 'anthropicApiKey', secret: true, env: 'ANTHROPIC_API_KEY', description: 'Anthropic API key for --provider claude' },
  'codex-api-key': { field: 'codexApiKey', secret: true, env: 'CODEX_API_KEY', description: 'Codex API key for --provider codex (otherwise the Codex CLI login is used)' },
  provider: { field: 'provider', secret: false, description: 'default provider: ollama, claude, codex' },
  model: { field: 'model', secret: false, env: 'PATCHPILOT_MODEL', description: 'default Ollama model' },
  'codemod-model': { field: 'codemodModel', secret: false, description: 'local model for breaking-change code edits' },
  'ollama-host': { field: 'ollamaHost', secret: false, env: 'OLLAMA_HOST', description: 'Ollama server URL' },
  'num-ctx': { field: 'numCtx', secret: false, description: 'context window sent to Ollama' },
  'max-steps': { field: 'maxSteps', secret: false, description: 'tool calls per investigation loop' },
  search: { field: 'search', secret: false, description: 'web search backend: auto, ollama, docs, brave, off' },
  think: { field: 'think', secret: false, description: 'thinking mode for models that support it: auto, on, off (default off)' },
  'fail-on': { field: 'failOn', secret: false, description: 'default --fail-on level' },
};

export function userConfigPath(homeDir: string = os.homedir()): string {
  return path.join(patchPilotHome(homeDir), USER_CONFIG_FILE_NAME);
}

// shared by file reader and config set
export function parseUserConfigValue(field: keyof UserConfigFile, value: unknown): string | number {
  switch (field) {
    case 'numCtx':
      return parseInteger('numCtx', value, NUM_CTX_RANGE.min, NUM_CTX_RANGE.max);
    case 'maxSteps':
      return parseInteger('maxSteps', value, MAX_STEPS_RANGE.min, MAX_STEPS_RANGE.max);
    case 'search':
      return parseEnum('search', value, SEARCH_MODES);
    case 'think':
      return parseEnum('think', value, THINK_MODES);
    case 'provider':
      return parseEnum('provider', value, PROVIDERS);
    case 'failOn':
      return parseEnum('failOn', value, FAIL_ON_VALUES);
    case 'ollamaHost':
      if (typeof value !== 'string') throw new ConfigError('"ollamaHost" must be a string');
      return normalizeOllamaHost(value);
    default:
      if (typeof value !== 'string' || value.trim() === '') throw new ConfigError(`"${field}" must be a non-empty string`);
      return value.trim();
  }
}

const USER_FIELDS = new Set<string>(Object.values(USER_CONFIG_KEYS).map((k) => k.field));

// reports every problem at once
export function validateUserConfig(raw: unknown, file: string): { data: UserConfigFile; warnings: string[] } {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new ConfigError(`${file} must contain a JSON object`);
  const errors: string[] = [];
  const warnings: string[] = [];
  const data: Record<string, string | number> = {};
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    if (!USER_FIELDS.has(key)) {
      warnings.push(`Unknown key "${key}" in ${file} (ignored)`);
      continue;
    }
    try {
      data[key] = parseUserConfigValue(key as keyof UserConfigFile, value);
    } catch (err) {
      errors.push(err instanceof Error ? err.message : String(err));
    }
  }
  if (errors.length > 0) {
    throw new ConfigError(`Invalid ${file}:\n  - ${errors.join('\n  - ')}`, {
      hint: 'Fix the file, or reset a value with: patch-pilot config unset <key>',
    });
  }
  return { data: data as UserConfigFile, warnings };
}

// node's message can quote the api key
export function describeJsonError(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err);
  const position = /position (\d+)/i.exec(message);
  const line = /line (\d+) column (\d+)/i.exec(message);
  if (line) return `syntax error at line ${line[1]}, column ${line[2]}`;
  if (position) return `syntax error at position ${position[1]}`;
  return 'syntax error';
}

// warns if others can read it
export async function readUserConfig(homeDir: string = os.homedir()): Promise<{ path: string; data: UserConfigFile; warnings: string[] } | null> {
  const file = userConfigPath(homeDir);
  let text: string;
  try {
    text = await readFile(file, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw new ConfigError(`Cannot read ${file}: ${(err as Error).message}`);
  }
  let raw: unknown;
  try {
    raw = text.trim() === '' ? {} : JSON.parse(text);
  } catch (err) {
    throw new ConfigError(`Invalid JSON in ${file}: ${describeJsonError(err)}`, {
      hint: 'Fix the file, or delete it and set values again with: patch-pilot config set <key> <value>',
    });
  }
  const { data, warnings } = validateUserConfig(raw, file);
  if (process.platform !== 'win32') {
    try {
      const mode = (await stat(file)).mode & 0o777;
      if ((mode & 0o077) !== 0) warnings.push(`${file} is readable by other users (mode ${mode.toString(8)}); fix it with: chmod 600 ${file}`);
    } catch {
    }
  }
  return { path: file, data, warnings };
}

async function resolveProjectRoot(cwd: string, dir: string | undefined): Promise<string> {
  const requested = path.resolve(cwd, dir ?? '.');
  let st;
  try {
    st = await stat(requested);
  } catch {
    throw new ConfigError(`Directory not found: ${requested}`, {
      hint: 'Check the path, or run patch-pilot inside the project directory.',
    });
  }
  if (!st.isDirectory()) {
    throw new ConfigError(`Not a directory: ${requested}`, {
      hint: 'Pass a project directory, for example: patch-pilot scan ./my-app',
    });
  }
  return realpath(requested);
}

// flags > env > project > user > defaults
export async function loadConfig(input: LoadConfigInput = {}): Promise<Config> {
  const env = input.env ?? process.env;
  const flags = input.flags ?? {};
  const cwd = input.cwd ?? process.cwd();
  const homeDir = input.homeDir ?? os.homedir();
  const projectRoot = await resolveProjectRoot(cwd, input.dir);
  const file = input.skipProjectFile ? null : await readProjectConfig(projectRoot);
  const fileData: ProjectConfigFile = file?.data ?? {};
  // never load the project's .env
  const user = await readUserConfig(homeDir);
  const userData: UserConfigFile = user?.data ?? {};
  const warnings: string[] = [...(file?.warnings ?? []), ...(user?.warnings ?? [])];
  const sources: Partial<Record<keyof Config, ConfigSource>> = {};

  function pick<K extends keyof Config>(key: K, candidates: [ConfigSource, Config[K] | undefined][], fallback: Config[K]): Config[K] {
    for (const [source, value] of candidates) {
      if (value !== undefined) {
        sources[key] = source;
        return value;
      }
    }
    sources[key] = 'default';
    return fallback;
  }

  const provider = pick(
    'provider',
    [
      ['flag', flags.provider === undefined ? undefined : parseEnum('--provider', flags.provider, PROVIDERS)],
      ['file', fileData.provider],
      ['user', userData.provider],
    ],
    DEFAULT_PROVIDER,
  );
  const providerSelection: ProviderSelection =
    sources.provider === 'flag' ? 'flag' : sources.provider === 'file' || sources.provider === 'user' ? 'config' : 'default';
  // mock verdicts never share a cache key
  const model = pick(
    'model',
    [['flag', nonEmpty(flags.model)], ['env', nonEmpty(env.PATCHPILOT_MODEL)], ['file', fileData.model], ['user', provider === 'mock' ? undefined : userData.model]],
    provider === 'mock' ? MOCK_MODEL : DEFAULT_MODEL,
  );
  const codemodModel = pick('codemodModel', [['flag', nonEmpty(flags.codemodModel)], ['file', fileData.codemodModel], ['user', userData.codemodModel]], null);
  const envHost = nonEmpty(env.OLLAMA_HOST);
  const ollamaHost = pick(
    'ollamaHost',
    [
      ['flag', flags.ollamaHost === undefined ? undefined : normalizeOllamaHost(flags.ollamaHost)],
      ['env', envHost === undefined ? undefined : normalizeOllamaHost(envHost)],
      ['file', fileData.ollamaHost],
      ['user', userData.ollamaHost],
    ],
    DEFAULT_OLLAMA_HOST,
  );
  const ollamaApiKey = pick('ollamaApiKey', [['env', nonEmpty(env.OLLAMA_API_KEY)], ['user', userData.ollamaApiKey]], null);
  const anthropicApiKey = pick('anthropicApiKey', [['env', nonEmpty(env.ANTHROPIC_API_KEY)], ['user', userData.anthropicApiKey]], null);
  // not OPENAI_API_KEY, would switch chatgpt login to api billing
  const codexApiKey = pick('codexApiKey', [['env', nonEmpty(env.CODEX_API_KEY)], ['user', userData.codexApiKey]], null);
  const githubToken = pick('githubToken', [['env', nonEmpty(env.GITHUB_TOKEN) ?? nonEmpty(env.GH_TOKEN)], ['user', userData.githubToken]], null);
  const braveApiKey = pick('braveApiKey', [['env', nonEmpty(env.BRAVE_SEARCH_API_KEY)], ['user', userData.braveApiKey]], null);
  const numCtx = pick(
    'numCtx',
    [
      ['flag', flags.numCtx === undefined ? undefined : parseInteger('--num-ctx', flags.numCtx, NUM_CTX_RANGE.min, NUM_CTX_RANGE.max)],
      ['file', fileData.numCtx],
      ['user', userData.numCtx],
    ],
    DEFAULT_NUM_CTX,
  );
  const think = pick(
    'think',
    [
      ['flag', flags.think === undefined ? undefined : parseEnum('--think', flags.think, THINK_MODES)],
      ['file', fileData.think],
      ['user', userData.think],
    ],
    DEFAULT_THINK,
  );
  const maxSteps = pick(
    'maxSteps',
    [
      ['flag', flags.maxSteps === undefined ? undefined : parseInteger('--max-steps', flags.maxSteps, MAX_STEPS_RANGE.min, MAX_STEPS_RANGE.max)],
      ['file', fileData.maxSteps],
      ['user', userData.maxSteps],
    ],
    DEFAULT_MAX_STEPS,
  );
  const limit = pick('limit', [['flag', flags.limit === undefined ? undefined : parseInteger('--limit', flags.limit, 1, 100_000)]], null);
  const maxCves = pick(
    'maxCves',
    [['flag', flags.maxCves === undefined ? undefined : parseInteger('--max-cves', flags.maxCves, 1, 100_000)]],
    null,
  );
  const seed = pick(
    'seed',
    [['flag', flags.seed === undefined ? undefined : parseInteger('--seed', flags.seed, 0, 2 ** 31 - 1)]],
    DEFAULT_SEED,
  );
  const search = pick(
    'search',
    [
      ['flag', flags.search === undefined ? undefined : parseEnum('--search', flags.search, SEARCH_MODES)],
      ['file', fileData.search],
      ['user', userData.search],
    ],
    DEFAULT_SEARCH,
  );
  const failOn = pick(
    'failOn',
    [
      ['flag', flags.failOn === undefined ? undefined : parseEnum('--fail-on', flags.failOn, FAIL_ON_VALUES)],
      ['file', fileData.failOn],
      ['user', userData.failOn],
    ],
    DEFAULT_FAIL_ON,
  );
  const debug = pick('debug', [['env', parseBoolEnv(env.PATCHPILOT_DEBUG)]], false);
  const noColorEnv = env.NO_COLOR !== undefined && env.NO_COLOR !== '' && env.FORCE_COLOR === undefined;
  const color = pick('color', [['flag', flags.color === false ? false : undefined], ['env', noColorEnv ? false : undefined]], true);
  const mockScriptRaw = nonEmpty(flags.mockScript) ?? nonEmpty(env.PATCHPILOT_MOCK_SCRIPT);
  const mockScript = pick(
    'mockScript',
    [['flag', mockScriptRaw === undefined ? undefined : path.resolve(cwd, mockScriptRaw)]],
    null,
  );

  const bool = <K extends keyof Config>(key: K, value: boolean | undefined): boolean => {
    sources[key] = value === undefined ? 'default' : 'flag';
    return value ?? false;
  };
  const ci = bool('ci', flags.ci);
  const json = bool('json', flags.json);
  const quiet = bool('quiet', flags.quiet);
  const verbose = bool('verbose', flags.verbose);
  const stdinTTY = input.stdinIsTTY ?? Boolean(process.stdin.isTTY);
  const stdoutTTY = input.stdoutIsTTY ?? Boolean(process.stdout.isTTY);
  const exclude = [...new Set([...DEFAULT_EXCLUDES, ...(fileData.exclude ?? [])])];
  const ignore = fileData.ignore ?? [];
  const now = new Date();
  for (const entry of ignore) {
    if (isIgnoreExpired(entry, now)) {
      warnings.push(`Accepted risk ${entry.id}${entry.package ? ` (${entry.package})` : ''} expired on ${entry.until}; it is reported again.`);
    }
  }
  if (quiet && verbose) warnings.push('--quiet and --verbose were both given; --quiet wins for progress output.');

  const config: Config = {
    projectRoot,
    provider,
    model,
    codemodModel,
    ollamaHost,
    ollamaApiKey,
    githubToken,
    braveApiKey,
    anthropicApiKey,
    codexApiKey,
    providerSelection,
    numCtx,
    think,
    maxSteps,
    limit,
    only: parseList(flags.only),
    maxCves,
    offline: bool('offline', flags.offline),
    dryRun: bool('dryRun', flags.dryRun),
    noCache: flags.cache === false,
    approveAll: bool('approveAll', flags.approveAll),
    approveCodemods: bool('approveCodemods', flags.approveCodemods),
    approve: parseList(flags.approve),
    trust: bool('trust', flags.trust),
    json,
    verbose,
    quiet,
    seed,
    search,
    ci,
    failOn,
    resume: bool('resume', flags.resume),
    exclude,
    ignore,
    debug,
    color,
    interactive: stdinTTY && stdoutTTY && !ci && !json,
    mockScript,
    paths: projectPaths(projectRoot, homeDir),
    timeouts: { ...DEFAULT_TIMEOUTS },
    configFile: file?.path ?? null,
    userConfigFile: user?.path ?? null,
    sources,
    warnings,
  };
  sources.noCache = flags.cache === false ? 'flag' : 'default';
  sources.only = flags.only === undefined ? 'default' : 'flag';
  sources.approve = flags.approve === undefined ? 'default' : 'flag';
  sources.exclude = fileData.exclude ? 'file' : 'default';
  sources.ignore = fileData.ignore ? 'file' : 'default';
  return config;
}

// ollama with a key, else docs, off offline
export function effectiveSearchBackend(config: Pick<Config, 'search' | 'ollamaApiKey' | 'braveApiKey' | 'offline'>): SearchMode {
  if (config.offline || config.search === 'off') return 'off';
  if (config.search === 'auto') return config.ollamaApiKey ? 'ollama' : 'docs';
  return config.search;
}

const FAIL_ON_RISK: Record<Exclude<FailOn, 'never'>, RiskLevel> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  noise: 'Noise',
};

export function riskRank(risk: RiskLevel): number {
  return RISK_ORDER.indexOf(risk);
}

export function riskAtOrAbove(risk: RiskLevel, failOn: FailOn): boolean {
  if (failOn === 'never') return false;
  return riskRank(risk) >= riskRank(FAIL_ON_RISK[failOn]);
}

// active accepted risks don't count
export function findingsExitCode(
  verdicts: readonly Pick<Verdict, 'vulnId' | 'package' | 'risk'>[],
  config: Pick<Config, 'failOn' | 'ignore'>,
  aliasesOf: (vulnId: string) => readonly string[] = () => [],
  now: Date = new Date(),
): 0 | 1 {
  for (const v of verdicts) {
    if (!riskAtOrAbove(v.risk, config.failOn)) continue;
    const accepted = findIgnore(config.ignore, v.vulnId, v.package, aliasesOf(v.vulnId), now);
    if (accepted && !accepted.expired) continue;
    return 1;
  }
  return 0;
}

export function worstRisk(risks: readonly RiskLevel[]): RiskLevel | null {
  let worst: RiskLevel | null = null;
  for (const r of risks) if (worst === null || riskRank(r) > riskRank(worst)) worst = r;
  return worst;
}

// date means end of day utc
export function parseUntil(until: string): Date | null {
  const s = until.trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) {
    const d = new Date(`${s}T23:59:59.999Z`);
    return Number.isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== s ? null : d;
  }
  if (!/^\d{4}-\d{2}-\d{2}T/.test(s)) return null;
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function isIgnoreExpired(entry: IgnoreEntry, now: Date = new Date()): boolean {
  if (!entry.until) return false;
  const until = parseUntil(entry.until);
  return until !== null && now.getTime() > until.getTime();
}

export function partitionIgnores(entries: readonly IgnoreEntry[], now: Date = new Date()): { active: IgnoreEntry[]; expired: IgnoreEntry[] } {
  const active: IgnoreEntry[] = [];
  const expired: IgnoreEntry[] = [];
  for (const e of entries) (isIgnoreExpired(e, now) ? expired : active).push(e);
  return { active, expired };
}

// id or alias, package if named
export function findIgnore(
  entries: readonly IgnoreEntry[],
  vulnId: string,
  pkg: string,
  aliases: readonly string[] = [],
  now: Date = new Date(),
): { entry: IgnoreEntry; expired: boolean } | null {
  const ids = new Set([vulnId, ...aliases].map((s) => s.toUpperCase()));
  for (const entry of entries) {
    if (!ids.has(entry.id.toUpperCase())) continue;
    if (entry.package && entry.package !== pkg) continue;
    return { entry, expired: isIgnoreExpired(entry, now) };
  }
  return null;
}

export async function readIgnoreEntries(projectRoot: string): Promise<IgnoreEntry[]> {
  return (await readProjectConfig(projectRoot))?.data.ignore ?? [];
}

// upsert by id + package
export async function addIgnoreEntry(projectRoot: string, entry: IgnoreEntry): Promise<IgnoreEntry[]> {
  if (entry.until !== undefined && parseUntil(entry.until) === null) {
    throw new ConfigError(`Invalid --until date: ${entry.until} (use YYYY-MM-DD)`);
  }
  if (entry.reason.trim() === '') throw new ConfigError('An accepted risk needs a reason (--reason "...")');
  const file = path.join(projectRoot, CONFIG_FILE_NAME);
  // report a broken file, don't overwrite
  await readProjectConfig(projectRoot);
  const next = await updateJsonFile<Record<string, unknown>>(file, (current) => {
    const list = Array.isArray(current.ignore) ? (current.ignore as IgnoreEntry[]) : [];
    const kept = list.filter((e) => !(e.id === entry.id && (e.package ?? null) === (entry.package ?? null)));
    return { ...current, ignore: [...kept, entry] };
  });
  return next.ignore as IgnoreEntry[];
}

// false when nothing matched
export async function removeIgnoreEntry(projectRoot: string, id: string, pkg?: string): Promise<boolean> {
  const file = path.join(projectRoot, CONFIG_FILE_NAME);
  const existing = await readProjectConfig(projectRoot);
  if (!existing?.data.ignore?.some((e) => e.id === id && (pkg === undefined || e.package === pkg))) return false;
  await updateJsonFile<Record<string, unknown>>(file, (current) => {
    const list = Array.isArray(current.ignore) ? (current.ignore as IgnoreEntry[]) : [];
    return { ...current, ignore: list.filter((e) => !(e.id === id && (pkg === undefined || e.package === pkg))) };
  });
  return true;
}
