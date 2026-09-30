import { randomBytes } from 'node:crypto';
import { chmod, mkdir, open, readFile, rename, stat, unlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { password } from '@inquirer/prompts';
import {
  CONFIG_FILE_NAME,
  DEFAULT_FAIL_ON,
  DEFAULT_MAX_STEPS,
  DEFAULT_MODEL,
  DEFAULT_NUM_CTX,
  DEFAULT_OLLAMA_HOST,
  DEFAULT_SEARCH,
  normalizeOllamaHost,
  parseUserConfigValue,
  readProjectConfig,
  USER_CONFIG_KEYS,
  userConfigPath,
  validateUserConfig,
  type UserConfigKeySpec,
} from './config.ts';
import type { ConfigSource, ProjectConfigFile, UserConfigFile } from './types.ts';
import type { Ui } from './ui.ts';
import { ConfigError, errorMessage, EXIT, PatchPilotError } from './util/errors.ts';
import { formatJson } from './util/fs.ts';

export interface ConfigCommandOptions {
  // default os.homedir()
  homeDir?: string;
  // unmasked get
  reveal?: boolean;
  interactive?: boolean;
  // default process.env
  env?: NodeJS.ProcessEnv;
  // default process.cwd()
  cwd?: string;
  // no-echo prompt
  promptHidden?: (message: string, validate: (value: string) => true | string, secret: boolean) => Promise<string>;
}

export const FILE_MODE = 0o600;
export const DIR_MODE = 0o700;

// never secrets
const PROJECT_FIELDS: readonly (keyof UserConfigFile & keyof ProjectConfigFile)[] = ['model', 'codemodModel', 'ollamaHost', 'numCtx', 'maxSteps', 'search', 'failOn'];

const DEFAULTS: Partial<Record<keyof UserConfigFile, string | number>> = {
  model: DEFAULT_MODEL,
  ollamaHost: DEFAULT_OLLAMA_HOST,
  numCtx: DEFAULT_NUM_CTX,
  maxSteps: DEFAULT_MAX_STEPS,
  search: DEFAULT_SEARCH,
  failOn: DEFAULT_FAIL_ON,
};

export interface ResolvedConfigKey {
  key: string;
  spec: UserConfigKeySpec;
}

function kebab(value: string): string {
  return value
    .trim()
    .replace(/([a-z0-9])([A-Z])/g, '$1-$2')
    .replace(/[_\s]+/g, '-')
    .toLowerCase();
}

const ALIASES: ReadonlyMap<string, string> = (() => {
  const map = new Map<string, string>();
  for (const [key, spec] of Object.entries(USER_CONFIG_KEYS)) {
    map.set(key, key);
    map.set(kebab(spec.field), key);
    if (spec.env) map.set(kebab(spec.env), key);
  }
  if (USER_CONFIG_KEYS['github-token']) map.set('gh-token', 'github-token');
  return map;
})();

function levenshtein(a: string, b: string): number {
  const row = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i += 1) {
    let prev = row[0] ?? 0;
    row[0] = i;
    for (let j = 1; j <= b.length; j += 1) {
      const cur = row[j] ?? 0;
      row[j] = Math.min((row[j] ?? 0) + 1, (row[j - 1] ?? 0) + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = cur;
    }
  }
  return row[b.length] ?? 0;
}

// kebab-case, camelCase or env name
export function resolveConfigKey(input: string): ResolvedConfigKey {
  const normalized = kebab(String(input ?? ''));
  const key = ALIASES.get(normalized);
  const spec = key ? USER_CONFIG_KEYS[key] : undefined;
  if (key && spec) return { key, spec };
  const valid = Object.keys(USER_CONFIG_KEYS);
  // never echo a pasted secret
  const looksLikeName = /^[A-Za-z][A-Za-z_-]{0,29}$/.test(String(input ?? '').trim());
  const guess = looksLikeName
    ? valid.find((k) => k.includes(normalized) || normalized.includes(k) || levenshtein(k, normalized) <= 2)
    : undefined;
  throw new ConfigError(`Unknown setting${looksLikeName ? ` "${String(input).trim()}"` : ' (the name is not shown)'}${guess ? `; did you mean ${guess}?` : ''}`, {
    hint: `Settings: ${valid.join(', ')}`,
  });
}

// **** plus last 4 (only **** under 12)
export function maskSecret(value: string): string {
  const text = String(value);
  return text.length >= 12 ? `****${text.slice(-4)}` : '****';
}

function display(spec: UserConfigKeySpec, value: string | number | null, reveal = false): string | null {
  if (value === null) return null;
  return spec.secret && !reveal ? maskSecret(String(value)) : String(value);
}

// errors never quote a secret
export function parseConfigValue(key: string, spec: UserConfigKeySpec, raw: unknown): string | number {
  if (spec.secret) {
    const value = typeof raw === 'string' ? raw.trim() : '';
    if (value === '') throw new ConfigError(`${key} needs a non-empty value`);
    if (/[\s\u0000-\u001f\u007f]/.test(value)) throw new ConfigError(`${key} must not contain spaces or control characters (check the pasted value)`);
    try {
      return parseUserConfigValue(spec.field, value);
    } catch {
      throw new ConfigError(`Invalid value for ${key}`);
    }
  }
  try {
    return parseUserConfigValue(spec.field, raw);
  } catch (err) {
    const message = errorMessage(err).replace(spec.field, key);
    throw new ConfigError(message);
  }
}

function tildePath(file: string, homeDir: string): string {
  const home = path.resolve(homeDir);
  if (file === home) return '~';
  return file.startsWith(home + path.sep) ? `~${file.slice(home.length)}` : file;
}

interface RawUserFile {
  exists: boolean;
  data: Record<string, unknown>;
}

async function readRawUserFile(file: string, shown: string): Promise<RawUserFile> {
  let text: string;
  try {
    text = await readFile(file, 'utf8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') return { exists: false, data: {} };
    throw new PatchPilotError(`Cannot read ${shown} (${code ?? errorMessage(err)})`, { exitCode: EXIT.USAGE });
  }
  if (text.trim() === '') return { exists: true, data: {} };
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    // parser messages can leak secrets
    const where = /position \d+(?: \(line \d+ column \d+\))?/.exec(errorMessage(err))?.[0];
    throw new ConfigError(`${shown} is not valid JSON${where ? ` (${where})` : ''}`, {
      hint: 'Fix it in an editor, or delete it and set the values again with: patch-pilot config set <key> <value>',
    });
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new ConfigError(`${shown} must contain a JSON object`, { hint: 'Delete it and set the values again with: patch-pilot config set <key> <value>' });
  }
  return { exists: true, data: raw as Record<string, unknown> };
}

// 0600 file, 0700 dir
export async function writePrivateJson(file: string, value: Record<string, unknown>): Promise<void> {
  const dir = path.dirname(file);
  await mkdir(dir, { recursive: true, mode: DIR_MODE });
  if (process.platform !== 'win32') {
    const mode = (await stat(dir)).mode & 0o777;
    if ((mode & 0o077) !== 0) await chmod(dir, DIR_MODE);
  }
  const tmp = path.join(dir, `.${path.basename(file)}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`);
  let renamed = false;
  try {
    const handle = await open(tmp, 'wx', FILE_MODE);
    try {
      await handle.chmod(FILE_MODE);
      await handle.writeFile(formatJson(value), 'utf8');
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(tmp, file);
    renamed = true;
    await chmod(file, FILE_MODE);
  } catch (err) {
    if (!renamed) await unlink(tmp).catch(() => {});
    const code = (err as NodeJS.ErrnoException).code;
    throw new PatchPilotError(`Cannot write ${file} (${code ?? errorMessage(err)})`, { exitCode: EXIT.USAGE, cause: err });
  }
}

function nonEmpty(value: string | undefined): string | undefined {
  return value !== undefined && value.trim() !== '' ? value.trim() : undefined;
}

function activeEnv(key: string, spec: UserConfigKeySpec, env: NodeJS.ProcessEnv): { name: string; value: string } | null {
  const names = spec.env ? [spec.env] : [];
  if (key === 'github-token') names.push('GH_TOKEN');
  for (const name of names) {
    const value = nonEmpty(env[name]);
    if (value !== undefined) return { name, value };
  }
  return null;
}

async function projectValue(spec: UserConfigKeySpec, cwd: string): Promise<{ file: string; value: string | number } | { error: string } | null> {
  const field = spec.field as (typeof PROJECT_FIELDS)[number];
  if (spec.secret || !PROJECT_FIELDS.includes(field)) return null;
  try {
    const project = await readProjectConfig(path.resolve(cwd));
    const value = project?.data[field];
    return project && value !== undefined ? { file: project.path, value } : null;
  } catch (err) {
    return { error: errorMessage(err).split('\n')[0] ?? 'invalid file' };
  }
}

export interface EffectiveValue {
  value: string | number | null;
  source: ConfigSource;
  // null for defaults
  origin: string | null;
  userValue: string | number | null;
  // never quotes a secret
  userProblem: string | null;
  projectProblem: string | null;
}

async function effectiveValue(key: string, spec: UserConfigKeySpec, user: RawUserFile, file: string, env: NodeJS.ProcessEnv, cwd: string): Promise<EffectiveValue> {
  let userValue: string | number | null = null;
  let userProblem: string | null = null;
  if (Object.hasOwn(user.data, spec.field)) {
    const raw = user.data[spec.field];
    try {
      userValue = parseConfigValue(key, spec, raw);
    } catch (err) {
      userProblem = errorMessage(err);
      userValue = typeof raw === 'string' || typeof raw === 'number' ? raw : JSON.stringify(raw);
    }
  }
  const base = { userValue, userProblem, projectProblem: null as string | null };
  const fromEnv = activeEnv(key, spec, env);
  if (fromEnv) {
    let value: string | number = fromEnv.value;
    if (spec.field === 'ollamaHost') {
      try {
        value = normalizeOllamaHost(fromEnv.value);
      } catch {
      }
    }
    return { ...base, value, source: 'env', origin: fromEnv.name };
  }
  const project = await projectValue(spec, cwd);
  if (project && 'error' in project) base.projectProblem = project.error;
  else if (project) return { ...base, value: project.value, source: 'file', origin: project.file };
  if (userValue !== null) return { ...base, value: userValue, source: 'user', origin: file };
  return { ...base, value: DEFAULTS[spec.field] ?? null, source: 'default', origin: null };
}

function sourceText(result: EffectiveValue, homeDir: string, cwd: string): string {
  switch (result.source) {
    case 'env':
      return `environment (${result.origin})`;
    case 'file':
      return result.origin && path.dirname(result.origin) === path.resolve(cwd) ? `${CONFIG_FILE_NAME} in this directory` : (result.origin ?? CONFIG_FILE_NAME);
    case 'user':
      return tildePath(result.origin ?? '', homeDir);
    default:
      return 'default';
  }
}

async function overrideNotices(key: string, spec: UserConfigKeySpec, env: NodeJS.ProcessEnv, cwd: string): Promise<string[]> {
  const notes: string[] = [];
  const fromEnv = activeEnv(key, spec, env);
  if (fromEnv) notes.push(`${fromEnv.name} is set in the environment and takes precedence over this setting`);
  const project = await projectValue(spec, cwd);
  if (project && !('error' in project)) notes.push(`${CONFIG_FILE_NAME} in this directory sets ${spec.field} (${String(project.value)}), which takes precedence in this project`);
  return notes;
}

function hiddenPrompt(ui: Ui): NonNullable<ConfigCommandOptions['promptHidden']> {
  return (message, validate, secret) =>
    password({
      message: ui.text(message),
      mask: false,
      toggleMask: !secret,
      validate,
      theme: { prefix: ui.blue(ui.glyphs.prompt), style: { maskedText: '(typing is hidden)' } },
    });
}

export async function configSet(key: string, value: string | undefined, ui: Ui, options: ConfigCommandOptions = {}): Promise<void> {
  const { key: name, spec } = resolveConfigKey(key);
  const homeDir = options.homeDir ?? os.homedir();
  const env = options.env ?? process.env;
  const cwd = options.cwd ?? process.cwd();
  const file = userConfigPath(homeDir);
  const shown = tildePath(file, homeDir);
  let input = value;
  if (input === undefined) {
    const interactive = (options.interactive ?? ui.interactive) && !ui.json;
    if (!interactive) {
      throw new ConfigError(`patch-pilot config set ${name} needs a value when it cannot ask for one`, {
        hint: spec.secret
          ? `Run it in a terminal to type the value without echo${spec.env ? `, or set ${spec.env} in the environment` : ''}.`
          : `Pass it: patch-pilot config set ${name} <value>`,
      });
    }
    const ask = options.promptHidden ?? hiddenPrompt(ui);
    input = await ask(
      `${name} ${ui.glyphs.dot} ${spec.description}:`,
      (candidate) => {
        try {
          parseConfigValue(name, spec, candidate);
          return true;
        } catch (err) {
          return errorMessage(err);
        }
      },
      spec.secret,
    );
  }
  const parsed = parseConfigValue(name, spec, input);
  // refuse invalid json, don't overwrite
  const current = await readRawUserFile(file, shown);
  const next: Record<string, unknown> = { ...current.data, [spec.field]: parsed };
  await writePrivateJson(file, next);

  const shownValue = display(spec, parsed) ?? '';
  if (ui.json) ui.printJson({ key: name, field: spec.field, value: shownValue, secret: spec.secret, file });
  else ui.check(`Set ${name}`, `${shownValue} ${ui.glyphs.dot} ${shown}`);
  for (const note of await overrideNotices(name, spec, env, cwd)) ui.warn(note);
  try {
    validateUserConfig(next, shown);
  } catch (err) {
    const [first = '', ...rest] = errorMessage(err).split('\n');
    ui.warn(`${first} (fix with patch-pilot config set or unset)`, rest.map((l) => l.trim()).join(' '));
  }
}

export async function configGet(key: string, ui: Ui, options: ConfigCommandOptions = {}): Promise<void> {
  const { key: name, spec } = resolveConfigKey(key);
  const homeDir = options.homeDir ?? os.homedir();
  const env = options.env ?? process.env;
  const cwd = options.cwd ?? process.cwd();
  const reveal = options.reveal ?? false;
  const file = userConfigPath(homeDir);
  const shown = tildePath(file, homeDir);
  const user = await readRawUserFile(file, shown);
  const result = await effectiveValue(name, spec, user, file, env, cwd);
  const value = display(spec, result.value, reveal);
  const userValue = display(spec, result.userValue, reveal);
  const masked = spec.secret && !reveal && result.value !== null;

  if (ui.json) {
    ui.printJson({
      key: name,
      field: spec.field,
      value,
      source: result.value === null ? null : result.source,
      origin: result.origin,
      secret: spec.secret,
      masked,
      userValue,
      ...(result.userProblem ? { problem: result.userProblem } : {}),
    });
    return;
  }
  if (result.value === null) {
    const hint =
      name === 'codemod-model'
        ? 'not set (code edits use the main model)'
        : `not set${spec.env ? ` (set it with: patch-pilot config set ${name}, or export ${spec.env})` : ` (set it with: patch-pilot config set ${name} <value>)`}`;
    ui.print(ui.kv([[name, ui.c.dim(hint)]], 0));
  } else {
    const pairs: [string, string][] = [
      [name, String(value)],
      ['source', ui.c.dim(ui.text(sourceText(result, homeDir, cwd)))],
    ];
    if (result.source !== 'user' && userValue !== null) pairs.push(['overrides', ui.c.dim(`${userValue} in ${shown}`)]);
    ui.print(ui.kv(pairs, 0));
  }
  if (result.userProblem) ui.warn(`The value in ${shown} is invalid: ${result.userProblem}`, `fix it with: patch-pilot config set ${name}`);
  if (result.projectProblem) ui.warn(`Ignoring ${CONFIG_FILE_NAME} in this directory: ${result.projectProblem}`);
}

export async function configUnset(key: string, ui: Ui, options: ConfigCommandOptions = {}): Promise<void> {
  const { key: name, spec } = resolveConfigKey(key);
  const homeDir = options.homeDir ?? os.homedir();
  const env = options.env ?? process.env;
  const file = userConfigPath(homeDir);
  const shown = tildePath(file, homeDir);
  const current = await readRawUserFile(file, shown);
  const had = Object.hasOwn(current.data, spec.field);
  if (had) {
    const next = { ...current.data };
    delete next[spec.field];
    await writePrivateJson(file, next);
  }
  if (ui.json) ui.printJson({ key: name, field: spec.field, removed: had, file });
  else if (had) ui.check(`Removed ${name}`, `from ${shown}`);
  else ui.infoLine(`${name} was not set`, shown);
  const fromEnv = activeEnv(name, spec, env);
  if (fromEnv) ui.warn(`${fromEnv.name} is still set in the environment, so it keeps applying`);
}
