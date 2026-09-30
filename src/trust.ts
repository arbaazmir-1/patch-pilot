// trust prompt, ~/.patch-pilot/trusted.json
import { realpath } from 'node:fs/promises';
import path from 'node:path';
import { formatIdentity } from './audit.ts';
import { isLocalHost, patchPilotHome } from './config.ts';
import type { Identity, ProviderName, TrustEntry, TrustStore } from './types.ts';
import type { Ui } from './ui.ts';
import { EXIT, PatchPilotError } from './util/errors.ts';
import { readJsonIfExists, writeJsonAtomic } from './util/fs.ts';
import { gitRemoteUrl } from './util/proc.ts';

export const TRUST_FILE_NAME = 'trusted.json';

export function trustStorePath(homeDir?: string): string {
  return path.join(patchPilotHome(homeDir), TRUST_FILE_NAME);
}

function emptyStore(): TrustStore {
  return { version: 1, directories: {} };
}

// missing or unreadable trusts nothing
export async function loadTrustStore(homeDir?: string): Promise<TrustStore> {
  let raw: unknown;
  try {
    raw = await readJsonIfExists(trustStorePath(homeDir));
  } catch {
    return emptyStore();
  }
  if (!raw || typeof raw !== 'object') return emptyStore();
  const dirs = (raw as { directories?: unknown }).directories;
  if (!dirs || typeof dirs !== 'object' || Array.isArray(dirs)) return emptyStore();
  const store = emptyStore();
  for (const [key, value] of Object.entries(dirs as Record<string, unknown>)) {
    if (!value || typeof value !== 'object') continue;
    const e = value as Partial<TrustEntry>;
    store.directories[key] = {
      path: typeof e.path === 'string' ? e.path : key,
      remote: typeof e.remote === 'string' ? e.remote : null,
      trustedAt: typeof e.trustedAt === 'string' ? e.trustedAt : '',
      by: typeof e.by === 'string' ? e.by : 'unknown',
      method: e.method === 'flag' || e.method === 'command' ? e.method : 'prompt',
    };
  }
  return store;
}

export async function saveTrustStore(store: TrustStore, homeDir?: string): Promise<void> {
  await writeJsonAtomic(trustStorePath(homeDir), store);
}

// symlink-resolved trust key
export async function canonicalDir(dir: string): Promise<string> {
  const abs = path.resolve(dir);
  try {
    return await realpath(abs);
  } catch {
    throw new PatchPilotError(`Directory not found: ${abs}`, { exitCode: EXIT.USAGE });
  }
}

// strips user and password
export function sanitizeRemote(remote: string | null): string | null {
  if (!remote) return null;
  try {
    const url = new URL(remote);
    if (url.username || url.password) {
      url.username = '';
      url.password = '';
    }
    return url.toString().replace(/\/$/, '');
  } catch {
    return remote; // scp-like git@host:org/repo.git
  }
}

export interface TrustLookupOptions {
  homeDir?: string;
  // tests override, else git
  remote?: string | null;
}

export interface TrustStatus {
  trusted: boolean;
  dir: string;
  remote: string | null;
  entry: TrustEntry | null;
  // why an entry went stale
  reason?: 'remote-changed';
}

async function currentRemote(dir: string, options: TrustLookupOptions): Promise<string | null> {
  if (options.remote !== undefined) return sanitizeRemote(options.remote);
  return sanitizeRemote(await gitRemoteUrl(dir));
}

// stale if the remote changed
export async function checkTrust(dir: string, options: TrustLookupOptions = {}): Promise<TrustStatus> {
  const key = await canonicalDir(dir);
  const [store, remote] = await Promise.all([loadTrustStore(options.homeDir), currentRemote(key, options)]);
  const entry = store.directories[key] ?? null;
  if (!entry) return { trusted: false, dir: key, remote, entry: null };
  if ((entry.remote ?? null) !== (remote ?? null)) return { trusted: false, dir: key, remote, entry, reason: 'remote-changed' };
  return { trusted: true, dir: key, remote, entry };
}

export interface TrustWriteOptions extends TrustLookupOptions {
  by?: string;
  method?: TrustEntry['method'];
  now?: Date;
}

// records the git remote
export async function trustDirectory(dir: string, options: TrustWriteOptions = {}): Promise<TrustEntry> {
  const key = await canonicalDir(dir);
  const remote = await currentRemote(key, options);
  const store = await loadTrustStore(options.homeDir);
  const entry: TrustEntry = {
    path: key,
    remote,
    trustedAt: (options.now ?? new Date()).toISOString(),
    by: options.by ?? 'unknown',
    method: options.method ?? 'command',
  };
  store.directories[key] = entry;
  await saveTrustStore(store, options.homeDir);
  return entry;
}

// false if absent
export async function untrustDirectory(dir: string, options: { homeDir?: string } = {}): Promise<boolean> {
  let key: string;
  try {
    key = await canonicalDir(dir);
  } catch {
    key = path.resolve(dir); // dir may be gone
  }
  const store = await loadTrustStore(options.homeDir);
  if (!store.directories[key]) return false;
  delete store.directories[key];
  await saveTrustStore(store, options.homeDir);
  return true;
}

export interface TrustPromptContext {
  dir: string;
  remote: string | null;
  ollamaHost: string;
  provider: ProviderName;
  // named in the notice
  model?: string;
  // shown when not local
  hostSource?: string;
  reason?: TrustStatus['reason'];
  previousRemote?: string | null;
}

// where snippets go
function modelPromise(ctx: Pick<TrustPromptContext, 'provider' | 'ollamaHost' | 'model'>): string {
  switch (ctx.provider) {
    case 'mock':
      return 'use the scripted mock model (no code leaves this machine)';
    case 'claude':
      return `send code snippets and file excerpts to Anthropic's Claude API (api.anthropic.com${ctx.model ? `, ${ctx.model}` : ''}): they leave this machine`;
    case 'codex':
      return `send code snippets and file excerpts to OpenAI through the Codex CLI (codex exec${ctx.model ? `, ${ctx.model}` : ''}): they leave this machine`;
    default:
      return `send code snippets only to your local Ollama model (${ctx.ollamaHost})`;
  }
}

// null for ollama and mock
export function cloudProviderNotice(provider: ProviderName, model?: string | null): string | null {
  if (provider === 'claude') {
    return `Cloud provider: code snippets and file excerpts from this project are sent to Anthropic (Claude API${model ? `, ${model}` : ''}). Use --provider ollama to keep them on this machine.`;
  }
  if (provider === 'codex') {
    return `Cloud provider: code snippets and file excerpts from this project are sent to OpenAI through the Codex CLI${model ? ` (${model})` : ''}. Use --provider ollama to keep them on this machine.`;
  }
  return null;
}

// plain without a Ui
export function trustPromptText(ctx: TrustPromptContext, ui?: Ui): string {
  const dim = (t: string): string => (ui ? ui.c.dim(ui.text(t)) : t);
  const bullet = ui ? ui.glyphs.bullet : '·';
  const lines: string[] = [];
  if (ctx.reason === 'remote-changed') {
    lines.push('The git remote of this directory changed since you trusted it:');
    lines.push(dim(`  was: ${ctx.previousRemote ?? '(none)'}`));
    lines.push(dim(`  now: ${ctx.remote ?? '(none)'}`));
  } else {
    lines.push('PatchPilot has not been used in this directory before:');
  }
  lines.push(`  ${ctx.dir}${ctx.remote ? dim(`  (git remote: ${ctx.remote})`) : ''}`);
  lines.push('');
  lines.push(dim('If you trust it, PatchPilot will:'));
  const promises = [
    'read the source files and the lockfile in this directory',
    modelPromise(ctx),
    'call OSV.dev, the npm registry and, for major-version migrations, public documentation pages',
    'write only under .patch-pilot/ in this directory',
    'never run npm or edit your code without asking for your approval first',
  ];
  for (const promise of promises) lines.push(dim(`  ${bullet} ${promise}`));
  const cloud = cloudProviderNotice(ctx.provider, ctx.model);
  if (cloud) {
    lines.push('');
    lines.push(ui ? ui.formatWarn(cloud, undefined, ui.c) : cloud);
  } else if (ctx.provider !== 'mock' && !isLocalHost(ctx.ollamaHost)) {
    lines.push('');
    const note = `Note: the Ollama host ${ctx.ollamaHost} is not on this machine${ctx.hostSource ? ` (set by ${ctx.hostSource})` : ''}; code snippets will be sent there.`;
    lines.push(ui ? ui.formatWarn(note, undefined, ui.c) : note);
  }
  return lines.join('\n');
}

// shell-quote for copy-paste
export function shellQuote(value: string): string {
  return /^[\w@%+=:,./-]+$/.test(value) ? value : `'${value.replace(/'/g, `'\\''`)}'`;
}

export type TrustVia = 'stored' | 'prompt' | 'flag';

export interface TrustDecision {
  via: TrustVia;
  entry: TrustEntry;
}

export interface EnsureTrustedOptions extends TrustLookupOptions {
  // config.interactive
  interactive: boolean;
  // set by --trust
  trustFlag: boolean;
  ollamaHost: string;
  provider: ProviderName;
  // named in the notice
  model?: string;
  hostSource?: string;
  identity?: Identity;
  // tests inject a fake
  ask?: (message: string) => Promise<boolean>;
}


// exit 2 if it can't ask or user says no
export async function ensureTrusted(dir: string, ui: Ui, options: EnsureTrustedOptions): Promise<TrustDecision> {
  const status = await checkTrust(dir, options);
  if (status.trusted && status.entry) return { via: 'stored', entry: status.entry };
  const by = options.identity ? formatIdentity(options.identity) : 'unknown';
  const lookup = { homeDir: options.homeDir, remote: status.remote };
  if (options.trustFlag) {
    const entry = await trustDirectory(status.dir, { ...lookup, by, method: 'flag' });
    return { via: 'flag', entry };
  }
  if (!options.interactive) {
    const why = status.reason === 'remote-changed' ? ' (its git remote changed since it was trusted)' : '';
    throw new PatchPilotError(`Directory not trusted${why}: ${status.dir}`, {
      exitCode: EXIT.USAGE,
      hint: `Run \`patch-pilot trust ${shellQuote(status.dir)}\` once, or pass --trust.`,
    });
  }
  ui.print('');
  ui.print(
    trustPromptText(
      {
        dir: status.dir,
        remote: status.remote,
        ollamaHost: options.ollamaHost,
        provider: options.provider,
        ...(options.model ? { model: options.model } : {}),
        hostSource: options.hostSource,
        reason: status.reason,
        previousRemote: status.entry?.remote ?? null,
      },
      ui,
    ),
  );
  ui.print('');
  const ask = options.ask ?? (async (question: string) => (await ui.singleKeyPrompt(question, 'y/n')) === 'y');
  const yes = await ask('Trust this directory?');
  if (!yes) {
    throw new PatchPilotError('Not trusted. Nothing was read or written.', {
      exitCode: EXIT.USAGE,
      hint: 'Run patch-pilot again when you are ready, or trust it later with: patch-pilot trust',
    });
  }
  const entry = await trustDirectory(status.dir, { ...lookup, by, method: 'prompt' });
  return { via: 'prompt', entry };
}
