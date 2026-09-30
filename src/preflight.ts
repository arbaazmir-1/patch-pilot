// env checks, doctor prints all
import { stat, statfs } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import semver from 'semver';
import { isLocalHost } from './config.ts';
import { discoverProject, MANAGER_INSTALL, MANAGER_NAMES } from './evidence/discover.ts';
import type {
  CheckStatus,
  Config,
  InstalledModel,
  OllamaProbe,
  PackageManager,
  PreflightCheck,
  PreflightCheckId,
  PreflightNeeds,
  PreflightResult,
} from './types.ts';
import { formatBytes, formatDuration, type Ui } from './ui.ts';
import { EnvironmentError } from './util/errors.ts';
import { commandVersion, which } from './util/proc.ts';
import { USER_AGENT, VERSION } from './version.ts';

export const MIN_NODE_VERSION = '22.12.0';
// json schema format needs 0.5
export const MIN_OLLAMA_VERSION = '0.5.0';
const MIN_FREE_BYTES = 50 * 1024 * 1024;
const LOW_FREE_BYTES = 500 * 1024 * 1024;
const MAX_SHOW_PROBES = 8;

export const LINKS = {
  node: 'https://nodejs.org/en/download',
  ollamaDownload: 'https://ollama.com/download',
  ollamaLibrary: 'https://ollama.com/library/',
  toolModels: 'https://ollama.com/search?c=tools',
  ollamaKeys: 'https://ollama.com/settings/keys',
  git: 'https://git-scm.com/downloads',
} as const;

const OSV_PROBE_URL = 'https://api.osv.dev/v1/vulns/GHSA-vh95-rmgr-6w4m';
const REGISTRY_PROBE_URL = 'https://registry.npmjs.org/-/ping';

export const NEEDS = {
  scan: { npm: true, ollama: true, disk: true, optional: true, extras: false },
  investigate: { npm: false, ollama: true, disk: true, optional: false, extras: false },
  apply: { npm: true, ollama: true, disk: true, optional: true, extras: false },
  db: { npm: false, ollama: false, disk: true, optional: false, extras: false },
  basic: { npm: false, ollama: false, disk: false, optional: false, extras: false },
  doctor: { npm: true, ollama: true, disk: true, optional: true, extras: true },
} as const satisfies Record<string, PreflightNeeds>;

const LABELS: Record<PreflightCheckId, string> = {
  node: 'Node.js',
  npm: 'npm',
  'ollama-binary': 'Ollama CLI',
  'ollama-server': 'Ollama server',
  model: 'Model',
  tools: 'Tool calling',
  'codemod-model': 'Codemod model',
  disk: 'Disk space',
  'search-key': 'Web search key',
  git: 'git',
  osv: 'OSV.dev',
  registry: 'npm registry',
  db: 'Local database',
};

// injectable for tests

export interface PreflightDeps {
  nodeVersion: string;
  env: NodeJS.ProcessEnv;
  which: (cmd: string) => Promise<string | null>;
  commandVersion: (cmd: string, args?: readonly string[]) => Promise<string | null>;
  fetch: typeof fetch;
  // null when unknown
  freeBytes: (dir: string) => Promise<number | null>;
  // null when missing
  fileInfo: (file: string) => Promise<{ size: number; mtimeMs: number } | null>;
  now: () => number;
  // null without a lockfile
  projectManager: (root: string) => Promise<PackageManager | null>;
}

async function nearestExistingDir(dir: string): Promise<string> {
  let current = dir;
  for (;;) {
    try {
      if ((await stat(current)).isDirectory()) return current;
    } catch {
      // walk up
    }
    const parent = path.dirname(current);
    if (parent === current) return current;
    current = parent;
  }
}

export function defaultPreflightDeps(): PreflightDeps {
  return {
    nodeVersion: process.versions.node,
    env: process.env,
    which: (cmd) => which(cmd),
    commandVersion: (cmd, args) => commandVersion(cmd, args),
    fetch: (input, init) => fetch(input, init),
    freeBytes: async (dir) => {
      try {
        const st = await statfs(await nearestExistingDir(dir));
        return Number(st.bavail) * Number(st.bsize);
      } catch {
        return null;
      }
    },
    fileInfo: async (file) => {
      try {
        const st = await stat(file);
        return { size: st.size, mtimeMs: st.mtimeMs };
      } catch {
        return null;
      }
    },
    now: () => Date.now(),
    projectManager: async (root) => (await discoverProject(root).catch(() => null))?.packageManager ?? null,
  };
}

// "mistral:7b" -> ["mistral", "7b"]
export function splitModelName(name: string): [string, string | null] {
  const trimmed = name.trim();
  const slash = trimmed.lastIndexOf('/');
  const colon = trimmed.lastIndexOf(':');
  if (colon > slash) return [trimmed.slice(0, colon), trimmed.slice(colon + 1)];
  return [trimmed, null];
}

function tagSizeBillions(tag: string): number | null {
  const m = /^(\d+(?:\.\d+)?)b(?:\b|[-_])/i.exec(`${tag}-`);
  return m && m[1] !== undefined ? Number(m[1]) : null;
}

function paramSizeBillions(size: string | null): number | null {
  if (!size) return null;
  const m = /^(\d+(?:\.\d+)?)\s*B$/i.exec(size.trim());
  return m && m[1] !== undefined ? Number(m[1]) : null;
}

// mistral:latest covers mistral:7b
export function resolveModelName(requested: string, installed: readonly InstalledModel[]): string | null {
  const want = requested.trim();
  if (want === '') return null;
  if (installed.some((m) => m.name === want)) return want;
  const [base, tag] = splitModelName(want);
  const sameBase = installed.filter((m) => splitModelName(m.name)[0] === base);
  if (sameBase.length === 0) return null;
  const latest = sameBase.find((m) => splitModelName(m.name)[1] === 'latest');
  if (tag === null || tag === 'latest') return (latest ?? sameBase[0])?.name ?? null;
  if (!latest) return null;
  const wanted = tagSizeBillions(tag);
  const have = paramSizeBillions(latest.parameterSize);
  if (wanted !== null && have !== null && Math.abs(have - wanted) < 1) return latest.name;
  return null;
}

// plain "mistral" for mistral:7b
export function pullCommandFor(model: string): string {
  const [base, tag] = splitModelName(model);
  if (base === 'mistral' && (tag === null || tag === 'latest' || tag === '7b')) return 'ollama pull mistral';
  return `ollama pull ${model}`;
}

// hf.co models go to Hugging Face
function libraryLink(model: string): string {
  const [base] = splitModelName(model);
  if (/^(hf\.co|huggingface\.co)\//.test(base)) return `https://${base}`;
  if (base.includes('/')) return `https://ollama.com/${base}`;
  return `${LINKS.ollamaLibrary}${base}`;
}

async function probeJson<T>(deps: PreflightDeps, url: string, init: RequestInit, timeoutMs: number): Promise<T> {
  const res = await deps.fetch(url, {
    ...init,
    headers: { 'user-agent': USER_AGENT, ...(init.body ? { 'content-type': 'application/json' } : {}), ...(init.headers as Record<string, string> | undefined) },
    signal: AbortSignal.timeout(timeoutMs),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`HTTP ${res.status}${text ? `: ${text.slice(0, 200)}` : ''}`);
  return JSON.parse(text) as T;
}

function describeFetchError(err: unknown): string {
  const e = err as { name?: string; message?: string; cause?: { code?: string; message?: string; errors?: { code?: string }[] } };
  if (e?.name === 'TimeoutError') return 'timed out';
  const cause = e?.cause;
  const code = cause?.code ?? cause?.errors?.find((x) => x?.code)?.code;
  if (code === 'ECONNREFUSED') return 'connection refused';
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') return 'host not found';
  if (code) return code;
  return cause?.message || e?.message || String(err);
}

interface TagsResponse {
  models?: {
    name?: string;
    model?: string;
    digest?: string;
    size?: number;
    details?: { parameter_size?: string };
    capabilities?: string[];
  }[];
}

async function showCapabilities(deps: PreflightDeps, host: string, model: string, timeoutMs: number): Promise<string[] | null> {
  try {
    const show = await probeJson<{ capabilities?: string[] }>(deps, `${host}/api/show`, { method: 'POST', body: JSON.stringify({ model }) }, timeoutMs);
    return Array.isArray(show.capabilities) ? show.capabilities : null;
  } catch {
    return null;
  }
}

export interface ProbeOptions {
  deps?: Partial<PreflightDeps>;
  // default 3 s, /api/show gets double
  timeoutMs?: number;
  // fall back to first tool-capable model
  allowFallback?: boolean;
  codemodModel?: string | null;
}

export async function probeOllama(host: string, requestedModel: string, options: ProbeOptions = {}): Promise<OllamaProbe> {
  const deps: PreflightDeps = { ...defaultPreflightDeps(), ...options.deps };
  const timeoutMs = options.timeoutMs ?? 3_000;
  const probe: OllamaProbe = {
    host,
    binary: await deps.which('ollama'),
    reachable: false,
    version: null,
    models: [],
    requestedModel,
    resolvedModel: null,
    fallback: false,
    toolsCapable: null,
    toolModels: [],
    codemodModel: options.codemodModel ?? null,
    codemodResolved: null,
    error: null,
  };
  try {
    const version = await probeJson<{ version?: string }>(deps, `${host}/api/version`, { method: 'GET' }, timeoutMs);
    probe.reachable = true;
    probe.version = typeof version.version === 'string' ? version.version : null;
  } catch (err) {
    probe.error = describeFetchError(err);
    return probe;
  }
  try {
    const tags = await probeJson<TagsResponse>(deps, `${host}/api/tags`, { method: 'GET' }, timeoutMs);
    probe.models = (tags.models ?? [])
      .map((m): InstalledModel => ({
        name: m.name ?? m.model ?? '',
        digest: m.digest ?? null,
        sizeBytes: typeof m.size === 'number' ? m.size : null,
        parameterSize: m.details?.parameter_size ?? null,
        capabilities: Array.isArray(m.capabilities) ? m.capabilities : null,
      }))
      .filter((m) => m.name !== '');
  } catch (err) {
    probe.error = `could not list models (${describeFetchError(err)})`;
    return probe;
  }
  probe.resolvedModel = resolveModelName(requestedModel, probe.models);
  if (probe.resolvedModel) {
    const model = probe.models.find((m) => m.name === probe.resolvedModel);
    const caps = await showCapabilities(deps, host, probe.resolvedModel, timeoutMs * 2);
    if (model && caps) model.capabilities = caps;
    const known = caps ?? model?.capabilities ?? null;
    probe.toolsCapable = known ? known.includes('tools') : null;
  }
  if (!probe.resolvedModel || probe.toolsCapable === false) {
    let probes = 0;
    for (const m of probe.models) {
      if (m.capabilities !== null || probes >= MAX_SHOW_PROBES) continue;
      probes += 1;
      m.capabilities = await showCapabilities(deps, host, m.name, timeoutMs * 2);
    }
  }
  probe.toolModels = probe.models.filter((m) => m.capabilities?.includes('tools')).map((m) => m.name);
  if (!probe.resolvedModel && options.allowFallback && probe.toolModels.length > 0) {
    probe.resolvedModel = probe.toolModels[0] ?? null;
    probe.fallback = true;
    probe.toolsCapable = true;
  }
  if (probe.codemodModel) probe.codemodResolved = resolveModelName(probe.codemodModel, probe.models);
  return probe;
}

function check(id: PreflightCheckId, status: CheckStatus, detail: string, hard: boolean, fix: string[] = [], links: string[] = []): PreflightCheck {
  return { id, label: LABELS[id], status, detail, hard, fix, links };
}

function tildify(p: string): string {
  const home = os.homedir();
  return p === home || p.startsWith(home + path.sep) ? `~${p.slice(home.length)}` : p;
}

function nodeCheck(version: string): PreflightCheck {
  const ok = semver.valid(version) !== null && semver.gte(version, MIN_NODE_VERSION);
  return ok
    ? check('node', 'ok', `v${version}`, true)
    : check('node', 'fail', `v${version} is too old (22.12 or newer required)`, true, [`Install the current LTS: ${LINKS.node}`], [LINKS.node]);
}

function ollamaChecks(config: Config, probe: OllamaProbe): PreflightCheck[] {
  const out: PreflightCheck[] = [];
  const local = isLocalHost(probe.host);
  if (probe.binary) {
    out.push(check('ollama-binary', 'ok', probe.binary, false));
  } else if (!local) {
    out.push(check('ollama-binary', 'skip', `not needed for a remote host (${probe.host})`, false));
  } else if (probe.reachable) {
    out.push(
      check('ollama-binary', 'warn', 'ollama CLI not on PATH (the server is reachable, so PatchPilot can continue)', false, [
        `Install the CLI to pull models yourself: ${LINKS.ollamaDownload}`,
      ]),
    );
  } else {
    out.push(
      check(
        'ollama-binary',
        'fail',
        'Ollama is not installed',
        true,
        [`Install Ollama: ${LINKS.ollamaDownload}`, 'macOS: brew install ollama also works', 'Then start it: ollama serve'],
        [LINKS.ollamaDownload],
      ),
    );
  }

  if (!probe.reachable) {
    if (!probe.binary && local) {
      out.push(check('ollama-server', 'skip', 'not running (install Ollama first)', true));
    } else {
      const fix = local
        ? [
            'Start it with: ollama serve   (or open the Ollama app)',
            `Probed: ${probe.host}/api/version`,
            'Different host? Pass --ollama-host <url> or set OLLAMA_HOST.',
          ]
        : [
            `Start Ollama on that machine (ollama serve), or check --ollama-host / OLLAMA_HOST.`,
            `Probed: ${probe.host}/api/version`,
          ];
      out.push(check('ollama-server', 'fail', `not reachable at ${probe.host} (${probe.error ?? 'no response'})`, true, fix));
    }
    out.push(check('model', 'skip', `${config.model} (Ollama not reachable)`, true));
    out.push(check('tools', 'skip', 'not checked', true));
    return out;
  }

  const version = probe.version ?? 'unknown version';
  const tooOld = probe.version !== null && semver.valid(probe.version) !== null && semver.lt(probe.version, MIN_OLLAMA_VERSION);
  if (tooOld) {
    out.push(
      check('ollama-server', 'fail', `Ollama ${version} at ${probe.host} is too old (0.5 or newer needed for structured outputs)`, true, [
        `Update Ollama: ${LINKS.ollamaDownload}`,
      ], [LINKS.ollamaDownload]),
    );
  } else if (probe.error) {
    out.push(check('ollama-server', 'fail', `${version} at ${probe.host}, but ${probe.error}`, true, ['Restart Ollama (ollama serve) and try again.']));
    return out;
  } else {
    out.push(check('ollama-server', 'ok', `${version} at ${probe.host}`, true));
  }

  const installedList = probe.models.map((m) => `${m.name}${m.capabilities ? (m.capabilities.includes('tools') ? ' (tools)' : ' (no tools)') : ''}`);
  if (probe.resolvedModel === null) {
    const fix = [
      `Pull the model: ${pullCommandFor(probe.requestedModel)}`,
      `Model page: ${libraryLink(probe.requestedModel)}`,
      'Or let PatchPilot pull it: patch-pilot doctor --fix',
    ];
    if (installedList.length > 0) fix.push(`Installed models: ${installedList.join(', ')} (pick one with --model <name>)`);
    out.push(check('model', 'fail', `${probe.requestedModel} is not installed`, true, fix, [libraryLink(probe.requestedModel)]));
    out.push(check('tools', 'skip', 'not checked (model missing)', true));
    return out;
  }
  if (probe.fallback) {
    out.push(
      check('model', 'warn', `${probe.requestedModel} is not installed; using ${probe.resolvedModel} (tool-capable)`, true, [
        `To use the default model: ${pullCommandFor(probe.requestedModel)}`,
      ]),
    );
  } else if (probe.resolvedModel !== probe.requestedModel) {
    out.push(check('model', 'ok', `${probe.resolvedModel} (satisfies ${probe.requestedModel})`, true));
  } else {
    out.push(check('model', 'ok', probe.resolvedModel, true));
  }

  if (probe.toolsCapable === true) {
    out.push(check('tools', 'ok', `${probe.resolvedModel} supports tools`, true));
  } else if (probe.toolsCapable === false) {
    const others = probe.toolModels.filter((m) => m !== probe.resolvedModel);
    const fix =
      others.length > 0
        ? [
            `Tool-capable models installed: ${others.join(', ')}`,
            `Pick one with: --model ${others[0]}   (or set PATCHPILOT_MODEL)`,
            `Browse tool-capable models: ${LINKS.toolModels}`,
          ]
        : [
            'No tool-capable model is installed. Pull one: ollama pull qwen3:8b (about 5 GB) or ollama pull mistral (about 4 GB)',
            `Browse tool-capable models: ${LINKS.toolModels}`,
          ];
    out.push(check('tools', 'fail', `${probe.resolvedModel} does not support tool calling`, true, fix, [LINKS.toolModels]));
  } else {
    out.push(
      check('tools', 'warn', `could not confirm that ${probe.resolvedModel} supports tools (continuing)`, false, [
        `Tool-capable models: ${LINKS.toolModels}`,
      ]),
    );
  }

  if (probe.codemodModel) {
    out.push(
      probe.codemodResolved
        ? check('codemod-model', 'ok', probe.codemodResolved, false)
        : check('codemod-model', 'warn', `${probe.codemodModel} is not installed; code edits will use ${probe.resolvedModel}`, false, [
            `Pull it: ${pullCommandFor(probe.codemodModel)}`,
          ]),
    );
  }
  return out;
}

async function reachability(deps: PreflightDeps, id: 'osv' | 'registry', url: string, what: string): Promise<PreflightCheck> {
  const started = deps.now();
  try {
    const res = await deps.fetch(url, { headers: { 'user-agent': USER_AGENT }, signal: AbortSignal.timeout(5_000) });
    await res.body?.cancel().catch(() => {});
    return check(id, 'ok', `reachable (${formatDuration(deps.now() - started)})`, false);
  } catch (err) {
    return check(id, 'warn', `not reachable (${describeFetchError(err)}); ${what}`, false);
  }
}

// PATH, else corepack. hard only for patch
async function managerCheck(manager: Exclude<PackageManager, 'npm'>, needs: PreflightNeeds, deps: PreflightDeps): Promise<PreflightCheck> {
  const bin = manager === 'pnpm' ? 'pnpm' : 'yarn';
  const label = MANAGER_NAMES[manager];
  const hard = needs.npm && !needs.extras;
  const [binPath, corepackPath] = await Promise.all([deps.which(bin), deps.which('corepack')]);
  const make = (status: CheckStatus, detail: string, fix: string[] = [], links: string[] = []): PreflightCheck => ({ id: 'npm', label, status, detail, hard, fix, links });
  if (binPath) {
    const version = needs.extras ? await deps.commandVersion(bin, ['--version']) : null;
    return make('ok', version ? `${version} (${binPath})` : binPath);
  }
  if (corepackPath) {
    const version = needs.extras ? await deps.commandVersion('corepack', ['--version']) : null;
    return make('ok', `${bin} not on PATH: runs through corepack${version ? ` ${version}` : ''} (${corepackPath})`);
  }
  const info = MANAGER_INSTALL[manager];
  return make(hard ? 'fail' : 'warn', `${bin} not found on PATH, and corepack is not available`, info.fix, info.links);
}

// never throws
export async function runPreflight(config: Config, needs: PreflightNeeds, depsIn: Partial<PreflightDeps> = {}): Promise<PreflightResult> {
  const deps: PreflightDeps = { ...defaultPreflightDeps(), ...depsIn };
  const started = deps.now();
  const checks: PreflightCheck[] = [nodeCheck(deps.nodeVersion)];
  const wantNpm = needs.npm || needs.extras;
  const wantGit = needs.optional || needs.extras;
  const useOllama = needs.ollama && config.provider !== 'mock';

  const [npmPath, gitPath, probe] = await Promise.all([
    wantNpm ? deps.which('npm') : Promise.resolve(null),
    wantGit ? deps.which('git') : Promise.resolve(null),
    useOllama
      ? probeOllama(config.ollamaHost, config.model, {
          deps,
          timeoutMs: config.timeouts.ollamaProbeMs,
          allowFallback: config.sources.model === 'default' || config.sources.model === undefined,
          codemodModel: config.codemodModel,
        })
      : Promise.resolve(null),
  ]);
  const [npmVersion, gitVersion] = await Promise.all([
    needs.extras && npmPath ? deps.commandVersion('npm', ['--version']) : Promise.resolve(null),
    needs.extras && gitPath ? deps.commandVersion('git', ['--version']) : Promise.resolve(null),
  ]);

  const manager = wantNpm ? await deps.projectManager(config.projectRoot).catch(() => null) : null;
  if (wantNpm && manager !== null && manager !== 'npm') {
    checks.push(await managerCheck(manager, needs, deps));
  } else if (wantNpm) {
    checks.push(
      npmPath
        ? check('npm', 'ok', npmVersion ? `${npmVersion} (${npmPath})` : npmPath, needs.npm)
        : check('npm', needs.npm ? 'fail' : 'warn', 'not found on PATH', needs.npm, [`npm ships with Node.js: ${LINKS.node}`], [LINKS.node]),
    );
  }

  if (needs.ollama) {
    if (probe) checks.push(...ollamaChecks(config, probe));
    else checks.push(check('ollama-server', 'skip', 'mock provider (Ollama not needed)', false));
  }

  if (needs.disk) {
    const free = await deps.freeBytes(config.paths.homeDir);
    const where = tildify(config.paths.homeDir);
    if (free === null) checks.push(check('disk', 'skip', `could not read free space for ${where}`, false));
    else if (free < MIN_FREE_BYTES) {
      checks.push(check('disk', 'fail', `only ${formatBytes(free)} free for ${where}`, true, ['Free some disk space (PatchPilot needs about 50 MB for its cache).']));
    } else if (free < LOW_FREE_BYTES) {
      checks.push(check('disk', 'warn', `${formatBytes(free)} free for ${where} (patch-pilot db sync needs about 500 MB)`, false));
    } else {
      checks.push(check('disk', 'ok', `${formatBytes(free)} free for ${where}`, false));
    }
  }

  if (needs.optional || needs.extras) {
    if (config.offline || config.search === 'off') {
      checks.push(check('search-key', 'skip', config.offline ? 'offline run' : 'web search is off (--search off)', false));
    } else if (config.search === 'brave') {
      checks.push(
        config.braveApiKey
          ? check('search-key', 'ok', 'BRAVE_SEARCH_API_KEY set (Brave search)', false)
          : check('search-key', 'warn', 'BRAVE_SEARCH_API_KEY not set: migration research falls back to the keyless docs backend', false),
      );
    } else if (config.ollamaApiKey) {
      const from = config.sources.ollamaApiKey === 'user' ? '~/.patch-pilot/config.json' : 'OLLAMA_API_KEY';
      checks.push(check('search-key', 'ok', `Ollama Web Search key set (${from})`, false));
    } else {
      checks.push(
        check(
          'search-key',
          config.search === 'ollama' ? 'warn' : 'info',
          'OLLAMA_API_KEY not set: migration research uses the keyless docs backend',
          false,
          [`Free key for web results: ${LINKS.ollamaKeys}`, 'Then: patch-pilot config set ollama-api-key (or export OLLAMA_API_KEY)'],
          [LINKS.ollamaKeys],
        ),
      );
    }
    checks.push(
      gitPath
        ? check('git', 'ok', gitVersion ? gitVersion.replace(/^git version\s*/, '') : gitPath, false)
        : check('git', 'warn', 'not found: approvals record the OS user only and the dirty-tree check is skipped', false, [`Install git: ${LINKS.git}`]),
    );
  }

  if (needs.extras) {
    if (config.offline) {
      checks.push(check('osv', 'skip', 'offline run', false), check('registry', 'skip', 'offline run', false));
    } else {
      const [osv, registry] = await Promise.all([
        reachability(deps, 'osv', OSV_PROBE_URL, 'scans fall back to the local cache'),
        reachability(deps, 'registry', REGISTRY_PROBE_URL, 'fix versions and deprecations come from the cache'),
      ]);
      checks.push(osv, registry);
    }
    const db = await deps.fileInfo(config.paths.dbFile);
    const where = tildify(config.paths.dbFile);
    checks.push(
      db
        ? check('db', 'ok', `${where}, ${formatBytes(db.size)}, updated ${formatDuration(Math.max(0, deps.now() - db.mtimeMs))} ago`, false)
        : check('db', 'info', `not created yet (${where})`, false, ['It is created on the first scan. For offline scans: patch-pilot db sync']),
    );
  }

  const ok = !checks.some((c) => c.hard && c.status === 'fail');
  return {
    ok,
    checks,
    ollama: probe,
    node: { version: deps.nodeVersion },
    npm: { path: npmPath, version: npmVersion },
    git: { path: gitPath, version: gitVersion },
    durationMs: deps.now() - started,
  };
}

export interface RenderPreflightOptions {
  // doctor shows all, failure only hard ones
  mode: 'doctor' | 'failure';
  stream?: 'stdout' | 'stderr';
  title?: string;
  dir?: string;
}

function failureTitle(failures: readonly PreflightCheck[]): string {
  if (failures.length !== 1) return `PatchPilot cannot start: ${failures.length} required checks failed.`;
  const f = failures[0] as PreflightCheck;
  switch (f.id) {
    case 'node':
      return 'PatchPilot cannot start: Node.js is too old.';
    case 'npm':
      return `PatchPilot cannot start: ${f.label === 'npm' ? 'npm' : (f.label.split(' ')[0] as string)} was not found.`;
    case 'ollama-binary':
      return 'PatchPilot cannot start: Ollama is not installed.';
    case 'ollama-server':
      return f.detail.includes('too old') ? 'PatchPilot cannot start: Ollama needs an update.' : 'PatchPilot cannot start: Ollama is not running.';
    case 'model':
      return 'PatchPilot cannot start: the model is not installed.';
    case 'tools':
      return 'PatchPilot cannot start: the model cannot call tools.';
    case 'disk':
      return 'PatchPilot cannot start: not enough disk space.';
    default:
      return `PatchPilot cannot start: ${f.label} check failed.`;
  }
}

// skip links already in the fix
function fixLines(chk: PreflightCheck): string[] {
  const lines = [...chk.fix];
  for (const link of chk.links) if (!lines.some((l) => l.includes(link))) lines.push(link);
  return lines;
}

// pure, tests pass fakes
export function renderPreflight(result: PreflightResult, ui: Ui, options: RenderPreflightOptions): string {
  const c = options.stream === 'stderr' ? ui.ce : ui.c;
  const labelWidth = Math.max(...Object.values(LABELS).map((l) => l.length));
  const glyphWidth = ui.glyphs.ok.length + 1;
  const lineFor = (chk: PreflightCheck, padLabel: boolean): string => {
    const label = padLabel ? chk.label.padEnd(labelWidth) : chk.label;
    switch (chk.status) {
      case 'ok':
        return ui.formatCheck(label, chk.detail, c);
      case 'fail':
        return ui.formatFail(label, chk.detail, c);
      case 'warn':
        return ui.formatWarn(label, chk.detail, c);
      default:
        return ui.formatInfoLine(label, chk.detail, c);
    }
  };
  const lines: string[] = [];

  if (options.mode === 'failure') {
    const failures = result.checks.filter((chk) => chk.hard && chk.status === 'fail');
    lines.push(c.bold(c.red(ui.text(options.title ?? failureTitle(failures)))));
    lines.push('');
    for (const f of failures) {
      lines.push(lineFor(f, false));
      const fixes = fixLines(f);
      if (fixes.length > 0) lines.push(ui.formatDimLines(fixes, glyphWidth + 2, c));
    }
    lines.push('');
    lines.push(c.dim('Run patch-pilot doctor to re-check everything once fixed.'));
    return lines.join('\n');
  }

  lines.push(ui.formatHeader(VERSION, 'Environment check', options.dir));
  lines.push('');
  for (const chk of result.checks) {
    lines.push(lineFor(chk, true));
    if (chk.status !== 'ok' && chk.status !== 'skip') {
      const fixes = fixLines(chk);
      if (fixes.length > 0) lines.push(ui.formatDimLines(fixes, glyphWidth + labelWidth + 2, c));
    }
  }
  lines.push('');
  const failures = result.checks.filter((chk) => chk.hard && chk.status === 'fail');
  const warnings = result.checks.filter((chk) => chk.status === 'warn');
  if (failures.length > 0) {
    lines.push(c.red(`${failures.length} required check${failures.length === 1 ? '' : 's'} failed. Fix the items above, then run patch-pilot doctor again.`));
  } else if (warnings.length > 0) {
    lines.push(`${ui.green('All required checks passed', c)} ${c.dim(`(${warnings.length} warning${warnings.length === 1 ? '' : 's'})`)}`);
  } else {
    lines.push(ui.green('All required checks passed.', c));
  }
  return lines.join('\n');
}

// Node v24.14.1 · Ollama 0.34.4 · mistral:7b
export function summarizePreflight(result: PreflightResult, config: Config, dot = '·'): string {
  const parts = [`Node v${result.node.version}`];
  const manager = result.checks.find((c) => c.id === 'npm' && c.label !== 'npm' && c.status === 'ok');
  if (manager) parts.push(manager.label);
  if (result.ollama?.reachable) {
    parts.push(`Ollama ${result.ollama.version ?? ''}`.trim());
    if (result.ollama.resolvedModel) parts.push(`${result.ollama.resolvedModel}${result.ollama.toolsCapable ? ' (tools)' : ''}`);
  } else if (config.provider === 'mock') {
    parts.push('mock provider');
  }
  return parts.join(` ${dot} `);
}

// hard failure throws (exit 3)
export async function ensurePreflight(config: Config, ui: Ui, needs: PreflightNeeds, deps: Partial<PreflightDeps> = {}): Promise<PreflightResult> {
  const result = await runPreflight(config, needs, deps);
  if (!result.ok) {
    ui.errorBlock(renderPreflight(result, ui, { mode: 'failure', stream: 'stderr' }));
    const failed = result.checks.filter((chk) => chk.hard && chk.status === 'fail').map((chk) => chk.label);
    throw new EnvironmentError(`Preflight failed: ${failed.join(', ')}`, { printed: true });
  }
  applyPreflightModels(config, result);
  if (needs.ollama || needs.npm) ui.check('Environment OK', summarizePreflight(result, config, ui.glyphs.dot));
  for (const chk of result.checks) {
    if (chk.status === 'warn') ui.warn(`${chk.label}: ${chk.detail}`, chk.fix[0]);
    else if (chk.status === 'info') ui.notice(`${chk.label}: ${chk.detail}`, chk.fix[0]);
  }
  return result;
}

export function applyPreflightModels(config: Config, result: PreflightResult): void {
  const probe = result.ollama;
  if (!probe) return;
  if (probe.resolvedModel && probe.resolvedModel !== config.model) config.model = probe.resolvedModel;
  if (probe.codemodModel) config.codemodModel = probe.codemodResolved;
}

// doctor --fix

export interface PullProgress {
  status: string;
  digest?: string;
  total?: number;
  completed?: number;
}

// NDJSON until {"status":"success"}
export async function pullModel(
  host: string,
  model: string,
  onProgress: (progress: PullProgress) => void,
  options: { fetch?: typeof fetch; signal?: AbortSignal } = {},
): Promise<void> {
  const doFetch = options.fetch ?? fetch;
  let res: Response;
  try {
    res = await doFetch(`${host}/api/pull`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'user-agent': USER_AGENT },
      body: JSON.stringify({ model, stream: true }),
      signal: options.signal,
    });
  } catch (err) {
    throw new EnvironmentError(`Cannot reach Ollama at ${host} to pull ${model} (${describeFetchError(err)})`, {
      hint: 'Start it with: ollama serve',
    });
  }
  if (!res.ok || !res.body) {
    const body = await res.text().catch(() => '');
    throw new EnvironmentError(`Pulling ${model} failed: HTTP ${res.status}${body ? ` ${body.slice(0, 200)}` : ''}`, {
      hint: `Try it directly: ${pullCommandFor(model)}`,
    });
  }
  const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
  let buffer = '';
  let success = false;
  const handle = (line: string): void => {
    if (line.trim() === '') return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      return;
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return;
    const obj = parsed as PullProgress & { error?: string };
    if (obj.error) throw new EnvironmentError(`Pulling ${model} failed: ${obj.error}`, { hint: `Check the name on ${libraryLink(model)}` });
    onProgress(obj);
    if (obj.status === 'success') success = true;
  };
  try {
    for (;;) {
      let chunk: Awaited<ReturnType<typeof reader.read>>;
      try {
        chunk = await reader.read();
      } catch (err) {
        if (options.signal?.aborted) throw err;
        throw new EnvironmentError(`Pulling ${model} was cut off (${describeFetchError(err)})`, {
          hint: `Check that Ollama is still running, then retry or run: ${pullCommandFor(model)}`,
        });
      }
      if (chunk.done) break;
      buffer += chunk.value;
      let nl = buffer.indexOf('\n');
      while (nl !== -1) {
        handle(buffer.slice(0, nl));
        buffer = buffer.slice(nl + 1);
        nl = buffer.indexOf('\n');
      }
    }
    handle(buffer);
  } finally {
    reader.cancel().catch(() => {});
  }
  if (!success) throw new EnvironmentError(`Pulling ${model} ended without success`, { hint: `Try it directly: ${pullCommandFor(model)}` });
}

// "pulling 6577803aa9a0  42% [########------------] 1.8 GB / 4.4 GB"
export function renderPullProgress(progress: PullProgress, barWidth = 20): string {
  const status = progress.digest ? `pulling ${progress.digest.replace(/^sha256:/, '').slice(0, 12)}` : progress.status;
  if (!progress.total || progress.total <= 0) return status;
  const done = Math.min(progress.completed ?? 0, progress.total);
  const ratio = done / progress.total;
  const filled = Math.round(ratio * barWidth);
  const bar = `[${'#'.repeat(filled)}${'-'.repeat(barWidth - filled)}]`;
  return `${status}  ${String(Math.floor(ratio * 100)).padStart(3)}% ${bar} ${formatBytes(done)} / ${formatBytes(progress.total)}`;
}

