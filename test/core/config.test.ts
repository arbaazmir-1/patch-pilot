import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import {
  addIgnoreEntry,
  DEFAULT_EXCLUDES,
  effectiveSearchBackend,
  findIgnore,
  findingsExitCode,
  isIgnoreExpired,
  loadConfig,
  normalizeOllamaHost,
  parseUntil,
  parseUserConfigValue,
  readIgnoreEntries,
  removeIgnoreEntry,
  riskAtOrAbove,
  USER_CONFIG_KEYS,
  worstRisk,
} from '../../src/config.ts';
import type { IgnoreEntry } from '../../src/types.ts';
import { ConfigError, EXIT } from '../../src/util/errors.ts';

let root: string;
let home: string;

async function project(name: string, config?: unknown, raw?: string): Promise<string> {
  const dir = path.join(root, name);
  await mkdir(dir, { recursive: true });
  if (raw !== undefined) await writeFile(path.join(dir, 'patch-pilot.config.json'), raw);
  else if (config !== undefined) await writeFile(path.join(dir, 'patch-pilot.config.json'), JSON.stringify(config, null, 2));
  return dir;
}

const base = { env: {}, stdinIsTTY: false, stdoutIsTTY: false };

before(async () => {
  root = await mkdtemp(path.join(os.tmpdir(), 'pp-config-'));
  home = path.join(root, 'home');
  await mkdir(home);
});

after(async () => {
  await rm(root, { recursive: true, force: true });
});

describe('loadConfig defaults', () => {
  it('uses the documented defaults', async () => {
    const dir = await project('defaults');
    const c = await loadConfig({ ...base, dir, homeDir: home });
    assert.equal(c.provider, 'ollama');
    assert.equal(c.model, 'qwen3:8b');
    assert.equal(c.ollamaHost, 'http://localhost:11434');
    assert.equal(c.numCtx, 16384);
    assert.equal(c.maxSteps, 3);
    assert.equal(c.search, 'auto');
    assert.equal(c.failOn, 'high');
    assert.equal(c.seed, 42);
    assert.equal(c.codemodModel, null);
    assert.equal(c.ollamaApiKey, null);
    assert.equal(c.noCache, false);
    assert.equal(c.interactive, false);
    assert.equal(c.configFile, null);
    assert.equal(c.sources.model, 'default');
    for (const glob of DEFAULT_EXCLUDES) assert.ok(c.exclude.includes(glob));
    assert.equal(c.paths.stateDir, path.join(c.projectRoot, '.patch-pilot'));
    assert.equal(c.paths.trustedFile, path.join(home, '.patch-pilot', 'trusted.json'));
    assert.equal(c.paths.dbFile, path.join(home, '.patch-pilot', 'patch-pilot.db'));
    assert.equal(c.timeouts.osvMs, 20_000);
    assert.equal(c.timeouts.llmMs, 180_000);
  });

  it('reports model "mock" for the mock provider unless a model is named', async () => {
    const dir = await project('mock');
    assert.equal((await loadConfig({ ...base, dir, homeDir: home, flags: { provider: 'mock' } })).model, 'mock');
    assert.equal((await loadConfig({ ...base, dir, homeDir: home, flags: { provider: 'mock', model: 'qwen3:8b' } })).model, 'qwen3:8b');
  });
});

describe('loadConfig precedence: flags > env > config file > defaults', () => {
  it('layers every source and records where each value came from', async () => {
    const dir = await project('layers', {
      model: 'file-model',
      numCtx: 8192,
      search: 'docs',
      failOn: 'medium',
      ollamaHost: 'http://file-host:11434',
      maxSteps: 4,
      exclude: ['fixtures/**'],
    });
    const env = { PATCHPILOT_MODEL: 'env-model', OLLAMA_HOST: 'env-host:1234' };
    const c = await loadConfig({ ...base, dir, homeDir: home, env, flags: { model: 'flag-model' } });
    assert.equal(c.model, 'flag-model');
    assert.equal(c.sources.model, 'flag');
    assert.equal(c.ollamaHost, 'http://env-host:1234');
    assert.equal(c.sources.ollamaHost, 'env');
    assert.equal(c.numCtx, 8192);
    assert.equal(c.sources.numCtx, 'file');
    assert.equal(c.search, 'docs');
    assert.equal(c.failOn, 'medium');
    assert.equal(c.maxSteps, 4);
    assert.ok(c.exclude.includes('fixtures/**'));
    assert.equal(c.configFile, path.join(c.projectRoot, 'patch-pilot.config.json'));

    const fileOnly = await loadConfig({ ...base, dir, homeDir: home });
    assert.equal(fileOnly.model, 'file-model');
    assert.equal(fileOnly.ollamaHost, 'http://file-host:11434');

    const envOverFile = await loadConfig({ ...base, dir, homeDir: home, env });
    assert.equal(envOverFile.model, 'env-model');

    const flags = await loadConfig({ ...base, dir, homeDir: home, env, flags: { failOn: 'critical', numCtx: '4096', ollamaHost: 'flag-host', search: 'off' } });
    assert.equal(flags.failOn, 'critical');
    assert.equal(flags.numCtx, 4096);
    assert.equal(flags.ollamaHost, 'http://flag-host:11434');
    assert.equal(flags.search, 'off');
  });

  it('reads keys and switches from the environment', async () => {
    const dir = await project('env');
    const c = await loadConfig({
      ...base,
      dir,
      homeDir: home,
      env: { OLLAMA_API_KEY: 'k1', GITHUB_TOKEN: 't1', BRAVE_SEARCH_API_KEY: 'b1', PATCHPILOT_DEBUG: '1', NO_COLOR: '1' },
    });
    assert.equal(c.ollamaApiKey, 'k1');
    assert.equal(c.githubToken, 't1');
    assert.equal(c.braveApiKey, 'b1');
    assert.equal(c.debug, true);
    assert.equal(c.color, false);
    assert.equal(c.sources.color, 'env');
    const off = await loadConfig({ ...base, dir, homeDir: home, env: { PATCHPILOT_DEBUG: '0', NO_COLOR: '1', FORCE_COLOR: '1' } });
    assert.equal(off.debug, false);
    assert.equal(off.color, true, 'FORCE_COLOR wins over NO_COLOR');
    assert.equal((await loadConfig({ ...base, dir, homeDir: home, flags: { color: false } })).color, false);
    assert.equal((await loadConfig({ ...base, dir, homeDir: home, env: { GH_TOKEN: 'gh' } })).githubToken, 'gh');
  });

  it('parses lists, --no-cache, the mock script path and interactivity', async () => {
    const dir = await project('flags');
    const c = await loadConfig({
      ...base,
      dir,
      homeDir: home,
      cwd: root,
      flags: { only: 'lodash, minimist,,marked', approve: ['a,b', 'c'], cache: false, mockScript: 'script.json' },
    });
    assert.deepEqual(c.only, ['lodash', 'minimist', 'marked']);
    assert.deepEqual(c.approve, ['a', 'b', 'c']);
    assert.equal(c.noCache, true);
    assert.equal(c.mockScript, path.join(root, 'script.json'));
    assert.equal((await loadConfig({ ...base, dir, homeDir: home, stdinIsTTY: true, stdoutIsTTY: true })).interactive, true);
    assert.equal((await loadConfig({ ...base, dir, homeDir: home, stdinIsTTY: true, stdoutIsTTY: true, flags: { ci: true } })).interactive, false);
    assert.equal((await loadConfig({ ...base, dir, homeDir: home, stdinIsTTY: true, stdoutIsTTY: true, flags: { json: true } })).interactive, false);
  });
});

describe('loadConfig validation', () => {
  it('rejects a missing directory or a file with exit code 2', async () => {
    await assert.rejects(loadConfig({ ...base, dir: path.join(root, 'nope'), homeDir: home }), (err: unknown) => {
      assert.ok(err instanceof ConfigError);
      assert.equal(err.exitCode, EXIT.USAGE);
      return true;
    });
    const file = path.join(root, 'a-file');
    await writeFile(file, 'x');
    await assert.rejects(loadConfig({ ...base, dir: file, homeDir: home }), ConfigError);
  });

  it('rejects invalid JSON and invalid values, listing every problem', async () => {
    const broken = await project('broken', undefined, '{ "model": ');
    await assert.rejects(loadConfig({ ...base, dir: broken, homeDir: home }), /Invalid JSON/);
    const invalid = await project('invalid', { numCtx: 5, search: 'google', failOn: 'huge', exclude: 'x', ignore: [{ id: '' }] });
    await assert.rejects(loadConfig({ ...base, dir: invalid, homeDir: home }), (err: unknown) => {
      assert.ok(err instanceof ConfigError);
      for (const text of ['numCtx', 'search', 'failOn', 'exclude', 'ignore[0].id', 'ignore[0].reason']) assert.match(err.message, new RegExp(text.replace(/[[\]]/g, '\\$&')));
      return true;
    });
  });

  it('rejects invalid flag values', async () => {
    const dir = await project('badflags');
    await assert.rejects(loadConfig({ ...base, dir, homeDir: home, flags: { numCtx: 100 } }), /--num-ctx/);
    await assert.rejects(loadConfig({ ...base, dir, homeDir: home, flags: { maxSteps: 0 } }), /--max-steps/);
    await assert.rejects(loadConfig({ ...base, dir, homeDir: home, flags: { provider: 'deepseek' } }), /--provider/);
    await assert.rejects(loadConfig({ ...base, dir, homeDir: home, flags: { ollamaHost: 'ftp://x' } }), /Ollama host/);
  });

  it('warns about unknown keys and skips the file when asked', async () => {
    const dir = await project('unknown', { model: 'x', colour: 'blue' });
    const c = await loadConfig({ ...base, dir, homeDir: home });
    assert.ok(c.warnings.some((w) => w.includes('colour')));
    const broken = await project('broken2', undefined, 'not json');
    const skipped = await loadConfig({ ...base, dir: broken, homeDir: home, skipProjectFile: true });
    assert.equal(skipped.configFile, null);
  });
});

describe('user-level config (~/.patch-pilot/config.json)', () => {
  async function userHome(name: string, config: unknown, mode = 0o600): Promise<string> {
    const dir = path.join(root, name);
    await mkdir(path.join(dir, '.patch-pilot'), { recursive: true });
    const file = path.join(dir, '.patch-pilot', 'config.json');
    await writeFile(file, JSON.stringify(config));
    await chmod(file, mode);
    return dir;
  }

  it('sits between the project config and the defaults', async () => {
    const userDir = await userHome('home-user', { model: 'user-model', numCtx: 8192, search: 'docs', ollamaApiKey: 'user-key', failOn: 'low' });
    const plain = await project('user-plain');
    const c = await loadConfig({ ...base, dir: plain, homeDir: userDir });
    assert.equal(c.model, 'user-model');
    assert.equal(c.sources.model, 'user');
    assert.equal(c.numCtx, 8192);
    assert.equal(c.search, 'docs');
    assert.equal(c.failOn, 'low');
    assert.equal(c.ollamaApiKey, 'user-key');
    assert.equal(c.sources.ollamaApiKey, 'user');
    assert.equal(c.userConfigFile, path.join(userDir, '.patch-pilot', 'config.json'));
    assert.equal(c.paths.userConfigFile, path.join(userDir, '.patch-pilot', 'config.json'));
    assert.deepEqual(c.warnings, []);

    const withProject = await project('user-project', { model: 'project-model', failOn: 'critical' });
    const p = await loadConfig({ ...base, dir: withProject, homeDir: userDir });
    assert.equal(p.model, 'project-model', 'project config wins over user config');
    assert.equal(p.failOn, 'critical');
    assert.equal(p.numCtx, 8192, 'user config still fills what the project leaves out');

    const e = await loadConfig({ ...base, dir: withProject, homeDir: userDir, env: { OLLAMA_API_KEY: 'env-key', PATCHPILOT_MODEL: 'env-model' } });
    assert.equal(e.ollamaApiKey, 'env-key', 'env wins over user config');
    assert.equal(e.model, 'env-model');
    assert.equal((await loadConfig({ ...base, dir: plain, homeDir: userDir, flags: { model: 'flag-model' } })).model, 'flag-model');
    assert.equal((await loadConfig({ ...base, dir: plain, homeDir: userDir, flags: { provider: 'mock' } })).model, 'mock');
  });

  it('never reads secrets from the project file or from .env files in the scanned project', async () => {
    const dir = await project('secrets', { model: 'x' });
    await writeFile(path.join(dir, '.env'), 'OLLAMA_API_KEY=from-project-dotenv\nPATCHPILOT_MODEL=evil\n');
    await writeFile(path.join(dir, '.env.local'), 'OLLAMA_API_KEY=from-project-dotenv-local\n');
    const c = await loadConfig({ ...base, dir, homeDir: home });
    assert.equal(c.ollamaApiKey, null);
    assert.equal(c.model, 'x');
    const withKey = await project('secrets-in-file', { ollamaApiKey: 'nope' });
    const k = await loadConfig({ ...base, dir: withKey, homeDir: home });
    assert.equal(k.ollamaApiKey, null);
    assert.ok(k.warnings.some((w) => w.includes('ollamaApiKey')), 'unknown key in the project file is ignored with a warning');
  });

  it('warns when the file is readable by other users and rejects invalid values', async (t) => {
    if (process.platform === 'win32') {
      t.skip('POSIX modes only');
      return;
    }
    const open = await userHome('home-open', { model: 'm' }, 0o644);
    const c = await loadConfig({ ...base, dir: await project('user-open'), homeDir: open });
    assert.ok(c.warnings.some((w) => w.includes('chmod 600')));
    const bad = await userHome('home-bad', { numCtx: 12, search: 'bing' });
    await assert.rejects(loadConfig({ ...base, dir: await project('user-bad'), homeDir: bad }), (err: unknown) => {
      assert.ok(err instanceof ConfigError);
      assert.match(err.message, /numCtx/);
      assert.match(err.message, /search/);
      return true;
    });
    const unknown = await userHome('home-unknown', { colour: 'blue' });
    assert.ok((await loadConfig({ ...base, dir: await project('user-unknown'), homeDir: unknown })).warnings.some((w) => w.includes('colour')));
  });

  it('exposes the keys for patch-pilot config set|get|unset', () => {
    assert.equal(USER_CONFIG_KEYS['ollama-api-key']?.field, 'ollamaApiKey');
    assert.equal(USER_CONFIG_KEYS['ollama-api-key']?.secret, true);
    assert.equal(USER_CONFIG_KEYS['ollama-host']?.secret, false);
    assert.equal(parseUserConfigValue('ollamaHost', 'gpu:11434'), 'http://gpu:11434');
    assert.equal(parseUserConfigValue('numCtx', '8192'), 8192);
    assert.throws(() => parseUserConfigValue('failOn', 'sometimes'), ConfigError);
  });
});

describe('normalizeOllamaHost', () => {
  it('follows the OLLAMA_HOST conventions', () => {
    assert.equal(normalizeOllamaHost('localhost:11434'), 'http://localhost:11434');
    assert.equal(normalizeOllamaHost('0.0.0.0'), 'http://127.0.0.1:11434');
    assert.equal(normalizeOllamaHost('gpu-box'), 'http://gpu-box:11434');
    assert.equal(normalizeOllamaHost('http://example.com'), 'http://example.com');
    assert.equal(normalizeOllamaHost('https://example.com/ollama/'), 'https://example.com/ollama');
    assert.equal(normalizeOllamaHost(' http://localhost:11434/ '), 'http://localhost:11434');
    assert.throws(() => normalizeOllamaHost(''), ConfigError);
    assert.throws(() => normalizeOllamaHost('ftp://x'), ConfigError);
  });
});

describe('accepted risks (ignore)', () => {
  it('writes entries into patch-pilot.config.json, preserving other keys and indentation', async () => {
    const dir = await project('ignore', undefined, '{\n    "model": "qwen3:8b"\n}\n');
    const entry: IgnoreEntry = { id: 'GHSA-xvch-5gv4-984h', package: 'minimist', reason: 'trusted input', by: 'Tester', createdAt: '2026-09-24T00:00:00.000Z', until: '2027-01-31' };
    await addIgnoreEntry(dir, entry);
    const text = await readFile(path.join(dir, 'patch-pilot.config.json'), 'utf8');
    assert.match(text, /^\{\n {4}"model": "qwen3:8b",/);
    assert.ok(text.endsWith('\n'));
    assert.deepEqual(await readIgnoreEntries(dir), [entry]);
    await addIgnoreEntry(dir, { ...entry, reason: 'updated' });
    const entries = await readIgnoreEntries(dir);
    assert.equal(entries.length, 1, 'same id + package replaces');
    assert.equal(entries[0]?.reason, 'updated');
    await addIgnoreEntry(dir, { ...entry, package: 'other' });
    assert.equal((await readIgnoreEntries(dir)).length, 2);
    assert.equal(await removeIgnoreEntry(dir, entry.id, 'other'), true);
    assert.equal(await removeIgnoreEntry(dir, 'GHSA-none'), false);
    assert.equal((await readIgnoreEntries(dir)).length, 1);
  });

  it('creates the file when it does not exist and refuses to overwrite a broken one', async () => {
    const fresh = await project('ignore-fresh');
    await addIgnoreEntry(fresh, { id: 'X-1', reason: 'r', by: 'b', createdAt: 'now' });
    assert.equal((await readIgnoreEntries(fresh)).length, 1);
    const broken = await project('ignore-broken', undefined, '{ nope');
    await assert.rejects(addIgnoreEntry(broken, { id: 'X-1', reason: 'r', by: 'b', createdAt: 'now' }), ConfigError);
    await assert.rejects(addIgnoreEntry(fresh, { id: 'X-2', reason: 'r', by: 'b', createdAt: 'now', until: '2027-02-30' }), /until/);
  });

  it('parses --until dates and detects expiry', () => {
    assert.equal(parseUntil('2026-12-31')?.toISOString(), '2026-12-31T23:59:59.999Z');
    assert.equal(parseUntil('2027-02-30'), null);
    assert.equal(parseUntil('next week'), null);
    assert.ok(parseUntil('2026-10-01T12:00:00Z'));
    const now = new Date('2027-01-01T00:00:00Z');
    assert.equal(isIgnoreExpired({ id: 'a', reason: 'r', by: 'b', createdAt: '', until: '2026-12-31' }, now), true);
    assert.equal(isIgnoreExpired({ id: 'a', reason: 'r', by: 'b', createdAt: '', until: '2027-01-01' }, now), false);
    assert.equal(isIgnoreExpired({ id: 'a', reason: 'r', by: 'b', createdAt: '' }, now), false);
  });

  it('matches by OSV id or CVE alias, scoped to a package when given', () => {
    const entries: IgnoreEntry[] = [
      { id: 'CVE-2021-44906', package: 'minimist', reason: 'r', by: 'b', createdAt: '' },
      { id: 'GHSA-aaaa-bbbb-cccc', reason: 'r', by: 'b', createdAt: '', until: '2020-01-01' },
    ];
    assert.ok(findIgnore(entries, 'GHSA-xvch-5gv4-984h', 'minimist', ['CVE-2021-44906']));
    assert.equal(findIgnore(entries, 'GHSA-xvch-5gv4-984h', 'other', ['CVE-2021-44906']), null);
    assert.equal(findIgnore(entries, 'GHSA-aaaa-bbbb-cccc', 'x')?.expired, true);
  });

  it('warns about expired entries when loading the config', async () => {
    const dir = await project('expired', { ignore: [{ id: 'GHSA-old', reason: 'r', until: '2020-01-01' }] });
    const c = await loadConfig({ ...base, dir, homeDir: home });
    assert.ok(c.warnings.some((w) => w.includes('GHSA-old') && w.includes('expired')));
    assert.equal(c.ignore[0]?.by, 'unknown');
  });
});

describe('--fail-on', () => {
  it('ranks risks', () => {
    assert.equal(riskAtOrAbove('Critical', 'high'), true);
    assert.equal(riskAtOrAbove('High', 'high'), true);
    assert.equal(riskAtOrAbove('Medium', 'high'), false);
    assert.equal(riskAtOrAbove('Noise', 'noise'), true);
    assert.equal(riskAtOrAbove('Critical', 'never'), false);
    assert.equal(worstRisk(['Low', 'High', 'Medium']), 'High');
    assert.equal(worstRisk([]), null);
  });

  it('computes the findings exit code, ignoring active accepted risks', () => {
    const verdicts = [
      { vulnId: 'GHSA-1', package: 'a', risk: 'High' as const },
      { vulnId: 'GHSA-2', package: 'b', risk: 'Low' as const },
    ];
    assert.equal(findingsExitCode(verdicts, { failOn: 'high', ignore: [] }), 1);
    assert.equal(findingsExitCode(verdicts, { failOn: 'critical', ignore: [] }), 0);
    const accepted: IgnoreEntry[] = [{ id: 'CVE-1', reason: 'r', by: 'b', createdAt: '' }];
    assert.equal(findingsExitCode(verdicts, { failOn: 'high', ignore: accepted }, (id) => (id === 'GHSA-1' ? ['CVE-1'] : [])), 0);
    const expired: IgnoreEntry[] = [{ id: 'GHSA-1', reason: 'r', by: 'b', createdAt: '', until: '2020-01-01' }];
    assert.equal(findingsExitCode(verdicts, { failOn: 'high', ignore: expired }), 1);
  });

  it('resolves the auto search backend', () => {
    assert.equal(effectiveSearchBackend({ search: 'auto', ollamaApiKey: 'k', braveApiKey: null, offline: false }), 'ollama');
    assert.equal(effectiveSearchBackend({ search: 'auto', ollamaApiKey: null, braveApiKey: null, offline: false }), 'docs');
    assert.equal(effectiveSearchBackend({ search: 'ollama', ollamaApiKey: 'k', braveApiKey: null, offline: true }), 'off');
  });
});
