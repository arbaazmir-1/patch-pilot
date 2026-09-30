import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { configGet, configSet, configUnset, maskSecret, resolveConfigKey, type ConfigCommandOptions } from '../../src/configCommand.ts';
import { ConfigError, EXIT } from '../../src/util/errors.ts';
import { captureUi } from '../investigation/helpers.ts';

const BIN = fileURLToPath(new URL('../../bin/patch-pilot.ts', import.meta.url));
const POSIX = process.platform !== 'win32';
const SECRET = 'sk-test-0123456789abcdef';

let home: string;
let cwd: string;
beforeEach(async () => {
  home = await mkdtemp(path.join(os.tmpdir(), 'pp-config-home-'));
  cwd = await mkdtemp(path.join(os.tmpdir(), 'pp-config-cwd-'));
});
afterEach(async () => {
  await rm(home, { recursive: true, force: true });
  await rm(cwd, { recursive: true, force: true });
});

const dirPath = (): string => path.join(home, '.patch-pilot');
const filePath = (): string => path.join(home, '.patch-pilot', 'config.json');
const modeOf = async (p: string): Promise<number> => (await stat(p)).mode & 0o777;
const readConfig = async (): Promise<Record<string, unknown>> => JSON.parse(await readFile(filePath(), 'utf8')) as Record<string, unknown>;
const opts = (extra: ConfigCommandOptions = {}): ConfigCommandOptions => ({ homeDir: home, env: {}, cwd, ...extra });

describe('config set', () => {
  it('writes ~/.patch-pilot/config.json with mode 0600 in a 0700 directory and parses values', async () => {
    const { ui, out } = captureUi();
    await configSet('model', 'qwen3:8b', ui, opts());
    await configSet('num-ctx', '8192', ui, opts());
    await configSet('fail-on', 'HIGH', ui, opts());
    await configSet('ollama-host', 'localhost:11500', ui, opts());
    assert.deepEqual(await readConfig(), { model: 'qwen3:8b', numCtx: 8192, failOn: 'high', ollamaHost: 'http://localhost:11500' });
    if (POSIX) {
      assert.equal(await modeOf(filePath()), 0o600);
      assert.equal(await modeOf(dirPath()), 0o700);
    }
    assert.match(out(), /\+ Set model {2}qwen3:8b - ~\/\.patch-pilot\/config\.json/);
    assert.match(out(), /\+ Set num-ctx {2}8192/);
  });

  it('masks secrets in its output and keeps the other keys', async () => {
    const { ui, out, err } = captureUi();
    await configSet('model', 'mistral:7b', ui, opts());
    await configSet('ollama-api-key', SECRET, ui, opts());
    assert.deepEqual(await readConfig(), { model: 'mistral:7b', ollamaApiKey: SECRET });
    assert.match(out(), /Set ollama-api-key {2}\*\*\*\*cdef/);
    assert.ok(!out().includes(SECRET) && !err().includes(SECRET));
  });

  it('tightens an existing file and directory that are too open', { skip: !POSIX }, async () => {
    await mkdir(dirPath(), { recursive: true });
    await chmod(dirPath(), 0o755);
    await writeFile(filePath(), JSON.stringify({ model: 'x', futureKey: true }), { mode: 0o644 });
    await chmod(filePath(), 0o644);
    const { ui } = captureUi();
    await configSet('search', 'docs', ui, opts());
    assert.equal(await modeOf(filePath()), 0o600);
    assert.equal(await modeOf(dirPath()), 0o700);
    assert.deepEqual(await readConfig(), { model: 'x', futureKey: true, search: 'docs' });
  });

  it('asks without echo when the value is omitted on a terminal', async () => {
    const { ui } = captureUi({ interactive: true });
    const asked: { message: string; secret: boolean; empty: true | string; spaced: true | string }[] = [];
    await configSet('brave-search-api-key', undefined, ui, {
      ...opts(),
      promptHidden: async (message, validate, secret) => {
        asked.push({ message, secret, empty: validate(''), spaced: validate('has a space') });
        return 'BSA-prompted-value-9876';
      },
    });
    assert.equal(asked.length, 1);
    assert.match(asked[0]?.message ?? '', /^brave-search-api-key - Brave Search key \(optional backend\):$/);
    assert.equal(asked[0]?.secret, true);
    assert.match(String(asked[0]?.empty), /needs a non-empty value/);
    assert.match(String(asked[0]?.spaced), /spaces or control characters/);
    assert.ok(!String(asked[0]?.spaced).includes('has a space'), 'the rejected value is not quoted');
    assert.deepEqual(await readConfig(), { braveApiKey: 'BSA-prompted-value-9876' });
  });

  it('refuses a missing value without a terminal (and with --json)', async () => {
    const { ui } = captureUi();
    await assert.rejects(configSet('ollama-api-key', undefined, ui, opts({ interactive: false })), (e: unknown) => {
      assert.ok(e instanceof ConfigError);
      assert.equal(e.exitCode, EXIT.USAGE);
      assert.match(e.message, /needs a value when it cannot ask for one/);
      assert.match(e.hint ?? '', /without echo, or set OLLAMA_API_KEY/);
      return true;
    });
    const json = captureUi({ json: true, interactive: true });
    await assert.rejects(configSet('model', undefined, json.ui, opts()), ConfigError);
    await assert.rejects(stat(filePath()), { code: 'ENOENT' });
  });

  it('validates values and never quotes a rejected secret', async () => {
    const { ui } = captureUi();
    await assert.rejects(configSet('num-ctx', 'lots', ui, opts()), /Invalid num-ctx: lots \(expected an integer from 2048 to 262144\)/);
    await assert.rejects(configSet('search', 'google', ui, opts()), /Invalid search: google \(expected one of auto, ollama, docs, brave, off\)/);
    await assert.rejects(configSet('model', '  ', ui, opts()), /must be a non-empty string/);
    await assert.rejects(configSet('ollama-host', 'ftp://x', ui, opts()), /only http and https/);
    await assert.rejects(configSet('ollama-api-key', 'sk-secret value', ui, opts()), (e: unknown) => {
      assert.ok(e instanceof ConfigError);
      assert.ok(!e.message.includes('secret'), e.message);
      return true;
    });
    await assert.rejects(stat(filePath()), { code: 'ENOENT' });
  });

  it('refuses to overwrite invalid JSON and does not quote the file', async () => {
    await mkdir(dirPath(), { recursive: true });
    const broken = '{"ollamaApiKey": sk-supersecret-value-123';
    await writeFile(filePath(), broken);
    const { ui } = captureUi();
    await assert.rejects(configSet('model', 'mistral:7b', ui, opts()), (e: unknown) => {
      assert.ok(e instanceof ConfigError);
      assert.match(e.message, /~\/\.patch-pilot\/config\.json is not valid JSON/);
      assert.ok(!e.message.includes('supersecret') && !(e.hint ?? '').includes('supersecret'), e.message);
      return true;
    });
    assert.equal(await readFile(filePath(), 'utf8'), broken);
    await assert.rejects(configGet('model', ui, opts()), /not valid JSON/);
  });

  it('can repair a file that has an invalid value', async () => {
    await mkdir(dirPath(), { recursive: true });
    await writeFile(filePath(), JSON.stringify({ numCtx: 'lots', maxSteps: 99, extra: 1 }));
    const { ui, err } = captureUi();
    await configSet('num-ctx', '8192', ui, opts());
    assert.deepEqual(await readConfig(), { numCtx: 8192, maxSteps: 99, extra: 1 });
    assert.match(err(), /Invalid maxSteps: 99/, 'the remaining problem is reported');
    await configUnset('max-steps', ui, opts());
    assert.deepEqual(await readConfig(), { numCtx: 8192, extra: 1 });
  });

  it('warns when the environment or the project file overrides the setting', async () => {
    await writeFile(path.join(cwd, 'patch-pilot.config.json'), JSON.stringify({ model: 'llama3.1' }));
    const { ui, err } = captureUi();
    await configSet('model', 'qwen3:8b', ui, opts({ env: { PATCHPILOT_MODEL: 'mistral:latest' } }));
    assert.match(err(), /PATCHPILOT_MODEL is set in the environment and takes precedence/);
    assert.match(err(), /patch-pilot\.config\.json in this directory sets model \(llama3\.1\)/);
    const quiet = captureUi();
    await configSet('ollama-api-key', SECRET, quiet.ui, opts({ env: { OLLAMA_API_KEY: 'sk-from-env-000000000000' } }));
    assert.match(quiet.err(), /OLLAMA_API_KEY is set in the environment/);
    assert.ok(!quiet.err().includes('sk-from-env'));
  });

  it('prints machine output with --json', async () => {
    const { ui, out } = captureUi({ json: true });
    await configSet('ollama-api-key', SECRET, ui, opts());
    assert.deepEqual(JSON.parse(out()), { key: 'ollama-api-key', field: 'ollamaApiKey', value: '****cdef', secret: true, file: filePath() });
  });
});

describe('config get', () => {
  it('prints the value and where it comes from', async () => {
    const set = captureUi();
    await configSet('model', 'qwen3:8b', set.ui, opts());
    const { ui, out } = captureUi();
    await configGet('model', ui, opts());
    assert.equal(out(), 'model   qwen3:8b\nsource  ~/.patch-pilot/config.json\n');
  });

  it('reports defaults, unset keys, the environment and the project file', async () => {
    const d = captureUi();
    await configGet('model', d.ui, opts());
    assert.equal(d.out(), 'model   qwen3:8b\nsource  default\n');
    const unset = captureUi();
    await configGet('ollama-api-key', unset.ui, opts());
    assert.match(unset.out(), /^ollama-api-key {2}not set \(set it with: patch-pilot config set ollama-api-key, or export OLLAMA_API_KEY\)\n$/);
    const codemod = captureUi();
    await configGet('codemod-model', codemod.ui, opts());
    assert.match(codemod.out(), /not set \(code edits use the main model\)/);

    const set = captureUi();
    await configSet('model', 'qwen3:8b', set.ui, opts());
    const env = captureUi();
    await configGet('model', env.ui, opts({ env: { PATCHPILOT_MODEL: 'mistral:latest' } }));
    assert.equal(env.out(), 'model      mistral:latest\nsource     environment (PATCHPILOT_MODEL)\noverrides  qwen3:8b in ~/.patch-pilot/config.json\n');

    await writeFile(path.join(cwd, 'patch-pilot.config.json'), JSON.stringify({ model: 'llama3.1', numCtx: 8192 }));
    const project = captureUi();
    await configGet('model', project.ui, opts());
    assert.match(project.out(), /^model {6}llama3\.1\nsource {5}patch-pilot\.config\.json in this directory\noverrides  qwen3:8b/);

    const gh = captureUi();
    await configGet('github-token', gh.ui, opts({ env: { GH_TOKEN: 'ghp_abcdefghijklmnop1234' } }));
    assert.match(gh.out(), /github-token {2}\*\*\*\*1234\nsource {8}environment \(GH_TOKEN\)/);
  });

  it('masks secrets unless --reveal, in text and JSON', async () => {
    const set = captureUi();
    await configSet('ollama-api-key', SECRET, set.ui, opts());
    const masked = captureUi();
    await configGet('ollama-api-key', masked.ui, opts());
    assert.match(masked.out(), /ollama-api-key {2}\*\*\*\*cdef/);
    assert.ok(!masked.out().includes(SECRET));
    const revealed = captureUi();
    await configGet('ollama-api-key', revealed.ui, opts({ reveal: true }));
    assert.match(revealed.out(), new RegExp(`ollama-api-key {2}${SECRET}`));
    const json = captureUi({ json: true });
    await configGet('ollamaApiKey', json.ui, opts());
    assert.deepEqual(JSON.parse(json.out()), {
      key: 'ollama-api-key',
      field: 'ollamaApiKey',
      value: '****cdef',
      source: 'user',
      origin: filePath(),
      secret: true,
      masked: true,
      userValue: '****cdef',
    });
    const jsonReveal = captureUi({ json: true });
    await configGet('ollama-api-key', jsonReveal.ui, opts({ reveal: true }));
    assert.equal((JSON.parse(jsonReveal.out()) as { value: string }).value, SECRET);
  });

  it('warns about an invalid stored value without quoting a secret', async () => {
    await mkdir(dirPath(), { recursive: true });
    await writeFile(filePath(), JSON.stringify({ ollamaApiKey: 'sk-with spaces-0000000000', numCtx: 'lots' }));
    const secret = captureUi();
    await configGet('ollama-api-key', secret.ui, opts());
    assert.match(secret.err(), /The value in ~\/\.patch-pilot\/config\.json is invalid: ollama-api-key must not contain spaces/);
    assert.ok(!secret.err().includes('with spaces') && !secret.out().includes('with spaces'));
    const num = captureUi();
    await configGet('num-ctx', num.ui, opts());
    assert.match(num.err(), /Invalid num-ctx: lots/);
  });
});

describe('config unset', () => {
  it('removes a key, keeps the mode, and says so when nothing was set', async () => {
    const set = captureUi();
    await configSet('model', 'qwen3:8b', set.ui, opts());
    await configSet('search', 'docs', set.ui, opts());
    const { ui, out } = captureUi();
    await configUnset('model', ui, opts());
    assert.deepEqual(await readConfig(), { search: 'docs' });
    if (POSIX) assert.equal(await modeOf(filePath()), 0o600);
    assert.match(out(), /\+ Removed model {2}from ~\/\.patch-pilot\/config\.json/);
    const again = captureUi();
    await configUnset('model', again.ui, opts());
    assert.match(again.out(), /model was not set/);
    const env = captureUi();
    await configUnset('github-token', env.ui, opts({ env: { GITHUB_TOKEN: 'ghp_x' } }));
    assert.match(env.err(), /GITHUB_TOKEN is still set in the environment/);
  });

  it('does not create the file when there is nothing to remove', async () => {
    const { ui } = captureUi();
    await configUnset('model', ui, opts());
    await assert.rejects(stat(filePath()), { code: 'ENOENT' });
  });
});

describe('keys and masking', () => {
  it('accepts the kebab-case key, the field name and the environment variable', () => {
    assert.equal(resolveConfigKey('ollama-api-key').key, 'ollama-api-key');
    assert.equal(resolveConfigKey('OLLAMA_API_KEY').key, 'ollama-api-key');
    assert.equal(resolveConfigKey('ollamaApiKey').key, 'ollama-api-key');
    assert.equal(resolveConfigKey('braveApiKey').key, 'brave-search-api-key');
    assert.equal(resolveConfigKey('BRAVE_SEARCH_API_KEY').key, 'brave-search-api-key');
    assert.equal(resolveConfigKey('GH_TOKEN').key, 'github-token');
    assert.equal(resolveConfigKey('PATCHPILOT_MODEL').key, 'model');
    assert.equal(resolveConfigKey('numCtx').key, 'num-ctx');
    assert.equal(resolveConfigKey('Fail_On').key, 'fail-on');
  });

  it('rejects unknown keys with a suggestion, never echoing something that looks like a secret', () => {
    assert.throws(
      () => resolveConfigKey('modle'),
      (e: unknown) => e instanceof ConfigError && /Unknown setting "modle"; did you mean model\?/.test(e.message) && /Settings: ollama-api-key/.test(e.hint ?? ''),
    );
    assert.throws(
      () => resolveConfigKey('sk-abc123def456ghi789'),
      (e: unknown) => e instanceof ConfigError && !e.message.includes('abc123') && /the name is not shown/.test(e.message),
    );
  });

  it('masks as **** plus the last 4 characters, and short values completely', () => {
    assert.equal(maskSecret(SECRET), '****cdef');
    assert.equal(maskSecret('short-key'), '****');
    assert.equal(maskSecret('exactly12chr'), '****2chr');
  });
});

describe('config through the CLI', () => {
  function cli(args: string[], extraEnv: Record<string, string> = {}): Promise<{ code: number; stdout: string; stderr: string }> {
    return new Promise((resolve) => {
      const child = execFile(
        process.execPath,
        [BIN, ...args],
        {
          cwd,
          env: { ...process.env, HOME: home, USERPROFILE: home, NO_COLOR: '1', FORCE_COLOR: undefined, OLLAMA_API_KEY: '', PATCHPILOT_MODEL: '', ...extraEnv },
          timeout: 30_000,
        },
        (error, stdout, stderr) => {
          const code = error ? (typeof (error as { code?: unknown }).code === 'number' ? (error as { code: number }).code : 1) : 0;
          resolve({ code, stdout: String(stdout), stderr: String(stderr) });
        },
      );
      child.stdin?.end();
    });
  }

  it('set, get, get --json, unset and the non-TTY refusal', async () => {
    const set = await cli(['config', 'set', 'model', 'mistral:7b']);
    assert.equal(set.code, 0, set.stderr);
    assert.match(set.stdout, /Set model {2}mistral:7b/);
    if (POSIX) assert.equal(await modeOf(filePath()), 0o600);
    const get = await cli(['config', 'get', 'model']);
    assert.equal(get.code, 0, get.stderr);
    assert.equal(get.stdout, 'model   mistral:7b\nsource  ~/.patch-pilot/config.json\n');
    const json = await cli(['config', 'get', 'model', '--json']);
    assert.equal((JSON.parse(json.stdout) as { source: string }).source, 'user');
    const noValue = await cli(['config', 'set', 'ollama-api-key']);
    assert.equal(noValue.code, EXIT.USAGE);
    assert.match(noValue.stderr, /needs a value when it cannot ask for one/);
    const bogus = await cli(['config', 'get', 'bogus']);
    assert.equal(bogus.code, EXIT.USAGE);
    assert.match(bogus.stderr, /Unknown setting "bogus"/);
    const unset = await cli(['config', 'unset', 'model']);
    assert.equal(unset.code, 0, unset.stderr);
    assert.deepEqual(await readConfig(), {});
  });
});
