import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { loadConfig, type CliFlags } from '../../src/config.ts';
import type { CodexStatus } from '../../src/llm/codex.ts';
import {
  applyProviderChoice,
  chooseProvider,
  detectProviders,
  modelStrength,
  parameterBillions,
  privacyNote,
  rankToolModels,
  renderProviderLines,
  SUBSCRIBER_NOTE,
  type PickerChoice,
  type PickerDeps,
} from '../../src/providerPicker.ts';
import { cloudProviderNotice, trustPromptText } from '../../src/trust.ts';
import type { Config } from '../../src/types.ts';
import { captureUi, tempDir } from '../investigation/helpers.ts';

let dir: string;
let cleanup: () => Promise<void>;

before(async () => {
  ({ dir, cleanup } = await tempDir('pp-picker-'));
});
after(async () => {
  await cleanup();
});

const TAGS = {
  models: [
    { name: 'mistral:7b', details: { parameter_size: '7.2B', family: 'llama' }, capabilities: ['completion', 'tools'] },
    { name: 'qwen3:8b', details: { parameter_size: '8.2B', family: 'qwen3' }, capabilities: ['completion', 'tools', 'thinking'] },
    { name: 'llama3.2:3b', details: { parameter_size: '3.2B', family: 'llama' }, capabilities: ['completion', 'tools'] },
    { name: 'nomic-embed-text:latest', details: { parameter_size: '137M', family: 'nomic-bert' }, capabilities: ['embedding'] },
  ],
};

function ollamaFetch(up: boolean): { fetch: typeof fetch; urls: string[] } {
  const urls: string[] = [];
  const fetchImpl = (async (url: string | URL | Request) => {
    urls.push(String(url));
    if (!up) throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } });
    if (String(url).endsWith('/api/version')) return new Response(JSON.stringify({ version: '0.34.4' }));
    if (String(url).endsWith('/api/tags')) return new Response(JSON.stringify(TAGS));
    return new Response('{}', { status: 404 });
  }) as typeof fetch;
  return { fetch: fetchImpl, urls };
}

const CODEX_IN: CodexStatus = { installed: true, path: '/usr/local/bin/codex', loggedIn: true, method: 'chatgpt', detail: 'Logged in using ChatGPT' };
const CODEX_OUT: CodexStatus = { installed: false, path: null, loggedIn: false, method: null, detail: 'not installed' };

async function config(name: string, options: { flags?: CliFlags; env?: NodeJS.ProcessEnv; tty?: boolean; user?: Record<string, unknown> } = {}): Promise<Config> {
  const root = path.join(dir, name);
  await mkdir(root, { recursive: true });
  const home = path.join(root, 'home');
  if (options.user) {
    await mkdir(path.join(home, '.patch-pilot'), { recursive: true });
    await writeFile(path.join(home, '.patch-pilot', 'config.json'), JSON.stringify(options.user), { mode: 0o600 });
  }
  return loadConfig({ dir: root, homeDir: home, env: options.env ?? {}, flags: options.flags ?? {}, stdinIsTTY: options.tty ?? false, stdoutIsTTY: options.tty ?? false });
}

interface Recorder {
  deps: PickerDeps;
  prompts: { message: string; choices: PickerChoice[]; defaultValue: string | undefined }[];
  remembered: { key: string; value: string }[][];
  urls: string[];
}

function recorder(options: { ollama: boolean; codex?: CodexStatus; answers?: string[]; remember?: boolean }): Recorder {
  const { fetch, urls } = ollamaFetch(options.ollama);
  const answers = [...(options.answers ?? [])];
  const rec: Recorder = { deps: {}, prompts: [], remembered: [], urls };
  rec.deps = {
    fetch,
    codexStatus: async () => options.codex ?? CODEX_OUT,
    select: async (message, choices, defaultValue) => {
      rec.prompts.push({ message, choices, defaultValue });
      return answers.shift() ?? defaultValue ?? choices[0]?.value ?? '';
    },
    ask: async () => options.remember ?? false,
    remember: async (values) => {
      rec.remembered.push(values);
    },
  };
  return rec;
}

describe('the local model strength hint', () => {
  it('rates qwen3 8b+ strong, 4b usable, smaller weak; other families 12b+ strong, 7b to 11b usable', () => {
    const rate = (name: string, size?: string, family?: string): string => modelStrength(name, parameterBillions(name, size), family);
    assert.equal(rate('qwen3:8b'), 'strong');
    assert.equal(rate('qwen3:30b-a3b'), 'strong');
    assert.equal(rate('qwen3:4b'), 'usable');
    assert.equal(rate('qwen3:1.7b'), 'weak');
    assert.equal(rate('qwen3:latest', '8.2B', 'qwen3'), 'strong');
    assert.equal(rate('mistral:7b'), 'usable');
    assert.equal(rate('mistral:latest', '7.2B', 'llama'), 'usable');
    assert.equal(rate('llama3.1:8b'), 'usable');
    assert.equal(rate('gemma3:12b'), 'strong');
    assert.equal(rate('gpt-oss:20b'), 'strong');
    assert.equal(rate('llama3.2:3b'), 'weak');
    assert.equal(rate('custom:latest'), 'unknown');
    assert.equal(parameterBillions('x:latest', '494M'), 0.494);
  });

  it('ranks tool-capable models strongest first, smaller first within a strength', () => {
    const models = [
      { name: 'big:70b', parameterSize: null, sizeB: 70, family: null, tools: true, strength: 'strong' as const },
      { name: 'qwen3:8b', parameterSize: null, sizeB: 8, family: 'qwen3', tools: true, strength: 'strong' as const },
      { name: 'mistral:7b', parameterSize: null, sizeB: 7, family: null, tools: true, strength: 'usable' as const },
      { name: 'embed', parameterSize: null, sizeB: 0.1, family: null, tools: false, strength: 'weak' as const },
    ];
    assert.deepEqual(
      rankToolModels(models).map((m) => m.name),
      ['qwen3:8b', 'big:70b', 'mistral:7b'],
    );
  });
});

describe('detectProviders', () => {
  it('reports Ollama models with the strength hint, the Claude key and the Codex login, each with its privacy note', async () => {
    const c = await config('detect', { env: { ANTHROPIC_API_KEY: 'sk-ant-x' } });
    const rec = recorder({ ollama: true, codex: CODEX_IN });
    const { options } = await detectProviders(c, rec.deps);
    const [ollama, claude, codex] = options;
    assert.equal(ollama?.available, true);
    assert.equal(ollama?.model, 'qwen3:8b', 'the configured model is suggested when installed');
    assert.equal(ollama?.strength, 'strong');
    assert.match(ollama?.detail ?? '', /3 tool-capable models · local, code stays on this machine/);
    assert.equal(claude?.available, true);
    assert.match(claude?.detail ?? '', /sonnet \(API key from ANTHROPIC_API_KEY\) · cloud: code snippets are sent to Anthropic/);
    assert.equal(codex?.available, true);
    assert.match(codex?.detail ?? '', /ChatGPT login\) · cloud: code snippets are sent to OpenAI/);
  });

  it('explains how to fix each unavailable provider, including the subscriber route', async () => {
    const c = await config('detect-none');
    const { options } = await detectProviders(c, recorder({ ollama: false }).deps);
    assert.deepEqual(
      options.map((o) => o.available),
      [false, false, false],
    );
    assert.match(options[0]?.detail ?? '', /not reachable at http:\/\/localhost:11434 \(connection refused\)/);
    assert.ok(options[0]?.fix?.some((f) => f.includes('ollama serve')));
    assert.ok(options[1]?.fix?.some((f) => f.includes('patch-pilot config set anthropic-api-key')));
    assert.ok(options[1]?.fix?.includes(SUBSCRIBER_NOTE));
    assert.ok(options[2]?.fix?.some((f) => f.includes('npm install -g @openai/codex')));
    const { ui, out } = captureUi();
    const block = renderProviderLines(options, ui, 'ollama');
    assert.match(block, /Providers/);
    assert.match(block, /x Ollama \* +not reachable/);
    assert.equal(block.split('mcp --print-config').length, 2, 'the subscriber note appears once');
    assert.match(block, /Claude API +no Anthropic API key/);
    assert.match(block, /patch-pilot mcp --print-config/);
    assert.equal(out(), '');
  });
});

describe('chooseProvider', () => {
  it('uses --provider without detecting or asking', async () => {
    const c = await config('flag', { flags: { provider: 'claude' }, env: { ANTHROPIC_API_KEY: 'k' }, tty: true });
    const rec = recorder({ ollama: true, codex: CODEX_IN });
    const { ui } = captureUi({ interactive: true });
    const choice = await chooseProvider(c, ui, rec.deps);
    assert.deepEqual({ provider: choice.provider, model: choice.model, selection: choice.selection, cloud: choice.cloud }, { provider: 'claude', model: 'claude-sonnet-5', selection: 'flag', cloud: true });
    assert.equal(rec.urls.length, 0, 'no detection');
    assert.equal(rec.prompts.length, 0);
  });

  it('uses a provider saved in the user config, with the saved model', async () => {
    const c = await config('saved', { user: { provider: 'claude', model: 'haiku' }, env: { ANTHROPIC_API_KEY: 'k' }, tty: true });
    const rec = recorder({ ollama: true });
    const { ui } = captureUi({ interactive: true });
    const choice = await chooseProvider(c, ui, rec.deps);
    assert.equal(choice.selection, 'config');
    assert.equal(choice.provider, 'claude');
    assert.equal(choice.model, 'claude-haiku-4-5');
    assert.equal(rec.prompts.length, 0);
    applyProviderChoice(c, choice);
    assert.equal(c.model, 'claude-haiku-4-5');
  });

  it('uses Ollama without a terminal, even when a cloud provider is configured', async () => {
    const c = await config('nontty', { env: { ANTHROPIC_API_KEY: 'k' } });
    const rec = recorder({ ollama: true, codex: CODEX_IN });
    const { ui } = captureUi();
    const choice = await chooseProvider(c, ui, rec.deps);
    assert.equal(choice.provider, 'ollama');
    assert.equal(choice.selection, 'default');
    assert.equal(rec.prompts.length, 0);
    assert.deepEqual(choice.notes, []);
  });

  it('without a terminal and without Ollama: Ollama (the preflight explains) plus a note naming the ready cloud provider', async () => {
    const c = await config('nontty-down', { env: { ANTHROPIC_API_KEY: 'k' } });
    const choice = await chooseProvider(c, captureUi().ui, recorder({ ollama: false }).deps);
    assert.equal(choice.provider, 'ollama');
    assert.match(choice.notes[0] ?? '', /Claude API is ready: pass --provider claude/);
    assert.match(choice.notes[0] ?? '', /sent to Anthropic/);
    const none = await chooseProvider(await config('nontty-none'), captureUi().ui, recorder({ ollama: false }).deps);
    assert.match(none.notes[0] ?? '', /No model provider is ready/);
    assert.match(none.notes[0] ?? '', /mcp --print-config/);
  });

  it('on a terminal with only Ollama available: no picker', async () => {
    const c = await config('tty-one', { tty: true });
    const rec = recorder({ ollama: true });
    const choice = await chooseProvider(c, captureUi({ interactive: true }).ui, rec.deps);
    assert.equal(choice.provider, 'ollama');
    assert.equal(choice.selection, 'default');
    assert.equal(rec.prompts.length, 0);
  });

  it('on a terminal with several providers: the picker with privacy notes, the Claude model, and remember', async () => {
    const c = await config('tty-many', { env: { ANTHROPIC_API_KEY: 'k' }, tty: true });
    const rec = recorder({ ollama: true, codex: CODEX_OUT, answers: ['claude', 'opus'], remember: true });
    const choice = await chooseProvider(c, captureUi({ interactive: true }).ui, rec.deps);
    assert.equal(choice.provider, 'claude');
    assert.equal(choice.model, 'claude-opus-5-5');
    assert.equal(choice.selection, 'picker');
    assert.equal(choice.remembered, true);
    const [providers, models] = rec.prompts;
    assert.deepEqual(
      providers?.choices.map((ch) => ch.value),
      ['ollama', 'claude', 'codex'],
    );
    assert.equal(providers?.defaultValue, 'ollama', 'local first');
    assert.equal(providers?.choices[0]?.description, 'local, code stays on this machine');
    assert.equal(providers?.choices[1]?.description, 'cloud: code snippets are sent to Anthropic');
    assert.equal(providers?.choices[2]?.disabled, 'Codex CLI not installed');
    assert.deepEqual(
      models?.choices.map((ch) => ch.value),
      ['sonnet', 'opus', 'haiku'],
    );
    assert.match(models?.choices[1]?.description ?? '', /\$4 in \/ \$20 out per million tokens/);
    assert.deepEqual(rec.remembered, [[{ key: 'provider', value: 'claude' }, { key: 'model', value: 'opus' }]]);
    applyProviderChoice(c, choice);
    assert.equal(c.provider, 'claude');
    assert.equal(c.providerSelection, 'picker');
    assert.equal(c.model, 'claude-opus-5-5');
  });

  it('asks which local model when Ollama is picked from several installed ones', async () => {
    const c = await config('tty-ollama', { env: { ANTHROPIC_API_KEY: 'k' }, tty: true });
    const rec = recorder({ ollama: true, answers: ['ollama', 'qwen3:8b'] });
    const choice = await chooseProvider(c, captureUi({ interactive: true }).ui, rec.deps);
    assert.deepEqual({ provider: choice.provider, model: choice.model, remembered: choice.remembered }, { provider: 'ollama', model: 'qwen3:8b', remembered: false });
    const models = rec.prompts[1];
    assert.deepEqual(
      models?.choices.map((ch) => ch.value),
      ['qwen3:8b', 'mistral:7b', 'llama3.2:3b'],
    );
    assert.equal(models?.defaultValue, 'qwen3:8b', 'the configured model is the default');
    assert.match(models?.choices[2]?.description ?? '', /weak/);
    assert.equal(rec.remembered.length, 0);
  });

  it('on a terminal with only a cloud provider: the picker still asks (code never leaves silently)', async () => {
    const c = await config('tty-cloud', { env: { ANTHROPIC_API_KEY: 'k' }, tty: true });
    const rec = recorder({ ollama: false, answers: ['claude', 'sonnet'] });
    const choice = await chooseProvider(c, captureUi({ interactive: true }).ui, rec.deps);
    assert.equal(rec.prompts.length, 2);
    assert.equal(rec.prompts[0]?.choices[0]?.disabled !== false, true, 'Ollama is shown as unavailable');
    assert.equal(choice.provider, 'claude');
    assert.equal(choice.cloud, true);
  });

  it('remembers through patch-pilot config set by default', async () => {
    const c = await config('remember', { env: { ANTHROPIC_API_KEY: 'k' }, tty: true });
    const rec = recorder({ ollama: true, answers: ['claude', 'haiku'], remember: true });
    delete rec.deps.remember;
    const home = path.join(dir, 'remember-home');
    const { ui } = captureUi({ interactive: true });
    const { configSet } = await import('../../src/configCommand.ts');
    rec.deps.remember = async (values) => {
      for (const v of values) await configSet(v.key, v.value, ui, { homeDir: home, env: {}, cwd: dir, interactive: false });
    };
    await chooseProvider(c, ui, rec.deps);
    const saved = JSON.parse(await readFile(path.join(home, '.patch-pilot', 'config.json'), 'utf8')) as Record<string, unknown>;
    assert.deepEqual(saved, { provider: 'claude', model: 'haiku' });
  });
});

describe('privacy notices for the cloud providers', () => {
  it('the trust prompt says plainly that snippets and file excerpts leave the machine', () => {
    const claude = trustPromptText({ dir: '/p', remote: null, ollamaHost: 'http://localhost:11434', provider: 'claude', model: 'claude-sonnet-5' });
    assert.match(claude, /send code snippets and file excerpts to Anthropic's Claude API \(api\.anthropic\.com, claude-sonnet-5\): they leave this machine/);
    assert.match(claude, /Cloud provider: code snippets and file excerpts from this project are sent to Anthropic/);
    assert.ok(!claude.includes('only to your local Ollama model'));
    const codex = trustPromptText({ dir: '/p', remote: null, ollamaHost: 'http://localhost:11434', provider: 'codex' });
    assert.match(codex, /to OpenAI through the Codex CLI \(codex exec\): they leave this machine/);
    const local = trustPromptText({ dir: '/p', remote: null, ollamaHost: 'http://localhost:11434', provider: 'ollama' });
    assert.match(local, /send code snippets only to your local Ollama model/);
    assert.ok(!local.includes('Cloud provider'));
  });

  it('the run header notice names the destination and how to stay local', () => {
    assert.match(String(cloudProviderNotice('claude', 'claude-opus-5-5')), /sent to Anthropic \(Claude API, claude-opus-5-5\)\. Use --provider ollama to keep them on this machine\./);
    assert.match(String(cloudProviderNotice('codex', 'gpt-5-codex')), /sent to OpenAI through the Codex CLI \(gpt-5-codex\)/);
    assert.equal(cloudProviderNotice('ollama'), null);
    assert.equal(cloudProviderNotice('mock'), null);
    assert.equal(privacyNote('ollama', 'http://gpu-box:11434'), 'code snippets are sent to your Ollama server at http://gpu-box:11434');
  });
});
