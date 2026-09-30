import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { EDITS_SCHEMA } from '../../src/remediation/codemod.ts';
import {
  rejectedApprovalFlag,
  buildCodexExecArgs,
  CodexChatProvider,
  CodexJsonlParser,
  codexModelLabel,
  codexStatus,
  describeCodexFailure,
  displayCodexCommand,
  mcpResultText,
  parseCodexEvent,
  readCodexConfigModel,
  runCodexExec,
  strictSchema,
  transcriptPrompt,
  type CodexEvent,
} from '../../src/llm/codex.ts';
import { LlmError } from '../../src/llm/provider.ts';
import { EnvironmentError } from '../../src/util/errors.ts';
import { tempDir } from '../investigation/helpers.ts';
import { fakeCodexEnv, writeFakeCodex } from './codex-helpers.ts';

let dir: string;
let cleanup: () => Promise<void>;
let binDir: string;
let logFile: string;

before(async () => {
  ({ dir, cleanup } = await tempDir('pp-codex-'));
  ({ binDir, logFile } = await writeFakeCodex(dir));
});
after(async () => {
  await cleanup();
});

async function invocations(): Promise<{ args: string[]; hasKey: boolean; keyOk: boolean; schema?: unknown; prompt?: string }[]> {
  const text = await readFile(logFile, 'utf8').catch(() => '');
  return text
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l) as { args: string[]; hasKey: boolean; keyOk: boolean });
}

describe('codex exec arguments', () => {
  it('builds the documented command line with TOML-quoted MCP overrides', () => {
    const args = buildCodexExecArgs({
      prompt: 'Investigate minimist',
      projectRoot: '/work/app',
      model: 'gpt-5-codex',
      outputSchemaFile: '/tmp/schema.json',
      outputFile: '/tmp/out.json',
      mcpServer: { name: 'patchpilot', command: '/usr/bin/node', args: ['/opt/pp "x"/bin.js', 'mcp', '--project', '/work/app'] },
    });
    assert.deepEqual(args, [
      'exec',
      'Investigate minimist',
      '--json',
      '--sandbox',
      'read-only',
      '-a',
      'never',
      '-C',
      '/work/app',
      '--skip-git-repo-check',
      '--output-schema',
      '/tmp/schema.json',
      '-o',
      '/tmp/out.json',
      '-m',
      'gpt-5-codex',
      '-c',
      'mcp_servers.patchpilot.command="/usr/bin/node"',
      '-c',
      'mcp_servers.patchpilot.args=["/opt/pp \\"x\\"/bin.js","mcp","--project","/work/app"]',
      '-c',
      'mcp_servers.patchpilot.startup_timeout_sec=30',
      '-c',
      'mcp_servers.patchpilot.tool_timeout_sec=180',
    ]);
    const configForm = buildCodexExecArgs({ prompt: 'p', projectRoot: '/w', approval: 'config' });
    assert.deepEqual(configForm.slice(4, 7), ['read-only', '-c', 'approval_policy="never"']);
    assert.ok(!configForm.includes('-a'));
    const minimal = buildCodexExecArgs({ prompt: 'p', projectRoot: '/w' });
    assert.ok(!minimal.includes('-m'), 'without a model Codex uses its own configuration');
    assert.deepEqual(displayCodexCommand('codex', minimal).slice(0, 3), ['codex', 'exec', '<prompt>']);
  });
});

describe('codex JSONL events', () => {
  it('parses every event type, across chunk boundaries, and ignores noise', () => {
    const lines = [
      '{"type":"thread.started","thread_id":"t1"}',
      '{"type":"turn.started"}',
      '{"type":"item.started","item":{"id":"i1","type":"mcp_tool_call","server":"patchpilot","tool":"get_usage","arguments":{"package":"lodash"},"status":"in_progress"}}',
      '{"type":"item.completed","item":{"id":"i1","type":"mcp_tool_call","server":"patchpilot","tool":"get_usage","arguments":{"package":"lodash"},"result":{"content":[{"type":"text","text":"3 calls\\nx"}]},"status":"completed"}}',
      '{"type":"item.completed","item":{"id":"i2","type":"command_execution","command":"ls","aggregated_output":"a","exit_code":0}}',
      'not json',
      '{"type":"item.completed","item":{"id":"i3","type":"agent_message","text":"done"}}',
      '{"type":"turn.completed","usage":{"input_tokens":10,"cached_input_tokens":2,"output_tokens":3,"reasoning_output_tokens":1}}',
      '{"type":"turn.failed","error":{"message":"boom"}}',
      '{"type":"error","message":"stream error"}',
      '{"type":"something.new","x":1}',
    ];
    const text = `${lines.join('\n')}\n`;
    const parser = new CodexJsonlParser();
    const events: CodexEvent[] = [];
    for (let i = 0; i < text.length; i += 17) events.push(...parser.push(text.slice(i, i + 17)));
    events.push(...parser.end());
    assert.deepEqual(
      events.map((e) => e.type),
      ['thread.started', 'turn.started', 'item.started', 'item.completed', 'item.completed', 'item.completed', 'turn.completed', 'turn.failed', 'error', 'other'],
    );
    const call = events[3];
    assert.ok(call && call.type === 'item.completed');
    assert.equal(call.item.tool, 'get_usage');
    assert.equal(mcpResultText(call.item.result), '3 calls\nx');
    const cmd = events[4];
    assert.ok(cmd && cmd.type === 'item.completed');
    assert.equal(cmd.item.command, 'ls');
    assert.equal(cmd.item.exitCode, 0);
    const usage = events[6];
    assert.ok(usage && usage.type === 'turn.completed');
    assert.deepEqual(usage.usage, { inputTokens: 10, cachedInputTokens: 2, outputTokens: 3, reasoningOutputTokens: 1 });
    const failed = events[7];
    assert.ok(failed && failed.type === 'turn.failed');
    assert.equal(failed.message, 'boom');
    assert.equal(parseCodexEvent(''), null);
  });
});

describe('runCodexExec with a fake codex on PATH', () => {
  it('streams events, collects usage and the final message, passes CODEX_API_KEY only through the environment', async () => {
    const seen: string[] = [];
    const result = await runCodexExec({
      prompt: 'Investigate',
      projectRoot: dir,
      outputFile: path.join(dir, 'answer.txt'),
      apiKey: 'codex-secret',
      timeoutMs: 20_000,
      env: fakeCodexEnv(binDir, { FAKE_CODEX_SCENARIO: 'ok', FAKE_CODEX_LOG: logFile }),
      onEvent: (e) => seen.push(e.type === 'item.completed' || e.type === 'item.started' ? `${e.type}:${e.item.type}` : e.type),
    });
    assert.equal(result.exitCode, 0);
    assert.equal(result.timedOut, false);
    assert.equal(result.toolCalls, 1);
    assert.deepEqual(result.usage, { inputTokens: 1200, cachedInputTokens: 200, outputTokens: 300, reasoningOutputTokens: 50 });
    assert.equal(result.finalMessage, '{"package":"minimist","submitted":[],"notes":"ok"}');
    assert.deepEqual(seen.slice(0, 4), ['thread.started', 'turn.started', 'item.started:mcp_tool_call', 'item.completed:mcp_tool_call']);
    assert.ok(seen.includes('turn.completed'));
    assert.equal(await readFile(path.join(dir, 'answer.txt'), 'utf8'), '{"package":"minimist","submitted":[],"notes":"ok"}');
    const last = (await invocations()).at(-1);
    assert.equal(last?.keyOk, true);
    assert.ok(!last?.args.includes('codex-secret'), 'the key never appears on the command line');
    assert.equal(result.command[2], '<prompt>');
  });

  it('reports a failed turn with the exit code and a login hint for 401', async () => {
    const result = await runCodexExec({ prompt: 'x', projectRoot: dir, timeoutMs: 20_000, env: fakeCodexEnv(binDir, { FAKE_CODEX_SCENARIO: 'fail' }) });
    assert.equal(result.exitCode, 1);
    assert.equal(result.lastError, 'unexpected status 401 Unauthorized');
    const failure = describeCodexFailure(result, 20_000);
    assert.equal(failure.auth, true);
    assert.match(failure.message, /exited with code 1: unexpected status 401 Unauthorized/);
    assert.match(failure.hint, /codex login/);
    assert.match(failure.hint, /CODEX_API_KEY/);
  });

  it('kills codex after the timeout', async () => {
    const result = await runCodexExec({ prompt: 'x', projectRoot: dir, timeoutMs: 700, env: fakeCodexEnv(binDir, { FAKE_CODEX_SCENARIO: 'hang' }) });
    assert.equal(result.timedOut, true);
    assert.notEqual(result.exitCode, 0);
    assert.match(describeCodexFailure(result, 700).message, /did not finish within/);
  });

  it('explains how to install codex when it is missing', async () => {
    await assert.rejects(
      () => runCodexExec({ prompt: 'x', projectRoot: dir, timeoutMs: 5_000, codexCommand: path.join(dir, 'no-such-codex') }),
      (err: unknown) => err instanceof EnvironmentError && /npm install -g @openai\/codex/.test(String(err.hint)) && /codex login/.test(String(err.hint)) && /developers\.openai\.com\/codex/.test(String(err.hint)),
    );
  });
});

describe('codex login status and model', () => {
  it('reads codex login status through the fake CLI and falls back to CODEX_API_KEY', async () => {
    const ok = await codexStatus({ env: fakeCodexEnv(binDir, { FAKE_CODEX_SCENARIO: 'ok' }) });
    assert.deepEqual({ installed: ok.installed, loggedIn: ok.loggedIn, method: ok.method, detail: ok.detail }, { installed: true, loggedIn: true, method: 'chatgpt', detail: 'Logged in using ChatGPT' });
    const out = await codexStatus({ env: fakeCodexEnv(binDir, { FAKE_CODEX_SCENARIO: 'logged-out' }) });
    assert.equal(out.loggedIn, false);
    const key = await codexStatus({ env: fakeCodexEnv(binDir, { FAKE_CODEX_SCENARIO: 'logged-out' }), apiKey: 'k' });
    assert.equal(key.loggedIn, true);
    assert.equal(key.method, 'api-key');
    const missing = await codexStatus({ which: async () => null });
    assert.equal(missing.installed, false);
  });

  it('labels verdicts with --model, else the model in CODEX_HOME/config.toml, else codex-default', async () => {
    const home = path.join(dir, 'codex-home');
    await mkdir(home, { recursive: true });
    assert.equal(readCodexConfigModel({ CODEX_HOME: home }), null);
    assert.equal(codexModelLabel(null, { CODEX_HOME: home }), 'codex-default');
    await writeFile(path.join(home, 'config.toml'), 'model = "gpt-5.5-codex"\n[profiles.x]\nmodel = "other"\n');
    assert.equal(codexModelLabel(null, { CODEX_HOME: home }), 'gpt-5.5-codex');
    assert.equal(codexModelLabel('o4-mini', { CODEX_HOME: home }), 'o4-mini');
  });
});

describe('CodexChatProvider (Phase 3 turns)', () => {
  it('runs one codex exec per turn with a strict output schema and returns the final answer', async () => {
    const p = new CodexChatProvider({
      projectRoot: dir,
      model: null,
      label: 'codex-default',
      apiKey: null,
      tmpDir: path.join(dir, 'tmp'),
      timeoutMs: 20_000,
      env: fakeCodexEnv(binDir, { FAKE_CODEX_SCENARIO: 'chat', FAKE_CODEX_LOG: logFile }),
    });
    assert.equal(p.name, 'codex');
    const res = await p.chat({
      messages: [
        { role: 'system', content: 'You edit code.' },
        { role: 'user', content: 'Change src/render.js' },
      ],
      format: EDITS_SCHEMA,
      purpose: 'codemod',
    });
    assert.equal(res.message.content, '{"edits":[]}');
    assert.equal(res.usage?.promptTokens, 1200);
    const last = (await invocations()).filter((i) => i.schema !== undefined).at(-1);
    assert.deepEqual(last?.schema, strictSchema(EDITS_SCHEMA));
    const items = (strictSchema(EDITS_SCHEMA).properties?.edits?.items ?? {}) as { additionalProperties?: unknown };
    assert.equal(items.additionalProperties, false);
    assert.match(String(last?.prompt), /## Instructions\nYou edit code\./);
    assert.match(transcriptPrompt({ messages: [{ role: 'user', content: 'q' }], format: 'json' }), /Reply with only a JSON object/);
    assert.deepEqual(p.usageSummary(), { requests: 1, inputTokens: 1200, outputTokens: 300, costUsd: null });
  });

  it('turns a failed run into an LlmError with the fix', async () => {
    const p = new CodexChatProvider({ projectRoot: dir, model: null, label: 'x', apiKey: null, tmpDir: path.join(dir, 'tmp'), timeoutMs: 20_000, env: fakeCodexEnv(binDir, { FAKE_CODEX_SCENARIO: 'fail' }) });
    await assert.rejects(() => p.chat({ messages: [{ role: 'user', content: 'q' }] }), (err: unknown) => err instanceof LlmError && err.kind === 'unreachable' && /codex login/.test(String(err.hint)));
  });
});

describe('a Codex build that does not take -a after exec', () => {
  it('is retried once with approval_policy="never" as a config override', async () => {
    const result = await runCodexExec({ prompt: 'x', projectRoot: dir, timeoutMs: 20_000, env: fakeCodexEnv(binDir, { FAKE_CODEX_SCENARIO: 'reject-a', FAKE_CODEX_LOG: logFile }) });
    assert.equal(result.exitCode, 0, result.stderr);
    const runs = (await invocations()).slice(-2);
    assert.ok(runs[0]?.args.includes('-a'));
    assert.ok(!runs[1]?.args.includes('-a'));
    assert.ok(runs[1]?.args.includes('approval_policy="never"'));
    assert.equal(rejectedApprovalFlag({ exitCode: 2, events: 0, stderr: "error: unexpected argument '-a' found" }), true);
    assert.equal(rejectedApprovalFlag({ exitCode: 1, events: 3, stderr: 'boom' }), false);
  });
});
