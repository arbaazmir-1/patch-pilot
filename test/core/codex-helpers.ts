// fake codex driven by FAKE_CODEX_SCENARIO
import { chmod, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

function script(): string {
  return `#!${process.execPath}
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
const args = process.argv.slice(2);
const scenario = process.env.FAKE_CODEX_SCENARIO || 'ok';
const logFile = process.env.FAKE_CODEX_LOG;
const record = (entry) => { if (logFile) appendFileSync(logFile, JSON.stringify(entry) + '\\n'); };
record({ args, hasKey: Boolean(process.env.CODEX_API_KEY), keyOk: process.env.CODEX_API_KEY === 'codex-secret' });
const emit = (obj) => process.stdout.write(JSON.stringify(obj) + '\\n');
const opt = (flag) => { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : undefined; };
if (args[0] === 'login' && args[1] === 'status') {
  if (scenario === 'logged-out') { process.stderr.write('Not logged in\\n'); process.exit(1); }
  process.stderr.write('Logged in using ChatGPT\\n');
  process.exit(0);
}
if (args[0] !== 'exec') { process.stderr.write('error: unexpected argument\\n'); process.exit(2); }
if (scenario === 'reject-a' && args.includes('-a')) { process.stderr.write("error: unexpected argument '-a' found\\n\\nUsage: codex exec [OPTIONS] [PROMPT]\\n"); process.exit(2); }
const prompt = args[1];
const out = opt('-o');
const schemaFile = opt('--output-schema');
const finish = (answer) => {
  if (out) writeFileSync(out, answer);
  emit({ type: 'item.completed', item: { id: 'msg_final', type: 'agent_message', text: answer } });
  emit({ type: 'turn.completed', usage: { input_tokens: 1200, cached_input_tokens: 200, output_tokens: 300, reasoning_output_tokens: 50 } });
};
emit({ type: 'thread.started', thread_id: 'thread_1' });
emit({ type: 'turn.started' });
if (scenario === 'fail') {
  emit({ type: 'turn.failed', error: { message: 'unexpected status 401 Unauthorized' } });
  process.stderr.write('Error: unexpected status 401 Unauthorized\\n');
  process.exit(1);
} else if (scenario === 'hang') {
  setTimeout(() => {}, 60000);
} else if (scenario === 'chat') {
  record({ schema: schemaFile ? JSON.parse(readFileSync(schemaFile, 'utf8')) : null, prompt });
  finish('{"edits":[]}');
} else if (scenario === 'ok' || scenario === 'reject-a') {
  emit({ type: 'item.started', item: { id: 'item_1', type: 'mcp_tool_call', server: 'patchpilot', tool: 'get_usage', arguments: { package: 'minimist' }, status: 'in_progress' } });
  emit({ type: 'item.completed', item: { id: 'item_1', type: 'mcp_tool_call', server: 'patchpilot', tool: 'get_usage', arguments: { package: 'minimist' }, result: { content: [{ type: 'text', text: '1 call to minimist\\n{}' }] }, status: 'completed' } });
  emit({ type: 'item.completed', item: { id: 'item_2', type: 'reasoning', text: 'minimist parses argv' } });
  emit({ type: 'item.completed', item: { id: 'item_3', type: 'command_execution', command: 'rg minimist', aggregated_output: 'src/cli.js', exit_code: 0, status: 'completed' } });
  finish('{"package":"minimist","submitted":[],"notes":"ok"}');
}
`;
}

export async function writeFakeCodex(dir: string): Promise<{ binDir: string; codex: string; logFile: string }> {
  const binDir = path.join(dir, 'bin');
  await mkdir(binDir, { recursive: true });
  const codex = path.join(binDir, 'codex');
  await writeFile(codex, script(), 'utf8');
  await chmod(codex, 0o755);
  await writeFile(path.join(binDir, 'package.json'), JSON.stringify({ type: 'module' }));
  return { binDir, codex, logFile: path.join(dir, 'codex-log.jsonl') };
}

export function fakeCodexEnv(binDir: string, extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  return { ...process.env, PATH: `${binDir}${path.delimiter}${process.env.PATH ?? ''}`, ...extra };
}
