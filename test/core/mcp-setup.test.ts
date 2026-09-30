import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { displayCommand, isMcpTarget, mcpGuidanceText, setupCommandFor, setupMcp } from '../../src/mcp/setup.ts';
import { createUi } from '../../src/ui.ts';
import { EXIT } from '../../src/util/errors.ts';
import type { RunResult } from '../../src/util/proc.ts';

function captureUi() {
  const chunks: string[] = [];
  const stream = { isTTY: false, write: (s: string) => (chunks.push(s), true) } as unknown as NodeJS.WriteStream;
  const ui = createUi({ stdout: stream, stderr: stream, color: false, interactive: false });
  return { ui, out: () => chunks.join('') };
}

const ok = (stdout = 'Added stdio MCP server patch-pilot'): RunResult => ({ ok: true, code: 0, signal: null, stdout, stderr: '', error: null, durationMs: 5 });
const failed = (stderr: string): RunResult => ({ ok: false, code: 1, signal: null, stdout: '', stderr, error: null, durationMs: 5 });
const launcher = async () => ({ command: 'patch-pilot', args: [] });

describe('mcp setup', () => {
  it('recognises the targets', () => {
    assert.equal(isMcpTarget('claude'), true);
    assert.equal(isMcpTarget('codex'), true);
    assert.equal(isMcpTarget('gemini'), false);
    assert.equal(isMcpTarget(undefined), false);
  });

  it('builds the official registration commands', () => {
    const claude = setupCommandFor('claude', '/work/app', { command: 'patch-pilot', args: [] });
    assert.deepEqual(claude, { command: 'claude', args: ['mcp', 'add', 'patch-pilot', '--', 'patch-pilot', 'mcp', '--project', '/work/app'] });
    const codex = setupCommandFor('codex', '/work/my app', { command: '/usr/bin/node', args: ['/x/bin/patch-pilot.js'] });
    assert.equal(displayCommand(codex), "codex mcp add patchpilot -- /usr/bin/node /x/bin/patch-pilot.js mcp --project '/work/my app'");
  });

  it('explains itself when started by hand', () => {
    const text = mcpGuidanceText('/work/app');
    assert.match(text, /started by Claude Code or\s+Codex, not by hand/);
    assert.match(text, /patch-pilot mcp claude/);
    assert.match(text, /patch-pilot mcp codex/);
    assert.match(text, /--print-config/);
  });

  it('fails with install instructions when the CLI is missing', async () => {
    const { ui, out } = captureUi();
    const code = await setupMcp('claude', { projectRoot: '/work/app', ui, interactive: false, deps: { which: async () => null, launcher } });
    assert.equal(code, EXIT.ENVIRONMENT);
    assert.match(out(), /Claude Code is not installed/);
    assert.match(out(), /npm install -g @anthropic-ai\/claude-code/);
    assert.match(out(), /claude mcp add patch-pilot -- patch-pilot mcp --project \/work\/app/);
  });

  it('registers without asking when not interactive and reports the next steps', async () => {
    const { ui, out } = captureUi();
    const calls: { bin: string; args: readonly string[] }[] = [];
    const code = await setupMcp('codex', {
      projectRoot: '/work/app',
      ui,
      interactive: false,
      deps: { which: async () => '/opt/homebrew/bin/codex', run: async (bin, args) => (calls.push({ bin, args }), ok('Added patchpilot')), launcher },
    });
    assert.equal(code, EXIT.OK);
    assert.deepEqual(calls, [{ bin: '/opt/homebrew/bin/codex', args: ['mcp', 'add', 'patchpilot', '--', 'patch-pilot', 'mcp', '--project', '/work/app'] }]);
    assert.match(out(), /Registered patchpilot in Codex/);
    assert.match(out(), /patch-pilot --provider codex/);
    assert.match(out(), /patch-pilot apply/);
  });

  it('reports a failed registration with the manual command', async () => {
    const { ui, out } = captureUi();
    const code = await setupMcp('claude', {
      projectRoot: '/work/app',
      ui,
      interactive: false,
      deps: { which: async () => '/usr/local/bin/claude', run: async () => failed('MCP server patch-pilot already exists in local config'), launcher },
    });
    assert.equal(code, EXIT.ENVIRONMENT);
    assert.match(out(), /did not register the server \(exit 1\)/);
    assert.match(out(), /already exists/);
    assert.match(out(), /claude mcp add patch-pilot/);
  });
});
