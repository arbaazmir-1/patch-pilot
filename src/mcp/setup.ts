import type { Ui } from '../ui.ts';
import { EXIT, type ExitCode } from '../util/errors.ts';
import { run as runProcess, which as whichOnPath } from '../util/proc.ts';
import { mcpConfigText, selfCommand } from './server.ts';

export type McpTarget = 'claude' | 'codex';

export const MCP_TARGETS: readonly McpTarget[] = ['claude', 'codex'];

export interface SetupDeps {
  which: (cmd: string) => Promise<string | null>;
  run: typeof runProcess;
  launcher: () => Promise<{ command: string; args: string[] }>;
}

const DEFAULT_DEPS: SetupDeps = {
  which: (cmd) => whichOnPath(cmd),
  run: runProcess,
  launcher: () => selfCommand(),
};

const TARGET_INFO: Record<McpTarget, { name: string; serverName: string; install: string[]; next: string[] }> = {
  claude: {
    name: 'Claude Code',
    serverName: 'patch-pilot',
    install: ['Install Claude Code: npm install -g @anthropic-ai/claude-code', 'Docs: https://code.claude.com/docs'],
    next: [
      'Open Claude Code in this project (claude) and ask it to investigate the dependencies with the patch-pilot tools,',
      'or run its /mcp__patch-pilot__investigate prompt. Verdicts land in .patch-pilot/assessment.json.',
      'Review and apply them with: patch-pilot apply',
    ],
  },
  codex: {
    name: 'Codex',
    serverName: 'patchpilot',
    install: ['Install the Codex CLI: npm install -g @openai/codex', 'Docs: https://developers.openai.com/codex'],
    next: [
      'Open Codex in this project (codex) and ask it to investigate the dependencies with the patchpilot tools.',
      'Or let PatchPilot drive Codex for you: patch-pilot --provider codex',
      'Verdicts land in .patch-pilot/assessment.json; review and apply them with: patch-pilot apply',
    ],
  },
};

export function isMcpTarget(value: string | undefined): value is McpTarget {
  return value === 'claude' || value === 'codex';
}

export function setupCommandFor(target: McpTarget, projectRoot: string, launcher: { command: string; args: string[] }): { command: string; args: string[] } {
  const serverArgs = [launcher.command, ...launcher.args, 'mcp', '--project', projectRoot];
  return { command: target, args: ['mcp', 'add', TARGET_INFO[target].serverName, '--', ...serverArgs] };
}

function quoteArg(value: string): string {
  return /^[\w@%+=:,./-]+$/.test(value) ? value : `'${value.replace(/'/g, `'\\''`)}'`;
}

export function displayCommand(cmd: { command: string; args: string[] }): string {
  return [cmd.command, ...cmd.args].map(quoteArg).join(' ');
}

// run by hand, not by a client
export function mcpGuidanceText(projectRoot: string): string {
  return [
    'patch-pilot mcp serves the investigation tools over MCP (stdio). It is started by Claude Code or',
    'Codex, not by hand: run on its own it waits for JSON-RPC messages on stdin.',
    '',
    'To set it up for this project:',
    '  patch-pilot mcp claude          register the tools in your own Claude Code (claude mcp add)',
    '  patch-pilot mcp codex           register the tools in your own Codex CLI (codex mcp add)',
    '  patch-pilot mcp --print-config  print the configuration snippets instead',
    '',
    `Project: ${projectRoot}`,
  ].join('\n');
}

export interface SetupOptions {
  projectRoot: string;
  ui: Ui;
  // ask on a tty, else just register
  interactive: boolean;
  deps?: Partial<SetupDeps>;
}

export async function setupMcp(target: McpTarget, options: SetupOptions): Promise<ExitCode> {
  const deps: SetupDeps = { ...DEFAULT_DEPS, ...options.deps };
  const { ui, projectRoot } = options;
  const info = TARGET_INFO[target];
  const launcher = await deps.launcher();
  const command = setupCommandFor(target, projectRoot, launcher);
  const manual = displayCommand(command);

  const binary = await deps.which(target);
  if (!binary) {
    ui.fail(`${info.name} is not installed (no \`${target}\` on the PATH)`);
    for (const line of info.install) ui.infoLine('', line);
    ui.infoLine('', `Once installed, run this command yourself or re-run patch-pilot mcp ${target}:`);
    ui.infoLine('', manual);
    return EXIT.ENVIRONMENT;
  }

  ui.info('');
  ui.infoLine(`Registering PatchPilot's tools in ${info.name} for ${projectRoot}`, manual);
  if (options.interactive) {
    const key = await ui.singleKeyPrompt(`Run this ${info.name} command now?`, 'y/n', { labels: { y: 'yes, register it', n: 'no, just show me the command' } });
    if (key !== 'y') {
      ui.infoLine('Not registered. Run it yourself when ready:', manual);
      ui.infoLine('Or print all snippets with:', 'patch-pilot mcp --print-config');
      return EXIT.OK;
    }
  }

  const result = await deps.run(binary, command.args, { timeoutMs: 60_000 });
  if (!result.ok) {
    const detail = (result.stderr || result.stdout).trim().split('\n').slice(-3).join(' ').slice(0, 300);
    ui.fail(`${info.name} did not register the server${result.code !== null ? ` (exit ${result.code})` : ''}`, detail || undefined);
    ui.infoLine('Run it yourself to see the full output:', manual);
    ui.infoLine('Or add it by hand from:', 'patch-pilot mcp --print-config');
    return EXIT.ENVIRONMENT;
  }
  ui.check(`Registered ${info.serverName} in ${info.name}`, result.stdout.trim().split('\n')[0] || undefined);
  for (const line of info.next) ui.infoLine('', line);
  return EXIT.OK;
}

export { mcpConfigText };
