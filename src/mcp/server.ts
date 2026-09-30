// stdout belongs to mcp
import path from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { AuditLog } from '../audit.ts';
import { loadConfig } from '../config.ts';
import { openDb, type PatchPilotDb } from '../evidence/db.ts';
import { PROMPT_VERSION, RISK_RUBRIC } from '../investigation/prompts.ts';
import type { AuditSink, ProviderName } from '../types.ts';
import { errorMessage } from '../util/errors.ts';
import { which } from '../util/proc.ts';
import { VERSION } from '../version.ts';
import { McpSession, MCP_PROMPT_VERSION, type McpToolOutput } from './tools.ts';

// tools appear as mcp__patch-pilot__<tool>
export const CLAUDE_CODE_SERVER_NAME = 'patch-pilot';
// tools appear as mcp__patchpilot__<tool>
export const CODEX_SERVER_NAME = 'patchpilot';
// verdicts from a claude code session
export const CLAUDE_CODE_MODEL = 'claude-code';

export const SERVER_INSTRUCTIONS = [
  'PatchPilot decides whether the known vulnerabilities of this npm project matter to its code.',
  'Workflow: list_cases shows the vulnerable packages and their vulnerabilities. For each vulnerability call get_case, make the calls it lists as required evidence (get_usage, read_file), investigate further with search_code, check_deps, get_advisory and get_changelog when useful, then call submit_verdict.',
  'submit_verdict refuses a verdict until the required evidence was collected in this session and names the exact call to make; follow it and submit again. It may also send a verdict back once when it contradicts the evidence rules. The recommended action and target version are derived by PatchPilot, not by you.',
  'All tools are read-only on the project; PatchPilot writes its results only under .patch-pilot/.',
].join('\n');

function toResult(output: McpToolOutput): CallToolResult {
  return { content: [{ type: 'text', text: output.text }], ...(output.isError ? { isError: true } : {}) };
}

async function guarded(work: () => Promise<McpToolOutput>): Promise<CallToolResult> {
  try {
    return toResult(await work());
  } catch (err) {
    return toResult({ text: `PatchPilot error: ${errorMessage(err)}`, isError: true });
  }
}

const readOnly = { readOnlyHint: true, destructiveHint: false, openWorldHint: false } as const;

// zod 4 drops additionalProperties for stripping objects; keep the zod 3 wire schema
function closedObject<Shape extends z.ZodRawShape>(shape: Shape, description?: string) {
  return z.object(shape).meta(description ? { description, additionalProperties: false } : { additionalProperties: false });
}

const verdictShape = closedObject(
  {
    risk: z.enum(['Critical', 'High', 'Medium', 'Low', 'Noise']).describe('Contextual risk for THIS project (see the rubric in get_case)'),
    reachable: z.enum(['yes', 'likely', 'unlikely', 'no', 'unknown']).describe('Is the blamed code reachable from the project?'),
    confidence: z.number().describe('0 to 1'),
    reasoning: z.string().describe('One or two sentences naming the decisive fact'),
    evidence: z.array(z.string()).describe('file:line facts and tool findings'),
    recommendationAction: z.enum(['upgrade', 'upgrade_major', 'update_transitive', 'override', 'remove', 'ignore', 'monitor']).describe('Your suggestion (PatchPilot derives the final action by rule)'),
  },
  'The verdict',
);

const dossierShape = closedObject(
  {
    inputSources: z.array(z.string()).describe('Where the data passed to the package comes from, with file:line'),
    callSiteNotes: z.array(z.string()).describe('file:line of each call and what is passed'),
    dependentsSummary: z.string().describe('Direct, transitive or dev-only, and who depends on it'),
    fixCost: z.string().describe('The fix version and whether it is a major bump'),
    openQuestions: z.array(z.string()).describe('What is still unknown'),
  },
  'Facts about how the project uses the package (no risk rating)',
);

// tests use in-memory transport
export function createMcpServer(session: McpSession): McpServer {
  const server = new McpServer({ name: 'patch-pilot', version: VERSION }, { instructions: SERVER_INSTRUCTIONS });
  const registry = session.registry;
  const describe = (name: string, fallback: string): string => registry.get(name)?.description ?? fallback;

  server.registerTool(
    'list_cases',
    {
      title: 'List vulnerable packages',
      description: 'The vulnerable packages of this project, worst first, with their vulnerabilities, blamed symbols, usage summary and fix versions. Investigated ones are marked with their risk.',
      annotations: readOnly,
    },
    async () => guarded(() => session.listCases()),
  );
  server.registerTool(
    'get_case',
    {
      title: 'Get one vulnerability case',
      description: 'The full case for one vulnerability (OSV id or CVE id): advisory details, blamed symbols, how the project uses the package, the evidence PatchPilot requires before it accepts a verdict, the risk rubric and the verdict format.',
      inputSchema: closedObject({ vulnId: z.string().describe('OSV id (GHSA-...) or CVE id') }),
      annotations: readOnly,
    },
    async ({ vulnId }) => guarded(() => session.getCase(vulnId)),
  );
  server.registerTool(
    'get_usage',
    {
      title: 'How the project uses a package',
      description: describe('get_usage', 'Import sites and calls of a package or one of its functions.'),
      inputSchema: closedObject({
        package: z.string().describe('npm package name, for example lodash'),
        symbol: z.string().optional().describe('Function or member to look for, for example template'),
      }),
      annotations: readOnly,
    },
    async (args) => guarded(() => session.runTool('get_usage', args)),
  );
  server.registerTool(
    'search_code',
    {
      title: 'Search the project code',
      description: describe('search_code', 'Regular-expression search over the project source.'),
      inputSchema: closedObject({
        pattern: z.string().describe('JavaScript regular expression, for example \\bmerge\\('),
        fileGlob: z.string().optional().describe('Only search files matching this glob, for example src/**/*.js'),
        maxResults: z.number().int().optional().describe('Maximum matches to return (default 10, at most 30)'),
      }),
      annotations: readOnly,
    },
    async (args) => guarded(() => session.runTool('search_code', args)),
  );
  server.registerTool(
    'read_file',
    {
      title: 'Read a project file',
      description: describe('read_file', 'Numbered lines from a project file.'),
      inputSchema: closedObject({
        path: z.string().describe('Project-relative path, for example src/render.js'),
        startLine: z.number().int().optional().describe('First line to read (1-based)'),
        endLine: z.number().int().optional().describe('Last line to read'),
      }),
      annotations: readOnly,
    },
    async (args) => guarded(() => session.runTool('read_file', args)),
  );
  server.registerTool(
    'get_advisory',
    {
      title: 'Read an advisory',
      description: describe('get_advisory', 'Full advisory text for one vulnerability id.'),
      inputSchema: closedObject({ id: z.string().describe('Vulnerability id, for example GHSA-xvch-5gv4-984h or CVE-2021-44906') }),
      annotations: readOnly,
    },
    async (args) => guarded(() => session.runTool('get_advisory', args)),
  );
  server.registerTool(
    'check_deps',
    {
      title: 'Dependency facts',
      description: describe('check_deps', 'Direct or transitive, dev-only, dependents and paths of a package.'),
      inputSchema: closedObject({ package: z.string().describe('npm package name, for example decode-uri-component') }),
      annotations: readOnly,
    },
    async (args) => guarded(() => session.runTool('check_deps', args)),
  );
  server.registerTool(
    'get_changelog',
    {
      title: 'Release notes between two versions',
      description: describe('get_changelog', 'Release notes between two versions of a package.'),
      inputSchema: closedObject({
        package: z.string().describe('npm package name'),
        fromVersion: z.string().describe('Installed version, for example 0.3.6'),
        toVersion: z.string().describe('Target version, for example 4.0.10'),
      }),
      annotations: { ...readOnly, openWorldHint: true },
    },
    async (args) => guarded(() => session.runTool('get_changelog', args)),
  );
  server.registerTool(
    'submit_dossier',
    {
      title: 'Save a fact dossier',
      description: 'Optional: save the facts about how the project uses a package (input sources, call sites, dependents, fix cost, open questions) before the per-vulnerability verdicts. No risk rating.',
      inputSchema: closedObject({ package: z.string().describe('npm package name'), dossier: dossierShape }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ package: pkg, dossier }) => guarded(() => session.submitDossier(pkg, dossier)),
  );
  server.registerTool(
    'submit_verdict',
    {
      title: 'Submit a verdict',
      description: `Submit the verdict for one vulnerability. PatchPilot refuses it until the required evidence (see get_case) was collected in this session and names the exact call to make; it checks the verdict against its evidence rules, derives the recommendation, and saves it to .patch-pilot/assessment.json.\nRisk rubric:\n${RISK_RUBRIC}`,
      inputSchema: closedObject({ vulnId: z.string().describe('OSV id or CVE id'), verdict: verdictShape }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ vulnId, verdict }) => guarded(() => session.submitVerdict(vulnId, verdict)),
  );

  server.registerPrompt(
    'investigate',
    {
      title: 'Investigate the vulnerabilities',
      description: 'Investigate the vulnerable dependencies of this project with the PatchPilot tools.',
      argsSchema: { package: z.string().optional().describe('Only this package') },
    },
    ({ package: pkg }) => ({
      messages: [
        {
          role: 'user',
          content: {
            type: 'text',
            text: [
              `Use the patch-pilot tools to decide how much each known vulnerability ${pkg ? `of the package ${pkg} ` : ''}matters to this project.`,
              'Call list_cases, then for each vulnerability get_case, make the calls it lists as required evidence, look further where the evidence is unclear, and call submit_verdict.',
              'Follow submit_verdict when it refuses a verdict or asks for a re-check. Do not edit any files. Finish with a short table of the verdicts.',
            ].join('\n'),
          },
        },
      ],
    }),
  );
  return server;
}

export interface McpCommandOptions {
  project?: string;
  session?: string;
  provider?: string;
  model?: string;
}

// until the client disconnects
export async function runMcpStdioServer(options: McpCommandOptions): Promise<void> {
  const config = await loadConfig({ dir: options.project, flags: {} });
  config.interactive = false;
  const provider: ProviderName = options.provider === 'codex' ? 'codex' : 'claude';
  const model = options.model?.trim() || (provider === 'codex' ? 'codex-default' : CLAUDE_CODE_MODEL);
  let audit: AuditSink;
  try {
    audit = AuditLog.open(config.paths.auditLog);
  } catch (err) {
    process.stderr.write(`patch-pilot mcp: audit log unavailable (${errorMessage(err)})\n`);
    audit = { log() {} };
  }
  let db: PatchPilotDb | null = null;
  try {
    db = openDb(config.paths.dbFile);
  } catch {
    db = null;
  }
  const session = new McpSession({
    config,
    provider,
    model,
    audit,
    sessionFile: options.session ? path.resolve(options.session) : null,
    cache: db,
  });
  const server = createMcpServer(session);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // tool calls wait on this
  session
    .ready()
    .then((caseFile) => {
      audit.log({
        event: 'investigate.start',
        packages: caseFile.packages.length,
        vulnerabilities: caseFile.vulnerabilities.length,
        provider,
        model,
        promptVersion: MCP_PROMPT_VERSION,
        resume: false,
      });
    })
    .catch((err: unknown) => {
      process.stderr.write(`patch-pilot mcp: cannot load the case file: ${errorMessage(err)}\n`);
      session.log({ type: 'error', message: `cannot load the case file: ${errorMessage(err)}` });
    });
  await new Promise<void>((resolve) => {
    const done = (): void => resolve();
    server.server.onclose = done;
    process.stdin.once('end', done);
    process.stdin.once('close', done);
    process.once('SIGTERM', done);
    process.once('SIGINT', done);
  });
  await server.close().catch(() => {});
  db?.close();
  // even with phase 1 in flight
  setTimeout(() => process.exit(process.exitCode ?? 0), 2_000).unref();
}

// --print-config

// patch-pilot on PATH, else node + script
export async function selfCommand(env: NodeJS.ProcessEnv = process.env): Promise<{ command: string; args: string[] }> {
  const onPath = await which('patch-pilot', env).catch(() => null);
  if (onPath) return { command: 'patch-pilot', args: [] };
  const script = process.argv[1] ? path.resolve(process.argv[1]) : '';
  return { command: process.execPath, args: script ? [script] : [] };
}

function shellWord(value: string): string {
  return /^[\w@%+=:,./-]+$/.test(value) ? value : `'${value.replace(/'/g, `'\\''`)}'`;
}

// plain-text config snippets
export function mcpConfigText(projectRoot: string, launcher: { command: string; args: string[] }): string {
  const args = [...launcher.args, 'mcp', '--project', projectRoot];
  const commandLine = [launcher.command, ...args].map(shellWord).join(' ');
  const json = JSON.stringify({ mcpServers: { [CLAUDE_CODE_SERVER_NAME]: { type: 'stdio', command: launcher.command, args } } });
  const toml = [`[mcp_servers.${CODEX_SERVER_NAME}]`, `command = ${JSON.stringify(launcher.command)}`, `args = ${JSON.stringify(args)}`].join('\n');
  return [
    `PatchPilot MCP server for ${projectRoot}`,
    '',
    'Claude Code (Pro or Max subscription, in your own session):',
    `  claude mcp add ${CLAUDE_CODE_SERVER_NAME} -- ${commandLine}`,
    '  or for one session:',
    `  claude --mcp-config ${shellWord(json)}`,
    `  Then ask Claude to use the ${CLAUDE_CODE_SERVER_NAME} tools, or run the /mcp__${CLAUDE_CODE_SERVER_NAME}__investigate prompt.`,
    `  Tools appear as mcp__${CLAUDE_CODE_SERVER_NAME}__<tool>. PatchPilot never runs claude itself and never reads Claude.ai credentials.`,
    '',
    'Codex CLI (~/.codex/config.toml), to use the tools in your own Codex sessions:',
    ...toml.split('\n').map((l) => `  ${l}`),
    `  patch-pilot --provider codex registers the server by itself for each run (tools appear as mcp__${CODEX_SERVER_NAME}__<tool>).`,
    '',
    'Tools: list_cases, get_case, get_usage, search_code, read_file, get_advisory, check_deps, get_changelog, submit_dossier, submit_verdict.',
    'Verdicts are saved to .patch-pilot/assessment.json; review and apply them with: patch-pilot apply',
    `Prompt version: ${MCP_PROMPT_VERSION} (investigation prompts ${PROMPT_VERSION}).`,
  ].join('\n');
}
