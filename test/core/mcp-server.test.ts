import assert from 'node:assert/strict';
import { cp, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { saveCaseFile } from '../../src/evidence/casefile.ts';
import { MemoryAudit } from '../../src/audit.ts';
import { loadAssessment } from '../../src/investigation/assessment.ts';
import { createMcpServer, mcpConfigText } from '../../src/mcp/server.ts';
import { McpSession, MCP_PROMPT_VERSION, type SessionLogEntry } from '../../src/mcp/tools.ts';
import type { CaseFile, Config } from '../../src/types.ts';
import { caseFileOf, fakeRegistry, lodashFixture, minimistFixture, tempDir, testConfig, usageResult } from '../investigation/helpers.ts';

const FIXTURE = fileURLToPath(new URL('../../examples/vulnerable-app', import.meta.url));
const BIN = fileURLToPath(new URL('../../bin/patch-pilot.ts', import.meta.url));

let dir: string;
let cleanup: () => Promise<void>;

before(async () => {
  ({ dir, cleanup } = await tempDir('pp-mcp-'));
});
after(async () => {
  await cleanup();
});

interface Harness {
  client: Client;
  session: McpSession;
  audit: MemoryAudit;
  config: Config;
  toolCalls: { tool: string; args: Record<string, unknown> }[];
  sessionFile: string;
  call: (name: string, args?: Record<string, unknown>) => Promise<{ text: string; isError: boolean }>;
}

async function harness(name: string, caseFile?: (root: string) => CaseFile): Promise<Harness> {
  const root = path.join(dir, name);
  await mkdir(root, { recursive: true });
  const config = await testConfig(root);
  const { pkg: minimist, vuln: minimistVuln } = minimistFixture();
  const { pkg: lodash, template } = lodashFixture();
  const lodashCase = { ...lodash, vulnIds: [template.id] };
  const cf = caseFile ? caseFile(root) : caseFileOf([minimist, lodashCase], [minimistVuln, template], root);
  const { registry, calls } = fakeRegistry({
    get_usage: (args) =>
      args.symbol
        ? usageResult(String(args.package), String(args.symbol), 0)
        : usageResult(String(args.package), null, 1, [{ path: 'src/cli.js', line: 9, member: null }]),
    read_file: (args) => ({ ok: true, hint: `${String(args.path)}:${String(args.startLine ?? 1)}-${String(args.endLine ?? 40)}`, text: '9: const argv = parseArgs(process.argv.slice(2));' }),
  });
  const audit = new MemoryAudit();
  const sessionFile = path.join(root, 'session.jsonl');
  const session = new McpSession({ config, provider: 'claude', model: 'claude-code', audit, sessionFile, registry, graph: null, loadCase: async () => cf, scanImports: async () => new Map() });
  const server = createMcpServer(session);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: 'test-host', version: '1.0.0' });
  await client.connect(clientTransport);
  const call = async (tool: string, args: Record<string, unknown> = {}): Promise<{ text: string; isError: boolean }> => {
    const res = (await client.callTool({ name: tool, arguments: args })) as { content: { type: string; text?: string }[]; isError?: boolean };
    return { text: res.content.map((c) => c.text ?? '').join('\n'), isError: Boolean(res.isError) };
  };
  return { client, session, audit, config, toolCalls: calls, sessionFile, call };
}

const HIGH = { risk: 'High', reachable: 'yes', confidence: 0.8, reasoning: 'minimist parses process.argv from the user.', evidence: ['src/cli.js:9'], recommendationAction: 'upgrade' };

describe('PatchPilot MCP server', () => {
  it('lists the investigation tools (never web_search or fetch_page) and the investigate prompt', async () => {
    const h = await harness('tools');
    const tools = (await h.client.listTools()).tools.map((t) => t.name).sort();
    assert.deepEqual(tools, ['check_deps', 'get_advisory', 'get_case', 'get_changelog', 'get_usage', 'list_cases', 'read_file', 'search_code', 'submit_dossier', 'submit_verdict']);
    const prompts = (await h.client.listPrompts()).prompts.map((p) => p.name);
    assert.deepEqual(prompts, ['investigate']);
    const instructions = h.client.getInstructions();
    assert.match(String(instructions), /submit_verdict refuses/);
  });

  it('list_cases shows packages worst first with blamed symbols, usage and fixes; get_case names the required calls', async () => {
    const h = await harness('cases');
    const list = JSON.parse((await h.call('list_cases')).text) as { packages: { package: string; vulnerabilities: { id: string; blamed: string[]; fixVersion: string; investigated: boolean }[]; usage: { importSites: string[] } }[] };
    assert.deepEqual(
      list.packages.map((p) => p.package),
      ['minimist', 'lodash'],
    );
    const minimist = list.packages[0];
    assert.equal(minimist?.vulnerabilities[0]?.id, 'GHSA-xvch-5gv4-984h');
    assert.deepEqual(minimist?.vulnerabilities[0]?.blamed, ['setKey (internal)']);
    assert.equal(minimist?.vulnerabilities[0]?.fixVersion, '1.2.6');
    assert.equal(minimist?.vulnerabilities[0]?.investigated, false);
    assert.match(minimist?.usage.importSites[0] ?? '', /src\/cli\.js:7/);
    const kase = await h.call('get_case', { vulnId: 'CVE-2021-44906' });
    assert.equal(kase.isError, false);
    assert.match(kase.text, /Evidence PatchPilot requires/);
    assert.match(kase.text, /get_usage\(\{"package":"minimist"\}\)/);
    assert.match(kase.text, /read_file\(\{"path":"src\/cli\.js"/);
    assert.match(kase.text, /Risk rubric/);
    const unknown = await h.call('get_case', { vulnId: 'CVE-1999-0001' });
    assert.equal(unknown.isError, true);
    assert.match(unknown.text, /Known ids: CVE-2021-44906/);
  });

  it('runs registry tools through ToolRegistry.execute with audit events and a session trace', async () => {
    const h = await harness('registry');
    const res = await h.call('get_usage', { package: 'minimist' });
    assert.equal(res.isError, false);
    assert.match(res.text, /minimist imported/);
    assert.deepEqual(h.toolCalls[0], { tool: 'get_usage', args: { package: 'minimist' } });
    const callEvent = h.audit.events('tool.call')[0];
    assert.equal(callEvent?.tool, 'get_usage');
    assert.equal(callEvent?.by, 'model');
    assert.equal(callEvent?.package, 'minimist');
    assert.equal(h.audit.events('tool.result')[0]?.ok, true);
    const lines = (await readFile(h.sessionFile, 'utf8')).trim().split('\n').map((l) => JSON.parse(l) as SessionLogEntry);
    const tool = lines.find((l) => l.type === 'tool');
    assert.ok(tool && tool.type === 'tool');
    assert.equal(tool.description, 'Checking how minimist is used...');
  });

  it('refuses a verdict without the evidence, naming the exact call, then accepts it and saves it', async () => {
    const h = await harness('gate');
    const refused = await h.call('submit_verdict', { vulnId: 'GHSA-xvch-5gv4-984h', verdict: HIGH });
    assert.equal(refused.isError, true);
    assert.match(refused.text, /Refused: the evidence for CVE-2021-44906 is incomplete/);
    assert.match(refused.text, /get_usage\(\{"package":"minimist"\}\)/);
    assert.match(refused.text, /Also required: read_file\(\{"path":"src\/cli\.js"/);
    assert.equal(h.audit.events('gate.evidence')[0]?.action, 'coached');
    await h.call('get_usage', { package: 'minimist' });
    await h.call('read_file', { path: 'src/cli.js', startLine: 1, endLine: 30 });
    const accepted = await h.call('submit_verdict', { vulnId: 'CVE-2021-44906', verdict: HIGH });
    assert.equal(accepted.isError, false, accepted.text);
    const body = JSON.parse(accepted.text) as { status: string; risk: string; recommendation: string };
    assert.equal(body.status, 'accepted');
    assert.equal(body.risk, 'High');
    assert.equal(body.recommendation, 'bump to 1.2.6', 'derived by rule from the case file');
    assert.ok(h.audit.events('gate.evidence').some((e) => e.action === 'satisfied'));
    const verdictEvent = h.audit.events('verdict')[0];
    assert.equal(verdictEvent?.risk, 'High');
    assert.equal(verdictEvent?.model, 'claude-code');
    const assessment = await loadAssessment(h.config.paths.assessmentFile);
    const v = assessment?.verdicts[0];
    assert.ok(v);
    assert.equal(v.vulnId, 'GHSA-xvch-5gv4-984h');
    assert.equal(v.investigation.provider, 'claude');
    assert.equal(v.investigation.model, 'claude-code');
    assert.equal(v.investigation.promptVersion, MCP_PROMPT_VERSION);
    assert.equal(v.investigation.gate?.coached, true);
    assert.ok(v.investigation.toolCalls.some((c) => c.tool === 'read_file'));
    const cache = JSON.parse(await readFile(h.config.paths.verdictCacheFile, 'utf8')) as { entries: Record<string, unknown> };
    assert.equal(Object.keys(cache.entries).length, 1);
    assert.ok(Object.keys(cache.entries)[0]?.startsWith('claude:'));
    const list = JSON.parse((await h.call('list_cases')).text) as { investigated: number; packages: { vulnerabilities: { investigated: boolean; risk?: string }[] }[] };
    assert.equal(list.investigated, 1);
    assert.equal(list.packages[0]?.vulnerabilities[0]?.risk, 'High');
  });

  it('runs the missing calls itself after a second refusal, then judges the next submission', async () => {
    const h = await harness('harness');
    const low = { ...HIGH, risk: 'Medium', reasoning: 'template() is not called.' };
    const first = await h.call('submit_verdict', { vulnId: 'CVE-2021-23337', verdict: low });
    assert.equal(first.isError, true);
    assert.match(first.text, /get_usage\(\{"package":"lodash","symbol":"template"\}\)/);
    const second = await h.call('submit_verdict', { vulnId: 'CVE-2021-23337', verdict: low });
    assert.equal(second.isError, true);
    assert.match(second.text, /PatchPilot ran the calls itself/);
    assert.match(second.text, /0 calls to _\.template/);
    assert.ok(h.audit.events('gate.evidence').some((e) => e.action === 'harness-ran'));
    assert.ok(h.audit.events('tool.call').some((e) => e.by === 'harness' && e.tool === 'get_usage'));
    const third = await h.call('submit_verdict', { vulnId: 'CVE-2021-23337', verdict: low });
    assert.equal(third.isError, false, third.text);
    const v = (await loadAssessment(h.config.paths.assessmentFile))?.verdicts[0];
    assert.deepEqual(v?.investigation.gate?.harnessCalls, ['get_usage(lodash, template)']);
  });

  it('sends a verdict outside the rails back once with the contradiction, then clamps it', async () => {
    const h = await harness('rails');
    await h.call('get_usage', { package: 'minimist' });
    await h.call('read_file', { path: 'src/cli.js', startLine: 1, endLine: 30 });
    const low = { ...HIGH, risk: 'Low', reasoning: 'Only a CLI.' };
    const reask = await h.call('submit_verdict', { vulnId: 'CVE-2021-44906', verdict: low });
    assert.equal(reask.isError, true);
    assert.match(reask.text, /Not accepted yet: you rated the risk Low, but minimist is imported in source and the package itself is called there/);
    assert.match(reask.text, /at least Medium/);
    const again = await h.call('submit_verdict', { vulnId: 'CVE-2021-44906', verdict: low });
    assert.equal(again.isError, false, again.text);
    const body = JSON.parse(again.text) as { risk: string; adjusted: { from: string; to: string } };
    assert.equal(body.risk, 'Medium');
    assert.deepEqual({ from: body.adjusted.from, to: body.adjusted.to }, { from: 'Low', to: 'Medium' });
    const adjusted = h.audit.events('verdict.adjusted')[0];
    assert.equal(adjusted?.originalRisk, 'Low');
    assert.equal(adjusted?.reasked, true);
    const v = (await loadAssessment(h.config.paths.assessmentFile))?.verdicts[0];
    assert.equal(v?.risk, 'Medium');
    assert.equal(v?.investigation.adjusted, true);
    assert.equal(v?.investigation.originalRisk, 'Low');
    const log = (await readFile(h.sessionFile, 'utf8')).trim().split('\n').map((l) => JSON.parse(l) as SessionLogEntry);
    assert.deepEqual(
      log.filter((l) => l.type === 'rails').map((l) => (l.type === 'rails' ? l.action : '')),
      ['reasked', 'adjusted'],
    );
    assert.ok(log.some((l) => l.type === 'verdict' && l.risk === 'Medium' && l.adjusted));
  });

  it('rejects a malformed verdict with the schema and saves a dossier', async () => {
    const h = await harness('dossier');
    const bad = await h.call('submit_verdict', { vulnId: 'CVE-2021-44906', verdict: { ...HIGH, risk: 'Severe' } });
    assert.equal(bad.isError, true);
    const saved = await h.call('submit_dossier', {
      package: 'minimist',
      dossier: { inputSources: ['process.argv'], callSiteNotes: ['src/cli.js:9'], dependentsSummary: 'direct', fixCost: '1.2.6', openQuestions: [] },
    });
    assert.equal(saved.isError, false, saved.text);
    const assessment = await loadAssessment(h.config.paths.assessmentFile);
    assert.equal(assessment?.dossiers[0]?.package, 'minimist');
    assert.deepEqual(assessment?.dossiers[0]?.inputSources, ['process.argv']);
    const kase = await h.call('get_case', { vulnId: 'CVE-2021-44906' });
    assert.match(kase.text, /Fact dossier \(submitted earlier\)/);
  });

  it('runs the real tools on the bundled fixture', async () => {
    const root = path.join(dir, 'fixture');
    await cp(FIXTURE, root, { recursive: true, filter: (src) => !src.includes(`${path.sep}.patch-pilot`) && !src.includes(`${path.sep}node_modules`) });
    const config = await testConfig(root);
    const { pkg, vuln } = minimistFixture();
    const audit = new MemoryAudit();
    const session = new McpSession({ config, provider: 'codex', model: 'test-model', audit, graph: null, loadCase: async () => caseFileOf([pkg], [vuln], root), scanImports: async () => new Map() });
    const usage = await session.runTool('get_usage', { package: 'minimist' });
    assert.equal(usage.isError, false, usage.text);
    assert.match(usage.text, /src\/cli\.js/);
    const file = await session.runTool('read_file', { path: 'src/cli.js', startLine: 1, endLine: 20 });
    assert.equal(file.isError, false, file.text);
    assert.match(file.text, /minimist/);
    const escape = await session.runTool('read_file', { path: '../../etc/passwd' });
    assert.equal(escape.isError, true, 'paths outside the project are refused by the registry tool');
    const web = await session.runTool('web_search', { query: 'x' });
    assert.equal(web.isError, true);
    const verdict = await session.submitVerdict('CVE-2021-44906', HIGH);
    assert.ok(!verdict.isError, verdict.text);
    const v = (await loadAssessment(config.paths.assessmentFile))?.verdicts[0];
    assert.equal(v?.investigation.provider, 'codex');
    assert.equal(v?.investigation.model, 'test-model');
  });
});

describe('patch-pilot mcp --print-config', () => {
  it('prints the Claude Code and Codex setup for the project and never runs claude itself', async () => {
    const text = mcpConfigText('/work/my app', { command: 'patch-pilot', args: [] });
    assert.match(text, /claude mcp add patch-pilot -- patch-pilot mcp --project '\/work\/my app'/);
    assert.match(text, /claude --mcp-config '\{"mcpServers":\{"patch-pilot":\{"type":"stdio","command":"patch-pilot","args":\["mcp","--project","\/work\/my app"\]\}\}\}'/);
    assert.match(text, /\[mcp_servers\.patchpilot\]/);
    assert.match(text, /args = \["mcp","--project","\/work\/my app"\]/);
    assert.match(text, /mcp__patch-pilot__<tool>/);
    assert.match(text, /never runs claude itself/);
    assert.ok(!/claude -p/.test(text));
    const dev = mcpConfigText('/p', { command: '/usr/local/bin/node', args: ['/src/bin/patch-pilot.ts'] });
    assert.match(dev, /claude mcp add patch-pilot -- \/usr\/local\/bin\/node \/src\/bin\/patch-pilot\.ts mcp --project \/p/);
    await writeFile(path.join(dir, 'unused'), '');
  });
});

describe('patch-pilot mcp over stdio', () => {
  it('prints the config from the CLI and serves the tools until the client disconnects', { timeout: 60_000 }, async () => {
    const root = path.join(dir, 'stdio');
    await mkdir(root, { recursive: true });
    const home = path.join(dir, 'stdio-home');
    await mkdir(home, { recursive: true });
    const env = { ...process.env, HOME: home, NO_COLOR: '1' } as Record<string, string>;
    const printed = await new Promise<{ code: number; stdout: string }>((resolve) => {
      execFile(process.execPath, [BIN, 'mcp', '--print-config', '--project', root], { env }, (error, stdout) => resolve({ code: error ? 1 : 0, stdout: String(stdout) }));
    });
    assert.equal(printed.code, 0);
    assert.match(printed.stdout, /claude mcp add patch-pilot -- /);
    assert.match(printed.stdout, /mcp --project /);
    const config = await testConfig(root);
    const { pkg, vuln } = minimistFixture();
    await saveCaseFile(config.paths.caseFile, { ...caseFileOf([pkg], [vuln], root), scannedAt: new Date(Date.now() + 1000).toISOString() });
    const session = path.join(root, 'trace.jsonl');
    const transport = new StdioClientTransport({ command: process.execPath, args: [BIN, 'mcp', '--project', root, '--session', session], env, stderr: 'pipe' });
    const client = new Client({ name: 'stdio-test', version: '1.0.0' });
    await client.connect(transport);
    assert.equal(client.getServerVersion()?.name, 'patch-pilot');
    const res = (await client.callTool({ name: 'list_cases', arguments: {} })) as { content: { text?: string }[] };
    const list = JSON.parse(res.content[0]?.text ?? '{}') as { packages: { package: string }[] };
    assert.deepEqual(
      list.packages.map((p) => p.package),
      ['minimist'],
    );
    const exited = new Promise<void>((resolve) => {
      transport.onclose = () => resolve();
    });
    await client.close();
    await exited;
    const lines = (await readFile(session, 'utf8')).trim().split('\n').map((l) => JSON.parse(l) as SessionLogEntry);
    assert.equal(lines[0]?.type, 'ready');
  });
});
