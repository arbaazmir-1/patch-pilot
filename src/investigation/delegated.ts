import { readFileSync } from 'node:fs';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { LlmError } from '../llm/errors.ts';
import {
  codexModelLabel,
  CODEX_DOCS,
  describeCodexFailure,
  mcpResultText,
  runCodexExec,
  strictSchema,
  type CodexEvent,
  type CodexItem,
  type CodexRunOptions,
  type CodexRunResult,
} from '../llm/codex.ts';
import { MCP_PROMPT_VERSION, MCP_TOOL_NAMES, type SessionLogEntry } from '../mcp/tools.ts';
import type { Assessment, AuditSink, CaseFile, Config, JsonSchema, PackageCase, Verdict, VulnCase } from '../types.ts';
import type { Spinner, Ui } from '../ui.ts';
import { EnvironmentError, errorMessage } from '../util/errors.ts';
import { alignAssessment, forcedVerdict, recommendationText, selectPackages } from './agent.ts';
import { caseFileHash, createAssessment, findVerdict, loadAssessment, saveAssessment, upsertVerdict } from './assessment.ts';
import { clip, dependencyText, displayVulnId, severityText } from './prompts.ts';
import { createToolRegistry, type ToolRegistry } from './tools/index.ts';
import { loadVerdictCache, lookupVerdict, usageEvidenceHash, verdictCacheKey, type VerdictCacheFile } from './verdictCache.ts';
import { usageOf } from './prompts.ts';

// tools show up as mcp__patchpilot__<tool>
export const DELEGATED_SERVER = 'patchpilot';

export interface DelegatedDeps {
  ui: Ui;
  audit: AuditSink;
  signal?: AbortSignal;
  // default: this node and script
  self?: { command: string; args: string[] };
  // default from PATH
  codexCommand?: string;
  env?: NodeJS.ProcessEnv;
  // 10 min + 4 per CVE, max 60
  timeoutMs?: number;
  // test hook
  runCodex?: (options: CodexRunOptions) => Promise<CodexRunResult>;
  now?: () => number;
}

// verdicts come via mcp, not here
export const DELEGATED_OUTPUT_SCHEMA: JsonSchema = strictSchema({
  type: 'object',
  properties: {
    package: { type: 'string' },
    submitted: { type: 'array', items: { type: 'string' } },
    notes: { type: 'string' },
  },
  required: ['package', 'submitted', 'notes'],
});

// type stripping for .ts sources
function passthroughExecArgv(): string[] {
  return process.execArgv.filter((a) => /^--(experimental-(strip|transform)-types|no-warnings|disable-warning=.+|enable-source-maps)$/.test(a));
}

export function defaultSelfCommand(): { command: string; args: string[] } {
  const script = process.argv[1] ? path.resolve(process.argv[1]) : '';
  return { command: process.execPath, args: [...passthroughExecArgv(), ...(script ? [script] : [])] };
}

export function delegatedPrompt(pkg: PackageCase, vulns: readonly VulnCase[]): string {
  const list = vulns.map((v) => `- ${v.id}${displayVulnId(v) !== v.id ? ` (${displayVulnId(v)})` : ''}, ${severityText(v)}: ${clip(v.summary, 120)}`);
  return [
    'You are the investigator for PatchPilot, a tool that decides whether known npm vulnerabilities matter to this project.',
    `Work only through the PatchPilot MCP tools (server "${DELEGATED_SERVER}"; they appear as mcp__${DELEGATED_SERVER}__<tool>). Do not edit files and do not run shell commands: the tools read the project for you.`,
    '',
    `Package: ${pkg.name}@${pkg.version}, ${dependencyText(pkg)}.`,
    'Decide these vulnerabilities:',
    ...list,
    '',
    'Steps:',
    '1. Call get_case for each vulnerability id above (list_cases shows the whole project if you need context).',
    '2. Make the calls get_case lists as required evidence first, then investigate further with get_usage, read_file, search_code, check_deps, get_advisory and get_changelog where the evidence is unclear. Judge by what the code does with untrusted input, not by the CVSS score alone.',
    '3. Optionally call submit_dossier with the facts about how the project uses the package.',
    '4. Call submit_verdict for every vulnerability id above. If it refuses, make exactly the call it names and submit again; if it asks you to re-check, reconsider the evidence and submit again.',
    `5. When every verdict is accepted, reply with the JSON summary: {"package": "${pkg.name}", "submitted": [the vulnerability ids], "notes": "one sentence"}.`,
  ].join('\n');
}

function scoreText(vuln: VulnCase): string | null {
  if (typeof vuln.severity?.cvssScore === 'number') return `CVSS ${vuln.severity.cvssScore.toFixed(1)}`;
  return vuln.severity?.ghsa ?? null;
}

function firstSentence(text: string): string {
  const one = text.replace(/\s+/g, ' ').trim();
  const m = /^[^]*?[.!?](?=\s|$)/.exec(one);
  return clip(m && m[0].length >= 20 ? m[0] : one, 260) || 'No reasoning given.';
}

function verdictKey(vulnId: string, pkg: string, version: string): string {
  return `${vulnId}|${pkg}|${version}`;
}

function parseArgs(value: unknown): Record<string, unknown> {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value as Record<string, unknown>;
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value) as unknown;
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed as Record<string, unknown>;
    } catch {
      // not json
    }
  }
  return {};
}

// codex stream + mcp log as live trace
export class DelegatedTrace {
  private readonly ui: Ui;
  private readonly registry: ToolRegistry;
  private readonly sessionFile: string;
  private readonly caseFile: CaseFile;
  private offset = 0;
  private partial = '';
  private readonly started = new Set<string>();
  private spinner: Spinner | null = null;
  readonly verdicts = new Set<string>();
  toolCalls = 0;
  // status bar "CVE j of m"
  onVuln: ((vulnId: string) => void) | null = null;

  constructor(ui: Ui, registry: ToolRegistry, sessionFile: string, caseFile: CaseFile) {
    this.ui = ui;
    this.registry = registry;
    this.sessionFile = sessionFile;
    this.caseFile = caseFile;
  }

  startSpinner(): void {
    this.spinner = this.ui.spinner(`${this.ui.purple('agent', this.ui.ce)} ${this.ui.ce.dim('codex is working...')}`);
  }

  stop(): void {
    this.spinner?.stop();
    this.spinner = null;
  }

  describe(item: CodexItem): string {
    const tool = String(item.tool ?? '').replace(/^mcp__[^_]+(?:_[^_]+)*__/, '');
    const args = parseArgs(item.arguments);
    const ours = !item.server || item.server === DELEGATED_SERVER || (MCP_TOOL_NAMES as readonly string[]).includes(tool);
    if (!ours) return `Calling ${item.server}.${tool}...`;
    switch (tool) {
      case 'list_cases':
        return 'Listing the vulnerable packages...';
      case 'get_case':
        return `Reading the case for ${String(args.vulnId ?? 'a vulnerability')}...`;
      case 'submit_dossier':
        return `Saving the fact dossier for ${String(args.package ?? 'the package')}...`;
      case 'submit_verdict': {
        const risk = (args.verdict as { risk?: unknown } | undefined)?.risk;
        return `Submitting the verdict for ${String(args.vulnId ?? 'a vulnerability')}${typeof risk === 'string' ? ` (${risk})` : ''}...`;
      }
      default:
        return this.registry.has(tool) ? this.registry.describeCall({ name: tool, arguments: args }) : `Calling ${tool || 'a tool'}...`;
    }
  }

  onEvent(event: CodexEvent): void {
    if (event.type === 'item.started' && event.item.type === 'mcp_tool_call') {
      this.started.add(event.item.id);
      this.ui.agentLine(this.describe(event.item));
      const vulnId = parseArgs(event.item.arguments).vulnId;
      if (typeof vulnId === 'string' && vulnId !== '') this.onVuln?.(vulnId);
      return;
    }
    if (event.type === 'turn.failed' || event.type === 'error') {
      this.ui.warn(`Codex: ${clip(event.message, 200)}`);
      return;
    }
    if (event.type !== 'item.completed') return;
    const item = event.item;
    switch (item.type) {
      case 'mcp_tool_call': {
        this.toolCalls += 1;
        if (!this.started.has(item.id)) this.ui.agentLine(this.describe(item));
        const text = item.error ? `failed: ${item.error}` : mcpResultText(item.result).split('\n')[0] ?? '';
        if (text.trim() !== '') this.ui.resultLine(clip(text, 200));
        this.drain();
        break;
      }
      case 'reasoning':
      case 'agent_message': {
        const text = (item.text ?? '').trim();
        if (text === '' || text.startsWith('{')) break;
        this.ui.agentThought(text.replace(/\*\*/g, ''));
        break;
      }
      case 'command_execution':
        this.ui.agentLine(`Running ${clip(item.command ?? 'a command', 90)}...`, { tag: 'codex' });
        if (typeof item.exitCode === 'number') this.ui.resultLine(`exit code ${item.exitCode}`);
        break;
      case 'file_change':
        this.ui.warn('Codex tried to change files; the read-only sandbox does not allow it');
        break;
      case 'web_search':
        this.ui.agentLine('Searching the web...', { tag: 'codex' });
        break;
      case 'error':
        if (item.text) this.ui.warn(`Codex: ${clip(item.text, 200)}`);
        break;
      default:
        break;
    }
  }

  // gate, rails, verdict cards
  drain(): void {
    let text: string;
    try {
      const buffer = readFileSync(this.sessionFile);
      if (buffer.length <= this.offset) return;
      text = this.partial + buffer.subarray(this.offset).toString('utf8');
      this.offset = buffer.length;
    } catch {
      return;
    }
    const lines = text.split('\n');
    this.partial = lines.pop() ?? '';
    for (const line of lines) {
      if (line.trim() === '') continue;
      let entry: SessionLogEntry;
      try {
        entry = JSON.parse(line) as SessionLogEntry;
      } catch {
        continue;
      }
      this.render(entry);
    }
  }

  private render(entry: SessionLogEntry): void {
    switch (entry.type) {
      case 'gate':
        this.ui.agentLine(
          entry.action === 'coached'
            ? `Evidence missing for ${entry.vulnId}: ${entry.reason}. Asked Codex for ${entry.calls[0] ?? 'the call'}`
            : `Codex skipped the evidence again; ran ${entry.calls.join(', ')} for ${entry.vulnId}`,
          { tag: 'evidence gate' },
        );
        break;
      case 'rails':
        this.ui.agentLine(
          entry.action === 'reasked'
            ? `Verdict ${entry.from} for ${entry.vulnId} breaks a rail (${entry.violation}); asked Codex to re-check`
            : `Risk ${entry.to === entry.from ? 'kept' : riskVerb(entry.from, entry.to)} from ${entry.from} to ${entry.to}: ${entry.violation}`,
          { tag: entry.action === 'reasked' ? 'rails' : 'adjusted' },
        );
        break;
      case 'verdict': {
        this.verdicts.add(entry.vulnId);
        const vuln = this.caseFile.vulnerabilities.find((v) => v.id === entry.vulnId);
        this.spinner?.stop();
        const card = this.ui.card(null);
        card.title(vuln ? displayVulnId(vuln) : entry.vulnId, `${entry.package}@${entry.version}`, vuln ? scoreText(vuln) : null);
        if (entry.adjusted) card.agent('Codex verdict clamped by the rails', { tag: 'adjusted' });
        card.verdict(entry.risk, firstSentence(entry.reasoning));
        card.confidence(entry.confidence, entry.recommendation);
        card.end();
        break;
      }
      case 'error':
        this.ui.warn(`PatchPilot MCP server: ${entry.message}`);
        break;
      default:
        break;
    }
  }
}

function riskVerb(from: string, to: string): string {
  const order = ['Noise', 'Low', 'Medium', 'High', 'Critical'];
  return order.indexOf(to) > order.indexOf(from) ? 'raised' : 'lowered';
}

function cachedCard(ui: Ui, pkg: PackageCase, vuln: VulnCase, verdict: Verdict): void {
  const card = ui.card(verdict.risk);
  card.title(displayVulnId(vuln), `${pkg.name}@${pkg.version}`, scoreText(vuln));
  card.agent('Same model, prompt and evidence as an earlier run: verdict reused', { tag: 'cached' });
  card.verdict(verdict.risk, firstSentence(verdict.reasoning));
  card.confidence(verdict.confidence, recommendationText(verdict.recommendation));
  card.end();
}

function forcedCard(ui: Ui, pkg: PackageCase, vuln: VulnCase, verdict: Verdict): void {
  const card = ui.card(null);
  card.title(displayVulnId(vuln), `${pkg.name}@${pkg.version}`, scoreText(vuln));
  card.agent('Codex did not submit a verdict; verdict derived from the evidence', { tag: 'forced' });
  card.verdict(verdict.risk, firstSentence(verdict.reasoning));
  card.confidence(verdict.confidence, recommendationText(verdict.recommendation));
  card.end();
}

export async function runPhase2Delegated(caseFile: CaseFile, config: Config, deps: DelegatedDeps): Promise<Assessment> {
  const { ui, audit } = deps;
  const now = deps.now ?? (() => Date.now());
  const started = now();
  const explicit = config.sources.model === 'flag' ? config.model : null;
  const label = codexModelLabel(explicit, deps.env ?? process.env);
  const meta = { provider: 'codex' as const, model: label, promptVersion: MCP_PROMPT_VERSION };
  const selected = selectPackages(caseFile, config);
  const totalCves = selected.reduce((n, e) => n + e.vulns.length, 0);
  const file = config.paths.assessmentFile;
  const registry = createToolRegistry();
  const self = deps.self ?? defaultSelfCommand();
  const run = deps.runCodex ?? runCodexExec;
  audit.log({ event: 'investigate.start', packages: selected.length, vulnerabilities: totalCves, provider: 'codex', model: label, promptVersion: MCP_PROMPT_VERSION, resume: config.resume });
  ui.sectionHeader('Investigating vulnerabilities with Codex...');

  let assessment = createAssessment(caseFile, meta);
  const done = new Set<string>();
  if (config.resume) {
    const existing = await loadAssessment(file).catch((err: unknown) => {
      ui.warn('Cannot resume: the saved assessment is unreadable; starting over', errorMessage(err));
      return null;
    });
    if (existing && existing.caseFileHash === caseFileHash(caseFile)) {
      assessment = { ...existing, complete: false };
      for (const v of existing.verdicts) done.add(verdictKey(v.vulnId, v.package, v.installedVersion));
      const resumable = selected.flatMap((e) => e.vulns.filter((v) => done.has(verdictKey(v.id, e.pkg.name, v.installedVersion || e.pkg.version))));
      ui.infoLine(`Resuming: ${resumable.length} of ${totalCves} CVEs already investigated`);
    } else if (existing) {
      ui.warn('Cannot resume: the saved assessment was made from a different case file; starting over');
    }
  }
  await saveAssessment(file, assessment);

  let cache: VerdictCacheFile | null = null;
  if (!config.noCache) {
    try {
      cache = await loadVerdictCache(config.paths.verdictCacheFile, { warn: (m, d) => ui.warn(m, d) });
    } catch {
      cache = null;
    }
  }
  const lookup = (pkg: PackageCase, vuln: VulnCase): { verdict: Verdict; key: string } | null => {
    if (!cache) return null;
    try {
      const key = verdictCacheKey({ provider: 'codex', vulnId: vuln.id, package: pkg.name, version: pkg.version, model: label, usageHash: usageEvidenceHash(usageOf(pkg), vuln), promptVersion: MCP_PROMPT_VERSION });
      const hit = lookupVerdict(cache, key);
      return hit ? { verdict: hit, key } : null;
    } catch {
      return null;
    }
  };

  const usageTotals = { inputTokens: 0, cachedInputTokens: 0, outputTokens: 0, reasoningOutputTokens: 0 };
  if (selected.length === 0) ui.infoLine('No vulnerable packages to investigate');
  await mkdir(config.paths.tmpDir, { recursive: true });
  try {
    for (const [i, { pkg, vulns }] of selected.entries()) {
      if (deps.signal?.aborted) throw new LlmError('aborted', 'Investigation aborted');
      const pending: VulnCase[] = [];
      for (const vuln of vulns) {
        const version = vuln.installedVersion || pkg.version;
        if (done.has(verdictKey(vuln.id, pkg.name, version))) continue;
        const hit = lookup(pkg, vuln);
        if (hit) {
          cachedCard(ui, pkg, vuln, hit.verdict);
          audit.log({ event: 'verdict.cached', vulnId: vuln.id, package: pkg.name, risk: hit.verdict.risk, key: hit.key });
          assessment = upsertVerdict(assessment, hit.verdict);
          await saveAssessment(file, assessment);
          continue;
        }
        pending.push(vuln);
      }
      if (pending.length === 0) continue;
      // activity line is the fallback
      const activity = `Investigating ${pkg.name}@${pkg.version} with Codex (${i + 1} of ${selected.length})`;
      ui.status.set({ activity, detail: `${pending.length} CVE${pending.length === 1 ? '' : 's'}` });
      if (!ui.status.active) ui.activity(`${activity}...`);
      const stamp = `${Date.now()}-${process.pid}`;
      const safe = pkg.name.replace(/[^a-zA-Z0-9._-]+/g, '_');
      const sessionFile = path.join(config.paths.tmpDir, `codex-session-${safe}-${stamp}.jsonl`);
      const work = await mkdtemp(path.join(config.paths.tmpDir, 'codex-run-'));
      const schemaFile = path.join(work, 'output-schema.json');
      const outputFile = path.join(work, 'answer.json');
      await writeFile(schemaFile, JSON.stringify(DELEGATED_OUTPUT_SCHEMA, null, 2), 'utf8');
      await writeFile(sessionFile, '', 'utf8');
      const timeoutMs = deps.timeoutMs ?? Math.min(60, 10 + 4 * pending.length) * 60_000;
      const trace = new DelegatedTrace(ui, registry, sessionFile, caseFile);
      trace.onVuln = (vulnId) => {
        const index = vulns.findIndex((v) => v.id === vulnId || v.aliases.includes(vulnId));
        const vuln = vulns[index];
        if (vuln) ui.status.set({ activity, detail: `CVE ${index + 1} of ${vulns.length} ${displayVulnId(vuln)}` });
      };
      const runStarted = now();
      let result: CodexRunResult;
      trace.startSpinner();
      try {
        result = await run({
          prompt: delegatedPrompt(pkg, pending),
          projectRoot: config.projectRoot,
          model: explicit,
          outputSchemaFile: schemaFile,
          outputFile,
          mcpServer: {
            name: DELEGATED_SERVER,
            command: self.command,
            args: [...self.args, 'mcp', '--project', config.projectRoot, '--session', sessionFile, '--provider', 'codex', '--model', label],
          },
          apiKey: config.codexApiKey,
          timeoutMs,
          ...(deps.signal ? { signal: deps.signal } : {}),
          ...(deps.codexCommand ? { codexCommand: deps.codexCommand } : {}),
          ...(deps.env ? { env: deps.env } : {}),
          onEvent: (event) => trace.onEvent(event),
        });
      } finally {
        trace.stop();
        await rm(work, { recursive: true, force: true }).catch(() => {});
      }
      trace.drain();
      usageTotals.inputTokens += result.usage.inputTokens;
      usageTotals.cachedInputTokens += result.usage.cachedInputTokens;
      usageTotals.outputTokens += result.usage.outputTokens;
      usageTotals.reasoningOutputTokens += result.usage.reasoningOutputTokens;

      // mcp server wrote these to disk
      const onDisk = await loadAssessment(file).catch(() => null);
      if (onDisk && onDisk.caseFileHash === assessment.caseFileHash) {
        let merged: Assessment = { ...assessment, dossiers: onDisk.dossiers };
        for (const v of onDisk.verdicts) merged = upsertVerdict(merged, v);
        assessment = merged;
      }
      const submitted = pending.filter((v) => findVerdict(assessment, v.id, pkg.name, v.installedVersion || pkg.version) && trace.verdicts.has(v.id)).length;
      audit.log({
        event: 'delegated.run',
        provider: 'codex',
        package: pkg.name,
        command: result.command,
        exitCode: result.exitCode,
        durationMs: now() - runStarted,
        toolCalls: result.toolCalls,
        verdicts: submitted,
        usage: { ...result.usage },
      });
      if (result.aborted) throw new LlmError('aborted', 'Investigation aborted');
      if (result.timedOut || result.exitCode !== 0) {
        const failure = describeCodexFailure(result, timeoutMs);
        await saveAssessment(file, assessment);
        throw new EnvironmentError(failure.message, { hint: `${failure.hint}\n  Verdicts accepted so far are saved; continue with: patch-pilot investigate --resume --provider codex` });
      }
      for (const vuln of pending) {
        const version = vuln.installedVersion || pkg.version;
        if (findVerdict(assessment, vuln.id, pkg.name, version)) continue;
        const forced = forcedVerdict(pkg, vuln, [], meta, { steps: 0, durationMs: now() - runStarted });
        forced.investigation.analysis = 'Codex finished without submitting a verdict for this vulnerability.';
        forcedCard(ui, pkg, vuln, forced);
        audit.log({
          event: 'verdict',
          vulnId: forced.vulnId,
          package: forced.package,
          installedVersion: forced.installedVersion,
          risk: forced.risk,
          reachable: forced.reachable,
          confidence: forced.confidence,
          action: forced.recommendation.action,
          forced: true,
          steps: 0,
          durationMs: forced.investigation.durationMs,
          model: label,
        });
        assessment = upsertVerdict(assessment, forced);
      }
      await saveAssessment(file, assessment);
    }
  } catch (err) {
    await saveAssessment(file, assessment).catch(() => {});
    if (err instanceof EnvironmentError || err instanceof LlmError) throw err;
    throw new EnvironmentError(`The Codex investigation failed: ${errorMessage(err)}`, { hint: `Docs: ${CODEX_DOCS}`, cause: err });
  }
  assessment = { ...alignAssessment(caseFile, assessment, config.ignore), complete: true, updatedAt: new Date().toISOString() };
  await saveAssessment(file, assessment);
  const tokens = usageTotals.inputTokens + usageTotals.outputTokens;
  if (tokens > 0) {
    ui.infoLine('Codex usage', `${usageTotals.inputTokens} input (${usageTotals.cachedInputTokens} cached) ${ui.glyphs.dot} ${usageTotals.outputTokens} output tokens`);
  }
  ui.footer({ model: `codex ${ui.glyphs.dot} ${label}`, packages: selected.length, cves: totalCves, elapsedMs: now() - started });
  return assessment;
}
