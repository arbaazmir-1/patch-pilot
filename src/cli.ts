// all commands and flags
import os from 'node:os';
import path from 'node:path';
import { Command, CommanderError, InvalidArgumentError, Option } from 'commander';
import { AuditLog, captureIdentity, formatIdentity } from './audit.ts';
import { addIgnoreEntry, findingsExitCode, loadConfig, parseUntil, projectPaths, USER_CONFIG_KEYS, type CliFlags } from './config.ts';
import { configGet, configSet, configUnset } from './configCommand.ts';
import { exitCodeFor, mergeExitCodes, printJson, summarizeForJson } from './ci.ts';
import { codexNotInstalled, codexStatus, CODEX_DOCS } from './llm/codex.ts';
import { createCodemodProvider, createProvider, formatUsageSummary, LlmError, missingAnthropicKey, type ChatProvider } from './llm/provider.ts';
import { loadCaseFile, runPhase1 } from './evidence/casefile.ts';
import { renderDbStatus, snapshotStatus, syncSnapshot } from './evidence/snapshot.ts';
import { runPhase2 } from './investigation/agent.ts';
import { runPhase2Delegated } from './investigation/delegated.ts';
import { mcpConfigText, runMcpStdioServer, selfCommand } from './mcp/server.ts';
import { isMcpTarget, mcpGuidanceText, setupMcp } from './mcp/setup.ts';
import { applyProviderChoice, chooseProvider, detectProviders, isCloudProvider, renderProviderLines, type ProviderChoice } from './providerPicker.ts';
import { loadAssessment } from './investigation/assessment.ts';
import { offerGitignore, openStateDb, rollbackLatest, runPhase3, stateDirExists } from './remediation/patch.ts';
import { presentFindings } from './remediation/present.ts';
import { writeReports } from './remediation/report.ts';
import { archiveLastRun, clearProjectState } from './runHistory.ts';
import { trackRun } from './runStatus.ts';
import { ensurePreflight, NEEDS, pullModel, renderPreflight, renderPullProgress, runPreflight, type PullProgress } from './preflight.ts';
import { cloudProviderNotice, ensureTrusted, trustDirectory, trustStorePath, untrustDirectory } from './trust.ts';
import type { Config, ConfigSource, Identity, IgnoreEntry, PreflightNeeds, PreflightResult, ProviderName } from './types.ts';
import { createUi, restoreTerminal, type FooterInfo, type PhaseNumber, type Ui } from './ui.ts';
import { ConfigError, EnvironmentError, errorMessage, EXIT, isNotImplemented, isPromptCancelled, PatchPilotError, type ExitCode } from './util/errors.ts';
import { NetworkError } from './util/http.ts';
import { VERSION } from './version.ts';

function intArg(flag: string): (value: string) => number {
  return (value: string): number => {
    const n = Number(value);
    if (!/^-?\d+$/.test(value.trim()) || !Number.isSafeInteger(n)) throw new InvalidArgumentError(`${flag} needs an integer.`);
    return n;
  };
}

const OPTIONS = {
  provider: () => new Option('--provider <name>', 'LLM provider: ollama (local), claude (API key), codex (Codex CLI login or API key); default ollama').choices(['ollama', 'claude', 'codex', 'mock']),
  model: () => new Option('--model <name>', 'Ollama model with tool support (default qwen3:8b, env PATCHPILOT_MODEL); with --provider claude: sonnet, opus or haiku'),
  codemodModel: () => new Option('--codemod-model <name>', 'local model for breaking-change code edits (default: --model)'),
  ollamaHost: () => new Option('--ollama-host <url>', 'Ollama server (default http://localhost:11434, env OLLAMA_HOST)'),
  numCtx: () => new Option('--num-ctx <n>', 'context window sent to Ollama (default 16384)').argParser(intArg('--num-ctx')),
  think: () => new Option('--think <mode>', 'thinking mode for models that support it, such as qwen3: auto, on, off (default off)').choices(['auto', 'on', 'off']),
  maxSteps: () => new Option('--max-steps <n>', 'tool calls per investigation loop (default 3)').argParser(intArg('--max-steps')),
  limit: () => new Option('--limit <n>', 'investigate at most N packages').argParser(intArg('--limit')),
  only: () => new Option('--only <list>', 'only these packages or vulnerability ids (comma-separated)'),
  maxCves: () => new Option('--max-cves <n>', 'investigate at most N vulnerabilities').argParser(intArg('--max-cves')),
  offline: () => new Option('--offline', 'no network: cached vulnerability data and sources only'),
  dryRun: () => new Option('--dry-run', 'stop after presenting the findings; change nothing'),
  noCache: () => new Option('--no-cache', 're-investigate every vulnerability (ignore the verdict cache)'),
  fresh: () => new Option('--fresh', 'start over: re-investigate everything with no cached verdicts (the last run is kept in .patch-pilot/history)'),
  approveAll: () => new Option('--approve-all', 'approve every version bump without prompting (code edits need --approve-codemods)'),
  approveCodemods: () => new Option('--approve-codemods', 'also approve code edits for major-version migrations'),
  approve: () => new Option('--approve <pkgs>', 'approve the actions for these packages only (comma-separated)'),
  trust: () => new Option('--trust', 'trust this directory without prompting (scripts and CI)'),
  json: () => new Option('--json', 'machine-readable JSON on stdout only'),
  verbose: () => new Option('--verbose', 'show full tool results and debug details'),
  quiet: () => new Option('--quiet', 'only results, warnings and errors'),
  seed: () => new Option('--seed <n>', 'sampling seed for reproducible runs (default 42)').argParser(intArg('--seed')),
  search: () => new Option('--search <backend>', 'web search for migrations (default auto)').choices(['auto', 'ollama', 'docs', 'brave', 'off']),
  ci: () => new Option('--ci', 'non-interactive: no prompts, no changes, JSON + Markdown reports, exit code from --fail-on'),
  failOn: () =>
    new Option('--fail-on <level>', 'exit 1 when a finding is at or above this risk (default high)').choices([
      'critical',
      'high',
      'medium',
      'low',
      'noise',
      'never',
    ]),
  resume: () => new Option('--resume', 'continue an interrupted investigation'),
  noColor: () => new Option('--no-color', 'disable colors (NO_COLOR is respected too)'),
  mockScript: () => new Option('--mock-script <file>', 'JSON script for --provider mock').hideHelp(),
} as const;

type OptionName = keyof typeof OPTIONS;

function withOptions(cmd: Command, names: readonly OptionName[]): Command {
  for (const name of names) cmd.addOption(OPTIONS[name]());
  return cmd;
}

const SCAN_OPTIONS: readonly OptionName[] = [
  'provider',
  'model',
  'codemodModel',
  'ollamaHost',
  'numCtx',
  'think',
  'maxSteps',
  'limit',
  'only',
  'maxCves',
  'offline',
  'dryRun',
  'noCache',
  'fresh',
  'approveAll',
  'approveCodemods',
  'approve',
  'trust',
  'json',
  'verbose',
  'quiet',
  'seed',
  'search',
  'ci',
  'failOn',
  'noColor',
  'mockScript',
];

const INVESTIGATE_OPTIONS: readonly OptionName[] = [
  'provider',
  'model',
  'ollamaHost',
  'numCtx',
  'think',
  'maxSteps',
  'limit',
  'only',
  'maxCves',
  'offline',
  'noCache',
  'resume',
  'trust',
  'json',
  'verbose',
  'quiet',
  'seed',
  'failOn',
  'noColor',
  'mockScript',
];

const APPLY_OPTIONS: readonly OptionName[] = [
  'provider',
  'model',
  'codemodModel',
  'ollamaHost',
  'numCtx',
  'think',
  'offline',
  'dryRun',
  'approveAll',
  'approveCodemods',
  'approve',
  'trust',
  'json',
  'verbose',
  'quiet',
  'seed',
  'search',
  'ci',
  'failOn',
  'noColor',
  'mockScript',
];

const OUTPUT_OPTIONS: readonly OptionName[] = ['json', 'quiet', 'verbose', 'noColor'];

export interface CommandContext {
  config: Config;
  ui: Ui;
  audit: AuditLog;
  identity: Identity;
  preflight: PreflightResult;
}

// "/Users/me/app" -> "~/app"
function tildify(p: string): string {
  const home = os.homedir();
  return p === home || p.startsWith(home + path.sep) ? `~${p.slice(home.length)}` : p;
}

function sourceLabel(source: ConfigSource | undefined): string | undefined {
  switch (source) {
    case 'file':
      return 'patch-pilot.config.json';
    case 'env':
      return 'OLLAMA_HOST';
    case 'flag':
      return '--ollama-host';
    default:
      return undefined;
  }
}

// logged in scan.start, no secrets
function runOptions(config: Config): Record<string, unknown> {
  return {
    provider: config.provider,
    model: config.model,
    codemodModel: config.codemodModel,
    ollamaHost: config.ollamaHost,
    numCtx: config.numCtx,
    think: config.think,
    maxSteps: config.maxSteps,
    limit: config.limit,
    only: config.only,
    maxCves: config.maxCves,
    offline: config.offline,
    dryRun: config.dryRun,
    noCache: config.noCache,
    approveAll: config.approveAll,
    approveCodemods: config.approveCodemods,
    approve: config.approve,
    search: config.search,
    ci: config.ci,
    failOn: config.failOn,
    resume: config.resume,
    seed: config.seed,
    interactive: config.interactive,
  };
}

// cloud providers skip ollama
export function needsFor(needs: PreflightNeeds, provider: ProviderName): PreflightNeeds {
  return isCloudProvider(provider) ? { ...needs, ollama: false } : needs;
}

// anthropic key or codex login
async function ensureProviderReady(config: Config, ui: Ui): Promise<void> {
  const dot = ui.glyphs.dot;
  if (config.provider === 'claude') {
    if (!config.anthropicApiKey) throw missingAnthropicKey();
    const from = config.sources.anthropicApiKey === 'user' ? '~/.patch-pilot/config.json' : 'ANTHROPIC_API_KEY';
    ui.check('Model provider', `Claude API ${dot} ${config.model} ${dot} API key from ${from}`);
  } else if (config.provider === 'codex') {
    const status = await codexStatus({ apiKey: config.codexApiKey });
    if (!status.installed) throw codexNotInstalled();
    if (!status.loggedIn) {
      throw new EnvironmentError('The Codex CLI is not logged in', {
        hint: `Sign in with: codex login (ChatGPT), or export CODEX_API_KEY=... (OpenAI recommends an API key for automation). Docs: ${CODEX_DOCS}`,
      });
    }
    ui.check('Model provider', `Codex CLI ${dot} ${status.detail} ${dot} ${config.model}`);
    if (config.codexApiKey && !process.env.CODEX_API_KEY && config.sources.codexApiKey === 'env' && status.method === 'chatgpt') {
      ui.notice('Codex runs with OPENAI_API_KEY (API billing) instead of your ChatGPT login', 'unset OPENAI_API_KEY for this run to use the login');
    }
  }
}

// config, preflight, trust gate, audit log
export async function openProject(
  command: string,
  dir: string | undefined,
  flags: CliFlags,
  needs: PreflightNeeds,
  logStart: boolean,
  usesModel = false,
): Promise<CommandContext> {
  const config = await loadConfig({ dir, flags });
  const ui = createUi(config);
  if (logStart) ui.header(VERSION, 'Dependency security agent', tildify(config.projectRoot));
  for (const warning of config.warnings) ui.warn(warning);
  let choice: ProviderChoice | null = null;
  if (usesModel) {
    choice = await chooseProvider(config, ui);
    applyProviderChoice(config, choice);
    for (const note of choice.notes) ui.notice(note);
    const cloud = cloudProviderNotice(config.provider, config.model);
    if (cloud) ui.warn(cloud);
    if (cloud && config.offline) ui.warn('--offline covers vulnerability data and documentation only', `--provider ${config.provider} still needs the network for the model`);
  }
  const preflight = await ensurePreflight(config, ui, needsFor(needs, config.provider));
  if (usesModel) await ensureProviderReady(config, ui);
  const identity = await captureIdentity(config.projectRoot);
  const trust = await ensureTrusted(config.projectRoot, ui, {
    interactive: config.interactive,
    trustFlag: config.trust,
    ollamaHost: config.ollamaHost,
    provider: config.provider,
    ...(isCloudProvider(config.provider) ? { model: config.model } : {}),
    hostSource: sourceLabel(config.sources.ollamaHost),
    identity,
  });
  const audit = AuditLog.open(config.paths.auditLog);
  if (trust.via !== 'stored') {
    audit.log({ event: 'trust.granted', dir: trust.entry.path, remote: trust.entry.remote, method: trust.entry.method, by: identity });
    if (trust.via === 'prompt') ui.check('Trusted', trust.entry.path);
  }
  if (choice) {
    audit.log({
      event: 'provider.selected',
      provider: config.provider,
      model: config.model,
      selection: config.providerSelection,
      cloud: choice.cloud,
      options: choice.options.map((o) => ({ provider: o.provider, available: o.available, detail: o.detail })),
    });
  }
  if (logStart) {
    audit.log({
      event: 'preflight',
      ok: preflight.ok,
      checks: preflight.checks.map(({ id, status, detail }) => ({ id, status, detail })),
      model: preflight.ollama?.resolvedModel ?? null,
      ollamaVersion: preflight.ollama?.version ?? null,
    });
    audit.log({
      event: 'scan.start',
      command,
      dir: config.projectRoot,
      version: VERSION,
      provider: config.provider,
      model: config.model,
      options: runOptions(config),
    });
  }
  return { config, ui, audit, identity, preflight };
}

// plus cost or tokens for cloud
function footerModel(config: Config, provider: ChatProvider, ui: Ui): string {
  const usage = formatUsageSummary(provider.usageSummary?.() ?? null, ui.glyphs.dot);
  if (config.provider === 'codex') return `codex ${ui.glyphs.dot} ${config.model}${usage ? ` ${ui.glyphs.dot} ${usage}` : ''}`;
  return usage ? `${provider.model} ${ui.glyphs.dot} ${usage}` : provider.model;
}

// no context size for cloud
function footerInfo(config: Config, provider: ChatProvider, ui: Ui, info: Omit<FooterInfo, 'model' | 'numCtx'>): FooterInfo {
  const model = footerModel(config, provider, ui);
  return isCloudProvider(config.provider) ? { ...info, model } : { ...info, model, numCtx: config.numCtx };
}

// footer shows cloud model and cost
function providerFooterUi(ui: Ui, config: Config, provider: ChatProvider): Ui {
  if (!isCloudProvider(config.provider)) return ui;
  return new Proxy(ui, {
    get(target, prop, receiver) {
      if (prop === 'footer') return (info: FooterInfo): void => target.footer(footerInfo(config, provider, target, info));
      return Reflect.get(target, prop, receiver) as unknown;
    },
  });
}

// status bar checklist, else plain lines
function enterPhase(ui: Ui, phase: PhaseNumber): void {
  ui.status.set({ phases: ui.phaseItems(phase) });
  ui.status.start();
  if (!ui.status.active) ui.phaseChecklist(phase);
  // phases 2 and 3 open with a header
  else if (phase === 1) ui.info('');
}

function noCaseFile(config: Config): PatchPilotError {
  return new PatchPilotError(`No case file found in ${config.paths.stateDir}`, {
    exitCode: EXIT.USAGE,
    hint: 'Run `patch-pilot scan` first (add --dry-run to stop after the findings).',
  });
}

// scan: phases 1-3
async function scanCommand(dir: string | undefined, flags: CliFlags): Promise<ExitCode> {
  const started = Date.now();
  const firstWrite = !stateDirExists(dir);
  const ctx = await openProject('scan', dir, flags, NEEDS.scan, true, true);
  const { config, ui, audit, identity } = ctx;
  if (firstWrite) await offerGitignore(config, ui);
  const archived = await archiveLastRun(config, { withCache: flags.fresh === true });
  if (archived) {
    audit.log({ event: 'history.archived', dir: archived.dir, files: archived.files });
    ui.check('Kept the last run', archived.dir);
  }
  if (flags.fresh) {
    const removed = await clearProjectState(config);
    audit.log({ event: 'state.reset', removed });
    ui.check('Starting fresh', 'every vulnerability is investigated again');
  }
  const provider = createProvider(config);
  const db = openStateDb(config, ui);
  const run = trackRun(config, ui, 'scan');
  try {
    enterPhase(ui, 1);
    const caseFile = await runPhase1(config, { ui, audit, db, provider });
    enterPhase(ui, 2);
    const assessment =
      config.provider === 'codex'
        ? await runPhase2Delegated(caseFile, config, { ui, audit })
        : await runPhase2(caseFile, config, { provider, ui: providerFooterUi(ui, config, provider), audit, cache: db });
    enterPhase(ui, 3);
    const phase3 = await runPhase3(caseFile, assessment, config, {
      ui,
      audit,
      provider,
      codemodProvider: createCodemodProvider(config),
      identity,
      db,
      // --verbose repeats cards with evidence
      showCards: config.verbose,
    });
    ui.status.stop();
    ui.footer(footerInfo(config, provider, ui, { packages: caseFile.packages.length, cves: caseFile.vulnerabilities.length, elapsedMs: Date.now() - started }));
    const gated = config.ci || config.sources.failOn === 'flag';
    const findings = gated ? exitCodeFor(assessment, config.failOn, { ignore: config.ignore, caseFile, phase3 }) : EXIT.OK;
    const exitCode = mergeExitCodes(findings, phase3.exitCode);
    if (config.json) await printJson(process.stdout, summarizeForJson(caseFile, assessment, phase3, { failOn: config.failOn, ignore: config.ignore, exitCode }));
    else if (findings === EXIT.FINDINGS) ui.warn(`Open findings at or above --fail-on ${config.failOn}`, 'exit code 1');
    run.finish('done');
    return exitCode;
  } catch (error) {
    run.finish('failed', error);
    throw error;
  } finally {
    ui.status.stop();
    db?.close();
  }
}

// investigate: phase 2 from case file
async function investigateCommand(dir: string | undefined, flags: CliFlags): Promise<ExitCode> {
  const firstWrite = !stateDirExists(dir);
  const ctx = await openProject('investigate', dir, flags, NEEDS.investigate, true, true);
  const { config, ui, audit } = ctx;
  if (firstWrite) await offerGitignore(config, ui);
  const caseFile = await loadCaseFile(config.paths.caseFile);
  if (!caseFile) throw noCaseFile(config);
  // a new investigation, not a resume
  if (!config.resume) {
    const archived = await archiveLastRun(config);
    if (archived) {
      audit.log({ event: 'history.archived', dir: archived.dir, files: archived.files });
      ui.check('Kept the last run', archived.dir);
    }
  }
  // damaged assessment, phase 2 restarts
  if (config.resume && (await loadAssessment(config.paths.assessmentFile).catch(() => undefined)) === null) {
    ui.infoLine('Nothing to resume', 'no saved assessment yet: starting a fresh investigation');
  }
  const provider = createProvider(config);
  const db = openStateDb(config, ui);
  const run = trackRun(config, ui, 'investigate');
  try {
    enterPhase(ui, 2);
    const assessment =
      config.provider === 'codex'
        ? await runPhase2Delegated(caseFile, config, { ui, audit })
        : await runPhase2(caseFile, config, { provider, ui: providerFooterUi(ui, config, provider), audit, cache: db });
    ui.status.stop();
    presentFindings(assessment, caseFile, config, ui, { cards: config.verbose });
    ui.info('');
    ui.infoLine('Next', 'patch-pilot apply reviews the fixes and applies the ones you approve');
    const exitCode = config.sources.failOn === 'flag' ? exitCodeFor(assessment, config.failOn, { ignore: config.ignore, caseFile }) : EXIT.OK;
    if (config.json) await printJson(process.stdout, summarizeForJson(caseFile, assessment, null, { failOn: config.failOn, ignore: config.ignore, exitCode }));
    else if (exitCode === EXIT.FINDINGS) ui.warn(`Open findings at or above --fail-on ${config.failOn}`, 'exit code 1');
    run.finish('done');
    return exitCode;
  } catch (error) {
    run.finish('failed', error);
    throw error;
  } finally {
    ui.status.stop();
    db?.close();
  }
}

// apply: phase 3 from assessment
async function applyCommand(dir: string | undefined, flags: CliFlags): Promise<ExitCode> {
  const started = Date.now();
  const firstWrite = !stateDirExists(dir);
  const ctx = await openProject('apply', dir, flags, NEEDS.apply, true, true);
  const { config, ui, audit, identity } = ctx;
  if (firstWrite) await offerGitignore(config, ui);
  const caseFile = await loadCaseFile(config.paths.caseFile);
  if (!caseFile) throw noCaseFile(config);
  const assessment = await loadAssessment(config.paths.assessmentFile);
  if (!assessment) {
    throw new PatchPilotError(`No assessment found in ${config.paths.stateDir}`, {
      exitCode: EXIT.USAGE,
      hint: 'Run `patch-pilot investigate` (or `patch-pilot scan`) first.',
    });
  }
  if (!assessment.complete) ui.warn('The saved investigation is incomplete', 'finish it with patch-pilot investigate --resume; applying the verdicts it has');
  const provider = createProvider(config);
  const db = openStateDb(config, ui);
  const run = trackRun(config, ui, 'apply');
  try {
    enterPhase(ui, 3);
    const phase3 = await runPhase3(caseFile, assessment, config, {
      ui,
      audit,
      provider,
      codemodProvider: createCodemodProvider(config),
      identity,
      db,
      showCards: true,
    });
    ui.status.stop();
    const investigated = new Set(assessment.verdicts.map((v) => `${v.package}@${v.installedVersion}`));
    ui.footer(footerInfo(config, provider, ui, { packages: investigated.size, cves: assessment.verdicts.length, elapsedMs: Date.now() - started }));
    const gated = config.ci || config.sources.failOn === 'flag';
    const findings = gated ? exitCodeFor(assessment, config.failOn, { ignore: config.ignore, caseFile, phase3 }) : EXIT.OK;
    const exitCode = mergeExitCodes(findings, phase3.exitCode);
    if (config.json) await printJson(process.stdout, summarizeForJson(caseFile, assessment, phase3, { failOn: config.failOn, ignore: config.ignore, exitCode }));
    else if (findings === EXIT.FINDINGS) ui.warn(`Open findings at or above --fail-on ${config.failOn}`, 'exit code 1');
    run.finish('done');
    return exitCode;
  } catch (error) {
    run.finish('failed', error);
    throw error;
  } finally {
    ui.status.stop();
    db?.close();
  }
}

// report: re-render md and json
async function reportCommand(dir: string | undefined, flags: CliFlags): Promise<ExitCode> {
  const ctx = await openProject('report', dir, flags, NEEDS.basic, false);
  const { config, ui, audit } = ctx;
  const written = await writeReports(config, { ui, audit });
  if (config.json) ui.printJson(written);
  else {
    const rel = (p: string): string => path.relative(config.projectRoot, p) || p;
    ui.check('Wrote the reports', `${rel(written.md)} ${ui.glyphs.dot} ${rel(written.json)}`);
  }
  return EXIT.OK;
}

// rollback: restore latest backup
async function rollbackCommand(dir: string | undefined, flags: CliFlags): Promise<ExitCode> {
  const ctx = await openProject('rollback', dir, flags, NEEDS.basic, false);
  const result = await rollbackLatest(ctx.config, ctx.ui, ctx.audit);
  // refresh rollbacks section, report optional
  const reports = await writeReports(ctx.config, { ui: ctx.ui, audit: ctx.audit }).catch(() => null);
  if (ctx.config.json) ctx.ui.printJson(result);
  else if (reports) ctx.ui.infoLine('Updated the report', path.relative(ctx.config.projectRoot, reports.md));
  return result.mismatched.length > 0 || result.missing.length > 0 ? EXIT.PATCH_FAILED : EXIT.OK;
}

interface IgnoreFlags extends CliFlags {
  reason: string;
  until?: string;
  package?: string;
  dir?: string;
}

// ignore <id>: accepted risk to config and audit
async function ignoreCommand(id: string, flags: IgnoreFlags): Promise<ExitCode> {
  const reason = flags.reason.trim();
  if (reason === '') throw new ConfigError('An accepted risk needs a reason: --reason "why this is acceptable"');
  if (flags.until !== undefined && parseUntil(flags.until) === null) {
    throw new ConfigError(`Invalid --until date: ${flags.until} (use YYYY-MM-DD)`);
  }
  const ctx = await openProject('ignore', flags.dir, flags, NEEDS.basic, false);
  const entry: IgnoreEntry = { id: id.trim(), reason, by: formatIdentity(ctx.identity), createdAt: new Date().toISOString() };
  if (flags.package) entry.package = flags.package.trim();
  if (flags.until) entry.until = flags.until.trim();
  await addIgnoreEntry(ctx.config.projectRoot, entry);
  ctx.audit.log({
    event: 'risk.accepted',
    vulnId: entry.id,
    ...(entry.package ? { package: entry.package } : {}),
    reason,
    ...(entry.until ? { until: entry.until } : {}),
    by: ctx.identity,
    source: 'command',
  });
  if (ctx.config.json) ctx.ui.printJson(entry);
  else {
    const scope = entry.package ? ` in ${entry.package}` : '';
    const expiry = entry.until ? ` until ${entry.until}` : '';
    ctx.ui.check(`Accepted risk ${entry.id}${scope}${expiry}`, 'recorded in patch-pilot.config.json');
    const untilDate = entry.until ? parseUntil(entry.until) : null;
    if (untilDate && untilDate.getTime() < Date.now()) ctx.ui.warn('That date is in the past, so the risk is reported again.');
  }
  return EXIT.OK;
}

async function trustCommand(dir: string | undefined, flags: CliFlags): Promise<ExitCode> {
  const config = await loadConfig({ dir, flags, skipProjectFile: true });
  const ui = createUi(config);
  await ensurePreflight(config, ui, NEEDS.basic);
  const identity = await captureIdentity(config.projectRoot);
  const entry = await trustDirectory(config.projectRoot, { by: formatIdentity(identity), method: 'command' });
  AuditLog.open(projectPaths(entry.path).auditLog).log({
    event: 'trust.granted',
    dir: entry.path,
    remote: entry.remote,
    method: 'command',
    by: identity,
  });
  if (config.json) ui.printJson(entry);
  else {
    ui.check(`Trusted ${entry.path}`, entry.remote ? `git remote ${entry.remote}` : undefined);
    ui.info(ui.formatDimLines([`stored in ${tildify(trustStorePath())}`]));
  }
  return EXIT.OK;
}

async function untrustCommand(dir: string | undefined, flags: CliFlags): Promise<ExitCode> {
  const ui = createUi({ json: flags.json, quiet: flags.quiet, color: flags.color });
  const target = dir ?? '.';
  const shown = target === '.' ? process.cwd() : target;
  const removed = await untrustDirectory(target);
  if (flags.json) ui.printJson({ dir: target, removed });
  else if (removed) ui.check('No longer trusted', shown);
  else ui.infoLine('Not in the trusted list', shown);
  return EXIT.OK;
}

interface DbSyncFlags extends CliFlags {
  includeMalware?: boolean;
  full?: boolean;
}

async function dbSyncCommand(flags: DbSyncFlags): Promise<ExitCode> {
  const config = await loadConfig({ flags, skipProjectFile: true });
  const ui = createUi(config);
  await ensurePreflight(config, ui, NEEDS.db);
  const result = await syncSnapshot(config, ui, { includeMalware: flags.includeMalware ?? false, full: flags.full ?? false });
  if (config.json) ui.printJson(result);
  return EXIT.OK;
}

async function dbStatusCommand(flags: CliFlags): Promise<ExitCode> {
  const config = await loadConfig({ flags, skipProjectFile: true });
  const ui = createUi(config);
  await ensurePreflight(config, ui, NEEDS.basic);
  const status = await snapshotStatus(config);
  if (config.json) ui.printJson(status);
  else ui.print(renderDbStatus(status, ui));
  return EXIT.OK;
}

function configUi(flags: CliFlags): Ui {
  return createUi({ json: flags.json, quiet: flags.quiet, color: flags.color, interactive: Boolean(process.stdin.isTTY && process.stdout.isTTY) });
}

async function configSetCommand(key: string, value: string | undefined, flags: CliFlags): Promise<ExitCode> {
  const ui = configUi(flags);
  await configSet(key, value, ui, { interactive: ui.interactive });
  return EXIT.OK;
}

async function configGetCommand(key: string, flags: CliFlags & { reveal?: boolean }): Promise<ExitCode> {
  const ui = configUi(flags);
  await configGet(key, ui, { reveal: flags.reveal ?? false });
  return EXIT.OK;
}

async function configUnsetCommand(key: string, flags: CliFlags): Promise<ExitCode> {
  const ui = configUi(flags);
  await configUnset(key, ui);
  return EXIT.OK;
}

interface DoctorFlags extends CliFlags {
  fix?: boolean;
}

async function doctorFix(config: Config, ui: Ui, result: PreflightResult): Promise<PreflightResult> {
  if (config.provider === 'mock') {
    ui.info('Nothing to fix: the mock provider does not need Ollama.');
    return result;
  }
  const probe = result.ollama;
  if (!probe?.reachable) {
    ui.warn('Cannot pull the model: Ollama is not reachable. Start it with: ollama serve');
    return result;
  }
  const modelMissing = probe.resolvedModel === null || probe.fallback;
  if (!modelMissing) {
    ui.info(`Nothing to pull: ${probe.resolvedModel} is installed.`);
    return result;
  }
  const model = probe.requestedModel;
  ui.info('');
  ui.activity(`Pulling ${model} from the Ollama library (this can take a few minutes)...`);
  const progress = ui.progressLine();
  let bucket = -1;
  await pullModel(config.ollamaHost, model, (p: PullProgress) => {
    if (progress.tty) {
      progress.update(renderPullProgress(p));
      return;
    }
    const pct = p.total ? Math.floor(((p.completed ?? 0) / p.total) * 4) : -1;
    if (pct !== bucket || !p.total) {
      bucket = pct;
      progress.update(renderPullProgress({ ...p, completed: p.total ? Math.floor((pct / 4) * p.total) : p.completed }));
    }
  });
  progress.done();
  ui.check(`Pulled ${model}`);
  const again = await runPreflight(config, NEEDS.doctor);
  ui.print('');
  ui.print(renderPreflight(again, ui, { mode: 'doctor', dir: tildify(config.projectRoot) }));
  return again;
}

// doctor: --fix pulls the model
async function doctorCommand(flags: DoctorFlags): Promise<ExitCode> {
  const config = await loadConfig({ flags });
  const ui = createUi(config);
  for (const warning of config.warnings) ui.warn(warning);
  let result = await runPreflight(config, needsFor(NEEDS.doctor, config.provider));
  const providers = await detectProviders(config).catch(() => null);
  const selected = providers?.options.find((o) => o.provider === config.provider);
  const providerOk = !isCloudProvider(config.provider) || Boolean(selected?.available);
  if (config.json && !flags.fix) {
    ui.printJson({ ...result, ok: result.ok && providerOk, providers: providers?.options ?? [] });
    return result.ok && providerOk ? EXIT.OK : EXIT.ENVIRONMENT;
  }
  ui.print(renderPreflight(result, ui, { mode: 'doctor', dir: tildify(config.projectRoot) }));
  if (providers) ui.print(renderProviderLines(providers.options, ui, config.provider));
  if (flags.fix) result = await doctorFix(config, ui, result);
  if (config.json) ui.printJson({ ...result, ok: result.ok && providerOk, providers: providers?.options ?? [] });
  return result.ok && providerOk ? EXIT.OK : EXIT.ENVIRONMENT;
}

interface McpFlags {
  project?: string;
  session?: string;
  printConfig?: boolean;
  provider?: string;
  model?: string;
}

// mcp: stdio, setup, or --print-config
async function mcpCommand(target: string | undefined, flags: McpFlags): Promise<ExitCode> {
  if (flags.printConfig) {
    const config = await loadConfig({ dir: flags.project, flags: {}, skipProjectFile: true });
    process.stdout.write(`${mcpConfigText(config.projectRoot, await selfCommand())}\n`);
    return EXIT.OK;
  }
  if (target !== undefined) {
    if (!isMcpTarget(target)) {
      throw new PatchPilotError(`Unknown MCP target "${target}"`, { exitCode: EXIT.USAGE, hint: 'Use: patch-pilot mcp claude, patch-pilot mcp codex, or patch-pilot mcp --print-config' });
    }
    const config = await loadConfig({ dir: flags.project, flags: {}, skipProjectFile: true });
    const ui = createUi(config);
    return setupMcp(target, { projectRoot: config.projectRoot, ui, interactive: config.interactive });
  }
  if (process.stdin.isTTY && process.stdout.isTTY) {
    // run by hand, explain instead of hanging
    const config = await loadConfig({ dir: flags.project, flags: {}, skipProjectFile: true });
    process.stdout.write(`${mcpGuidanceText(config.projectRoot)}\n`);
    return EXIT.USAGE;
  }
  await runMcpStdioServer({
    ...(flags.project ? { project: flags.project } : {}),
    ...(flags.session ? { session: flags.session } : {}),
    ...(flags.provider ? { provider: flags.provider } : {}),
    ...(flags.model ? { model: flags.model } : {}),
  });
  return EXIT.OK;
}

const HELP_FOOTER = `
Examples:
  $ cd my-app && patch-pilot          scan, investigate and fix, asking before any change
  $ patch-pilot scan --dry-run        findings only, change nothing
  $ patch-pilot --only lodash,marked  investigate two packages
  $ patch-pilot --ci --fail-on high   CI: reports plus an exit code, no prompts, no changes
  $ patch-pilot doctor --fix          check prerequisites and pull the model
  $ patch-pilot mcp --print-config    use PatchPilot's tools inside Claude Code or Codex

Exit codes:
  0 ok, 1 findings at or above --fail-on, 2 usage/config error or untrusted directory,
  3 environment error (Ollama, model, lockfile), 4 patch failed (backup restored)
`;

export interface ProgramState {
  exitCode: ExitCode;
}

// handlers store exit code in state
export function buildProgram(state: ProgramState = { exitCode: EXIT.OK }): Command {
  const run =
    <A extends unknown[]>(handler: (...args: A) => Promise<ExitCode>) =>
    async (...args: A): Promise<void> => {
      state.exitCode = await handler(...args);
    };

  const program = new Command('patch-pilot');
  program
    .description(
      'Local-first agent that checks whether your npm dependency vulnerabilities are really reachable in your code, ' +
        'explains the risk, and applies only the fixes you approve, with a full audit trail.',
    )
    .version(VERSION, '-v, --version', 'print the version')
    .helpOption('-h, --help', 'show help')
    .exitOverride()
    .showHelpAfterError('(run patch-pilot --help for usage)')
    .addHelpText('after', HELP_FOOTER);

  withOptions(
    program
      .command('scan [dir]', { isDefault: true })
      .description('(default command) preflight, trust gate, then phases 1-3: evidence, investigation, approved fixes'),
    SCAN_OPTIONS,
  ).action(run((dir: string | undefined, opts: CliFlags) => scanCommand(dir, opts)));

  withOptions(
    program.command('investigate [dir]').description('phase 2 only: investigate the saved case file (.patch-pilot/case-file.json)'),
    INVESTIGATE_OPTIONS,
  ).action(run((dir: string | undefined, opts: CliFlags) => investigateCommand(dir, opts)));

  withOptions(
    program.command('apply [dir]').description('phase 3 only: present, approve and apply from the saved assessment'),
    APPLY_OPTIONS,
  ).action(run((dir: string | undefined, opts: CliFlags) => applyCommand(dir, opts)));

  withOptions(program.command('report [dir]').description('re-render .patch-pilot/report.md and report.json'), [
    'trust',
    ...OUTPUT_OPTIONS,
  ]).action(run((dir: string | undefined, opts: CliFlags) => reportCommand(dir, opts)));

  withOptions(
    program
      .command('ignore <id>')
      .description('accept a risk: recorded in patch-pilot.config.json and the audit log')
      .requiredOption('--reason <text>', 'why the risk is acceptable')
      .option('--until <date>', 'expiry date (YYYY-MM-DD); the finding resurfaces afterwards')
      .option('--package <name>', 'limit the entry to one package')
      .option('--dir <dir>', 'project directory (default: current directory)'),
    ['trust', 'json', 'quiet', 'noColor'],
  ).action(run((id: string, opts: IgnoreFlags) => ignoreCommand(id, opts)));

  withOptions(program.command('trust [dir]').description('trust a directory (stored in ~/.patch-pilot/trusted.json)'), [
    'json',
    'quiet',
    'noColor',
  ]).action(run((dir: string | undefined, opts: CliFlags) => trustCommand(dir, opts)));

  withOptions(program.command('untrust [dir]').description('remove a directory from the trusted list'), [
    'json',
    'quiet',
    'noColor',
  ]).action(run((dir: string | undefined, opts: CliFlags) => untrustCommand(dir, opts)));

  const db = program.command('db').description('offline OSV snapshot management (~/.patch-pilot/patch-pilot.db)');
  withOptions(
    db
      .command('sync')
      .description('download the OSV npm snapshot for offline scans (about 216 MB)')
      .option('--include-malware', 'also load MAL-* malware records')
      .option('--full', 're-download everything instead of an incremental sync'),
    OUTPUT_OPTIONS,
  ).action(run((opts: DbSyncFlags) => dbSyncCommand(opts)));
  withOptions(db.command('status').description('show the local database and snapshot status'), ['json', 'noColor']).action(
    run((opts: CliFlags) => dbStatusCommand(opts)),
  );

  const configCmd = program
    .command('config')
    .description('user-level settings in ~/.patch-pilot/config.json (mode 0600), for example the Ollama API key');
  const keyList = Object.keys(USER_CONFIG_KEYS).join(', ');
  withOptions(
    configCmd
      .command('set <key> [value]')
      .description(`set a value (omit it to be asked without echo). Keys: ${keyList}`),
    ['json', 'quiet', 'noColor'],
  ).action(run((key: string, value: string | undefined, opts: CliFlags) => configSetCommand(key, value, opts)));
  withOptions(
    configCmd
      .command('get <key>')
      .description('print a value and where it comes from (secrets are masked)')
      .option('--reveal', 'print secret values instead of masking them'),
    ['json', 'noColor'],
  ).action(run((key: string, opts: CliFlags & { reveal?: boolean }) => configGetCommand(key, opts)));
  withOptions(configCmd.command('unset <key>').description('remove a value from ~/.patch-pilot/config.json'), ['json', 'quiet', 'noColor']).action(
    run((key: string, opts: CliFlags) => configUnsetCommand(key, opts)),
  );

  withOptions(
    program
      .command('doctor')
      .description('check Node, npm, Ollama, the model and its tool support, keys, OSV, the registry and the local DB')
      .option('--fix', 'pull the missing model through Ollama'),
    ['provider', 'model', 'codemodModel', 'ollamaHost', 'offline', 'search', 'json', 'verbose', 'noColor'],
  ).action(run((opts: DoctorFlags) => doctorCommand(opts)));

  withOptions(program.command('rollback [dir]').description('restore the last backup (package.json, lockfile, edited source files)'), [
    'trust',
    ...OUTPUT_OPTIONS,
  ]).action(run((dir: string | undefined, opts: CliFlags) => rollbackCommand(dir, opts)));

  program
    .command('mcp [target]')
    .description(
      "use PatchPilot's investigation tools inside your own Claude Code or Codex: `mcp claude` or `mcp codex` registers the server for this project, `--print-config` prints the snippets; with no argument it serves MCP over stdio (started by those tools, not by hand)",
    )
    .option('--project <dir>', 'project directory (default: current directory)')
    .option('--session <file>', 'append a JSONL trace of every tool call and verdict to this file')
    .option('--print-config', 'print the Claude Code and Codex configuration for this project')
    .addOption(new Option('--provider <name>', 'provider recorded in the verdicts').choices(['claude', 'codex']).hideHelp())
    .addOption(new Option('--model <name>', 'model recorded in the verdicts').hideHelp())
    .action(run((target: string | undefined, opts: McpFlags) => mcpCommand(target, opts)));

  return program;
}

// returns the exit code
export function reportError(err: unknown, options: { verbose?: boolean } = {}): ExitCode {
  if (err instanceof CommanderError) {
    if (err.code === 'commander.helpDisplayed' || err.code === 'commander.version' || err.exitCode === 0) return EXIT.OK;
    return EXIT.USAGE; // commander already printed it
  }
  const ui = createUi({});
  if (isPromptCancelled(err)) {
    ui.error('Cancelled.');
    return EXIT.INTERRUPTED;
  }
  const hint = (text: string): void => ui.errorBlock(ui.formatDimLines([text], 2, ui.ce));
  if (err instanceof PatchPilotError) {
    if (!err.printed) {
      ui.error(err.message);
      if (err.hint) hint(err.hint);
    }
    return err.exitCode;
  }
  if (err instanceof LlmError) {
    ui.error(err.message);
    if (err.hint) hint(err.hint);
    return EXIT.ENVIRONMENT;
  }
  if (err instanceof NetworkError) {
    ui.error(err.message);
    hint('Check your connection, or re-run with --offline to use cached data.');
    return EXIT.ENVIRONMENT;
  }
  if (isNotImplemented(err)) {
    ui.error(`${errorMessage(err)}. This part of PatchPilot is not built yet.`);
    return EXIT.INTERNAL;
  }
  ui.error(`Unexpected error: ${errorMessage(err)}`);
  if (options.verbose && err instanceof Error && err.stack) ui.errorBlock(ui.ce.dim(err.stack));
  else hint('Re-run with --verbose (or PATCHPILOT_DEBUG=1) for the stack trace.');
  return EXIT.INTERNAL;
}

// entry for bin, sets process.exitCode
export async function main(argv: readonly string[] = process.argv): Promise<ExitCode> {
  const state: ProgramState = { exitCode: EXIT.OK };
  const program = buildProgram(state);
  let code: ExitCode;
  try {
    await program.parseAsync([...argv]);
    code = state.exitCode;
  } catch (err) {
    // restore terminal before printing
    restoreTerminal();
    code = reportError(err, { verbose: argv.includes('--verbose') || Boolean(process.env.PATCHPILOT_DEBUG) });
  }
  process.exitCode = code;
  return code;
}
