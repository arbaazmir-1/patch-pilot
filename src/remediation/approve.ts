// approval gate
import { select } from '@inquirer/prompts';
import { formatIdentity } from '../audit.ts';
import { addIgnoreEntry, parseUntil } from '../config.ts';
import type { Action, ApprovalChoice, ApprovalMode, ApprovalRecord, Assessment, AuditSink, CaseFile, Config, Identity, IgnoreEntry } from '../types.ts';
import type { Ui } from '../ui.ts';
import { ConfigError } from '../util/errors.ts';
import type { MigrationFns } from './patch.ts';
import { actionLabel, renderActionDetails, renderMigrationReview, type ActionDetailsOptions } from './present.ts';

export type GateChoice = 'approve' | 'reject' | 'details' | 'accept-risk' | 'reject-all';

// injectable for tests
export interface PromptAdapter {
  select<T extends string>(message: string, choices: { name: string; value: T; description?: string }[]): Promise<T>;
  input(message: string, options?: { default?: string; validate?: (value: string) => true | string }): Promise<string>;
  confirm(message: string, defaultValue?: boolean): Promise<boolean>;
  // returns the key pressed
  key?(question: string, keys: string, options?: { defaultKey?: string; labels?: Record<string, string> }): Promise<string>;
}

export interface ApprovalContext {
  config: Config;
  ui: Ui;
  audit: AuditSink;
  identity: Identity;
  prompt?: PromptAdapter;
  // verdict reasoning and evidence
  caseFile?: CaseFile | null;
  assessment?: Assessment | null;
  // real command in the details view
  details?: Pick<ActionDetailsOptions, 'graph' | 'manager' | 'invocation'>;
  // runPhase3 applies approvals here
  onDecision?: (action: Action, record: ApprovalRecord) => Promise<void>;
  // injectable for tests
  migration?: Partial<Pick<MigrationFns, 'renderBrief' | 'manualChecklist'>>;
}

export const KEY_CHOICES: Record<string, string> = {
  y: 'yes, apply it',
  n: 'no, skip it',
  d: 'details (or the diff)',
  a: 'accept the risk, with a reason',
  q: 'quit: skip the rest',
};

export const KEY_LEGEND = 'y apply the patch  n skip it  d show details or the diff  a accept the risk with a reason  q stop and skip the rest  ? show this again';

// tty, not --ci or --json
export function canPrompt(config: Pick<Config, 'interactive'>, ui: Pick<Ui, 'interactive'>, prompt?: PromptAdapter): boolean {
  return config.interactive && (prompt !== undefined || ui.interactive);
}

// select via @inquirer/prompts
export function defaultPromptAdapter(ui: Ui): PromptAdapter {
  return {
    select: <T extends string>(message: string, choices: { name: string; value: T; description?: string }[]): Promise<T> =>
      select<T>({ message: ui.text(message), choices }),
    input: (message, options = {}) => ui.textPrompt(message, options),
    confirm: async (message, defaultValue = false) => (await ui.singleKeyPrompt(message, 'y/n', defaultValue ? { defaultKey: 'y' } : {})) === 'y',
    key: (question, keys, options = {}) => ui.singleKeyPrompt(question, keys, options),
  };
}

async function askKey(prompt: PromptAdapter, question: string, keys: string): Promise<string> {
  if (prompt.key) return (await prompt.key(question, keys, { labels: KEY_CHOICES })).toLowerCase();
  const choices = keys
    .split('/')
    .map((k) => k.trim())
    .filter(Boolean)
    .map((k) => ({ name: `${k}  ${KEY_CHOICES[k] ?? k}`, value: k }));
  return prompt.select(`${question} (${keys})`, choices);
}

// flags given, never prompt
export function flagMode(config: Pick<Config, 'approveAll' | 'approve' | 'approveCodemods'>): boolean {
  return config.approveAll || config.approve.length > 0 || config.approveCodemods;
}

// name, name@from, name@to or id
export function approveMatches(list: readonly string[], action: Pick<Action, 'id' | 'package' | 'fromVersion' | 'toVersion'>): boolean {
  return list.some((raw) => {
    const entry = raw.trim();
    return entry === action.package || entry === `${action.package}@${action.fromVersion}` || entry === `${action.package}@${action.toVersion}` || entry === action.id;
  });
}

function scopeOf(action: Action): ApprovalRecord['scope'] {
  return action.requiresMigration && (action.codemod?.patches.length ?? 0) > 0 ? 'transaction' : 'bump';
}

export function makeRecord(
  action: Pick<Action, 'id' | 'package'> & Partial<Action>,
  decision: ApprovalChoice,
  mode: ApprovalMode,
  identity: Identity,
  extra: Partial<ApprovalRecord> = {},
): ApprovalRecord {
  return {
    actionId: action.id,
    package: action.package,
    decision,
    mode,
    scope: action.kind ? scopeOf(action as Action) : 'bump',
    by: identity,
    at: new Date().toISOString(),
    ...extra,
  };
}

export function logApproval(audit: AuditSink, action: Pick<Action, 'kind'>, record: ApprovalRecord): void {
  audit.log({
    event: 'approval',
    actionId: record.actionId,
    package: record.package,
    kind: action.kind,
    decision: record.decision,
    mode: record.mode,
    scope: record.scope,
    ...(record.files ? { files: record.files } : {}),
    by: record.by,
    ...(record.reason ? { reason: record.reason } : {}),
  });
}

// reject all without a tty
export function nonInteractiveApprovals(actions: readonly Action[], config: Config, identity: Identity): ApprovalRecord[] {
  const flags = flagMode(config);
  return actions.map((action) => {
    if (!flags) {
      return makeRecord(action, 'reject', 'non-interactive', identity, {
        reason: 'no interactive terminal: nothing is applied without --approve-all or --approve <pkgs>',
      });
    }
    const selected = config.approveAll || approveMatches(config.approve, action);
    if (!selected) {
      return makeRecord(action, 'reject', 'flag', identity, {
        reason: config.approve.length > 0 ? 'not listed in --approve' : '--approve-codemods alone approves nothing (add --approve-all or --approve <pkgs>)',
      });
    }
    const via = config.approveAll ? '--approve-all' : `--approve ${action.package}`;
    if (action.requiresMigration) {
      const patches = action.codemod?.patches ?? [];
      if (!config.approveCodemods) {
        return makeRecord(action, 'reject', 'flag', identity, { reason: 'major bump with source changes: code edits need --approve-codemods' });
      }
      if (patches.length === 0) {
        return makeRecord(action, 'reject', 'flag', identity, {
          reason: 'no validated code edits for this major bump: review the migration checklist in a terminal',
        });
      }
      return makeRecord(action, 'approve', 'flag', identity, {
        scope: 'transaction',
        files: patches.map((p) => ({ file: p.file, approved: true })),
        reason: `${via} --approve-codemods`,
      });
    }
    return makeRecord(action, 'approve', 'flag', identity, { reason: via });
  });
}

// config file and audit
export async function acceptRisk(action: Action, reason: string, until: string | undefined, ctx: ApprovalContext): Promise<IgnoreEntry[]> {
  const { config, audit, identity, ui } = ctx;
  const why = reason.trim();
  if (why === '') throw new ConfigError('An accepted risk needs a reason');
  const expiry = until?.trim() || undefined;
  if (expiry !== undefined && parseUntil(expiry) === null) throw new ConfigError(`Invalid expiry date: ${expiry} (use YYYY-MM-DD)`);
  const by = formatIdentity(identity);
  const createdAt = new Date().toISOString();
  const entries: IgnoreEntry[] = [];
  for (const vulnId of action.vulnIds) {
    const entry: IgnoreEntry = { id: vulnId, package: action.package, reason: why, by, createdAt };
    if (expiry) entry.until = expiry;
    await addIgnoreEntry(config.projectRoot, entry);
    audit.log({ event: 'risk.accepted', vulnId, package: action.package, reason: why, ...(expiry ? { until: expiry } : {}), by: identity, source: 'gate' });
    config.ignore = [...config.ignore.filter((e) => !(e.id === entry.id && (e.package ?? null) === entry.package)), entry];
    entries.push(entry);
  }
  ui.check(
    `Accepted the risk of ${entries.length} ${entries.length === 1 ? 'CVE' : 'CVEs'} in ${action.package}`,
    `recorded in patch-pilot.config.json${expiry ? ` until ${expiry}` : ''}`,
  );
  return entries;
}

async function acceptRiskFlow(action: Action, ctx: ApprovalContext, prompt: PromptAdapter): Promise<ApprovalRecord> {
  const reason = (await prompt.input('Why is this risk acceptable?', { validate: (v) => (v.trim() !== '' ? true : 'A reason is required') })).trim();
  const until = (
    await prompt.input('Accept until (YYYY-MM-DD, empty for no expiry)?', {
      validate: (v) => (v.trim() === '' || parseUntil(v.trim()) !== null ? true : 'Use a date such as 2026-12-31, or leave it empty'),
    })
  ).trim();
  await acceptRisk(action, reason, until || undefined, ctx);
  return makeRecord(action, 'accept-risk', 'interactive', ctx.identity, { reason, ...(until ? { until } : {}) });
}

// no edits means bump only
async function reviewMigration(action: Action, ctx: ApprovalContext, prompt: PromptAdapter): Promise<ApprovalRecord> {
  const { ui, identity } = ctx;
  ui.info('');
  ui.info(renderMigrationReview(action, ui, ctx.migration));
  const patches = action.codemod?.patches ?? [];
  if (patches.length > 0) {
    const bodyLines = (diff: string): number => diff.split('\n').filter((l) => /^[ +-]/.test(l) && !/^(---|\+\+\+) /.test(l)).length;
    const truncated = patches.some((p) => bodyLines(p.diff) > 40);
    ui.info('');
    for (const p of patches) ui.diffBlock(p.file, p.diff);
    for (;;) {
      const key = await askKey(prompt, 'Apply these changes?', truncated ? 'y/n/d' : 'y/n');
      if (key === 'd') {
        for (const p of patches) ui.diffBlock(p.file, p.diff, Number.MAX_SAFE_INTEGER);
        continue;
      }
      const approved = key === 'y';
      return makeRecord(action, approved ? 'approve' : 'reject', 'interactive', identity, {
        scope: 'transaction',
        files: patches.map((p) => ({ file: p.file, approved })),
      });
    }
  }
  const key = await askKey(prompt, `Bump ${action.package} to ${action.toVersion} without code changes?`, 'y/n');
  return makeRecord(action, key === 'y' ? 'approve' : 'reject', 'interactive', identity, {
    scope: 'bump',
    reason: key === 'y' ? 'bumped without code changes: the migration is done by hand' : 'no validated code edits for the major bump',
  });
}

async function askAction(action: Action, ctx: ApprovalContext, prompt: PromptAdapter): Promise<ApprovalRecord | 'reject-all'> {
  const { ui, identity } = ctx;
  for (;;) {
    ui.info('');
    const key = await askKey(prompt, `Apply patch for ${action.package}@${action.toVersion}?`, 'y/n/d/a/q');
    switch (key) {
      case 'n':
        return makeRecord(action, 'reject', 'interactive', identity);
      case 'q':
        return 'reject-all';
      case 'a':
        return acceptRiskFlow(action, ctx, prompt);
      case 'y':
        return action.requiresMigration ? reviewMigration(action, ctx, prompt) : makeRecord(action, 'approve', 'interactive', identity);
      case 'd':
        if (action.requiresMigration) return reviewMigration(action, ctx, prompt);
        ui.info('');
        ui.info(renderActionDetails(action, ui, { ...ctx.details, caseFile: ctx.caseFile ?? null, assessment: ctx.assessment ?? null }));
        break;
      default:
        break;
    }
  }
}

export async function runApprovalGate(actions: readonly Action[], ctx: ApprovalContext): Promise<ApprovalRecord[]> {
  const { config, ui, audit, identity } = ctx;
  const records: ApprovalRecord[] = [];
  if (actions.length === 0) return records;
  const emit = async (action: Action, record: ApprovalRecord): Promise<void> => {
    logApproval(audit, action, record);
    records.push(record);
    await ctx.onDecision?.(action, record);
  };

  const flags = flagMode(config);
  if (flags || !canPrompt(config, ui, ctx.prompt)) {
    const unknown = config.approve.filter((name) => !actions.some((a) => approveMatches([name], a)));
    if (unknown.length > 0) ui.warn(`--approve ${unknown.join(', ')}: no planned action for ${unknown.length === 1 ? 'that package' : 'those packages'}`);
    if (config.approveCodemods && !config.approveAll && config.approve.length === 0) {
      ui.warn('--approve-codemods only adds code edits to --approve-all or --approve <pkgs>');
    }
    if (!flags) ui.infoLine('No interactive terminal: nothing is applied', 'approve with --approve-all (version bumps) or --approve <pkgs>');
    const decided = nonInteractiveApprovals(actions, config, identity);
    for (const [i, action] of actions.entries()) {
      const record = decided[i] as ApprovalRecord;
      if (flags) {
        ui.info('');
        if (record.decision === 'approve') ui.check(`Approved ${actionLabel(action, ui)}`, record.reason);
        else ui.infoLine(`Skipped ${actionLabel(action, ui)}`, record.reason);
      }
      await emit(action, record);
    }
    return records;
  }

  const prompt = ctx.prompt ?? defaultPromptAdapter(ui);
  ui.info('');
  ui.infoLine('Keys', KEY_LEGEND);
  let rejectAll = false;
  for (const action of actions) {
    if (rejectAll) {
      await emit(action, makeRecord(action, 'reject', 'interactive', identity, { reason: 'reject all remaining' }));
      continue;
    }
    const answer = await askAction(action, ctx, prompt);
    if (answer === 'reject-all') {
      rejectAll = true;
      await emit(action, makeRecord(action, 'reject', 'interactive', identity, { reason: 'reject all remaining' }));
      const left = actions.length - records.length;
      ui.infoLine(`Rejected ${action.package}${left > 0 ? ` and the ${left} remaining ${left === 1 ? 'action' : 'actions'}` : ''}`);
      continue;
    }
    await emit(action, answer);
  }
  return records;
}
