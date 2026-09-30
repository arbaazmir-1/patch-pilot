// table, cards, action list, gate views
import { findIgnore, riskRank } from '../config.ts';
import { severityLabel } from '../evidence/casefile.ts';
import { recommendationText } from '../investigation/agent.ts';
import { displayVulnId, vulnLabel } from '../investigation/prompts.ts';
import type {
  Action,
  Assessment,
  CaseFile,
  Config,
  DependencyGraph,
  LockfileNodeChange,
  MigrationBrief,
  PackageManager,
  Recommendation,
  RiskLevel,
  SeverityLabel,
  Verdict,
  VulnCase,
} from '../types.ts';
import type { ActionItemInfo, TableColumn, Ui } from '../ui.ts';
import { wrapText } from '../ui.ts';
import { errorMessage } from '../util/errors.ts';
import { manualChecklist as defaultManualChecklist, renderBrief as defaultRenderBrief } from './migration.ts';
import type { ManagerCommandOptions, ManagerInvocation, MigrationFns } from './patch.ts';
import { commandLine, directAlias, managerMajor, overrideEntries, pnpmOverrideEntries, pnpmOverrideFile, yarnResolutionEntries } from './patch.ts';

const EM_DASH = new RegExp(`\\s*${String.fromCharCode(0x2014)}\\s*`, 'g');

// em dashes to commas
export function clean(text: string | null | undefined): string {
  return String(text ?? '').replace(EM_DASH, ', ');
}

const GHSA_RANK: Record<SeverityLabel, number> = { UNKNOWN: 0, LOW: 1, MODERATE: 2, HIGH: 3, CRITICAL: 4 };

function plural(n: number, word: string, pluralWord = `${word}s`): string {
  return `${n} ${n === 1 ? word : pluralWord}`;
}

function vulnKey(id: string, pkg: string, version: string): string {
  return `${id}|${pkg}|${version}`;
}

// keyed by id, package, version
export function indexVulns(caseFile: CaseFile | null | undefined): Map<string, VulnCase> {
  const map = new Map<string, VulnCase>();
  for (const v of caseFile?.vulnerabilities ?? []) map.set(vulnKey(v.id, v.package, v.installedVersion), v);
  return map;
}

export function vulnFor(verdict: Pick<Verdict, 'vulnId' | 'package' | 'installedVersion'>, caseFile: CaseFile | null | undefined): VulnCase | undefined {
  return caseFile?.vulnerabilities.find((v) => v.id === verdict.vulnId && v.package === verdict.package && v.installedVersion === verdict.installedVersion);
}

function ghsaOf(vuln: VulnCase | undefined): SeverityLabel {
  return vuln ? severityLabel(vuln.severity, vuln.malware) : 'UNKNOWN';
}

// "CVSS 7.5", else the GHSA severity
export function scoreText(vuln: VulnCase | undefined): string | null {
  if (!vuln) return null;
  if (typeof vuln.severity?.cvssScore === 'number') return `CVSS ${vuln.severity.cvssScore.toFixed(1)}`;
  return vuln.severity?.ghsa ?? null;
}

// risk, then ghsa severity, then name
export function sortVerdicts(verdicts: readonly Verdict[], caseFile: CaseFile): Verdict[] {
  const vulns = indexVulns(caseFile);
  const vulnOf = (v: Verdict): VulnCase | undefined => vulns.get(vulnKey(v.vulnId, v.package, v.installedVersion));
  return [...verdicts].sort((a, b) => {
    const va = vulnOf(a);
    const vb = vulnOf(b);
    return (
      riskRank(b.risk) - riskRank(a.risk) ||
      GHSA_RANK[ghsaOf(vb)] - GHSA_RANK[ghsaOf(va)] ||
      (a.package < b.package ? -1 : a.package > b.package ? 1 : 0) ||
      (vb?.severity.cvssScore ?? 0) - (va?.severity.cvssScore ?? 0) ||
      (a.vulnId < b.vulnId ? -1 : a.vulnId > b.vulnId ? 1 : 0)
    );
  });
}

// harness badges: cached, adjusted, forced
export function verdictBadges(verdict: Verdict): string[] {
  const out: string[] = [];
  if (verdict.investigation?.cached) out.push('cached');
  if (verdict.investigation?.adjusted) out.push('adjusted');
  if (verdict.investigation?.forced) out.push('forced');
  return out;
}

// short form for the table, e.g. "bump 4.18.1" or "monitor"
export function shortRecommendation(rec: Recommendation): string {
  const to = rec.targetVersion;
  switch (rec.action) {
    case 'upgrade':
      return to ? `bump ${to}` : 'upgrade';
    case 'upgrade_major':
      return to ? `major ${to}` : 'major upgrade';
    case 'update_transitive':
      return to ? `update ${to}` : 'update';
    case 'override':
      return to ? `override ${to}` : 'override';
    default:
      return rec.action;
  }
}

const TABLE_COLUMNS: TableColumn[] = [
  { key: 'package', header: 'Package', maxWidth: 22, minWidth: 8 },
  { key: 'version', header: 'Version', maxWidth: 12, minWidth: 7 },
  { key: 'vuln', header: 'Vulnerability', maxWidth: 19, minWidth: 14 },
  { key: 'ghsa', header: 'GHSA', maxWidth: 8, minWidth: 8 },
  { key: 'risk', header: 'Risk', maxWidth: 8, minWidth: 8 },
  { key: 'reach', header: 'Reach', maxWidth: 8, minWidth: 5 },
  { key: 'conf', header: 'Conf', align: 'right', maxWidth: 4, minWidth: 4 },
  { key: 'action', header: 'Recommended', maxWidth: 16, minWidth: 7 },
  { key: 'badges', header: 'Badges', maxWidth: 17, minWidth: 6 },
];

export function renderFindingsTable(assessment: Assessment, caseFile: CaseFile, ui: Ui): string {
  const vulns = indexVulns(caseFile);
  const rows = sortVerdicts(assessment.verdicts, caseFile).map((v) => {
    const vuln = vulns.get(vulnKey(v.vulnId, v.package, v.installedVersion));
    return {
      package: v.package,
      version: v.installedVersion,
      vuln: vuln ? displayVulnId(vuln) : v.vulnId,
      ghsa: ui.severity(ghsaOf(vuln)),
      risk: ui.risk(v.risk),
      reach: v.reachable,
      conf: `${Math.round(Math.min(1, Math.max(0, v.confidence)) * 100)}%`,
      action: shortRecommendation(v.recommendation),
      badges: ui.c.dim(verdictBadges(v).join(' ')),
    };
  });
  return ui.table(TABLE_COLUMNS, rows);
}

export function renderVerdictCard(verdict: Verdict, vuln: VulnCase | undefined, ui: Ui): string {
  const card = ui.card(verdict.risk);
  const inner = ui.width - 2;
  const c = ui.c;
  const lines: string[] = [];
  lines.push(ui.formatCardTitle(vuln ? displayVulnId(vuln) : verdict.vulnId, `${verdict.package}@${verdict.installedVersion}`, scoreText(vuln), verdict.risk));
  if (vuln && displayVulnId(vuln) !== vuln.id) lines.push(c.dim(ui.text(`${vuln.id} ${ui.glyphs.dot} ${clean(vuln.summary)}`)));
  else if (vuln?.summary) lines.push(c.dim(ui.text(clean(vuln.summary))));
  lines.push('');
  lines.push(...ui.formatVerdictLine(verdict.risk, clean(verdict.reasoning).trim() || 'No reasoning given.', inner));
  lines.push(ui.formatConfidenceLine(verdict.confidence, recommendationText(verdict.recommendation)));
  lines.push(c.dim(ui.text(`Reachable: ${verdict.reachable}${vuln ? ` ${ui.glyphs.dot} GHSA ${ghsaOf(vuln)}` : ''}`)));
  const evidence = verdict.evidence.map((e) => clean(e).trim()).filter(Boolean);
  if (evidence.length > 0) {
    lines.push('');
    lines.push(c.dim('Evidence'));
    for (const item of evidence.slice(0, 5)) {
      const wrapped = wrapText(ui.text(item), Math.max(20, inner - 4));
      wrapped.forEach((l, i) => lines.push(c.dim(`${i === 0 ? `  ${ui.glyphs.bullet} ` : '    '}${l}`)));
    }
    if (evidence.length > 5) lines.push(c.dim(`  ${ui.glyphs.ellipsis} ${evidence.length - 5} more`));
  }
  const notes = verdict.recommendation.notes ? clean(verdict.recommendation.notes) : '';
  if (notes) lines.push(...wrapText(ui.text(notes), inner).map((l) => c.dim(l)));
  const badges = verdictBadges(verdict);
  if (badges.length > 0) {
    const detail = verdict.investigation?.adjusted && verdict.investigation.originalRisk
      ? ` ${verdict.investigation.originalRisk} ${ui.glyphs.arrow} ${verdict.risk}${verdict.investigation.adjustReason ? `: ${clean(verdict.investigation.adjustReason)}` : ''}`
      : '';
    lines.push(...wrapText(ui.text(`${badges.map((b) => `[${b}]`).join(' ')}${detail}`), inner).map((l) => c.dim(l)));
  }
  return card.format(lines);
}

export interface PresentOptions {
  // phase 2 already printed cards
  cards?: boolean;
}

// with expiry state
export function acceptedRisks(caseFile: CaseFile | null, config: Pick<Config, 'ignore'>, now: Date = new Date()): { vuln: VulnCase; entry: Config['ignore'][number]; expired: boolean }[] {
  const out: { vuln: VulnCase; entry: Config['ignore'][number]; expired: boolean }[] = [];
  for (const vuln of caseFile?.vulnerabilities ?? []) {
    const hit = findIgnore(config.ignore, vuln.id, vuln.package, [...vuln.aliases, ...vuln.mergedIds], now);
    if (hit) out.push({ vuln, entry: hit.entry, expired: hit.expired });
  }
  return out;
}

// table, cards, accepted risks, summary
export function presentFindings(assessment: Assessment, caseFile: CaseFile, config: Config, ui: Ui, options: PresentOptions = {}): void {
  if (config.json) return;
  const total = caseFile.vulnerabilities.length;
  if (assessment.verdicts.length === 0) {
    ui.sectionHeader('Summary');
    ui.print(total === 0 ? ui.green('No known vulnerabilities in the lockfile.') : `${plural(total, 'CVE')} found, none investigated yet.`);
    return;
  }
  const sorted = sortVerdicts(assessment.verdicts, caseFile);
  ui.sectionHeader('Findings');
  ui.print(renderFindingsTable(assessment, caseFile, ui));
  if (options.cards !== false) {
    ui.info('');
    for (const verdict of sorted) {
      ui.info(renderVerdictCard(verdict, vulnFor(verdict, caseFile), ui));
      ui.info('');
    }
  }

  ui.sectionHeader('Summary');
  const byRisk: Partial<Record<RiskLevel, number>> = {};
  for (const v of assessment.verdicts) byRisk[v.risk] = (byRisk[v.risk] ?? 0) + 1;
  const all = assessment.verdicts.length >= total;
  ui.print(ui.formatSummaryLine({ total: assessment.verdicts.length, byRisk, noun: all ? 'CVEs scanned' : `of ${total} CVEs investigated` }));
  const counts = { cached: 0, adjusted: 0, forced: 0 };
  for (const v of assessment.verdicts) {
    if (v.investigation?.cached) counts.cached += 1;
    if (v.investigation?.adjusted) counts.adjusted += 1;
    if (v.investigation?.forced) counts.forced += 1;
  }
  const harness = [
    counts.cached > 0 ? `${counts.cached} from the verdict cache` : '',
    counts.adjusted > 0 ? `${counts.adjusted} adjusted by the rails` : '',
    counts.forced > 0 ? `${counts.forced} forced (the model did not answer)` : '',
  ].filter(Boolean);
  if (harness.length > 0) ui.info(ui.c.dim(harness.join(` ${ui.glyphs.dot} `)));
  if (!all) {
    ui.infoLine(`${total - assessment.verdicts.length} more CVEs were not investigated`, 'run patch-pilot scan without --only, --limit or --max-cves to include them');
  }
  const accepted = acceptedRisks(caseFile, config);
  for (const { vuln, entry, expired } of accepted) {
    const until = entry.until ? ` ${ui.glyphs.dot} until ${entry.until}` : '';
    const text = `${vulnLabel(vuln)} in ${vuln.package}: ${clean(entry.reason)} (accepted by ${entry.by}${until})`;
    if (expired) ui.warn(`Accepted risk expired, reported again: ${vulnLabel(vuln)}`, `${vuln.package}, expired ${entry.until}`);
    else ui.infoLine('Accepted risk', text);
  }
}

// label like "lodash 4.17.20 → 4.18.1"
export function actionLabel(action: Pick<Action, 'package' | 'fromVersion' | 'toVersion'>, ui: Pick<Ui, 'glyphs'>): string {
  return `${action.package} ${action.fromVersion} ${ui.glyphs.arrow} ${action.toVersion}`;
}

export function kindLabel(action: Pick<Action, 'kind' | 'requiresMigration'>): string {
  switch (action.kind) {
    case 'bump':
      return 'version bump';
    case 'bump-major':
      return action.requiresMigration ? 'major version bump with source changes (one transaction)' : 'major version bump';
    case 'update-transitive':
      return 'transitive update inside the parent range';
    case 'override-transitive':
      return 'parent-scoped override';
  }
}

function parentsText(action: Action, onlyExcluding = false): string {
  const list = onlyExcluding ? action.parents.filter((p) => !p.acceptsTarget) : action.parents;
  return [...new Set(list.map((p) => `${p.name} ${p.range}`))].join(', ');
}

// patch and source notes
export function actionItemInfo(action: Action, n: number, researched = true): ActionItemInfo {
  const closes = `closes ${plural(action.vulnIds.length, 'CVE')}`;
  let patchNote: string;
  let sourceNote: string;
  switch (action.kind) {
    case 'bump':
      patchNote = `Patch: version bump only, no breaking changes (${closes})`;
      sourceNote = 'Source changes: none required';
      break;
    case 'bump-major':
      if (!action.requiresMigration) {
        patchNote = `Patch: major version (${closes}); ${action.package} is not imported in source`;
        sourceNote = 'Source changes: none expected';
      } else {
        const items = action.brief?.items.length ?? 0;
        patchNote = action.brief ? `Patch: major version, ${plural(items, 'breaking change')} detected (${closes})` : `Patch: major version (${closes})`;
        const patches = action.codemod?.patches ?? [];
        if (patches.length > 0) {
          sourceNote = `Source changes: ${plural(patches.length, 'file')} ${patches.length === 1 ? 'needs' : 'need'} updates (${patches.map((p) => p.file).join(', ')})`;
        } else if (action.brief) {
          sourceNote = 'Source changes: manual migration (no validated edits; checklist at the prompt)';
        } else if (!researched) {
          sourceNote = 'Source changes: likely (imported in source); researched before approval';
        } else {
          sourceNote = 'Source changes: unknown (migration research unavailable)';
        }
      }
      break;
    case 'update-transitive':
      patchNote = `Patch: in-range update inside ${parentsText(action) || 'the parent range'} (${closes}), no package.json change`;
      sourceNote = 'Source changes: none required';
      break;
    case 'override-transitive':
      patchNote = `Patch: parent-scoped override in package.json (${closes}); ${[...new Set(action.parents.filter((p) => !p.acceptsTarget).map((p) => p.name))].join(', ')} not tested with ${action.toVersion}`;
      sourceNote = 'Source changes: none required';
      break;
  }
  if (action.notes.some((note) => note.startsWith('Still affected at'))) patchNote += '; some CVEs remain';
  if (action.engines?.compatible === false && action.engines.message) patchNote += `; ${action.engines.message}`;
  return { n, pkg: action.package, from: action.fromVersion, to: action.toVersion, risk: action.worstRisk, patchNote: clean(patchNote), sourceNote: clean(sourceNote) };
}

export interface PresentActionsOptions {
  caseFile?: CaseFile | null;
  assessment?: Assessment | null;
  config?: Config;
  // false under --dry-run and --ci
  researched?: boolean;
}

export function presentActions(actions: readonly Action[], ui: Ui, options: PresentActionsOptions = {}): void {
  if (options.config?.json) return;
  ui.sectionHeader('Action required', 'green');
  if (actions.length === 0) {
    ui.print(ui.c.dim('Nothing to patch: every investigated CVE is fixed, accepted or has no published fix.'));
  }
  actions.forEach((action, i) => {
    ui.print(ui.formatActionItem(actionItemInfo(action, i + 1, options.researched ?? true)));
    ui.print('');
  });
  const assessment = options.assessment;
  const caseFile = options.caseFile;
  if (assessment && caseFile) {
    const planned = new Set(actions.flatMap((a) => a.vulnIds.map((id) => `${id}|${a.package}`)));
    const now = new Date();
    const noFix = assessment.verdicts.filter((v) => {
      if (planned.has(`${v.vulnId}|${v.package}`)) return false;
      const vuln = vulnFor(v, caseFile);
      if (!vuln || vuln.recommendedFix) return false;
      const hit = options.config ? findIgnore(options.config.ignore, vuln.id, vuln.package, vuln.aliases, now) : null;
      return !(hit && !hit.expired);
    });
    if (noFix.length > 0) {
      ui.infoLine(
        `No fixed version published yet for ${plural(noFix.length, 'CVE')}`,
        noFix.map((v) => `${v.package} ${vulnFor(v, caseFile) ? displayVulnId(vulnFor(v, caseFile) as VulnCase) : v.vulnId}`).join(', '),
      );
    }
  }
}

export interface ActionDetailsOptions {
  caseFile?: CaseFile | null;
  assessment?: Assessment | null;
  // pre-change graph: manager, alias, workspaces
  graph?: DependencyGraph | null;
  manager?: PackageManager;
  invocation?: Pick<ManagerInvocation, 'display' | 'version'> | null;
}

// from the scanned lockfile name
export function detailsManager(options: Pick<ActionDetailsOptions, 'caseFile' | 'graph' | 'manager'>): PackageManager {
  if (options.manager) return options.manager;
  if (options.graph?.packageManager) return options.graph.packageManager;
  const project = options.caseFile?.project;
  const file = (project?.lockfile ?? '').split(/[\\/]/).pop() ?? '';
  if (file === 'pnpm-lock.yaml') return 'pnpm';
  if (file === 'yarn.lock') return project?.lockfileVersion === 1 ? 'yarn' : 'yarn-berry';
  return 'npm';
}

function overridePair(action: Action, manager: PackageManager, invocation: ActionDetailsOptions['invocation']): [string, string] {
  if (manager === 'npm') {
    return ['Override', Object.entries(overrideEntries(action)).map(([parent, v]) => `"${parent}": ${JSON.stringify(v)}`).join(', ')];
  }
  const yarn = manager !== 'pnpm';
  const entries = yarn ? yarnResolutionEntries(action) : pnpmOverrideEntries(action);
  const where = yarn ? 'resolutions in package.json' : pnpmOverrideFile(managerMajor(invocation)) === 'package.json' ? 'pnpm.overrides in package.json' : 'overrides in pnpm-workspace.yaml';
  const list = Object.entries(entries).map(([key, v]) => `"${key}": ${JSON.stringify(v)}`).join(', ');
  return [yarn ? 'Resolution' : 'Override', `${list} (${where})`];
}

// command, parents, engines, verdicts
export function renderActionDetails(action: Action, ui: Ui, options: ActionDetailsOptions = {}): string {
  const c = ui.c;
  const lines: string[] = [];
  lines.push(`${c.bold(actionLabel(action, ui))} ${c.dim(`${ui.glyphs.dot} ${kindLabel(action)}`)}`);
  const pairs: [string, string][] = [];
  const manager = detailsManager(options);
  const alias = options.graph ? directAlias(action, options.graph) : undefined;
  const commandOptions: ManagerCommandOptions = { workspaces: (options.graph?.workspaceKeys.length ?? 0) > 0, alias };
  // shown as .patch-pilot/tmp/yarn-modules
  if (manager === 'yarn') commandOptions.modulesFolder = 'yarn-modules';
  if (action.kind === 'override-transitive') pairs.push(overridePair(action, manager, options.invocation));
  pairs.push(['Command', commandLine(action, manager, options.invocation, commandOptions)]);
  if (action.direct) pairs.push(['package.json', `${action.direct.depType} "${alias ?? action.package}": "${action.direct.spec}" (${action.direct.specStyle})`]);
  for (const p of action.parents) {
    pairs.push(['Required by', `${p.name}@${p.version} ${p.range} (${p.acceptsTarget ? 'accepts' : 'excludes'} ${action.toVersion})`]);
  }
  if (action.engines) {
    const e = action.engines;
    const state = e.compatible === null ? 'unknown' : e.compatible ? 'compatible' : 'incompatible';
    pairs.push(['Node', `${e.targetNode ? `target needs ${e.targetNode}` : 'no target requirement'} ${ui.glyphs.dot} project ${e.projectNode ?? 'unspecified'} ${ui.glyphs.dot} running ${e.runningNode}: ${state}`]);
  }
  lines.push(ui.kv(pairs.map(([k, v]) => [k, ui.text(clean(v))] as const)));
  lines.push('');
  lines.push(c.dim(`Closes ${plural(action.vulnIds.length, 'CVE')}:`));
  for (const id of action.vulnIds) {
    const vuln = options.caseFile?.vulnerabilities.find((v) => v.id === id && v.package === action.package);
    const verdict = options.assessment?.verdicts.find((v) => v.vulnId === id && v.package === action.package);
    const head = vuln ? vulnLabel(vuln) : id;
    const sev = vuln ? ghsaOf(vuln) : 'UNKNOWN';
    const verdictText = verdict
      ? `${ui.risk(verdict.risk)} ${c.dim(`${ui.glyphs.dot} reachable ${verdict.reachable} ${ui.glyphs.dot} ${Math.round(verdict.confidence * 100)}%`)}`
      : c.dim('not investigated');
    lines.push(`  ${ui.glyphs.bullet} ${head} ${c.dim(sev)} ${verdictText}`);
    const reason = verdict ? clean(verdict.reasoning) : vuln ? clean(vuln.summary) : '';
    if (reason) lines.push(...wrapText(ui.text(reason), Math.max(20, ui.width - 6)).map((l) => `    ${c.dim(l)}`));
  }
  if (action.notes.length > 0) {
    lines.push('');
    for (const note of action.notes) lines.push(...wrapText(ui.text(clean(note)), Math.max(20, ui.width - 4)).map((l, i) => c.dim(`${i === 0 ? `${ui.glyphs.bullet} ` : '  '}${l}`)));
  }
  return lines.join('\n');
}

// when renderBrief is unavailable
export function renderBriefFallback(brief: MigrationBrief, ui: Ui): string {
  const c = ui.c;
  const lines: string[] = [];
  lines.push(
    `${c.bold(`Migration brief: ${brief.package} ${brief.from} ${ui.glyphs.arrow} ${brief.to}`)} ${c.dim(`${ui.glyphs.dot} ${plural(brief.sources.length, 'source')}${brief.offline ? ` ${ui.glyphs.dot} offline (cached sources only)` : ''}`)}`,
  );
  for (const item of brief.items) {
    const flag = item.verified ? 'verified' : 'unverified';
    lines.push(`  ${ui.glyphs.bullet} ${ui.text(clean(item.change))} ${c.dim(`[applies: ${item.appliesToProject}, ${flag}]`)}`);
    if (item.oldApi || item.newApi) lines.push(`    ${c.dim(ui.text(`${clean(item.oldApi)} ${ui.glyphs.arrow} ${clean(item.newApi)}`))}`);
    if (item.evidenceQuote) lines.push(`    ${c.dim(ui.text(`"${clean(item.evidenceQuote)}"${item.evidenceUrl ? ` (${item.evidenceUrl})` : ''}`))}`);
    if (item.affectedFiles.length > 0) lines.push(`    ${c.dim(`files: ${item.affectedFiles.join(', ')}`)}`);
  }
  if (brief.items.length === 0) lines.push(c.dim('  No breaking change found in the sources.'));
  if (brief.sources.length > 0) {
    lines.push(c.dim('  Sources:'));
    for (const s of brief.sources.slice(0, 6)) lines.push(c.dim(`    ${ui.glyphs.bullet} ${s.url} (${s.kind}${s.cached ? ', cached' : ''})`));
  }
  return lines.join('\n');
}

// shown before the apply prompt
export function renderMigrationReview(action: Action, ui: Ui, fns: Partial<Pick<MigrationFns, 'renderBrief' | 'manualChecklist'>> = {}): string {
  const c = ui.c;
  const heading = `${c.bold(actionLabel(action, ui))} ${c.dim(`${ui.glyphs.dot} ${kindLabel(action)}`)}`;
  const lines: string[] = [];
  const brief = action.brief;
  if (brief) {
    let text: string | null = null;
    try {
      text = (fns.renderBrief ?? defaultRenderBrief)(brief, ui);
    } catch {
      text = null;
    }
    if (text && text.trim() !== '') lines.push(heading, '', clean(text));
    else lines.push(heading, renderBriefFallback(brief, ui));
  } else {
    lines.push(heading);
    const reason = action.notes.find((n) => n.startsWith('Migration research unavailable')) ?? 'Migration research unavailable.';
    lines.push(ui.formatWarn(clean(reason), 'the code changes for this major bump are unknown', ui.c));
  }
  const codemod = action.codemod;
  const patches = codemod?.patches ?? [];
  if (patches.length === 0) {
    let checklist: string[] | null = codemod?.manualChecklist ?? null;
    if (!checklist && brief) {
      try {
        checklist = (fns.manualChecklist ?? defaultManualChecklist)(brief);
      } catch (err) {
        checklist = brief.items.filter((i) => i.appliesToProject !== 'no').map((i) => `${i.change}${i.evidenceUrl ? ` (${i.evidenceUrl})` : ''}`);
        if (checklist.length === 0) checklist = [`Read the release notes of ${action.package} ${action.toVersion} (${errorMessage(err)})`];
      }
    }
    if (checklist && checklist.length > 0) {
      lines.push('');
      lines.push(c.bold('Manual migration checklist'));
      for (const item of checklist) lines.push(...wrapText(ui.text(clean(item)), Math.max(20, ui.width - 4)).map((l, i) => `${i === 0 ? `  ${ui.glyphs.bullet} ` : '    '}${l}`));
    }
    const other = action.notes.find((n) => n.startsWith('Code edits unavailable'));
    if (other) lines.push(c.dim(clean(other)));
  }
  if (codemod && codemod.rejected.length > 0) {
    lines.push(c.dim(`${plural(codemod.rejected.length, 'proposed edit')} rejected by validation: ${codemod.rejected.slice(0, 3).map((r) => `${r.file}: ${clean(r.reason)}`).join('; ')}`));
  }
  return lines.join('\n');
}

// aligned dim lines
export function renderLockfileChanges(changes: readonly LockfileNodeChange[], ui: Ui): string {
  const width = Math.max(0, ...changes.map((ch) => ch.key.length));
  return changes
    .map((ch) => {
      const versions = ch.change === 'changed' ? `${ch.from ?? '?'} ${ui.glyphs.arrow} ${ch.to ?? '?'}` : ch.change === 'added' ? (ch.to ?? '') : (ch.from ?? '');
      return `    ${ui.c.dim(ch.change.padEnd(8))}${ch.key.padEnd(width)}  ${ui.c.dim(versions)}`;
    })
    .join('\n');
}
