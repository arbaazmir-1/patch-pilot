// all versioned by PROMPT_VERSION
import type { BlamedSymbol, Dossier, InvestigationStage, JsonSchema, PackageCase, UsageEvidence, VulnCase } from '../types.ts';
import { compareVersions } from '../util/semver.ts';

// bump on wording change, busts verdict cache
export const PROMPT_VERSION = 'b1-2026-09-24.5';

// spelled out for small models
export const RISK_RUBRIC = [
  'Critical = vulnerable function reachable with untrusted input in production code and high/critical severity.',
  'High = reachable in production code, exploitability unclear, or direct production use of a high-severity issue.',
  'Medium = package used in production but the vulnerable function not found (may be indirect), or reachable only in scripts/tooling.',
  'Low = dev-only dependency or vulnerable path clearly unused.',
  'Noise = package not imported anywhere and not applicable (or preconditions the project cannot meet).',
].join('\n');

const stringList: JsonSchema = { type: 'array', items: { type: 'string' } };

// stage 1: facts only, no risk
export const DOSSIER_SCHEMA: JsonSchema = {
  type: 'object',
  properties: {
    inputSources: stringList,
    callSiteNotes: stringList,
    dependentsSummary: { type: 'string' },
    fixCost: { type: 'string' },
    openQuestions: stringList,
  },
  required: ['inputSources', 'callSiteNotes', 'dependentsSummary', 'fixCost', 'openQuestions'],
};

// judgement only, rest is derived
export const VERDICT_SCHEMA: JsonSchema = {
  type: 'object',
  properties: {
    risk: { type: 'string', enum: ['Critical', 'High', 'Medium', 'Low', 'Noise'] },
    reachable: { type: 'string', enum: ['yes', 'likely', 'unlikely', 'no', 'unknown'] },
    confidence: { type: 'number', minimum: 0, maximum: 1 },
    reasoning: { type: 'string' },
    evidence: stringList,
    recommendationAction: {
      type: 'string',
      enum: ['upgrade', 'upgrade_major', 'update_transitive', 'override', 'remove', 'ignore', 'monitor'],
    },
  },
  required: ['risk', 'reachable', 'confidence', 'reasoning', 'evidence', 'recommendationAction'],
};

// tests and trace match these
export const NUDGE_TEXT = '1 tool call left, wrap up';
export const REPEAT_NOTE = 'You already have this result from an earlier call; do not repeat it.';

// shared with agent.ts

// collapse whitespace, cut with "..."
export function clip(text: string | null | undefined, max: number): string {
  const one = String(text ?? '').replace(/\s+/g, ' ').trim();
  return one.length > max ? `${one.slice(0, Math.max(0, max - 3)).trimEnd()}...` : one;
}

// "_.template()" or "_['template']" -> "template"
export function symbolName(name: string): string {
  const trimmed = name.trim().replace(/\(.*\)$/, '').replace(/^[`'"]+|[`'"]+$/g, '');
  const bracket = /\[\s*['"]([^'"\]]+)['"]\s*\]$/.exec(trimmed);
  if (bracket && bracket[1] !== undefined) return bracket[1].trim();
  return (trimmed.split('.').pop() ?? trimmed).trim();
}

// cve alias, else osv id
export function displayVulnId(vuln: Pick<VulnCase, 'id' | 'aliases'>): string {
  return vuln.aliases?.find((a) => /^CVE-\d{4}-\d+$/i.test(a)) ?? vuln.id;
}

// e.g. "GHSA-35jh-r3h4-6jhm (CVE-2021-23337)"
export function vulnLabel(vuln: Pick<VulnCase, 'id' | 'aliases'>): string {
  const cve = displayVulnId(vuln);
  return cve !== vuln.id ? `${vuln.id} (${cve})` : vuln.id;
}

// "HIGH, CVSS 7.2", "MODERATE" or "severity unknown"
export function severityText(vuln: Pick<VulnCase, 'severity'>): string {
  const parts: string[] = [];
  if (vuln.severity?.ghsa) parts.push(vuln.severity.ghsa);
  if (typeof vuln.severity?.cvssScore === 'number') parts.push(`CVSS ${vuln.severity.cvssScore.toFixed(1)}`);
  return parts.length > 0 ? parts.join(', ') : 'severity unknown';
}

const EMPTY_USAGE: UsageEvidence = {
  package: '',
  imported: false,
  files: [],
  scopes: { source: 0, test: 0, config: 0, scripts: 0 },
  membersUsed: {},
  bindingCalls: 0,
  scannedFiles: 0,
};

// all fields filled
export function usageOf(pkg: Pick<PackageCase, 'name' | 'usage'>): UsageEvidence {
  const u = pkg.usage ?? EMPTY_USAGE;
  return {
    ...EMPTY_USAGE,
    ...u,
    package: u.package || pkg.name,
    files: Array.isArray(u.files) ? u.files : [],
    scopes: { ...EMPTY_USAGE.scopes, ...(u.scopes ?? {}) },
    membersUsed: u.membersUsed ?? {},
    bindingCalls: typeof u.bindingCalls === 'number' ? u.bindingCalls : 0,
  };
}

function membersText(usage: UsageEvidence, binding: string | null): string {
  const entries = Object.entries(usage.membersUsed)
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  if (entries.length === 0) return 'none';
  const prefix = binding ? `${binding}.` : '';
  return entries
    .slice(0, 12)
    .map(([m, n]) => `${prefix}${m} (${n})`)
    .join(', ');
}

// where the package sits, e.g. "direct production dependency"
export function dependencyText(pkg: PackageCase): string {
  const kind = pkg.isDirect ? 'direct' : 'transitive';
  const env = pkg.isDevOnly ? 'dev-only' : 'production';
  const spec = pkg.isDirect && pkg.spec ? ` (${pkg.depType ?? 'dependencies'}: ${pkg.spec})` : '';
  const dependents = (pkg.dependents ?? []).map((d) => `${d.name}@${d.version}`);
  const via = !pkg.isDirect && dependents.length > 0 ? `, required by ${dependents.slice(0, 4).join(', ')}` : '';
  const also = pkg.isDirect && dependents.length > 0 ? `, also required by ${dependents.slice(0, 4).join(', ')}` : '';
  return `${kind} ${env} dependency${spec}${via}${also}`;
}

export function usageLines(pkg: PackageCase): string[] {
  const usage = usageOf(pkg);
  const scanned = usage.scannedFiles > 0 ? ` (${usage.scannedFiles} files scanned${usage.truncated ? ', file cap hit' : ''})` : '';
  if (usage.files.length === 0) {
    const via = (pkg.dependents ?? []).map((d) => `${d.name}@${d.version}`);
    return [
      `- Not imported anywhere in the project${scanned}.${via.length > 0 ? ` It is installed because ${via.slice(0, 4).join(', ')} depend${via.length === 1 ? 's' : ''} on it.` : ''}`,
    ];
  }
  const lines: string[] = [];
  const bySite = usage.files.slice(0, 5).map((f) => `${f.path}:${f.line} \`${clip(f.statement, 90)}\`${f.binding ? ` as ${f.binding}` : ''} [${f.scope}]`);
  lines.push(`- Import sites${scanned}: ${bySite.join('; ')}${usage.files.length > 5 ? `; ${usage.files.length - 5} more` : ''}`);
  const s = usage.scopes;
  lines.push(`- Imported in: source ${s.source}, test ${s.test}, config ${s.config}, scripts ${s.scripts} file(s)`);
  const binding = usage.files.find((f) => f.binding)?.binding ?? null;
  lines.push(`- Members called: ${membersText(usage, binding)}; the imported binding itself is called ${usage.bindingCalls} time${usage.bindingCalls === 1 ? '' : 's'}`);
  return lines;
}

function blamedText(symbols: readonly BlamedSymbol[]): string {
  if (!symbols || symbols.length === 0) return 'none named in the advisory';
  return symbols
    .slice(0, 8)
    .map((s) => `${symbolName(s.name)} (${s.kind === 'exported' ? 'exported: public API the project could call' : 'internal: runs inside the package'})`)
    .join(', ');
}

function fixText(vuln: VulnCase): string {
  const fixed = vuln.fixedVersions?.length ? vuln.fixedVersions.slice(0, 6).join(', ') : 'none published';
  const rec = vuln.recommendedFix;
  const recText = rec ? `${rec.version} (${rec.majorBump ? 'MAJOR bump, breaking changes likely' : 'no major bump'})` : 'none';
  const skipped = rec?.skippedDeprecated?.length ? `, skipping deprecated ${rec.skippedDeprecated.join(', ')}` : '';
  return `affected ${vuln.affectedRange || 'unknown'}; fixed in ${fixed}; recommended fix ${recText}${skipped}`;
}

// highest fix, clears every cve
export function packageFixText(vulns: readonly VulnCase[]): string {
  const fixes = vulns.map((v) => v.recommendedFix).filter((f): f is NonNullable<VulnCase['recommendedFix']> => Boolean(f));
  if (fixes.length === 0) return 'no fixed version is published';
  const best = [...fixes].sort((a, b) => compareVersions(b.version, a.version))[0];
  if (!best) return 'no fixed version is published';
  const major = fixes.some((f) => f.majorBump);
  return `upgrading to ${best.version} clears ${fixes.length === vulns.length ? 'all of them' : `${fixes.length} of ${vulns.length}`}${major ? ' (MAJOR bump: breaking changes likely)' : ' (no major bump)'}`;
}

function jsonCall(tool: string, args: Record<string, unknown>): string {
  return JSON.stringify({ name: tool, arguments: args });
}

function shapeOf(schema: JsonSchema): string {
  if (schema.enum) return schema.enum.map((e) => JSON.stringify(e)).join('|');
  if (schema.type === 'array') return `${schema.items ? shapeOf(schema.items) : 'any'}[]`;
  if (schema.type === 'object') {
    const props = Object.entries(schema.properties ?? {}).map(([key, prop]) => `${JSON.stringify(key)}: ${shapeOf(prop)}`);
    return `{${props.join(', ')}}`;
  }
  if ((schema.type === 'number' || schema.type === 'integer') && schema.minimum !== undefined && schema.maximum !== undefined) {
    return `${schema.type} ${schema.minimum}..${schema.maximum}`;
  }
  return schema.type ?? 'any';
}

// fields, enums, ranges, required marked
export function schemaText(schema: JsonSchema): string {
  const required = schema.required ?? [];
  const all = Object.keys(schema.properties ?? {});
  const note = required.length === all.length ? ' (all fields required)' : required.length > 0 ? ` (required: ${required.join(', ')})` : '';
  return `${shapeOf(schema)}${note}`;
}

function toolRules(budget: number): string {
  return `Tool rules: prefer one tool call per turn; never repeat an identical call; budget ${budget} tool call${budget === 1 ? '' : 's'}. Stop as soon as the evidence answers the question and reply in two or three sentences without a tool call.`;
}

// recon or verdict, with tool budget
export function systemPrompt(stage: InvestigationStage, budget: number): string {
  if (stage === 'recon') {
    return [
      'You are PatchPilot, a security engineer checking how THIS project uses one vulnerable npm package. Collect facts for the per-CVE verdicts that follow; do not rate the risk yet.',
      'Method: 1. Where is the package imported and called (source, tests, scripts)? 2. Where does the data passed to it come from: user input, CLI arguments, network, user files, or constants and trusted config? 3. Is it direct, transitive or dev-only, and who depends on it? 4. What does the fix cost: a patch or a major bump with breaking changes?',
      toolRules(budget),
      `At the end you write a fact dossier as JSON: ${schemaText(DOSSIER_SCHEMA)}`,
    ].join('\n\n');
  }
  return [
    'You are PatchPilot, a security engineer deciding how much one npm vulnerability matters to THIS project. Judge by what the code does, not by the CVSS score alone.',
    'Method: 1. Is the package imported, and where (source, tests, scripts)? 2. Which functions does the advisory blame, and does the project call them with untrusted input (user data, CLI arguments, network, user files)? 3. Is it direct, transitive or dev-only? 4. Is there a fix, and is it a major bump?',
    toolRules(budget),
    `Risk rubric:\n${RISK_RUBRIC}`,
    `At the end you give the verdict as JSON: ${schemaText(VERDICT_SCHEMA)}`,
  ].join('\n\n');
}

// stage 1: package case, usage, cve one-liners
export function reconPrompt(pkg: PackageCase, vulns: readonly VulnCase[]): string {
  const path = pkg.dependencyPaths?.[0];
  const lines = [
    `Package case: ${pkg.name}@${pkg.version}, ${dependencyText(pkg)}.`,
    path && path.length > 0 ? `Dependency path: ${path.join(' > ')}` : null,
    pkg.deprecated ? `Registry note: this version is deprecated (${clip(pkg.deprecated, 120)}).` : null,
    '',
    'Phase 1 usage evidence (deterministic scan):',
    ...usageLines(pkg),
    '',
    `Vulnerabilities (${vulns.length}):`,
    ...vulns.slice(0, 8).map((v, i) => `${i + 1}. ${vulnLabel(v)}, ${severityText(v)}: ${clip(v.summary, 120)}. Blamed: ${blamedText(v.blamedSymbols)}. Fix: ${fixText(v)}.`),
    vulns.length > 8 ? `(${vulns.length - 8} more with the same package)` : null,
    `Fix cost: ${packageFixText(vulns)}.`,
    '',
    `Task: find the facts the verdicts will need. Where does the data passed to ${pkg.name} come from (read_file around a call site)? Who else depends on it (check_deps)? What does the fix cost (get_changelog)? Calling no tool is fine when the evidence above already answers this.`,
  ];
  return lines.filter((l): l is string => l !== null).join('\n');
}

// mirrors the evidence gate
function suggestedCall(pkg: PackageCase, vuln: VulnCase): string | null {
  const usage = usageOf(pkg);
  if (usage.scopes.source <= 0 && usage.files.length === 0) return null;
  const exported = (vuln.blamedSymbols ?? []).find((s) => s.kind === 'exported' && s.via !== 'default-callable');
  if (exported) return jsonCall('get_usage', { package: pkg.name, symbol: symbolName(exported.name) });
  return jsonCall('get_usage', { package: pkg.name });
}

function dossierLines(dossier: Dossier | null | undefined): string[] {
  if (!dossier) return ['- (no dossier)'];
  const list = (items: readonly string[] | undefined): string => {
    const clean = (items ?? []).map((i) => clip(i, 160)).filter(Boolean);
    return clean.length > 0 ? clean.slice(0, 5).join('; ') : 'none';
  };
  return [
    `- Input sources: ${list(dossier.inputSources)}`,
    `- Call sites: ${list(dossier.callSiteNotes)}`,
    `- Dependents: ${clip(dossier.dependentsSummary, 200) || 'unknown'}`,
    `- Fix cost: ${clip(dossier.fixCost, 200) || 'unknown'}`,
    `- Open questions: ${list(dossier.openQuestions)}`,
  ];
}

// stage 2: dossier plus full cve case
export function verdictPrompt(pkg: PackageCase, vuln: VulnCase, dossier: Dossier): string {
  const suggestion = suggestedCall(pkg, vuln);
  const lines = [
    `Vulnerability: ${vulnLabel(vuln)} in ${pkg.name}@${vuln.installedVersion || pkg.version}, ${severityText(vuln)}${vuln.cweIds?.length ? `, ${vuln.cweIds.slice(0, 3).join(', ')}` : ''}.`,
    vuln.malware ? 'This is a MALWARE record: the installed version itself is malicious.' : null,
    `Summary: ${clip(vuln.summary, 200)}`,
    `Details: ${clip(vuln.detailsExcerpt, 700) || '(none)'}`,
    `Blamed symbols: ${blamedText(vuln.blamedSymbols)}`,
    `Fix: ${fixText(vuln)}`,
    '',
    `Package: ${dependencyText(pkg)}.`,
    ...usageLines(pkg),
    '',
    'Dossier from the package investigation (facts, not a verdict):',
    ...dossierLines(dossier),
    '',
    `Question: is the code this advisory blames reachable from this project, and with untrusted input?${suggestion ? ` Start with this tool call: ${suggestion}` : ''} When the evidence answers the question, reply in two or three sentences without a tool call.`,
  ];
  return lines.filter((l): l is string => l !== null).join('\n');
}

// dossier turn, no tools
export function dossierTurnPrompt(): string {
  return [
    'Now write the fact dossier as JSON matching the dossier schema, using only facts shown in this conversation (the case above and the tool results).',
    'inputSources: where the data passed to the package comes from, each with file:line and its kind (user input, CLI arguments, network, a file, constants); write "unknown" when no evidence here shows it.',
    'callSiteNotes: file:line of each call and what is passed. dependentsSummary: direct, transitive or dev-only, and who depends on it. fixCost: the fix version and whether it is a major bump. openQuestions: what is still unknown.',
    'No risk rating.',
  ].join('\n');
}

// re-ask when contradiction is set
export function verdictTurnPrompt(contradiction?: string): string {
  const fields =
    'risk (apply the rubric), reachable, confidence (0 to 1), reasoning (one or two sentences naming the decisive fact), evidence (file:line facts and tool findings), recommendationAction.';
  if (contradiction) {
    return [
      `Your verdict breaks a rule: ${contradiction}`,
      `Re-read the evidence and the rubric, then give the corrected verdict as JSON matching the verdict schema: ${fields}`,
    ].join('\n');
  }
  return `Now give your verdict as JSON matching the verdict schema: ${fields} Base it only on the evidence in this conversation.`;
}

// verdict broke the rails
export function railsReaskPrompt(contradiction: string): string {
  return verdictTurnPrompt(contradiction);
}

// nudge at budget-1
export function continuePrompt(remaining: number, budget: number): string {
  if (remaining <= 1) {
    return `${NUDGE_TEXT}: make one last call only if it is essential, otherwise reply now in two or three sentences without a tool call.`;
  }
  return `${remaining} of ${budget} tool calls left. Call another tool only if it answers an open question; otherwise reply in two or three sentences without a tool call.`;
}

// names the exact call to make
export function coachingPrompt(missing: { tool: string; args: Record<string, unknown>; reason: string }): string {
  return `The evidence is incomplete: ${missing.reason}. Reply with only this tool call and no text:\n${jsonCall(missing.tool, missing.args)}`;
}

// repeat: note plus earlier result
export function repeatNote(previous: string): string {
  return `${REPEAT_NOTE}\n${previous}`;
}

// second repeat ends the loop
export function repeatStopNote(): string {
  return 'Repeated call again: no more tool calls in this step. The investigation continues with the evidence you have.';
}

// over budget
export function budgetSpentNote(): string {
  return 'Not run: the tool budget for this step is spent. Answer with the evidence you have.';
}
