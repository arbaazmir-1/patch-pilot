// get_usage tool
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { DEFAULT_EXCLUDES } from '../../config.ts';
import { classifyFile, collectDependentUsage, findImportsInSource, findUsage, walkProject } from '../../evidence/codebase.ts';
import type {
  AnalysisMethod,
  DependentUsage,
  DynamicAccess,
  FileScope,
  ImportKind,
  ImportSite,
  IndirectPath,
  PackageCase,
  ToolContext,
  ToolHandler,
  ToolResult,
  UsageMatch,
} from '../../types.ts';

export interface GetUsageArgs {
  package: string;
  symbol?: string;
}

export interface GetUsageDeps {
  findUsage: typeof findUsage;
  findImportsInSource: typeof findImportsInSource;
  walkProject: typeof walkProject;
  readText: (abs: string) => Promise<string>;
  scanDependents: typeof collectDependentUsage;
  hasNodeModules: (root: string) => boolean;
}

export interface UsageCallSite {
  path: string;
  line: number;
  text: string;
  scope: FileScope;
  binding: string;
  // null when the binding is called
  member: string | null;
}

export interface GetUsageData {
  package: string;
  // normalised
  symbol: string | null;
  imported: boolean;
  importSites: { path: string; line: number; statement: string; binding: string | null; kind: ImportKind; scope: FileScope; subpath?: string }[];
  membersUsed: Record<string, number>;
  bindingCalls: number;
  symbolCalls: number | null;
  // else the binding's call sites
  callSites: UsageCallSite[];
  // no matches, shows other calls
  fallback: boolean;
  importedByName?: boolean;
  // not statically resolvable
  dynamicAccess?: string[];
  // no matches, but package is called
  entryPointCalled?: boolean;
  scannedFiles: number;
  method?: AnalysisMethod;
  // via the project's own functions
  indirectPaths?: IndirectPath[];
  indirectCalls?: number;
  dynamicDetails?: DynamicAccess[];
  // calls inside dependents' code
  dependentUsage?: DependentUsage[];
  dependentsScanned?: 'scanned' | 'no-node-modules';
}

const SITES_WITH_CONTEXT = 3;
const MAX_CALL_SITES = 12;
const LINE_CHARS = 140;
const INDIRECT_LINES = 4;
const DEPENDENT_LINES = 3;

// "_['template']" -> "template"
export function normalizeSymbol(symbol: string): string {
  const trimmed = symbol.trim().replace(/\(.*\)$/, '').replace(/^[`'"]+|[`'"]+$/g, '');
  const bracket = /\[\s*['"]([^'"\]]+)['"]\s*\]$/.exec(trimmed);
  if (bracket && bracket[1] !== undefined) return bracket[1].trim();
  const last = trimmed.split('.').pop() ?? trimmed;
  return last.trim();
}

function clipLine(text: string): string {
  const t = text.replace(/\t/g, '  ').trimEnd();
  return t.length > LINE_CHARS ? `${t.slice(0, LINE_CHARS - 3)}...` : t;
}

function findPackageCase(ctx: ToolContext, name: string): PackageCase | undefined {
  const cases = (ctx.caseFile?.packages ?? []).filter((p) => p.name === name);
  if (cases.length <= 1) return cases[0];
  return cases.find((p) => p.version === ctx.focus?.version) ?? cases[0];
}

async function scanImports(ctx: ToolContext, pkg: string, deps: GetUsageDeps): Promise<{ sites: ImportSite[]; scanned: number }> {
  const walk = await deps.walkProject(ctx.projectRoot, { exclude: ctx.config?.exclude ?? DEFAULT_EXCLUDES, ...(ctx.signal ? { signal: ctx.signal } : {}) });
  const sites: ImportSite[] = [];
  for (const file of walk.files) {
    let source: string;
    try {
      source = await deps.readText(file.abs);
    } catch {
      continue;
    }
    if (!source.includes(pkg)) continue;
    sites.push(...deps.findImportsInSource(source, file.path, [pkg]));
  }
  return { sites, scanned: walk.files.length };
}

function toCallSite(m: UsageMatch): UsageCallSite {
  return { path: m.path, line: m.line, text: m.text, scope: m.scope, binding: m.binding, member: m.member };
}

function dedupeMatches(matches: readonly UsageMatch[]): UsageMatch[] {
  const seen = new Set<string>();
  return matches.filter((m) => {
    const key = `${m.path}:${m.line}:${m.member ?? ''}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// local bound to a member counts
function attributeLocals(matches: readonly UsageMatch[], sites: readonly ImportSite[]): UsageMatch[] {
  const locals = new Map<string, string>();
  for (const s of sites) {
    if (s.subpath && s.binding) locals.set(`${s.path}|${s.binding}`, normalizeSymbol(s.subpath.replace(/\//g, '.')));
    for (const [imported, local] of Object.entries(s.named ?? {})) locals.set(`${s.path}|${local}`, normalizeSymbol(imported));
  }
  if (locals.size === 0) return [...matches];
  return matches.map((m) => {
    if (m.member !== null) return m;
    const member = locals.get(`${m.path}|${m.binding}`);
    return member ? { ...m, member } : m;
  });
}

function countMembers(matches: readonly UsageMatch[]): { members: Record<string, number>; bindingCalls: number } {
  const members: Record<string, number> = {};
  let bindingCalls = 0;
  for (const m of matches) {
    if (m.member === null) bindingCalls += 1;
    else members[m.member] = (members[m.member] ?? 0) + 1;
  }
  return { members, bindingCalls };
}

function sortedMembers(members: Record<string, number>): [string, number][] {
  return Object.entries(members)
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

// "_.merge (3), _.get (2)"
function membersList(members: Record<string, number>, binding: string | null, limit = 6): string {
  const entries = sortedMembers(members);
  const shown = entries.slice(0, limit).map(([m, n]) => `${binding ? `${binding}.${m}` : `${m}()`} (${n})`);
  if (entries.length > limit) shown.push(`${entries.length - limit} more`);
  return shown.join(', ');
}

function formatSite(m: UsageMatch): string[] {
  const out = [`${m.path}:${m.line}${m.scope !== 'source' ? ` [${m.scope}]` : ''}`];
  const before = m.context?.before ?? [];
  const after = m.context?.after ?? [];
  const width = String(m.line + after.length).length;
  before.forEach((text, i) => out.push(`  ${String(m.line - before.length + i).padStart(width)}| ${clipLine(text)}`));
  out.push(`> ${String(m.line).padStart(width)}| ${clipLine(m.text)}`);
  after.forEach((text, i) => out.push(`  ${String(m.line + 1 + i).padStart(width)}| ${clipLine(text)}`));
  return out;
}

function formatSites(matches: readonly UsageMatch[]): string[] {
  const out: string[] = [];
  matches.slice(0, SITES_WITH_CONTEXT).forEach((m) => out.push(...formatSite(m)));
  const rest = matches.slice(SITES_WITH_CONTEXT, MAX_CALL_SITES).map((m) => `${m.path}:${m.line}`);
  if (rest.length > 0) out.push(`Other call sites: ${rest.join(', ')}${matches.length > MAX_CALL_SITES ? `, ${matches.length - MAX_CALL_SITES} more` : ''}`);
  return out;
}

function rankSites(matches: readonly UsageMatch[]): UsageMatch[] {
  const scopeRank: Record<FileScope, number> = { source: 0, scripts: 1, config: 2, test: 3 };
  return [...matches].sort(
    (a, b) =>
      scopeRank[a.scope] - scopeRank[b.scope] ||
      Number(a.member !== null) - Number(b.member !== null) ||
      a.path.localeCompare(b.path) ||
      a.line - b.line,
  );
}

function importLine(sites: readonly ImportSite[]): string {
  const files = [...new Set(sites.map((s) => s.path))];
  const first = sites
    .slice(0, 3)
    .map((s) => `${s.path}:${s.line} \`${clipLine(s.statement)}\`${s.binding ? ` as ${s.binding}` : ''}${s.scope !== 'source' ? ` [${s.scope}]` : ''}`);
  return `Imported in ${files.length} file${files.length === 1 ? '' : 's'}: ${first.join('; ')}${sites.length > 3 ? `; ${sites.length - 3} more` : ''}`;
}

function escapeRe(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// non-literal index, max 5
async function dynamicAccessSites(ctx: ToolContext, sites: readonly ImportSite[], deps: GetUsageDeps): Promise<string[]> {
  const byFile = new Map<string, Set<string>>();
  for (const s of sites) if (s.binding) byFile.set(s.path, (byFile.get(s.path) ?? new Set<string>()).add(s.binding));
  const out: string[] = [];
  for (const [file, bindings] of byFile) {
    let text: string;
    try {
      text = await deps.readText(path.join(ctx.projectRoot, file));
    } catch {
      continue;
    }
    const lines = text.split('\n');
    for (const binding of bindings) {
      const re = new RegExp(`(?<![\\w$.])${escapeRe(binding)}\\s*\\[\\s*(?![\\s'"\`\\d\\]])`);
      lines.forEach((line, i) => {
        if (re.test(line)) out.push(`${file}:${i + 1}`);
      });
    }
  }
  return [...new Set(out)].slice(0, 5);
}

function camelCase(name: string): string {
  const bare = name.startsWith('@') ? (name.split('/')[1] ?? name) : name;
  return bare.replace(/[-_.]+([a-zA-Z0-9])/g, (_m, c: string) => c.toUpperCase());
}

// e.g. _.template(), marked()
function memberDisplay(pkg: string, binding: string | null, member: string | null): string {
  if (member === null) return `${binding ?? camelCase(pkg)}()`;
  return binding ? `${binding}.${member}()` : `${member}()`;
}

function scopeTag(file: string): string {
  const s = classifyFile(file);
  return s === 'source' ? '' : ` [${s}]`;
}

// "src/cli.js:31 via compile() -> _.template()"
function indirectLine(p: IndirectPath, pkg: string, binding: string | null): string {
  return `${p.path}:${p.line}${scopeTag(p.path)} via ${p.via.map((v) => `${v}()`).join(' -> ')} -> ${memberDisplay(pkg, binding, p.member)}`;
}

function indirectBlock(paths: readonly IndirectPath[], pkg: string, binding: string | null, heading: string): string[] {
  if (paths.length === 0) return [];
  const lines = paths.slice(0, INDIRECT_LINES).map((p) => `  ${indirectLine(p, pkg, binding)}`);
  if (paths.length > INDIRECT_LINES) lines.push(`  ${paths.length - INDIRECT_LINES} more`);
  return [heading, ...lines];
}

// package's own calls match its name
function indirectFor(paths: readonly IndirectPath[], symbol: string | null, pkg: string): IndirectPath[] {
  if (symbol === null) return [...paths];
  const s = symbol.toLowerCase();
  const defaultNames = new Set([pkg.toLowerCase(), camelCase(pkg).toLowerCase(), 'default']);
  return paths.filter((p) => (p.member === null ? defaultNames.has(s) : p.member.toLowerCase() === s));
}

function locations(entries: readonly { path: string; line: number }[], limit = 3): string {
  const shown = entries.slice(0, limit).map((e) => `${e.path}:${e.line}`);
  return `${shown.join(', ')}${entries.length > limit ? `, and ${entries.length - limit} more` : ''}`;
}

// grouped by reason
function dynamicLines(details: readonly DynamicAccess[], symbol: string | null): string[] {
  const out: string[] = [];
  const by = (reason: DynamicAccess['reason']): DynamicAccess[] => details.filter((d) => d.reason === reason);
  const computed = by('computed-member');
  if (computed.length > 0) {
    const texts = [...new Set(computed.map((d) => `\`${d.text}\``))].slice(0, 2).join(', ');
    const reach = symbol ? `; it could reach ${symbol}` : '';
    out.push(`${computed.length} computed access${computed.length === 1 ? '' : 'es'} ${texts} at ${locations(computed)} cannot be resolved statically${reach}.`);
  }
  const requires = by('dynamic-require');
  if (requires.length > 0) {
    const texts = [...new Set(requires.map((d) => `\`${d.text}\``))].slice(0, 2).join(', ');
    out.push(`${requires.length} dynamic require${requires.length === 1 ? '' : 's'} ${texts} at ${locations(requires)} cannot be resolved statically; it may load the package.`);
  }
  const reassigned = by('reassigned-binding');
  if (reassigned.length > 0) {
    out.push(`The binding is reassigned at ${locations(reassigned)} (\`${reassigned[0]?.text ?? ''}\`), so later uses may hold another value.`);
  }
  const unparsed = by('unparsed-file');
  for (const d of unparsed.slice(0, 2)) out.push(`${d.path}${d.line > 1 ? `:${d.line}` : ''}: ${d.text}.`);
  if (unparsed.length > 2) out.push(`${unparsed.length - 2} more files were not parsed.`);
  return out;
}

function dependentLine(u: DependentUsage, pkg: string): string {
  return `${u.dependent} calls ${memberDisplay(pkg, u.member === null ? null : camelCase(pkg), u.member)} in ${u.path}:${u.line}`;
}

// all of them without a symbol
function dependentFor(uses: readonly DependentUsage[], symbol: string | null, pkg: string): DependentUsage[] {
  if (symbol === null) return [...uses];
  const s = symbol.toLowerCase();
  const defaultNames = new Set([pkg.toLowerCase(), camelCase(pkg).toLowerCase(), 'default']);
  return uses.filter((u) => (u.member === null ? defaultNames.has(s) : u.member.toLowerCase() === s));
}

// two lines of context
async function indirectSites(ctx: ToolContext, paths: readonly IndirectPath[], deps: GetUsageDeps): Promise<UsageMatch[]> {
  const out: UsageMatch[] = [];
  const texts = new Map<string, string[] | null>();
  for (const p of paths.slice(0, MAX_CALL_SITES)) {
    if (!texts.has(p.path)) {
      try {
        texts.set(p.path, (await deps.readText(path.join(ctx.projectRoot, p.path))).split('\n').map((l) => l.replace(/\r$/, '')));
      } catch {
        texts.set(p.path, null);
      }
    }
    const lines = texts.get(p.path) ?? null;
    const text = lines?.[p.line - 1]?.trim() ?? '';
    const match: UsageMatch = { path: p.path, line: p.line, text, scope: classifyFile(p.path), binding: p.via[0] ?? '', member: p.member };
    if (lines) match.context = { before: lines.slice(Math.max(0, p.line - 3), p.line - 1), after: lines.slice(p.line, p.line + 2) };
    out.push(match);
  }
  return out;
}

export function makeGetUsageHandler(overrides: Partial<GetUsageDeps> = {}): ToolHandler<GetUsageArgs> {
  const deps: GetUsageDeps = {
    findUsage,
    findImportsInSource,
    walkProject,
    readText: (abs) => readFile(abs, 'utf8'),
    scanDependents: collectDependentUsage,
    hasNodeModules: (root) => existsSync(path.join(root, 'node_modules')),
    ...overrides,
  };
  return async (args: GetUsageArgs, ctx: ToolContext): Promise<ToolResult> => {
    const pkgName = String(args.package ?? '').trim();
    if (pkgName === '') return { ok: false, error: 'package is required', hint: 'Give the npm package name, for example {"package": "lodash"}' };
    const symbol = args.symbol && normalizeSymbol(args.symbol) !== '' ? normalizeSymbol(args.symbol) : null;
    const pkgCase = findPackageCase(ctx, pkgName);
    let sites: ImportSite[];
    let scanned: number;
    if (pkgCase?.usage && Array.isArray(pkgCase.usage.files)) {
      sites = pkgCase.usage.files;
      scanned = pkgCase.usage.scannedFiles ?? 0;
    } else {
      const scan = await scanImports(ctx, pkgName, deps);
      sites = scan.sites;
      scanned = scan.scanned;
    }
    const evidence = pkgCase?.usage;
    const base: GetUsageData = {
      package: pkgName,
      symbol,
      imported: sites.length > 0,
      importSites: sites.map((s) => ({
        path: s.path,
        line: s.line,
        statement: s.statement,
        binding: s.binding,
        kind: s.kind,
        scope: s.scope,
        ...(s.subpath ? { subpath: s.subpath } : {}),
      })),
      membersUsed: {},
      bindingCalls: 0,
      symbolCalls: symbol ? 0 : null,
      callSites: [],
      fallback: false,
      scannedFiles: scanned,
    };
    if (evidence?.method) base.method = evidence.method;
    const details = Array.isArray(evidence?.dynamicAccess) ? evidence.dynamicAccess : [];
    if (details.length > 0) base.dynamicDetails = details;

    if (sites.length === 0) {
      const via = (pkgCase?.dependents ?? []).map((d) => `${d.name}@${d.version}`);
      let dependentUsage = Array.isArray(evidence?.dependentUsage) ? evidence.dependentUsage : undefined;
      let notInstalled = false;
      if (dependentUsage === undefined && pkgCase && pkgCase.dependents.length > 0) {
        if (!deps.hasNodeModules(ctx.projectRoot)) notInstalled = true;
        else dependentUsage = await deps.scanDependents(ctx.projectRoot, [pkgName], pkgCase.dependents).catch(() => undefined);
      }
      if (dependentUsage !== undefined) {
        base.dependentUsage = dependentUsage;
        base.dependentsScanned = 'scanned';
      } else if (notInstalled) {
        base.dependentsScanned = 'no-node-modules';
      }
      if (details.length > 0) base.dynamicAccess = details.map((d) => `${d.path}:${d.line}`);
      const relevant = dependentUsage ? dependentFor(dependentUsage, symbol, pkgName) : [];
      const shown = relevant.length > 0 ? relevant : (dependentUsage ?? []);
      const scannedText = scanned > 0 ? ` (${scanned} files scanned)` : '';
      const first = shown[0];
      const hint = [
        `${pkgName} is not imported in the project${scannedText}${via.length > 0 ? `; it is installed for ${via.slice(0, 3).join(', ')}` : ''}`,
        first ? `; ${dependentLine(first, pkgName)}` : '',
        details.length > 0 ? `; ${details.length} dynamic access${details.length === 1 ? '' : 'es'} may load it` : '',
      ].join('');
      const dependentText: string[] = [];
      if (dependentUsage && shown.length > 0) {
        dependentText.push(`Inside its dependents: ${shown.slice(0, DEPENDENT_LINES).map((u) => dependentLine(u, pkgName)).join('; ')}${shown.length > DEPENDENT_LINES ? `; and ${shown.length - DEPENDENT_LINES} more` : ''}.`);
        for (const u of shown.slice(0, 2)) dependentText.push(`  ${u.path}:${u.line}| ${clipLine(u.text)}`);
        if (symbol && relevant.length === 0) dependentText.push(`None of them calls ${symbol}.`);
      } else if (dependentUsage) {
        dependentText.push(`Its dependents' installed code was scanned: none of them calls ${pkgName} directly.`);
      } else if (notInstalled) {
        dependentText.push('Dependents not scanned: node_modules is not installed.');
      }
      const text = [
        `${pkgName} is not imported by any project file${scannedText}.`,
        via.length > 0 ? `It is a dependency of ${via.join(', ')}; the project reaches it only through those packages.` : null,
        ...dependentText,
        ...dynamicLines(details, symbol),
        symbol ? `So ${symbol} is not called by project code directly.` : null,
      ]
        .filter(Boolean)
        .join('\n');
      return { ok: true, hint, text, data: base };
    }

    const all = rankSites(dedupeMatches(attributeLocals(await deps.findUsage(ctx.projectRoot, sites, undefined, { contextLines: 2, maxResults: 200 }), sites)));
    const counted = countMembers(all);
    const membersUsed = all.length > 0 ? counted.members : (evidence?.membersUsed ?? {});
    const bindingCalls = all.length > 0 ? counted.bindingCalls : (evidence?.bindingCalls ?? 0);
    const binding = sites.find((s) => s.binding && (s.kind === 'cjs-require' || s.kind === 'esm-default' || s.kind === 'esm-namespace'))?.binding ?? sites.find((s) => s.binding)?.binding ?? null;
    const data: GetUsageData = { ...base, membersUsed, bindingCalls };
    const bindingCallText =
      bindingCalls > 0 ? `${binding ?? pkgName}() is called directly ${bindingCalls} time${bindingCalls === 1 ? '' : 's'}` : 'the binding itself is never called';
    const memberText = sortedMembers(membersUsed).length > 0 ? membersList(membersUsed, binding) : 'no members';
    const allIndirect = Array.isArray(evidence?.indirectPaths) ? evidence.indirectPaths : [];
    const indirect = indirectFor(allIndirect, symbol, pkgName);
    if (indirect.length > 0) {
      data.indirectPaths = indirect.slice(0, MAX_CALL_SITES);
      data.indirectCalls = indirect.length;
    }
    const detailLines = dynamicLines(details, symbol);
    const detailLocations = details.map((d) => `${d.path}:${d.line}`);
    const firstIndirect = indirect[0];
    const indirectHint = firstIndirect
      ? `; called indirectly ${indirect.length === 1 ? 'once' : `${indirect.length} times`}: ${indirectLine(firstIndirect, pkgName, binding)}${indirect.length > 1 ? ', ...' : ''}`
      : '';

    if (symbol) {
      const direct = attributeLocals(await deps.findUsage(ctx.projectRoot, sites, symbol, { contextLines: 2, maxResults: 50 }), sites);
      const matches = rankSites(dedupeMatches([...direct, ...all].filter((m) => m.member === symbol)));
      const display = binding ? `${binding}.${symbol}` : `${symbol}()`;
      if (matches.length > 0) {
        const files = [...new Set(matches.map((m) => m.path))];
        data.symbolCalls = matches.length;
        data.callSites = matches.slice(0, MAX_CALL_SITES).map(toCallSite);
        if (detailLocations.length > 0) data.dynamicAccess = detailLocations;
        const refs = matches.slice(0, 3).map((m) => `${m.path}:${m.line}`);
        const hint = `${matches.length} call${matches.length === 1 ? '' : 's'} to ${display} in ${files.length} file${files.length === 1 ? '' : 's'}: ${refs.join(', ')}${matches.length > 3 ? ', ...' : ''}${indirectHint}`;
        const text = [
          importLine(sites),
          `${matches.length} call${matches.length === 1 ? '' : 's'} to ${display}:`,
          ...formatSites(matches),
          ...indirectBlock(indirect, pkgName, binding, "Called indirectly (through the project's own functions):"),
          ...detailLines,
        ].join('\n');
        return { ok: true, hint, text, data };
      }
      const importedByName = sites.some((s) => s.named && Object.keys(s.named).some((k) => normalizeSymbol(k) === symbol));
      if (importedByName) data.importedByName = true;
      if (indirect.length > 0) {
        // only via own wrapper or re-export
        const outer = rankSites(await indirectSites(ctx, indirect, deps));
        data.callSites = outer.map(toCallSite);
        if (detailLocations.length > 0) data.dynamicAccess = detailLocations;
        const hint = `0 direct calls to ${display}, but it is called indirectly ${indirect.length === 1 ? 'once' : `${indirect.length} times`}: ${indirectLine(firstIndirect as IndirectPath, pkgName, binding)}${indirect.length > 1 ? ', ...' : ''}`;
        const text = [
          importLine(sites),
          `No direct call to ${display} was found, but the project calls it through its own modules:`,
          ...indirectBlock(indirect, pkgName, binding, 'Called indirectly:').slice(1),
          'The outer call sites:',
          ...formatSites(outer),
          ...detailLines,
          `What the project calls directly: ${memberText}; ${bindingCallText}.`,
        ].join('\n');
        return { ok: true, hint, text, data };
      }
      const scannedDynamic = await dynamicAccessSites(ctx, sites, deps);
      const computedDetails = details.filter((d) => d.reason === 'computed-member');
      const dynamic = [...new Set([...scannedDynamic, ...detailLocations])];
      data.fallback = true;
      data.dynamicAccess = dynamic;
      data.callSites = all.slice(0, MAX_CALL_SITES).map(toCallSite);
      const dynamicText = dynamic.length > 0 ? `; dynamic access at ${dynamic.slice(0, 2).join(', ')}` : '';
      const dynamicLine = !binding
        ? null
        : computedDetails.length > 0
          ? null
          : scannedDynamic.length > 0
            ? `Dynamic member access (${binding}[...]) at ${scannedDynamic.join(', ')} could reach ${symbol} indirectly.`
            : `No dynamic member access (${binding}[...]) was found in the importing files either.`;
      const entryCalls = all.filter((m) => m.member === null);
      if (bindingCalls > 0) {
        // entry point may be the blamed api
        const first = entryCalls[0];
        const times = `${bindingCalls} time${bindingCalls === 1 ? '' : 's'}`;
        const members = sortedMembers(membersUsed).length > 0 ? `; it also calls ${membersList(membersUsed, binding, 4)}` : '';
        data.entryPointCalled = true;
        const hint = `0 calls to ${display}, but the package itself is called ${times}${first ? ` (${first.path}:${first.line})` : ''}; the default call is the package's main entry point${members}${dynamicText}`;
        const others = all.filter((m) => m.member !== null);
        const text = [
          importLine(sites),
          `No call to ${display} was found${importedByName ? ` (it is imported by name but never called)` : ''}, but the package itself is called ${times}: the default call is the package's main entry point.`,
          dynamicLine,
          ...detailLines,
          `The package itself is called here:`,
          ...formatSites(entryCalls),
          ...(others.length > 0 ? [`Members called: ${memberText}.`, ...formatSites(others)] : []),
        ]
          .filter((l): l is string => l !== null)
          .join('\n');
        return { ok: true, hint, text, data };
      }
      const calls = sortedMembers(membersUsed).length > 0 ? `project calls ${membersList(membersUsed, binding, 4)}` : `no calls on ${pkgName} found`;
      const hint = `0 calls to ${display}; ${calls}${dynamicText}`;
      const text = [
        importLine(sites),
        `No call to ${display} was found${importedByName ? ` (it is imported by name but never called)` : ''}.`,
        dynamicLine,
        ...detailLines,
        `What the project calls instead: ${memberText}; ${bindingCallText}.`,
        ...(all.length > 0 ? formatSites(all) : []),
      ]
        .filter((l): l is string => l !== null)
        .join('\n');
      return { ok: true, hint, text, data };
    }

    data.callSites = all.slice(0, MAX_CALL_SITES).map(toCallSite);
    if (detailLocations.length > 0) data.dynamicAccess = detailLocations;
    const files = [...new Set(sites.map((s) => s.path))];
    const hintParts = [`${pkgName} imported in ${files.slice(0, 2).join(', ')}${files.length > 2 ? ` and ${files.length - 2} more` : ''}${binding ? ` as ${binding}` : ''}`];
    if (sortedMembers(membersUsed).length > 0) hintParts.push(`calls ${membersList(membersUsed, binding, 4)}`);
    if (bindingCalls > 0) {
      const first = all.find((m) => m.member === null);
      hintParts.push(`called directly ${bindingCalls} time${bindingCalls === 1 ? '' : 's'}${first ? ` (${first.path}:${first.line})` : ''}`);
    }
    if (sortedMembers(membersUsed).length === 0 && bindingCalls === 0) hintParts.push('no calls found');
    if (firstIndirect) hintParts.push(`called indirectly: ${indirectLine(firstIndirect, pkgName, binding)}${indirect.length > 1 ? `, and ${indirect.length - 1} more` : ''}`);
    const computed = details.filter((d) => d.reason === 'computed-member');
    if (computed.length > 0) hintParts.push(`${computed.length} computed access${computed.length === 1 ? '' : 'es'} cannot be resolved statically`);
    const text = [
      importLine(sites),
      `Members called: ${memberText}; ${bindingCallText}.`,
      ...indirectBlock(indirect, pkgName, binding, "Called indirectly (through the project's own functions):"),
      ...detailLines,
      ...(all.length > 0 ? ['Call sites:', ...formatSites(all)] : []),
    ].join('\n');
    return { ok: true, hint: hintParts.join('; '), text, data };
  };
}

export async function handleGetUsage(args: GetUsageArgs, ctx: ToolContext): Promise<ToolResult> {
  return defaultHandler(args, ctx);
}

const defaultHandler = makeGetUsageHandler();
