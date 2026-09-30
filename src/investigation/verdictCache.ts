// reuse verdicts if model, prompt, evidence unchanged
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { RISK_ORDER } from '../config.ts';
import type { ProviderName, UsageEvidence, Verdict, VulnCase } from '../types.ts';
import { createUi } from '../ui.ts';
import { errorMessage } from '../util/errors.ts';
import { hashJson, writeJsonAtomic } from '../util/fs.ts';

export const VERDICT_CACHE_VERSION = 1;

// oldest dropped first
export const MAX_ENTRIES = 1000;

export interface VerdictCacheKeyInput {
  // keeps mock verdicts off real models
  provider: ProviderName;
  vulnId: string;
  package: string;
  version: string;
  model: string;
  // from usageEvidenceHash()
  usageHash: string;
  promptVersion: string;
}

export interface VerdictCacheEntry {
  verdict: Verdict;
  storedAt: string;
}

export interface VerdictCacheFile {
  version: number;
  entries: Record<string, VerdictCacheEntry>;
}

export interface LoadVerdictCacheOptions {
  // corrupt-file warning, default stderr
  warn?: (message: string, detail?: string) => void;
}

const KEY_RE = /^([a-z][a-z0-9-]*):([0-9a-f]{64})$/;

function emptyCache(): VerdictCacheFile {
  return { version: VERDICT_CACHE_VERSION, entries: {} };
}

function required(name: string, value: unknown): string {
  if (typeof value !== 'string' || value.trim() === '') throw new TypeError(`verdictCacheKey: ${name} must be a non-empty string`);
  return value.trim();
}

export function verdictCacheKey(input: VerdictCacheKeyInput): string {
  const provider = required('provider', input.provider);
  if (!/^[a-z][a-z0-9-]*$/.test(provider)) throw new TypeError(`verdictCacheKey: invalid provider "${provider}"`);
  const hash = hashJson({
    v: VERDICT_CACHE_VERSION,
    provider,
    vulnId: required('vulnId', input.vulnId),
    package: required('package', input.package),
    version: required('version', input.version),
    model: required('model', input.model),
    usageHash: required('usageHash', input.usageHash),
    promptVersion: required('promptVersion', input.promptVersion),
  });
  return `${provider}:${hash}`;
}

// null when malformed
export function providerOfKey(key: string): string | null {
  return KEY_RE.exec(key)?.[1] ?? null;
}

const sorted = <T>(items: readonly T[] | undefined, by: (item: T) => string): T[] =>
  [...(items ?? [])].sort((a, b) => {
    const x = by(a);
    const y = by(b);
    return x < y ? -1 : x > y ? 1 : 0;
  });

// usage plus advisory facts
export function usageEvidenceHash(usage: UsageEvidence, vuln: VulnCase): string {
  const sites = sorted(usage.files, (f) => `${f.path}\u0000${String(f.line).padStart(9, '0')}\u0000${f.statement}`).map((f) => ({
    path: f.path,
    line: f.line,
    statement: f.statement,
    binding: f.binding ?? null,
    kind: f.kind,
    named: f.named ?? null,
    subpath: f.subpath ?? null,
    scope: f.scope,
  }));
  const fix = vuln.recommendedFix
    ? {
        version: vuln.recommendedFix.version,
        majorBump: vuln.recommendedFix.majorBump,
        skippedDeprecated: sorted(vuln.recommendedFix.skippedDeprecated, (v) => v),
      }
    : null;
  return hashJson({
    usage: {
      package: usage.package,
      imported: Boolean(usage.imported),
      sites,
      scopes: usage.scopes ?? {},
      membersUsed: usage.membersUsed ?? {},
      bindingCalls: usage.bindingCalls ?? 0,
      truncated: Boolean(usage.truncated),
      // any change re-investigates
      method: usage.method ?? 'regex',
      dynamicAccess: sorted(usage.dynamicAccess ?? [], (d) => `${d.path}\u0000${String(d.line).padStart(9, '0')}\u0000${d.reason}`).map((d) => ({ path: d.path, line: d.line, reason: d.reason })),
      indirectPaths: sorted(usage.indirectPaths ?? [], (p) => `${p.path}\u0000${String(p.line).padStart(9, '0')}\u0000${p.via.join('>')}\u0000${p.member ?? ''}`).map((p) => ({ path: p.path, line: p.line, via: p.via, member: p.member ?? null })),
      dependentUsage: sorted(usage.dependentUsage ?? [], (d) => `${d.dependent}\u0000${d.path}\u0000${String(d.line).padStart(9, '0')}`).map((d) => ({ dependent: d.dependent, version: d.version, path: d.path, line: d.line, member: d.member ?? null })),
    },
    vuln: {
      aliases: sorted(vuln.aliases, (a) => a),
      summary: vuln.summary ?? '',
      detailsExcerpt: vuln.detailsExcerpt ?? '',
      blamedSymbols: sorted(vuln.blamedSymbols, (s) => `${s.name}\u0000${s.kind}`).map((s) => ({ name: s.name, kind: s.kind })),
      severity: vuln.severity ?? {},
      cweIds: sorted(vuln.cweIds, (c) => c),
      malware: Boolean(vuln.malware),
      affectedRange: vuln.affectedRange ?? '',
      fixedVersions: sorted(vuln.fixedVersions, (v) => v),
      recommendedFix: fix,
      isDirect: Boolean(vuln.isDirect),
      isDevOnly: Boolean(vuln.isDevOnly),
      dependencyPaths: sorted(vuln.dependencyPaths, (p) => p.join('>')),
    },
  });
}

function isVerdict(value: unknown): value is Verdict {
  if (!value || typeof value !== 'object') return false;
  const v = value as Partial<Verdict>;
  const inv = v.investigation as Partial<Verdict['investigation']> | undefined;
  return (
    typeof v.vulnId === 'string' &&
    typeof v.package === 'string' &&
    typeof v.installedVersion === 'string' &&
    typeof v.risk === 'string' &&
    (RISK_ORDER as readonly string[]).includes(v.risk) &&
    typeof v.reachable === 'string' &&
    typeof v.confidence === 'number' &&
    typeof v.reasoning === 'string' &&
    Array.isArray(v.evidence) &&
    Boolean(v.recommendation) &&
    typeof v.recommendation === 'object' &&
    Boolean(inv) &&
    typeof inv === 'object' &&
    typeof inv.provider === 'string' &&
    typeof inv.model === 'string'
  );
}

function isEntry(key: string, value: unknown): value is VerdictCacheEntry {
  if (!value || typeof value !== 'object') return false;
  const entry = value as Partial<VerdictCacheEntry>;
  if (!isVerdict(entry.verdict) || typeof entry.storedAt !== 'string') return false;
  return providerOfKey(key) === entry.verdict.investigation.provider;
}

function defaultWarn(message: string, detail?: string): void {
  createUi({}).warn(message, detail);
}

// missing or bad file: empty cache
export async function loadVerdictCache(file: string, options: LoadVerdictCacheOptions = {}): Promise<VerdictCacheFile> {
  const warn = options.warn ?? defaultWarn;
  const name = path.basename(file);
  let text: string;
  try {
    text = await readFile(file, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return emptyCache();
    warn(`Cannot read the verdict cache (${name}); investigating without cached verdicts`, (err as NodeJS.ErrnoException).code ?? errorMessage(err));
    return emptyCache();
  }
  if (text.trim() === '') return emptyCache();
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    warn(`The verdict cache (${name}) is not valid JSON; starting with an empty cache`, 'it is rewritten after the next verdict');
    return emptyCache();
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    warn(`The verdict cache (${name}) has an unexpected shape; starting with an empty cache`);
    return emptyCache();
  }
  const obj = raw as { version?: unknown; entries?: unknown };
  if (obj.version !== VERDICT_CACHE_VERSION) {
    const which = typeof obj.version === 'number' ? `version ${obj.version}` : 'no version';
    warn(`The verdict cache (${name}) was written in another format (${which}); starting with an empty cache`);
    return emptyCache();
  }
  if (!obj.entries || typeof obj.entries !== 'object' || Array.isArray(obj.entries)) {
    warn(`The verdict cache (${name}) has no entries table; starting with an empty cache`);
    return emptyCache();
  }
  const cache = emptyCache();
  let dropped = 0;
  for (const [key, value] of Object.entries(obj.entries as Record<string, unknown>)) {
    if (isEntry(key, value)) cache.entries[key] = value;
    else dropped += 1;
  }
  if (dropped > 0) warn(`Ignored ${dropped} malformed entr${dropped === 1 ? 'y' : 'ies'} in the verdict cache (${name})`);
  return cache;
}

export async function saveVerdictCache(file: string, cache: VerdictCacheFile): Promise<void> {
  const entries: Record<string, VerdictCacheEntry> = {};
  for (const [key, entry] of Object.entries(cache.entries)) if (isEntry(key, entry)) entries[key] = entry;
  await writeJsonAtomic(file, { version: VERDICT_CACHE_VERSION, entries } satisfies VerdictCacheFile);
}

// marked investigation.cached
export function lookupVerdict(cache: VerdictCacheFile, key: string): Verdict | null {
  if (!cache || !cache.entries || !Object.hasOwn(cache.entries, key)) return null;
  const entry = cache.entries[key];
  if (!isEntry(key, entry)) return null;
  const verdict = structuredClone(entry.verdict);
  return { ...verdict, investigation: { ...verdict.investigation, cached: true } };
}

export function storeVerdict(cache: VerdictCacheFile, key: string, verdict: Verdict): void {
  const provider = providerOfKey(key);
  if (provider === null) throw new TypeError(`storeVerdict: malformed cache key "${key}" (use verdictCacheKey)`);
  if (!isVerdict(verdict)) throw new TypeError('storeVerdict: not a verdict');
  if (verdict.investigation.provider !== provider) {
    throw new TypeError(`storeVerdict: a ${verdict.investigation.provider} verdict cannot be stored under a ${provider} key`);
  }
  // never cache forced, re-ask next time
  if (verdict.investigation.forced) return;
  const copy = structuredClone(verdict);
  delete copy.investigation.cached;
  cache.entries[key] = { verdict: copy, storedAt: new Date().toISOString() };
  const keys = Object.keys(cache.entries);
  if (keys.length > MAX_ENTRIES) {
    const oldest = keys
      .filter((k) => k !== key)
      .sort((a, b) => (cache.entries[a]?.storedAt ?? '').localeCompare(cache.entries[b]?.storedAt ?? ''))
      .slice(0, keys.length - MAX_ENTRIES);
    for (const k of oldest) delete cache.entries[k];
  }
}
