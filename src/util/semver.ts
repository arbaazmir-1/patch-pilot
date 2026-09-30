// osv ranges and fix picking
import semver from 'semver';
import type { OsvAffected, OsvEvent, OsvRange, RecommendedFix, SpecStyle } from '../types.ts';

type EventKind = 'introduced' | 'fixed' | 'last_affected' | 'limit';

interface NormalEvent {
  kind: EventKind;
  // null means "0"
  version: semver.SemVer | null;
  raw: string;
}

const KIND_ORDER: Record<EventKind, number> = { introduced: 0, last_affected: 1, fixed: 2, limit: 3 };

// allows leading "v" or "="
export function parseVersion(version: string): semver.SemVer | null {
  if (typeof version !== 'string' || version.trim() === '') return null;
  return semver.parse(version.trim(), { loose: true }) ?? null;
}

export function isValidVersion(version: string): boolean {
  return parseVersion(version) !== null;
}

// unparseable sorts first
export function compareVersions(a: string, b: string): number {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  if (!pa && !pb) return a.localeCompare(b);
  if (!pa) return -1;
  if (!pb) return 1;
  return semver.compare(pa, pb);
}

export function sortVersions(versions: readonly string[]): string[] {
  return [...versions].sort(compareVersions);
}

function eventKind(event: OsvEvent): EventKind | null {
  if ('introduced' in event) return 'introduced';
  if ('fixed' in event) return 'fixed';
  if ('last_affected' in event) return 'last_affected';
  if ('limit' in event) return 'limit';
  return null;
}

function eventValue(event: OsvEvent): string {
  const record = event as Record<string, unknown>;
  const kind = eventKind(event);
  return kind ? String(record[kind] ?? '') : '';
}

function normaliseEvents(range: OsvRange): NormalEvent[] {
  const out: NormalEvent[] = [];
  for (const event of range.events ?? []) {
    const kind = eventKind(event);
    if (!kind) continue;
    const raw = eventValue(event).trim();
    if (raw === '*' && kind === 'limit') continue; // "*" means unlimited
    if (raw === '0' && kind === 'introduced') {
      out.push({ kind, version: null, raw });
      continue;
    }
    const version = parseVersion(raw);
    if (!version) continue;
    out.push({ kind, version, raw });
  }
  out.sort((a, b) => {
    if (a.version === null && b.version === null) return KIND_ORDER[a.kind] - KIND_ORDER[b.kind];
    if (a.version === null) return -1;
    if (b.version === null) return 1;
    const cmp = semver.compare(a.version, b.version);
    return cmp !== 0 ? cmp : KIND_ORDER[a.kind] - KIND_ORDER[b.kind];
  });
  return out;
}

function evaluatesSemver(range: OsvRange): boolean {
  return range.type === 'SEMVER' || range.type === 'ECOSYSTEM';
}

// per the osv spec
export function isAffectedByRange(version: string, range: OsvRange): boolean {
  if (!evaluatesSemver(range)) return false;
  const v = parseVersion(version);
  if (!v) return false;
  const events = normaliseEvents(range);
  for (const e of events) {
    if (e.kind === 'limit' && e.version && semver.gte(v, e.version)) return false;
  }
  let affected = false;
  for (const e of events) {
    if (e.kind === 'introduced') {
      if (e.version === null || semver.gte(v, e.version)) affected = true;
    } else if (e.kind === 'fixed') {
      if (e.version && semver.gte(v, e.version)) affected = false;
    } else if (e.kind === 'last_affected') {
      if (e.version && semver.gt(v, e.version)) affected = false;
    }
  }
  return affected;
}

export function isAffected(version: string, ranges: readonly OsvRange[]): boolean {
  return ranges.some((range) => isAffectedByRange(version, range));
}

export function isAffectedByEntry(version: string, affected: OsvAffected): boolean {
  if (affected.versions?.includes(version)) return true;
  return isAffected(version, affected.ranges ?? []);
}

// deduped and sorted
export function fixedVersionsFromRanges(ranges: readonly OsvRange[]): string[] {
  const seen = new Set<string>();
  for (const range of ranges) {
    if (!evaluatesSemver(range)) continue;
    for (const e of normaliseEvents(range)) {
      if (e.kind === 'fixed' && e.version) seen.add(e.version.version);
    }
  }
  return sortVersions([...seen]);
}

// e.g. ">=4.0.0 <4.18.0"
export function describeRanges(ranges: readonly OsvRange[]): string {
  const segments: { low: semver.SemVer | null; text: string }[] = [];
  for (const range of ranges) {
    if (!evaluatesSemver(range)) continue;
    let start: NormalEvent | null = null;
    let open = false;
    for (const e of normaliseEvents(range)) {
      if (e.kind === 'introduced') {
        if (!open) {
          start = e;
          open = true;
        }
      } else if ((e.kind === 'fixed' || e.kind === 'last_affected' || e.kind === 'limit') && open) {
        const low = start?.version ? `>=${start.version.version} ` : '';
        const high = e.kind === 'last_affected' ? `<=${e.raw}` : `<${e.version?.version ?? e.raw}`;
        segments.push({ low: start?.version ?? null, text: `${low}${high}` });
        open = false;
        start = null;
      }
    }
    if (open) {
      segments.push({ low: start?.version ?? null, text: start?.version ? `>=${start.version.version}` : '*' });
    }
  }
  if (segments.length === 0) return 'unknown';
  segments.sort((a, b) => {
    if (a.low === null && b.low === null) return 0;
    if (a.low === null) return -1;
    if (b.low === null) return 1;
    return semver.compare(a.low, b.low);
  });
  return [...new Set(segments.map((s) => s.text))].join(' || ');
}

// npm caret semantics
export function isSameLine(installed: string, candidate: string): boolean {
  const a = parseVersion(installed);
  const b = parseVersion(candidate);
  if (!a || !b) return false;
  if (a.major !== b.major) return false;
  if (a.major > 0) return true;
  if (a.minor !== b.minor) return false;
  if (a.minor > 0) return true;
  return a.patch === b.patch;
}

export function isMajorBump(from: string, to: string): boolean {
  return !isSameLine(from, to);
}

// e.g. "^0.2.0"
export function satisfiesRange(version: string, range: string): boolean {
  const v = parseVersion(version);
  if (!v) return false;
  try {
    return semver.satisfies(v, range, { includePrerelease: false, loose: true });
  } catch {
    return false;
  }
}

const SIMPLE_RANGE_BODY = String.raw`v?\d+(?:\.(?:\d+|x|X|\*)){0,2}(?:-[0-9A-Za-z.-]+)?`;
const CARET_SPEC = new RegExp(`^\\^${SIMPLE_RANGE_BODY}$`);
const TILDE_SPEC = new RegExp(`^~${SIMPLE_RANGE_BODY}$`);
const EXACT_SPEC = /^=?v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

export function specStyle(spec: string): SpecStyle {
  const s = spec.trim();
  if (CARET_SPEC.test(s)) return 'caret';
  if (TILDE_SPEC.test(s)) return 'tilde';
  if (EXACT_SPEC.test(s) && parseVersion(s.replace(/^=/, ''))) return 'exact';
  return 'other';
}

export interface PickFixOptions {
  // to replace a deprecated fix
  available?: readonly string[];
  // skip candidates in these
  ranges?: readonly OsvRange[];
  // true if installed is a prerelease
  allowPrerelease?: boolean;
}

function isPrerelease(v: semver.SemVer): boolean {
  return v.prerelease.length > 0;
}

// installed line first, else smallest
export function pickFix(
  fixedVersions: readonly string[],
  installed: string,
  deprecated: ReadonlySet<string>,
  options: PickFixOptions = {},
): RecommendedFix | null {
  const inst = parseVersion(installed);
  if (!inst) return null;
  const allowPre = options.allowPrerelease ?? isPrerelease(inst);
  const available = (options.available ?? [])
    .map((v) => parseVersion(v))
    .filter((v): v is semver.SemVer => v !== null && (allowPre || !isPrerelease(v)))
    .sort(semver.compare);
  const ranges = options.ranges ?? [];
  const skipped = new Set<string>();
  const chosen = new Set<string>();

  for (const raw of fixedVersions) {
    const fix = parseVersion(raw);
    if (!fix || !semver.gt(fix, inst)) continue;
    if (!allowPre && isPrerelease(fix)) continue;
    let candidate: semver.SemVer | null = fix;
    if (deprecated.has(fix.version)) {
      skipped.add(fix.version);
      candidate =
        available.find(
          (v) =>
            semver.gt(v, fix) &&
            isSameLine(fix.version, v.version) &&
            !deprecated.has(v.version) &&
            (ranges.length === 0 || !isAffected(v.version, ranges)),
        ) ?? null;
    }
    if (!candidate) continue;
    if (ranges.length > 0 && isAffected(candidate.version, ranges)) continue;
    chosen.add(candidate.version);
  }

  const sorted = sortVersions([...chosen]);
  const sameLine = sorted.find((v) => isSameLine(inst.version, v));
  const version = sameLine ?? sorted[0];
  if (version === undefined) return null;
  const fixResult: RecommendedFix = { version, majorBump: sameLine === undefined };
  if (skipped.size > 0) fixResult.skippedDeprecated = sortVersions([...skipped]);
  return fixResult;
}

export interface PackageFixInput {
  id: string;
  ranges: readonly OsvRange[];
  fixedVersions: readonly string[];
}

export interface PackageFix {
  version: string;
  majorBump: boolean;
  clears: string[];
  // empty for a full fix
  remaining: string[];
  // when the full fix is major
  sameLineBest?: { version: string; clears: string[]; remaining: string[] };
}

// else the one clearing most
export function pickPackageFix(
  vulns: readonly PackageFixInput[],
  installed: string,
  available: readonly string[],
  deprecated: ReadonlySet<string>,
): PackageFix | null {
  const inst = parseVersion(installed);
  if (!inst || vulns.length === 0) return null;
  const pool = available.length > 0 ? available : vulns.flatMap((v) => v.fixedVersions);
  const candidates = sortVersions(
    [...new Set(pool)].filter((raw) => {
      const v = parseVersion(raw);
      return v !== null && !isPrerelease(v) && semver.gt(v, inst) && !deprecated.has(v.version);
    }),
  );

  const evaluate = (version: string): { clears: string[]; remaining: string[] } => {
    const clears: string[] = [];
    const remaining: string[] = [];
    for (const vuln of vulns) (isAffected(version, vuln.ranges) ? remaining : clears).push(vuln.id);
    return { clears, remaining };
  };

  let best: { version: string; clears: string[]; remaining: string[] } | null = null;
  let bestSameLine: { version: string; clears: string[]; remaining: string[] } | null = null;
  for (const version of candidates) {
    const result = evaluate(version);
    if (result.clears.length === 0) continue;
    const entry = { version, ...result };
    if (isSameLine(inst.version, version) && (!bestSameLine || result.clears.length > bestSameLine.clears.length)) {
      bestSameLine = entry;
    }
    if (!best || result.clears.length > best.clears.length) best = entry;
    if (result.remaining.length === 0) break;
  }
  if (!best) return null;
  const fix: PackageFix = {
    version: best.version,
    majorBump: !isSameLine(inst.version, best.version),
    clears: best.clears,
    remaining: best.remaining,
  };
  if (fix.majorBump && bestSameLine) fix.sameLineBest = bestSameLine;
  return fix;
}
