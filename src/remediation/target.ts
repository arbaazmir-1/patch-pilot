// the version a package action moves to
import type { CaseFile, VulnCase } from '../types.ts';
import { compareVersions, isAffected, isAffectedByEntry, isSameLine, parseVersion } from '../util/semver.ts';

function unique<T>(items: readonly T[]): T[] {
  return [...new Set(items)];
}

// falls back to osv version lists
export function vulnAffects(vuln: VulnCase, version: string, caseFile?: CaseFile | null): boolean {
  if (vuln.ranges.length > 0) return isAffected(version, vuln.ranges);
  const entries = [vuln.id, ...vuln.mergedIds].flatMap((id) =>
    (caseFile?.osvRecords?.[id]?.affected ?? []).filter((a) => a.package?.name === vuln.package && (a.package.ecosystem ?? '').toLowerCase() === 'npm'),
  );
  if (entries.length === 0) return version === vuln.installedVersion;
  return entries.some((entry) => isAffectedByEntry(version, entry));
}

export interface TargetChoice {
  version: string;
  full: boolean;
  clears: VulnCase[];
  remaining: VulnCase[];
}

// else best in installed line
export function chooseTarget(vulns: readonly VulnCase[], installed: string, caseFile?: CaseFile | null): TargetChoice | null {
  const candidates = unique(
    vulns
      .map((v) => v.recommendedFix?.version)
      .filter((v): v is string => typeof v === 'string' && parseVersion(v) !== null && compareVersions(v, installed) > 0),
  ).sort((a, b) => compareVersions(b, a));
  if (candidates.length === 0) return null;
  const evaluate = (version: string): { clears: VulnCase[]; remaining: VulnCase[] } => {
    const clears: VulnCase[] = [];
    const remaining: VulnCase[] = [];
    for (const vuln of vulns) (vulnAffects(vuln, version, caseFile) ? remaining : clears).push(vuln);
    return { clears, remaining };
  };
  for (const version of candidates) {
    const result = evaluate(version);
    if (result.remaining.length === 0) return { version, full: true, ...result };
  }
  const scored = candidates.map((version) => ({ version, ...evaluate(version) })).filter((s) => s.clears.length > 0);
  const best = (list: typeof scored): (typeof scored)[number] | undefined =>
    [...list].sort((a, b) => b.clears.length - a.clears.length || compareVersions(b.version, a.version))[0];
  const pick = best(scored.filter((s) => isSameLine(installed, s.version))) ?? best(scored);
  return pick ? { ...pick, full: false } : null;
}
