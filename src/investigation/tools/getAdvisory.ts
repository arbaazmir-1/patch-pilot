// get_advisory: by id or alias, from the case file
import type { OsvRecord, ToolContext, ToolResult, VulnCase } from '../../types.ts';
import { describeRanges, fixedVersionsFromRanges } from '../../util/semver.ts';

export interface GetAdvisoryArgs {
  id: string;
}

const DETAILS_CHARS = 1100;
const MAX_REFERENCES = 4;
const REFERENCE_ORDER = ['ADVISORY', 'FIX', 'REPORT', 'ARTICLE', 'WEB', 'PACKAGE'];

function eq(a: string | undefined, b: string): boolean {
  return typeof a === 'string' && a.toLowerCase() === b.toLowerCase();
}

function findRecord(records: Record<string, OsvRecord>, id: string, vuln: VulnCase | undefined): OsvRecord | undefined {
  const exact = records[id];
  if (exact) return exact;
  const values = Object.values(records);
  const byKey = Object.entries(records).find(([key]) => eq(key, id))?.[1];
  if (byKey) return byKey;
  const byAlias = values.find((r) => eq(r.id, id) || (r.aliases ?? []).some((a) => eq(a, id)));
  if (byAlias) return byAlias;
  if (vuln) return records[vuln.id] ?? values.find((r) => eq(r.id, vuln.id) || vuln.mergedIds.some((m) => eq(r.id, m)));
  return undefined;
}

function findVuln(vulns: readonly VulnCase[], id: string): VulnCase | undefined {
  return vulns.find((v) => eq(v.id, id) || v.aliases.some((a) => eq(a, id)) || (v.mergedIds ?? []).some((m) => eq(m, id)));
}

function day(iso: string | undefined): string | null {
  if (!iso) return null;
  return iso.length >= 10 ? iso.slice(0, 10) : iso;
}

function cleanDetails(text: string): string {
  return text
    .replace(/\r\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

export async function handleGetAdvisory(args: GetAdvisoryArgs, ctx: ToolContext): Promise<ToolResult> {
  const id = String(args.id ?? '').trim();
  if (id === '') return { ok: false, error: 'id is required', hint: 'Give a GHSA, CVE or OSV id, for example GHSA-35jh-r3h4-6jhm' };
  const records = ctx.caseFile?.osvRecords ?? {};
  const vulns = ctx.caseFile?.vulnerabilities ?? [];
  const vuln = findVuln(vulns, id);
  const record = findRecord(records, id, vuln);
  if (!record && !vuln) {
    const focus = ctx.focus?.package;
    const known = vulns.filter((v) => !focus || v.package === focus).flatMap((v) => [v.id, ...v.aliases.filter((a) => a.startsWith('CVE-'))]);
    return {
      ok: false,
      error: `Unknown advisory id ${id}`,
      hint: known.length > 0 ? `Known ids${focus ? ` for ${focus}` : ''}: ${[...new Set(known)].slice(0, 8).join(', ')}` : 'No advisories are loaded in the case file',
    };
  }
  const recordId = record?.id ?? vuln?.id ?? id;
  const aliases = [...new Set([...(record?.aliases ?? []), ...(vuln?.aliases ?? [])])].filter((a) => a !== recordId);
  const cve = aliases.find((a) => a.toUpperCase().startsWith('CVE-'));
  const severity = (record?.database_specific?.severity as string | undefined) ?? vuln?.severity.ghsa ?? null;
  const score = vuln?.severity.cvssScore;
  const cwes = [...new Set([...((record?.database_specific?.cwe_ids as string[] | undefined) ?? []), ...(vuln?.cweIds ?? [])])];
  const summary = record?.summary ?? vuln?.summary ?? '';
  const details = cleanDetails(record?.details ?? vuln?.detailsExcerpt ?? '');
  const pkg = vuln?.package ?? ctx.focus?.package;
  let affected = vuln ? `${vuln.affectedRange}${vuln.fixedVersions.length > 0 ? `; fixed in ${vuln.fixedVersions.join(', ')}` : '; no fix published'}` : null;
  if (!affected && record && pkg) {
    const entry = (record.affected ?? []).find((a) => a.package?.name === pkg);
    if (entry) {
      const fixed = fixedVersionsFromRanges(entry.ranges ?? []);
      affected = `${describeRanges(entry.ranges ?? [])}${fixed.length > 0 ? `; fixed in ${fixed.join(', ')}` : ''}`;
    }
  }
  const refs = [...(record?.references ?? vuln?.references ?? [])]
    .sort((a, b) => {
      const ra = REFERENCE_ORDER.indexOf(a.type);
      const rb = REFERENCE_ORDER.indexOf(b.type);
      return (ra === -1 ? 99 : ra) - (rb === -1 ? 99 : rb);
    })
    .slice(0, MAX_REFERENCES);
  const head = `${recordId}${cve ? ` (${cve})` : ''}${severity ? ` · ${severity}` : ''}${typeof score === 'number' ? ` · CVSS ${score.toFixed(1)}` : ''}${vuln?.malware ? ' · MALWARE' : ''}`;
  const lines = [
    head,
    summary ? `Summary: ${summary}` : null,
    [day(record?.published ?? vuln?.published) ? `Published: ${day(record?.published ?? vuln?.published)}` : null, day(record?.modified ?? vuln?.modified) ? `Modified: ${day(record?.modified ?? vuln?.modified)}` : null]
      .filter(Boolean)
      .join(' · ') || null,
    cwes.length > 0 ? `CWE: ${cwes.join(', ')}` : null,
    affected && pkg ? `Affected ${pkg}: ${affected}` : null,
    details ? `Details:\n${details.length > DETAILS_CHARS ? `${details.slice(0, DETAILS_CHARS)}... [${details.length - DETAILS_CHARS} more characters]` : details}` : null,
    refs.length > 0 ? `References:\n${refs.map((r) => `- ${r.url}${r.type ? ` (${r.type.toLowerCase()})` : ''}`).join('\n')}` : null,
  ].filter((l): l is string => Boolean(l));
  const hint = `${recordId}: ${summary || 'no summary'}${severity || cwes.length > 0 ? ` (${[severity, ...cwes.slice(0, 2)].filter(Boolean).join(', ')})` : ''}`;
  return { ok: true, hint, text: lines.join('\n'), truncated: details.length > DETAILS_CHARS };
}
