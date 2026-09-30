// live phase 1 against osv.dev and npm
import { mkdtemp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { AuditLog, readAuditFile } from '../../src/audit.ts';
import { loadConfig } from '../../src/config.ts';
import { runPhase1 } from '../../src/evidence/casefile.ts';
import { createUi } from '../../src/ui.ts';

const args = process.argv.slice(2);
const flag = (name: string): boolean => args.includes(name);
const option = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i === -1 ? undefined : args[i + 1];
};
const positional = args.filter((a, i) => !a.startsWith('--') && args[i - 1] !== '--home');
const dir = positional[0] ?? 'examples/vulnerable-app';
const home = option('--home');

const config = await loadConfig({ dir, flags: { offline: flag('--offline'), trust: true }, homeDir: home ? path.resolve(home) : undefined });
const ui = createUi(config);
const auditDir = await mkdtemp(path.join(os.tmpdir(), 'patch-pilot-live-'));
const audit = AuditLog.open(path.join(auditDir, 'audit.jsonl'));
const caseFile = await runPhase1(config, { ui, audit });

const digest = {
  project: caseFile.project,
  vulnSource: caseFile.vulnSource,
  counts: caseFile.counts,
  packages: caseFile.packages.map((p) => ({
    pkg: `${p.name}@${p.version}`,
    direct: p.isDirect,
    devOnly: p.isDevOnly,
    depType: p.depType,
    spec: p.spec,
    dependents: p.dependents.map((d) => `${d.name}@${d.version}`),
    paths: p.dependencyPaths.map((hops) => hops.join(' > ')),
    worst: p.worstSeverity,
    latest: p.latestVersion,
    usage: {
      imported: p.usage.imported,
      sites: p.usage.files.map((s) => `${s.path}:${s.line} ${s.kind} ${s.binding ?? '-'} (${s.scope})`),
      members: p.usage.membersUsed,
      bindingCalls: p.usage.bindingCalls,
    },
  })),
  vulnerabilities: caseFile.vulnerabilities.map((v) => ({
    id: v.id,
    merged: v.mergedIds,
    pkg: `${v.package}@${v.installedVersion}`,
    ghsa: v.severity.ghsa ?? null,
    cvss: v.severity.cvssScore ?? null,
    range: v.affectedRange,
    fixed: v.fixedVersions,
    fix: v.recommendedFix,
    blamed: v.blamedSymbols.map((s) => `${s.name}:${s.kind}:${s.via}`),
  })),
  audit: readAuditFile(audit.file).map((r) => r.event),
};
if (flag('--json')) console.log(JSON.stringify(digest, null, 2));
else {
  console.log('');
  console.log(JSON.stringify(digest.vulnSource));
  console.log(JSON.stringify(digest.counts));
  for (const p of digest.packages) console.log(JSON.stringify(p));
  for (const v of digest.vulnerabilities) console.log(JSON.stringify(v));
  console.log('audit events:', digest.audit.join(', '));
  console.log('audit log:', audit.file);
}
