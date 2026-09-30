// phase 2 test doubles
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Writable } from 'node:stream';
import { loadConfig, type CliFlags } from '../../src/config.ts';
import { createToolRegistry, type ToolRegistry } from '../../src/investigation/tools/index.ts';
import type {
  CaseFile,
  Config,
  Dossier,
  ImportSite,
  OsvRecord,
  PackageCase,
  ToolContext,
  ToolName,
  ToolResult,
  UsageEvidence,
  UsageMatch,
  VulnCase,
} from '../../src/types.ts';
import { Ui } from '../../src/ui.ts';

export function captureUi(options: ConstructorParameters<typeof Ui>[0] = {}): { ui: Ui; out: () => string; err: () => string } {
  let out = '';
  let err = '';
  const stream = (write: (s: string) => void): Writable =>
    new Writable({
      write(chunk, _enc, cb) {
        write(String(chunk));
        cb();
      },
    });
  const ui = new Ui({
    color: false,
    env: {},
    stdout: stream((s) => (out += s)) as never,
    stderr: stream((s) => (err += s)) as never,
    ...options,
  });
  return { ui, out: () => out, err: () => err };
}

export async function tempDir(prefix = 'pp-phase2-'): Promise<{ dir: string; cleanup: () => Promise<void> }> {
  const dir = await mkdtemp(path.join(os.tmpdir(), prefix));
  return { dir, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

export async function testConfig(dir: string, flags: CliFlags = {}): Promise<Config> {
  return loadConfig({ dir, homeDir: dir, env: {}, flags: { provider: 'mock', ...flags }, stdinIsTTY: false, stdoutIsTTY: false });
}

export function usage(partial: Partial<UsageEvidence> & { package: string }): UsageEvidence {
  const files = partial.files ?? [];
  const scopes = { source: 0, test: 0, config: 0, scripts: 0 };
  for (const f of files) scopes[f.scope] += 1;
  return {
    imported: files.length > 0,
    files,
    scopes: partial.scopes ?? scopes,
    membersUsed: {},
    bindingCalls: 0,
    scannedFiles: 6,
    ...partial,
  };
}

export function site(p: string, line: number, statement: string, binding: string | null, extra: Partial<ImportSite> = {}): ImportSite {
  return { path: p, line, statement, binding, kind: 'cjs-require', scope: 'source', ...extra };
}

export function pkgCase(partial: Partial<PackageCase> & { name: string; version: string }): PackageCase {
  return {
    keys: [`node_modules/${partial.name}`],
    isDirect: true,
    isDevOnly: false,
    depType: 'dependencies',
    spec: partial.version,
    dependencyPaths: [['vulnerable-app@1.0.0', `${partial.name}@${partial.version}`]],
    dependents: [],
    vulnIds: [],
    worstSeverity: 'HIGH',
    usage: usage({ package: partial.name }),
    deprecated: null,
    latestVersion: null,
    ...partial,
  };
}

export function vulnCase(partial: Partial<VulnCase> & { id: string; package: string; installedVersion: string }): VulnCase {
  return {
    aliases: [],
    mergedIds: [],
    summary: `Vulnerability ${partial.id}`,
    detailsExcerpt: '',
    blamedSymbols: [],
    severity: { ghsa: 'HIGH' },
    cweIds: [],
    malware: false,
    affectedRange: '<99.0.0',
    ranges: [],
    fixedVersions: [],
    recommendedFix: null,
    isDirect: true,
    isDevOnly: false,
    dependencyPaths: [],
    references: [],
    published: '2021-02-15T11:28:00Z',
    modified: '2024-01-01T00:00:00Z',
    ...partial,
  };
}

// synthetic lodash, minimist, marked, json5, semver and decode-uri-component cases

export const LODASH_TEMPLATE_DETAILS =
  'Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.';

export function lodashFixture(): { pkg: PackageCase; template: VulnCase; merge: VulnCase } {
  const template = vulnCase({
    id: 'GHSA-35jh-r3h4-6jhm',
    aliases: ['CVE-2021-23337'],
    package: 'lodash',
    installedVersion: '4.17.20',
    summary: 'Command Injection in lodash',
    detailsExcerpt: LODASH_TEMPLATE_DETAILS,
    blamedSymbols: [{ name: 'template', kind: 'exported', via: 'backticks' }],
    severity: { ghsa: 'HIGH', cvssScore: 7.2, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H' },
    cweIds: ['CWE-77', 'CWE-94'],
    affectedRange: '<4.17.21',
    fixedVersions: ['4.17.21'],
    recommendedFix: { version: '4.17.21', majorBump: false },
  });
  // fake advisory, hits the floor rail
  const merge = vulnCase({
    id: 'GHSA-test-merge-0001',
    aliases: ['CVE-2099-0001'],
    package: 'lodash',
    installedVersion: '4.17.20',
    summary: 'Prototype pollution in merge',
    blamedSymbols: [{ name: '_.merge', kind: 'exported', via: 'member-access' }],
    severity: { ghsa: 'MODERATE', cvssScore: 5.6 },
    fixedVersions: ['4.17.21'],
    recommendedFix: { version: '4.17.21', majorBump: false },
  });
  const pkg = pkgCase({
    name: 'lodash',
    version: '4.17.20',
    vulnIds: [template.id, merge.id],
    usage: usage({
      package: 'lodash',
      files: [site('src/config.js', 7, "const _ = require('lodash');", '_')],
      membersUsed: { merge: 1, get: 3 },
      bindingCalls: 0,
    }),
  });
  return { pkg, template, merge };
}

export function minimistFixture(): { pkg: PackageCase; vuln: VulnCase } {
  const vuln = vulnCase({
    id: 'GHSA-xvch-5gv4-984h',
    aliases: ['CVE-2021-44906'],
    package: 'minimist',
    installedVersion: '1.2.5',
    summary: 'Prototype Pollution in minimist',
    detailsExcerpt: 'Minimist <=1.2.5 is vulnerable to Prototype Pollution via file index.js, function setKey() (lines 69-95).',
    blamedSymbols: [{ name: 'setKey', kind: 'internal', via: 'call' }],
    severity: { ghsa: 'CRITICAL', cvssScore: 9.8 },
    cweIds: ['CWE-1321'],
    affectedRange: '<1.2.6',
    fixedVersions: ['1.2.6'],
    recommendedFix: { version: '1.2.6', majorBump: false },
  });
  const pkg = pkgCase({
    name: 'minimist',
    version: '1.2.5',
    worstSeverity: 'CRITICAL',
    vulnIds: [vuln.id],
    usage: usage({
      package: 'minimist',
      files: [site('src/cli.js', 7, "const parseArgs = require('minimist');", 'parseArgs')],
      bindingCalls: 1,
    }),
  });
  return { pkg, vuln };
}

export function semverFixture(): { pkg: PackageCase; vuln: VulnCase } {
  const vuln = vulnCase({
    id: 'GHSA-c2qf-rxjj-qqgw',
    aliases: ['CVE-2022-25883'],
    package: 'semver',
    installedVersion: '5.7.1',
    summary: 'semver vulnerable to Regular Expression Denial of Service',
    severity: { ghsa: 'HIGH', cvssScore: 7.5 },
    isDevOnly: true,
    fixedVersions: ['5.7.2'],
    recommendedFix: { version: '5.7.2', majorBump: false },
  });
  const pkg = pkgCase({
    name: 'semver',
    version: '5.7.1',
    isDevOnly: true,
    depType: 'devDependencies',
    vulnIds: [vuln.id],
    usage: usage({ package: 'semver', files: [site('scripts/check-version.js', 4, "const semver = require('semver');", 'semver', { scope: 'scripts' })], membersUsed: { satisfies: 1 } }),
  });
  return { pkg, vuln };
}

export function decodeFixture(): { pkg: PackageCase; vuln: VulnCase } {
  const vuln = vulnCase({
    id: 'GHSA-w573-4hg7-7wgq',
    aliases: ['CVE-2022-38900'],
    package: 'decode-uri-component',
    installedVersion: '0.2.0',
    summary: 'decode-uri-component vulnerable to Denial of Service (DoS)',
    severity: { ghsa: 'HIGH', cvssScore: 7.5 },
    isDirect: false,
    fixedVersions: ['0.2.1'],
    recommendedFix: { version: '0.2.1', majorBump: false },
  });
  const pkg = pkgCase({
    name: 'decode-uri-component',
    version: '0.2.0',
    keys: ['node_modules/decode-uri-component'],
    isDirect: false,
    depType: null,
    spec: null,
    dependents: [{ name: 'query-string', version: '6.14.1' }],
    dependencyPaths: [['vulnerable-app@1.0.0', 'query-string@6.14.1', 'decode-uri-component@0.2.0']],
    vulnIds: [vuln.id],
    usage: usage({ package: 'decode-uri-component' }),
  });
  return { pkg, vuln };
}

export function markedFixture(): { pkg: PackageCase; vuln: VulnCase } {
  const vuln = vulnCase({
    id: 'GHSA-rrrm-qjm4-v8hf',
    aliases: ['CVE-2022-21681'],
    package: 'marked',
    installedVersion: '0.3.6',
    summary: 'Inefficient Regular Expression Complexity in marked',
    blamedSymbols: [{ name: 'marked', kind: 'exported', via: 'default-callable' }],
    severity: { ghsa: 'HIGH', cvssScore: 7.5 },
    fixedVersions: ['4.0.10'],
    recommendedFix: { version: '4.0.10', majorBump: true },
  });
  const pkg = pkgCase({
    name: 'marked',
    version: '0.3.6',
    vulnIds: [vuln.id],
    usage: usage({ package: 'marked', files: [site('src/render.js', 5, "const marked = require('marked');", 'marked')], bindingCalls: 1 }),
  });
  return { pkg, vuln };
}

// blames marked.parse, app calls marked(md)
export function markedParseFixture(): { pkg: PackageCase; vuln: VulnCase } {
  const { pkg, vuln } = markedFixture();
  return {
    pkg,
    vuln: {
      ...vuln,
      id: 'GHSA-5v2h-r2cx-5xgj',
      aliases: ['CVE-2022-21680'],
      summary: 'Inefficient Regular Expression Complexity in marked',
      blamedSymbols: [{ name: 'marked.parse', kind: 'exported', via: 'member-access' }],
    },
  };
}

export function caseFileOf(packages: PackageCase[], vulns: VulnCase[], root = '/tmp/project', records: Record<string, OsvRecord> = {}): CaseFile {
  return {
    version: 1,
    project: { root, name: 'vulnerable-app', lockfile: 'package-lock.json', lockfileVersion: 3 },
    scannedAt: '2026-09-24T10:00:00.000Z',
    vulnSource: { mode: 'live', fetchedAt: '2026-09-24T10:00:00.000Z', ageHours: 0 },
    counts: { dependencies: 12, direct: 6, dev: 1, vulnerablePackages: packages.length, vulnerabilities: vulns.length, bySeverity: { LOW: 0, MODERATE: 0, HIGH: 0, CRITICAL: 0, UNKNOWN: 0 } },
    packages,
    vulnerabilities: vulns,
    osvRecords: records,
  };
}

export function dossierFor(pkg: PackageCase, partial: Partial<Dossier> = {}): Dossier {
  return {
    package: pkg.name,
    version: pkg.version,
    inputSources: ['config file from disk'],
    callSiteNotes: ['src/config.js:21 _.merge(...)'],
    dependentsSummary: 'direct dependency',
    fixCost: 'patch bump',
    openQuestions: [],
    toolCalls: [],
    steps: 1,
    durationMs: 1,
    ...partial,
  };
}

function escapeRe(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// regex stand-in for findUsage
export function fakeFindUsage(files: Record<string, string>) {
  return async (_root: string, sites: readonly ImportSite[], symbol: string | undefined, options: { contextLines?: number; maxResults?: number }): Promise<UsageMatch[]> => {
    const out: UsageMatch[] = [];
    const ctxLines = options.contextLines ?? 0;
    for (const s of sites) {
      const source = files[s.path];
      if (source === undefined || !s.binding) continue;
      const lines = source.split('\n');
      const b = escapeRe(s.binding);
      lines.forEach((text, i) => {
        if (i + 1 === s.line) return;
        const found: (string | null)[] = [];
        for (const m of text.matchAll(new RegExp(`(?<![\\w$.])${b}(?:\\.(\\w+)|\\[['"](\\w+)['"]\\])?\\s*\\(`, 'g'))) found.push(m[1] ?? m[2] ?? null);
        for (const member of found) {
          if (symbol !== undefined && member !== symbol) continue;
          out.push({
            path: s.path,
            line: i + 1,
            text: text.trim(),
            scope: s.scope,
            binding: s.binding as string,
            member,
            context: { before: lines.slice(Math.max(0, i - ctxLines), i), after: lines.slice(i + 1, i + 1 + ctxLines) },
          });
        }
      });
    }
    return out.slice(0, options.maxResults ?? 100);
  };
}

export type FakeHandler = (args: Record<string, unknown>, ctx: ToolContext) => Promise<ToolResult> | ToolResult;

export function fakeRegistry(handlers: Partial<Record<ToolName, FakeHandler>>): { registry: ToolRegistry; calls: { tool: ToolName; args: Record<string, unknown> }[] } {
  const registry = createToolRegistry();
  const calls: { tool: ToolName; args: Record<string, unknown> }[] = [];
  for (const [name, handler] of Object.entries(handlers) as [ToolName, FakeHandler][]) {
    registry.setHandler(name, async (args: Record<string, unknown>, ctx: ToolContext) => {
      calls.push({ tool: name, args });
      return handler(args, ctx);
    });
  }
  return { registry, calls };
}

// shape the evidence gate reads
export function usageResult(pkg: string, symbol: string | null, calls: number, callSites: { path: string; line: number; member: string | null }[] = []): ToolResult {
  const display = symbol ? `_.${symbol}` : pkg;
  return {
    ok: true,
    hint: symbol ? (calls > 0 ? `${calls} calls to ${display}` : `0 calls to ${display}; project calls _.merge (1), _.get (3)`) : `${pkg} imported`,
    data: {
      package: pkg,
      symbol,
      imported: true,
      importSites: [],
      membersUsed: {},
      bindingCalls: 0,
      symbolCalls: symbol ? calls : null,
      callSites: callSites.map((c) => ({ ...c, text: 'x', scope: 'source', binding: 'b' })),
      fallback: Boolean(symbol) && calls === 0,
      scannedFiles: 6,
    },
    text: 'usage text',
  };
}
