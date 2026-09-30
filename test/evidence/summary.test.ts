import assert from 'node:assert/strict';
import { Writable } from 'node:stream';
import { describe, it } from 'node:test';
import { advisorySentence, renderCaseFileSummary, renderVulnerabilityList } from '../../src/evidence/casefile.ts';
import type { CaseFile, FileScope, GhsaSeverity, PackageCase, UsageEvidence, VulnCase } from '../../src/types.ts';
import { Ui, type UiOptions } from '../../src/ui.ts';

function makeUi(options: UiOptions = {}): Ui {
  const sink = new Writable({
    write(_chunk, _enc, cb) {
      cb();
    },
  });
  return new Ui({ stdout: sink as never, stderr: sink as never, color: false, unicode: true, env: {}, ...options });
}

function usage(name: string, sites: readonly [string, FileScope][] = []): UsageEvidence {
  const scopes: Record<FileScope, number> = { source: 0, test: 0, config: 0, scripts: 0 };
  for (const [, scope] of sites) scopes[scope] += 1;
  return {
    package: name,
    imported: sites.length > 0,
    files: sites.map(([file, scope], i) => ({ path: file, line: i + 1, statement: `import x from '${name}';`, binding: 'x', kind: 'esm-default', scope })),
    scopes,
    membersUsed: {},
    bindingCalls: 0,
    scannedFiles: 40,
  };
}

function pkg(name: string, version: string, extra: Partial<PackageCase> = {}): PackageCase {
  return {
    name,
    version,
    keys: [`node_modules/${name}`],
    isDirect: true,
    isDevOnly: false,
    depType: 'dependencies',
    spec: `^${version}`,
    dependencyPaths: [[`${name}@${version}`]],
    dependents: [],
    vulnIds: [],
    worstSeverity: 'UNKNOWN',
    usage: usage(name),
    deprecated: null,
    latestVersion: null,
    ...extra,
  };
}

function vuln(id: string, owner: PackageCase, ghsa: GhsaSeverity, summary: string, fixed: string | null, extra: Partial<VulnCase> = {}): VulnCase {
  return {
    id,
    aliases: [],
    mergedIds: [],
    package: owner.name,
    installedVersion: owner.version,
    summary,
    detailsExcerpt: '',
    blamedSymbols: [],
    severity: { ghsa },
    cweIds: [],
    malware: false,
    affectedRange: fixed ? `<${fixed}` : 'all versions',
    ranges: [{ type: 'SEMVER', events: fixed ? [{ introduced: '0' }, { fixed }] : [{ introduced: '0' }] }],
    fixedVersions: fixed ? [fixed] : [],
    recommendedFix: fixed ? { version: fixed, majorBump: false } : null,
    isDirect: owner.isDirect,
    isDevOnly: owner.isDevOnly,
    dependencyPaths: owner.dependencyPaths,
    references: [],
    published: '2024-01-01T00:00:00Z',
    modified: '2024-01-01T00:00:00Z',
    ...extra,
  };
}

const astro = pkg('astro', '4.16.0', {
  worstSeverity: 'CRITICAL',
  usage: usage('astro', [
    ['src/pages/index.astro', 'source'],
    ['src/lib/render.ts', 'source'],
    ['src/lib/render.ts', 'source'],
  ]),
});
const axios = pkg('axios', '1.6.0', {
  worstSeverity: 'HIGH',
  usage: usage('axios', [
    ['src/api.ts', 'source'],
    ['test/api.test.ts', 'test'],
  ]),
});
const esbuild = pkg('esbuild', '0.24.0', {
  isDirect: false,
  depType: null,
  spec: null,
  worstSeverity: 'HIGH',
  dependencyPaths: [['astro@4.16.0', 'vite@5.4.0', 'esbuild@0.24.0']],
  dependents: [{ name: 'vite', version: '5.4.0' }],
});
const prettier = pkg('prettier', '3.0.0', { isDevOnly: true, depType: 'devDependencies', worstSeverity: 'LOW', usage: usage('prettier', [['scripts/format.js', 'scripts']]) });

const AXIOS_SUMMARY = 'Server-Side Request Forgery in axios when a path-relative URL is processed as a protocol-relative URL, letting an attacker reach internal hosts';
const ESBUILD_SUMMARY = 'esbuild enables any website to send any requests to the development server and read the response';

const vulns: VulnCase[] = [
  vuln('GHSA-pppp-pppp-pppp', prettier, 'LOW', '', null, {
    aliases: ['CVE-2024-0009'],
    detailsExcerpt: 'Prettier can be made to hang on a crafted input. The issue is in the markdown parser, see `parseInline`.',
  }),
  vuln('GHSA-dddd-dddd-dddd', astro, 'MODERATE', 'Open redirect in the `redirects` config', '5.0.0', { aliases: ['CVE-2023-0001'] }),
  vuln('GHSA-67mh-4wv8-2f99', esbuild, 'HIGH', ESBUILD_SUMMARY, '0.25.0'),
  vuln('GHSA-cccc-cccc-cccc', astro, 'HIGH', 'Path traversal in the static file handler', '4.16.5'),
  vuln('GHSA-8hc4-vh64-cxmj', axios, 'HIGH', AXIOS_SUMMARY, '1.7.4', { aliases: ['CVE-2024-39338'] }),
  vuln('GHSA-bbbb-bbbb-bbbb', astro, 'HIGH', 'Cross-site scripting in the dev toolbar', '5.14.1', { aliases: ['CVE-2024-0002'] }),
  vuln('GHSA-aaaa-aaaa-aaaa', astro, 'CRITICAL', 'Server-side request forgery in the image endpoint. Details follow in the advisory.', '4.16.1', {
    aliases: ['GHSA-zzzz-zzzz-zzzz', 'CVE-2025-0003'],
  }),
];

const caseFile: CaseFile = {
  version: 1,
  project: { root: '/tmp/site', name: 'site', lockfile: 'package-lock.json', lockfileVersion: 3 },
  scannedAt: '2026-09-25T00:00:00Z',
  vulnSource: { mode: 'live', fetchedAt: '2026-09-25T00:00:00Z', ageHours: 0 },
  counts: { dependencies: 861, direct: 24, dev: 310, vulnerablePackages: 4, vulnerabilities: 7, bySeverity: { CRITICAL: 1, HIGH: 4, MODERATE: 1, LOW: 1, UNKNOWN: 0 } },
  // out of order on purpose
  packages: [prettier, esbuild, axios, astro],
  vulnerabilities: vulns,
  osvRecords: {},
};

const HEADERS = [
  'astro@4.16.0  direct · imported in 2 source files · 4 CVEs · fix 5.14.1 (major)',
  'axios@1.6.0  direct · imported in 1 source file, 1 test file · 1 CVE · fix 1.7.4',
  'esbuild@0.24.0  transitive via vite · not imported · 1 CVE · fix 0.25.0 (major)',
  'prettier@3.0.0  direct · dev only · imported in 1 script · 1 CVE · no fix',
];

describe('the vulnerability list after the Phase 1 table', () => {
  it('groups the CVEs under one header per package, worst severity first, then by name', () => {
    const lines = renderVulnerabilityList(caseFile, makeUi(), 120).split('\n');
    assert.deepEqual(
      lines.filter((l) => l !== '' && !l.startsWith(' ')),
      HEADERS,
    );
    const blocks = renderVulnerabilityList(caseFile, makeUi(), 120).split('\n\n');
    assert.deepEqual(
      blocks.map((b) => b.split('\n').length),
      [5, 2, 2, 2],
      'every CVE is listed under its package, a blank line between packages',
    );
  });

  it('orders the CVEs by severity then id, with the CVE alias first and the OSV id in brackets', () => {
    const astroLines = renderVulnerabilityList(caseFile, makeUi(), 120).split('\n\n')[0]?.split('\n').slice(1) ?? [];
    assert.deepEqual(astroLines, [
      '  CRITICAL  CVE-2025-0003 (GHSA-aaaa-aaaa-aaaa)  Server-side request forgery in the image endpoint.  → fixed in 4.16.1',
      '  HIGH      CVE-2024-0002 (GHSA-bbbb-bbbb-bbbb)  Cross-site scripting in the dev toolbar             → fixed in 5.14.1',
      '  HIGH      GHSA-cccc-cccc-cccc                  Path traversal in the static file handler           → fixed in 4.16.5',
      '  MODERATE  CVE-2023-0001 (GHSA-dddd-dddd-dddd)  Open redirect in the redirects config               → fixed in 5.0.0',
    ]);
  });

  it('falls back to the first sentence of the details, and says when there is no fix', () => {
    const prettierLine = renderVulnerabilityList(caseFile, makeUi(), 120).split('\n').at(-1);
    assert.equal(prettierLine, '  LOW       CVE-2024-0009 (GHSA-pppp-pppp-pppp)  Prettier can be made to hang on a crafted input.  no fix');
    assert.equal(advisorySentence({ ...vulns[0], detailsExcerpt: '' } as VulnCase, { osvRecords: { 'GHSA-pppp-pppp-pppp': { id: 'GHSA-pppp-pppp-pppp', modified: '', details: '## Impact\n\nVersions before 3.1.0 hang. Upgrade.' } } }), 'Versions before 3.1.0 hang.');
  });

  it('cuts a long advisory with an ellipsis so the line fits the width', () => {
    const width = 90;
    const lines = renderVulnerabilityList(caseFile, makeUi(), width).split('\n');
    for (const line of lines) assert.ok(line.length <= width, `${line.length}: ${line}`);
    const axiosLine = lines.find((l) => l.includes('CVE-2024-39338')) ?? '';
    assert.equal(axiosLine.length, width);
    assert.equal(axiosLine, '  HIGH      CVE-2024-39338 (GHSA-8hc4-vh64-cxmj)  Server-Side Request F…  → fixed in 1.7.4');
  });

  it('uses the terminal width, 100 columns when it is unknown, and drops the second id when narrow', () => {
    // piped: 100-column fallback
    const fallback = renderCaseFileSummary(caseFile, makeUi(), { checks: false, table: false }).split('\n');
    const esbuildLine = fallback.find((l) => l.includes('GHSA-67mh-4wv8-2f99')) ?? '';
    assert.equal(esbuildLine.length, 100, esbuildLine);
    assert.ok(esbuildLine.includes('…'));
    for (const line of fallback) assert.ok(line.length <= 100, line);
    // wide: advisory shown whole
    const wide = renderVulnerabilityList(caseFile, makeUi({ width: 160 }));
    assert.ok(wide.includes(`GHSA-67mh-4wv8-2f99  ${ESBUILD_SUMMARY}  → fixed in 0.25.0`), wide);
    // narrow: second id drops first
    const narrow = renderVulnerabilityList(caseFile, makeUi({ width: 64 })).split('\n');
    assert.ok(!narrow.some((l) => l.includes('(GHSA-')));
    assert.ok(narrow.includes('  CRITICAL  CVE-2025-0003        Server-side…  → fixed in 4.16.1'), narrow.join('\n'));
    for (const line of narrow) assert.ok(line.length <= 64, line);
  });

  it('keeps the check lines and the table, then a blank line and the list; omitted with --quiet', () => {
    const ui = makeUi({ width: 120 });
    const text = renderCaseFileSummary(caseFile, ui);
    const lines = text.split('\n');
    assert.equal(lines[0], '✓ Discovered lockfile  package-lock.json');
    assert.equal(lines[3], '✓ Found 7 CVEs across 4 packages');
    assert.equal(lines[4], '');
    assert.match(lines[5] ?? '', /^ {2}Severity {2}CVEs {2}Packages/);
    const tableEnd = lines.findIndex((l, i) => i > 5 && l === '');
    assert.equal(lines[tableEnd - 1], '  LOW          1  prettier');
    assert.equal(lines[tableEnd + 1], HEADERS[0]);
    assert.equal(text.split('\n\n').length, 6, 'checks, table, then the four package blocks');
    assert.ok(!renderCaseFileSummary(caseFile, makeUi({ quiet: true })).includes('astro@4.16.0'));
    assert.ok(!renderCaseFileSummary(caseFile, ui, { list: false }).includes('astro@4.16.0'));
  });

  it('colours the severity word and dims the second id and the fix', () => {
    const coloured = renderVulnerabilityList(caseFile, makeUi({ color: undefined, env: { FORCE_COLOR: '1' } }), 120);
    const line = coloured.split('\n')[1] ?? '';
    assert.ok(line.startsWith('  \u001b[31mCRITICAL\u001b[39m  CVE-2025-0003 \u001b[2m(GHSA-aaaa-aaaa-aaaa)\u001b[22m'), JSON.stringify(line));
    assert.ok(line.endsWith('\u001b[2m→ fixed in 4.16.1\u001b[22m'), JSON.stringify(line));
    assert.ok(coloured.startsWith('\u001b[1mastro@4.16.0\u001b[22m  \u001b[2mdirect'), JSON.stringify(coloured.slice(0, 60)));
  });
});
