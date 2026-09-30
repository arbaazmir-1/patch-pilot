import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { PassThrough, Writable } from 'node:stream';
import { after, afterEach, before, describe, it } from 'node:test';
import { MemoryAudit } from '../../src/audit.ts';
import { loadConfig } from '../../src/config.ts';
import type { ChatProvider } from '../../src/llm/provider.ts';
import {
  buildCaseFile,
  CASE_FILE_VERSION,
  cvssScore,
  excerpt,
  loadCaseFile,
  mergeAliasedRecords,
  recordAffects,
  renderCaseFileSummary,
  runPhase1,
  saveCaseFile,
  severityLabel,
  severityOf,
} from '../../src/evidence/casefile.ts';
import { collectUsageEvidence } from '../../src/evidence/codebase.ts';
import { openDb } from '../../src/evidence/db.ts';
import { loadDependencyGraph } from '../../src/evidence/lockfile.ts';
import { pairKey, type OsvQueryResult } from '../../src/evidence/osv.ts';
import type { CaseFile, DependencyGraph, OsvRecord, UsageEvidence } from '../../src/types.ts';
import { Ui } from '../../src/ui.ts';
import { hashJson } from '../../src/util/fs.ts';
import { DEFAULT_EXCLUDES } from '../../src/config.ts';
import { captureUi, copyFixtureApp, FIXTURE_APP, fixtureData, fixtureServer, recordById, stubFetch, tempDir, type FixtureData } from './helpers.ts';

describe('mergeAliasedRecords', async () => {
  const data = await fixtureData();
  const lodash = ['GHSA-29mw-wpgm-hmr9', 'GHSA-35jh-r3h4-6jhm', 'GHSA-f23m-r3pf-42rh', 'GHSA-r5fr-rjxr-66jc', 'GHSA-xxjr-mmjv-4gpg'].map((id) => recordById(data, id));

  it('turns the five lodash records into three cases (35jh + r5fr, xxjr + f23m), earliest published first', () => {
    const groups = mergeAliasedRecords(lodash).map((g) => g.map((r) => r.id));
    assert.deepEqual(groups, [['GHSA-29mw-wpgm-hmr9'], ['GHSA-35jh-r3h4-6jhm', 'GHSA-r5fr-rjxr-66jc'], ['GHSA-xxjr-mmjv-4gpg', 'GHSA-f23m-r3pf-42rh']]);
  });

  it('merges on a shared CVE alias and on ids that alias each other, transitively', () => {
    const r = (id: string, aliases: string[], published = '2020-01-01T00:00:00Z'): OsvRecord => ({ id, modified: '2026-01-01T00:00:00Z', aliases, published });
    const groups = mergeAliasedRecords([
      r('GHSA-b', ['CVE-1'], '2021-01-01T00:00:00Z'),
      r('GHSA-a', ['CVE-1'], '2020-01-01T00:00:00Z'),
      r('GHSA-c', ['GHSA-a']),
      r('GHSA-d', ['CVE-2']),
      r('GHSA-b', ['CVE-1'], '2021-01-01T00:00:00Z'),
    ]).map((g) => g.map((x) => x.id));
    assert.deepEqual(groups, [['GHSA-a', 'GHSA-c', 'GHSA-b'], ['GHSA-d']]);
    assert.deepEqual(mergeAliasedRecords([]), []);
  });
});

describe('severityOf', async () => {
  const data = await fixtureData();

  it('prefers CVSS v3, computes the base score and reads the GHSA severity', () => {
    assert.deepEqual(severityOf(recordById(data, 'GHSA-35jh-r3h4-6jhm')), {
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',
      cvssScore: 7.2,
      cvssVersion: '3.1',
      ghsa: 'HIGH',
    });
    assert.equal(severityOf(recordById(data, 'GHSA-xvch-5gv4-984h')).cvssScore, 9.8);
    const both = severityOf(recordById(data, 'GHSA-xxjr-mmjv-4gpg'));
    assert.equal(both.cvssVersion, '3.1', 'v3 wins over v4');
    assert.equal(both.cvssScore, 6.5);
    assert.equal(severityOf(recordById(data, 'GHSA-7px7-7xjx-hxm8')).cvssScore, 6.1, 'CVSS 3.0 rounding');
  });

  it('accepts CVSS v4 vectors (with threat metrics) when there is no v3', () => {
    assert.deepEqual(severityOf(recordById(data, 'GHSA-p9wx-2529-fp83')), {
      cvssVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N',
      cvssScore: 6.9,
      cvssVersion: '4.0',
      ghsa: 'MODERATE',
    });
    assert.equal(severityOf(recordById(data, 'GHSA-vcc3-ghjq-m6fr')).cvssScore, 6.6, 'E:U lowers the score like GitHub shows it');
  });

  it('tolerates missing severity arrays and odd values', () => {
    assert.deepEqual(severityOf({ id: 'X', modified: '' }), {});
    assert.deepEqual(severityOf({ id: 'X', modified: '', database_specific: { severity: 'medium' } }), { ghsa: 'MODERATE' });
    assert.deepEqual(severityOf({ id: 'X', modified: '', severity: [], affected: [{ database_specific: { severity: 'HIGH' } }] }), { ghsa: 'HIGH' });
    assert.deepEqual(severityOf({ id: 'X', modified: '', severity: [{ type: 'CVSS_V3', score: '7.5' }] }), { cvssScore: 7.5, cvssVersion: '3.1' });
    assert.deepEqual(severityOf({ id: 'X', modified: '', severity: [{ type: 'CVSS_V2', score: 'AV:N/AC:L/Au:N/C:P/I:P/A:P' }] }), {
      cvssVector: 'AV:N/AC:L/Au:N/C:P/I:P/A:P',
      cvssScore: 7.5,
      cvssVersion: '2.0',
    });
    assert.deepEqual(severityOf({ id: 'X', modified: '', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N' }] }), { cvssVector: 'CVSS:3.1/AV:N', cvssVersion: '3.1' });
    assert.equal(severityLabel({ cvssScore: 9.1 }), 'CRITICAL');
    assert.equal(severityLabel({}), 'UNKNOWN');
    assert.equal(severityLabel({}, true), 'CRITICAL', 'malware without a rating');
  });

  it('matches the reference CVSS 4.0 calculator (scores pinned from cvss40.js)', async () => {
    const pinned = JSON.parse(await readFile(new URL('./fixtures/cvss4-pinned.json', import.meta.url), 'utf8')) as [string, number][];
    assert.ok(pinned.length >= 20);
    for (const [vector, score] of pinned) assert.equal(cvssScore(vector).score, score, vector);
    assert.equal(cvssScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N').score, 0);
    assert.equal(cvssScore('CVSS:4.0/AV:N').score, null);
  });
});

async function fixtureInput(data: FixtureData, graph: DependencyGraph, usage: Map<string, UsageEvidence>, withRegistry = true) {
  const records = new Map(data.records.map((r) => [r.id, r]));
  const idsByPackage = new Map(Object.entries(data.querybatch).map(([key, vulns]) => [key, vulns.map((v) => v.id)]));
  const osv: OsvQueryResult = {
    idsByPackage,
    records,
    source: { mode: 'live', fetchedAt: '2026-09-24T12:00:00.000Z', ageHours: 0 },
    stats: { queried: 10, vulnIds: 15, hydrated: 15, cacheHits: 0, durationMs: 1 },
  };
  const deprecated = new Map<string, Set<string>>();
  const available = new Map<string, string[]>();
  const latest = new Map<string, string>();
  if (withRegistry) {
    for (const [name, p] of Object.entries(data.packuments)) {
      available.set(name, Object.keys(p.versions));
      deprecated.set(name, new Set(Object.values(p.versions).filter((v) => v.deprecated).map((v) => v.version)));
      latest.set(name, p['dist-tags'].latest as string);
    }
  }
  return {
    projectRoot: FIXTURE_APP,
    projectName: 'vulnerable-app',
    lockfilePath: path.join(FIXTURE_APP, 'package-lock.json'),
    graph,
    osv,
    usage,
    deprecated,
    available,
    latest,
    scannedAt: '2026-09-24T12:00:00.000Z',
  };
}

describe('buildCaseFile on the fixture', async () => {
  const data = await fixtureData();
  const graph = await loadDependencyGraph(FIXTURE_APP, 'package-lock.json');
  const usage = await collectUsageEvidence(FIXTURE_APP, ['lodash', 'minimist', 'marked', 'json5', 'semver', 'decode-uri-component'], { exclude: DEFAULT_EXCLUDES });
  const caseFile = buildCaseFile(await fixtureInput(data, graph, usage));
  const vuln = (id: string) => {
    const v = caseFile.vulnerabilities.find((x) => x.id === id);
    assert.ok(v, id);
    return v;
  };
  const pkg = (name: string) => {
    const p = caseFile.packages.find((x) => x.name === name);
    assert.ok(p, name);
    return p;
  };

  it('counts dependencies, packages and cases by GHSA severity', () => {
    assert.equal(caseFile.version, CASE_FILE_VERSION);
    assert.deepEqual(caseFile.project, { root: FIXTURE_APP, name: 'vulnerable-app', lockfile: 'package-lock.json', lockfileVersion: 3 });
    assert.deepEqual(caseFile.counts, {
      dependencies: 10,
      direct: 6,
      dev: 1,
      vulnerablePackages: 6,
      vulnerabilities: 13,
      bySeverity: { CRITICAL: 1, HIGH: 7, MODERATE: 5, LOW: 0, UNKNOWN: 0 },
    });
    assert.equal(Object.keys(caseFile.osvRecords).length, 15, 'every record, merged duplicates too');
    assert.deepEqual(
      caseFile.packages.map((p) => p.name),
      ['minimist', 'marked', 'lodash', 'decode-uri-component', 'json5', 'semver'],
      'worst severity first',
    );
  });

  it('lodash: three merged cases, and the deprecated 4.18.0 fix resolves to 4.18.1', () => {
    assert.deepEqual(pkg('lodash').vulnIds, ['GHSA-35jh-r3h4-6jhm', 'GHSA-xxjr-mmjv-4gpg', 'GHSA-29mw-wpgm-hmr9']);
    const template = vuln('GHSA-35jh-r3h4-6jhm');
    assert.deepEqual(template.mergedIds, ['GHSA-r5fr-rjxr-66jc']);
    assert.deepEqual(template.aliases, ['CVE-2021-23337', 'CVE-2026-4800', 'GHSA-r5fr-rjxr-66jc']);
    assert.deepEqual(template.fixedVersions, ['4.17.21', '4.18.0']);
    assert.deepEqual(template.recommendedFix, { version: '4.18.1', majorBump: false, skippedDeprecated: ['4.18.0'] });
    assert.equal(template.severity.cvssScore, 8.1, 'worst score of the merged records');
    assert.deepEqual(template.blamedSymbols, [
      { name: 'template', kind: 'exported', via: 'member-access' },
      { name: 'assignInWith', kind: 'exported', via: 'backticks' },
    ]);
    assert.equal(template.ranges.length, 2);
    assert.deepEqual(vuln('GHSA-xxjr-mmjv-4gpg').mergedIds, ['GHSA-f23m-r3pf-42rh']);
    assert.deepEqual(vuln('GHSA-xxjr-mmjv-4gpg').fixedVersions, ['4.17.23', '4.18.0']);
    assert.equal(vuln('GHSA-xxjr-mmjv-4gpg').recommendedFix?.version, '4.18.1');
    assert.deepEqual(vuln('GHSA-29mw-wpgm-hmr9').recommendedFix, { version: '4.17.21', majorBump: false });
    assert.equal(pkg('lodash').latestVersion, '4.18.1');
    assert.deepEqual(pkg('lodash').usage.membersUsed, { get: 3, merge: 1 });
  });

  it('minimist: CRITICAL, fixed in 1.2.6, setKey internal, one binding call', () => {
    const m = vuln('GHSA-xvch-5gv4-984h');
    assert.equal(m.severity.ghsa, 'CRITICAL');
    assert.deepEqual(m.fixedVersions, ['1.2.6'], 'the 0.2.4 fix of the other line is below the installed version');
    assert.deepEqual(m.recommendedFix, { version: '1.2.6', majorBump: false });
    assert.deepEqual(m.blamedSymbols, [{ name: 'setKey', kind: 'internal', via: 'call' }]);
    assert.equal(m.affectedRange, '<0.2.4 || >=1.0.0 <1.2.6');
    const p = pkg('minimist');
    assert.equal(p.usage.bindingCalls, 1);
    assert.equal(p.usage.files[0]?.path, 'src/cli.js');
    assert.deepEqual(p.dependents, [{ name: 'json5', version: '2.2.0' }]);
    assert.deepEqual(p.dependencyPaths, [['minimist@1.2.5'], ['json5@2.2.0', 'minimist@1.2.5']]);
    assert.equal(p.depType, 'dependencies');
    assert.equal(p.spec, '1.2.5');
  });

  it('marked: five cases, 4.0.10 is a major bump', () => {
    assert.equal(pkg('marked').vulnIds.length, 5);
    const fixes = caseFileFixes(caseFile, 'marked');
    assert.deepEqual(fixes, ['0.3.17', '0.3.7', '0.3.9', '4.0.10 (major)', '4.0.10 (major)']);
  });

  it('json5, semver and decode-uri-component', () => {
    const j = vuln('GHSA-9c47-m6qq-7p4h');
    assert.equal(j.severity.ghsa, 'HIGH');
    assert.equal(j.recommendedFix?.version, '2.2.2');
    assert.deepEqual(j.blamedSymbols, [{ name: 'parse', kind: 'exported', via: 'member-access' }]);
    const s = vuln('GHSA-c2qf-rxjj-qqgw');
    assert.equal(s.recommendedFix?.version, '5.7.2');
    assert.equal(s.isDevOnly, true);
    assert.equal(pkg('semver').depType, 'devDependencies');
    assert.deepEqual(pkg('semver').usage.scopes, { source: 0, test: 0, config: 0, scripts: 1 });
    assert.deepEqual(caseFileFixes(caseFile, 'decode-uri-component'), ['0.2.1', '0.5.0 (major)']);
    const d = pkg('decode-uri-component');
    assert.equal(d.isDirect, false);
    assert.equal(d.depType, null);
    assert.equal(d.usage.imported, false);
    assert.deepEqual(d.dependencyPaths, [['query-string@6.14.1', 'decode-uri-component@0.2.0']]);
  });

  it('without registry data the deprecated fix cannot be skipped', async () => {
    const bare = buildCaseFile(await fixtureInput(data, graph, usage, false));
    const template = bare.vulnerabilities.find((v) => v.id === 'GHSA-35jh-r3h4-6jhm');
    assert.deepEqual(template?.recommendedFix, { version: '4.18.0', majorBump: false });
    assert.equal(bare.packages.find((p) => p.name === 'lodash')?.latestVersion, null);
  });

  it('marks malware, skips withdrawn records and records outside the installed range', async () => {
    const input = await fixtureInput(data, graph, usage);
    const mal: OsvRecord = { id: 'MAL-2026-9', modified: '2026-01-01T00:00:00Z', summary: 'Malicious code in minimist', affected: [{ package: { name: 'minimist', ecosystem: 'npm' }, versions: ['1.2.5'] }] };
    const gone: OsvRecord = { ...recordById(data, 'GHSA-xvch-5gv4-984h'), id: 'GHSA-gone', aliases: [], withdrawn: '2026-01-01T00:00:00Z' };
    const other: OsvRecord = { id: 'GHSA-other', modified: '2026-01-01T00:00:00Z', affected: [{ package: { name: 'minimist', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '2.0.0' }] }] }] };
    for (const r of [mal, gone, other]) input.osv.records.set(r.id, r);
    input.osv.idsByPackage.set(pairKey('minimist', '1.2.5'), ['GHSA-xvch-5gv4-984h', 'MAL-2026-9', 'GHSA-gone', 'GHSA-other']);
    const cf = buildCaseFile(input);
    const minimist = cf.vulnerabilities.filter((v) => v.package === 'minimist');
    assert.deepEqual(minimist.map((v) => v.id), ['MAL-2026-9', 'GHSA-xvch-5gv4-984h']);
    assert.equal(minimist[0]?.malware, true);
    assert.equal(minimist[0]?.recommendedFix, null);
    assert.equal(minimist[0]?.affectedRange, 'versions 1.2.5');
    assert.equal(recordAffects(other, 'minimist', '1.2.5'), false);
    assert.equal(recordAffects({ id: 'Y', modified: '' }, 'minimist', '1.2.5'), true, 'no data for the package: trust OSV');
  });
});

// fake tty answers first prompt
function interactiveUi(key: string): { ui: Ui; out: () => string } {
  let out = '';
  const stdout = new Writable({
    write(chunk, _enc, cb) {
      out += String(chunk);
      cb();
    },
  });
  const stderr = new Writable({
    write(_chunk, _enc, cb) {
      cb();
    },
  });
  const stdin = Object.assign(new PassThrough(), { isTTY: true, isRaw: false, setRawMode(mode: boolean) {
    stdin.isRaw = mode;
    return stdin;
  } });
  const answer = (): void => {
    if (stdin.listenerCount('data') > 0) stdin.write(key);
    else setImmediate(answer);
  };
  setImmediate(answer);
  const ui = new Ui({ stdout, stderr, stdin, interactive: true, unicode: true, color: false, env: {} });
  return { ui, out: () => out };
}

function caseFileFixes(caseFile: CaseFile, name: string): string[] {
  return caseFile.vulnerabilities
    .filter((v) => v.package === name)
    .map((v) => `${v.recommendedFix?.version}${v.recommendedFix?.majorBump ? ' (major)' : ''}`)
    .sort();
}

describe('case file persistence and summary', async () => {
  const data = await fixtureData();
  const graph = await loadDependencyGraph(FIXTURE_APP, 'package-lock.json');
  const usage = await collectUsageEvidence(FIXTURE_APP, ['lodash', 'minimist', 'marked', 'json5', 'semver', 'decode-uri-component'], { exclude: DEFAULT_EXCLUDES });
  const caseFile = buildCaseFile(await fixtureInput(data, graph, usage));

  it('saves atomically, returns hashJson and loads it back', async () => {
    const tmp = await tempDir();
    try {
      const file = path.join(tmp.dir, '.patch-pilot', 'case-file.json');
      const sha = await saveCaseFile(file, caseFile);
      assert.equal(sha, hashJson(caseFile));
      const loaded = await loadCaseFile(file);
      assert.ok(loaded);
      assert.equal(hashJson(loaded), sha, 'the assessment links by this hash');
      assert.equal(await loadCaseFile(path.join(tmp.dir, 'none.json')), null);
      await writeFile(file, JSON.stringify({ ...caseFile, version: 99 }));
      await assert.rejects(loadCaseFile(file), /version 99/);
      await writeFile(file, '{ nope');
      await assert.rejects(loadCaseFile(file), /unreadable/);
      await writeFile(file, '{"hello": 1}');
      await assert.rejects(loadCaseFile(file), /not a PatchPilot case file/);
    } finally {
      await tmp.cleanup();
    }
  });

  it('renders the check lines and a table by GHSA severity', () => {
    const { ui } = captureUi();
    const text = renderCaseFileSummary(caseFile, ui);
    const lines = text.split('\n');
    assert.equal(lines[0], '✓ Discovered lockfile  package-lock.json');
    assert.equal(lines[1], '✓ Parsed 10 dependencies  6 direct · 1 dev');
    assert.equal(lines[2], '✓ Vulnerability data  OSV.dev (live, just now)');
    assert.equal(lines[3], '✓ Found 13 CVEs across 6 packages');
    assert.match(text, /CRITICAL\s+1\s+minimist/);
    assert.match(text, /MODERATE\s+5\s+marked, lodash, decode-uri-component/);
    const tableOnly = renderCaseFileSummary(caseFile, ui, { checks: false });
    assert.ok(!tableOnly.includes('Discovered'));
    assert.ok(tableOnly.includes('Severity'));
  });

  it('cuts the details excerpt without code blocks or headings', () => {
    const text = excerpt(recordById(data, 'GHSA-9c47-m6qq-7p4h').details ?? '', 200);
    assert.ok(text.length <= 201);
    assert.ok(!text.includes('```'));
    assert.ok(text.startsWith('The `parse` method of the JSON5 library'));
    assert.equal(excerpt('### Impact\n\nShort text.'), 'Short text.');
  });
});

describe('runPhase1 end to end (fetch stubbed, fixture copied to a temp dir)', async () => {
  const data = await fixtureData();
  let app: { dir: string; cleanup: () => Promise<void> };
  let home: { dir: string; cleanup: () => Promise<void> };
  let stub: ReturnType<typeof stubFetch> | null = null;

  before(async () => {
    app = await copyFixtureApp();
    home = await tempDir('pp-home-');
  });
  afterEach(() => {
    stub?.restore();
    stub = null;
  });
  after(async () => {
    await app.cleanup();
    await home.cleanup();
  });

  it('discovers, parses, queries, maps usage, saves the case file and logs the audit events', async () => {
    stub = stubFetch(fixtureServer(data));
    const config = await loadConfig({ dir: app.dir, flags: { trust: true }, homeDir: home.dir, stdinIsTTY: false, stdoutIsTTY: false });
    const { ui, out } = captureUi();
    const audit = new MemoryAudit();
    let warmed = 0;
    const provider = { name: 'mock', model: 'mock', warmup: async () => void (warmed += 1) } as unknown as ChatProvider;
    const caseFile = await runPhase1(config, { ui, audit, provider });
    assert.equal(warmed, 1, 'the model is pre-warmed');
    assert.equal(caseFile.counts.vulnerabilities, 13);
    assert.equal(caseFile.vulnSource.mode, 'live');
    assert.equal(caseFile.project.root, config.projectRoot, 'the symlink-resolved root');
    assert.equal(caseFile.project.lockfile, 'package-lock.json');
    const text = out();
    assert.match(text, /^✓ Discovered lockfile {2}package-lock\.json$/m);
    assert.match(text, /^✓ Parsed 10 dependencies {2}6 direct · 1 dev$/m);
    assert.match(text, /^✓ Vulnerability data {2}OSV\.dev \(live, just now\)$/m);
    assert.match(text, /^✓ Found 13 CVEs across 6 packages$/m);
    assert.match(text, /^✓ Located usage evidence {2}5 files scanned · 5 of 6 vulnerable packages imported$/m);
    assert.deepEqual(
      audit.records.map((r) => r.event),
      ['discover.lockfile', 'deps.parsed', 'osv.query', 'casefile.saved'],
    );
    const saved = audit.events('casefile.saved')[0];
    assert.equal(saved?.path, '.patch-pilot/case-file.json');
    assert.equal(saved?.sha256, hashJson(caseFile));
    assert.deepEqual(audit.events('discover.lockfile')[0], {
      ...audit.events('discover.lockfile')[0],
      lockfile: 'package-lock.json',
      kind: 'package-lock',
      lockfileVersion: 3,
      generated: false,
      unsupported: [],
    });
    assert.deepEqual(
      (({ total, direct, dev }) => ({ total, direct, dev }))(audit.events('deps.parsed')[0] ?? { total: 0, direct: 0, dev: 0 }),
      { total: 10, direct: 6, dev: 1 },
    );
    assert.equal(audit.events('osv.query')[0]?.mode, 'live');
    const onDisk = await loadCaseFile(config.paths.caseFile);
    assert.equal(onDisk?.counts.vulnerabilities, 13);
    assert.ok(existsSync(config.paths.dbFile), 'the SQLite cache lives under the (temp) home');
  });

  it('runs offline from the cache the first run filled', async () => {
    stub = stubFetch(() => {
      throw new Error('no network under --offline');
    });
    const config = await loadConfig({ dir: app.dir, flags: { offline: true, trust: true }, homeDir: home.dir, stdinIsTTY: false, stdoutIsTTY: false });
    const { ui, out } = captureUi();
    const audit = new MemoryAudit();
    const caseFile = await runPhase1(config, { ui, audit });
    assert.equal(stub.calls.length, 0);
    assert.equal(caseFile.vulnSource.mode, 'cache');
    assert.equal(caseFile.counts.vulnerabilities, 13);
    assert.equal(caseFile.vulnerabilities.find((v) => v.id === 'GHSA-35jh-r3h4-6jhm')?.recommendedFix?.version, '4.18.1', 'registry data from the cache');
    assert.match(out(), /OSV\.dev \(cache, /);
  });

  it('warns when OSV.dev is unreachable and serves the cache', async () => {
    stub = stubFetch(fixtureServer(data, { osvDown: true }));
    const db = openDb(path.join(home.dir, '.patch-pilot', 'patch-pilot.db'));
    try {
      const config = await loadConfig({ dir: app.dir, flags: { trust: true }, homeDir: home.dir, stdinIsTTY: false, stdoutIsTTY: false });
      const { ui, err } = captureUi();
      const caseFile = await runPhase1(config, { ui, audit: new MemoryAudit(), db });
      assert.equal(caseFile.vulnSource.mode, 'cache');
      assert.match(err(), /! OSV\.dev could not be reached/);
    } finally {
      db.close();
    }
  });

  it('offers a scratch lockfile on a TTY and scans it when the user says yes', async () => {
    const project = await tempDir('pp-nolock-');
    try {
      await writeFile(path.join(project.dir, 'package.json'), JSON.stringify({ name: 'no-lock', version: '1.0.0', private: true }));
      stub = stubFetch(() => {
        throw new Error('a project without dependencies needs no network');
      });
      for (const answer of ['n', 'y']) {
        const config = await loadConfig({ dir: project.dir, flags: { trust: true }, homeDir: home.dir, stdinIsTTY: true, stdoutIsTTY: true });
        assert.equal(config.interactive, true);
        const { ui, out } = interactiveUi(answer);
        const audit = new MemoryAudit();
        if (answer === 'n') {
          await assert.rejects(runPhase1(config, { ui, audit, db: null }), (e: unknown) => (e as { exitCode?: number }).exitCode === 3);
          assert.match(out(), /Generate a scratch lockfile in \.patch-pilot\/tmp\/\? \(y\/n\) n/);
          assert.ok(!existsSync(path.join(project.dir, '.patch-pilot', 'tmp', 'scratch')));
          continue;
        }
        const caseFile = await runPhase1(config, { ui, audit, db: null });
        assert.equal(caseFile.project.lockfile, '.patch-pilot/tmp/scratch/package-lock.json');
        assert.equal(caseFile.counts.dependencies, 0);
        assert.match(out(), /✓ Discovered lockfile {2}\.patch-pilot\/tmp\/scratch\/package-lock\.json \(generated from package\.json\)/);
        assert.equal(audit.events('discover.lockfile')[0]?.generated, true);
        assert.equal(existsSync(path.join(project.dir, 'package-lock.json')), false, 'the project itself is not touched');
      }
    } finally {
      await project.cleanup();
    }
  });

  it('stops with exit 3 and the lockfile command when there is no lockfile (non-interactive)', async () => {
    await rm(path.join(app.dir, 'package-lock.json'));
    const config = await loadConfig({ dir: app.dir, flags: { trust: true }, homeDir: home.dir, stdinIsTTY: false, stdoutIsTTY: false });
    const { ui } = captureUi();
    const audit = new MemoryAudit();
    await assert.rejects(runPhase1(config, { ui, audit, db: null }), (e: unknown) => {
      const error = e as { exitCode?: number; hint?: string; message: string };
      assert.equal(error.exitCode, 3);
      assert.match(error.message, /No package-lock\.json/);
      assert.match(error.hint ?? '', /npm install --package-lock-only --ignore-scripts/);
      return true;
    });
    assert.deepEqual(audit.events('discover.lockfile')[0]?.lockfile, null);
  });
});
