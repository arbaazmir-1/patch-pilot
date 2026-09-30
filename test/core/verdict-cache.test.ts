import assert from 'node:assert/strict';
import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { MemoryAudit } from '../../src/audit.ts';
import { MockProvider } from '../../src/llm/mock.ts';
import { runPhase2 } from '../../src/investigation/agent.ts';
import {
  loadVerdictCache,
  lookupVerdict,
  MAX_ENTRIES,
  providerOfKey,
  saveVerdictCache,
  storeVerdict,
  usageEvidenceHash,
  VERDICT_CACHE_VERSION,
  verdictCacheKey,
  type VerdictCacheFile,
  type VerdictCacheKeyInput,
} from '../../src/investigation/verdictCache.ts';
import type { UsageEvidence, Verdict, VulnCase } from '../../src/types.ts';
import { captureUi, caseFileOf, fakeRegistry, lodashFixture, minimistFixture, testConfig, usageResult } from '../investigation/helpers.ts';

const KEY_INPUT: VerdictCacheKeyInput = {
  provider: 'ollama',
  vulnId: 'GHSA-xvch-5gv4-984h',
  package: 'minimist',
  version: '1.2.5',
  model: 'mistral:7b',
  usageHash: 'a'.repeat(64),
  promptVersion: 'b1-2026-09-24.4',
};

function usage(partial: Partial<UsageEvidence> = {}): UsageEvidence {
  return {
    package: 'lodash',
    imported: true,
    files: [
      { path: 'src/config.js', line: 7, statement: "const _ = require('lodash');", binding: '_', kind: 'cjs-require', scope: 'source' },
      { path: 'test/config.test.js', line: 2, statement: "const _ = require('lodash');", binding: '_', kind: 'cjs-require', scope: 'test' },
    ],
    scopes: { source: 1, test: 1, config: 0, scripts: 0 },
    membersUsed: { merge: 1, get: 3 },
    bindingCalls: 0,
    scannedFiles: 6,
    ...partial,
  };
}

function vuln(partial: Partial<VulnCase> = {}): VulnCase {
  return {
    id: 'GHSA-35jh-r3h4-6jhm',
    aliases: ['CVE-2021-23337'],
    mergedIds: [],
    package: 'lodash',
    installedVersion: '4.17.20',
    summary: 'Command Injection in lodash',
    detailsExcerpt: 'Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.',
    blamedSymbols: [
      { name: 'template', kind: 'exported', via: 'backticks' },
      { name: 'trim', kind: 'internal', via: 'call' },
    ],
    severity: { ghsa: 'HIGH', cvssScore: 7.2 },
    cweIds: ['CWE-77', 'CWE-94'],
    malware: false,
    affectedRange: '<4.17.21',
    ranges: [],
    fixedVersions: ['4.17.21', '4.18.1'],
    recommendedFix: { version: '4.17.21', majorBump: false },
    isDirect: true,
    isDevOnly: false,
    dependencyPaths: [['vulnerable-app@1.0.0', 'lodash@4.17.20']],
    references: [],
    published: '2021-02-15T11:28:00Z',
    modified: '2024-01-01T00:00:00Z',
    ...partial,
  };
}

function verdict(partial: Partial<Verdict> = {}, investigation: Partial<Verdict['investigation']> = {}): Verdict {
  return {
    vulnId: 'GHSA-xvch-5gv4-984h',
    package: 'minimist',
    installedVersion: '1.2.5',
    risk: 'High',
    reachable: 'yes',
    confidence: 0.8,
    reasoning: 'minimist parses process.argv in src/cli.js.',
    evidence: ['src/cli.js:7 parseArgs(process.argv.slice(2))'],
    recommendation: { action: 'upgrade', targetVersion: '1.2.6', majorBump: false },
    investigation: { provider: 'ollama', model: 'mistral:7b', promptVersion: 'b1-2026-09-24.4', steps: 2, toolCalls: [], durationMs: 1200, forced: false, ...investigation },
    ...partial,
  };
}

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(path.join(os.tmpdir(), 'pp-verdict-cache-'));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('verdictCacheKey', () => {
  it('is stable, independent of field order, and names the provider', () => {
    const key = verdictCacheKey(KEY_INPUT);
    assert.match(key, /^ollama:[0-9a-f]{64}$/);
    assert.equal(verdictCacheKey({ ...KEY_INPUT }), key);
    const reordered = Object.fromEntries(Object.entries(KEY_INPUT).reverse()) as unknown as VerdictCacheKeyInput;
    assert.equal(verdictCacheKey(reordered), key);
    assert.equal(providerOfKey(key), 'ollama');
    assert.equal(providerOfKey('not-a-key'), null);
  });

  it('changes with every input, including provider and model', () => {
    const base = verdictCacheKey(KEY_INPUT);
    const variants: Partial<VerdictCacheKeyInput>[] = [
      { provider: 'mock' },
      { vulnId: 'GHSA-other' },
      { package: 'minimist2' },
      { version: '1.2.6' },
      { model: 'qwen3:8b' },
      { usageHash: 'b'.repeat(64) },
      { promptVersion: 'b1-2026-09-24.5' },
    ];
    const keys = new Set([base]);
    for (const change of variants) {
      const key = verdictCacheKey({ ...KEY_INPUT, ...change });
      assert.notEqual(key, base, JSON.stringify(change));
      keys.add(key);
    }
    assert.equal(keys.size, variants.length + 1);
    assert.match(verdictCacheKey({ ...KEY_INPUT, provider: 'mock' }), /^mock:/);
  });

  it('rejects incomplete input', () => {
    assert.throws(() => verdictCacheKey({ ...KEY_INPUT, model: '' }), /model/);
    assert.throws(() => verdictCacheKey({ ...KEY_INPUT, vulnId: '   ' }), /vulnId/);
  });
});

describe('usageEvidenceHash', () => {
  it('ignores ordering and the scanned-file count', () => {
    const base = usageEvidenceHash(usage(), vuln());
    assert.match(base, /^[0-9a-f]{64}$/);
    const u = usage();
    const shuffled = usage({ files: [...u.files].reverse(), membersUsed: { get: 3, merge: 1 }, scannedFiles: 60 });
    const v = vuln();
    const reordered = vuln({ blamedSymbols: [...v.blamedSymbols].reverse(), fixedVersions: [...v.fixedVersions].reverse(), cweIds: [...v.cweIds].reverse() });
    assert.equal(usageEvidenceHash(shuffled, reordered), base);
  });

  it('changes when the evidence behind a verdict changes', () => {
    const base = usageEvidenceHash(usage(), vuln());
    const u = usage();
    const file0 = u.files[0];
    assert.ok(file0);
    const changed: [string, UsageEvidence, VulnCase][] = [
      ['another import site', usage({ files: [...u.files, { ...file0, path: 'src/api.js' }] }), vuln()],
      ['import statement', usage({ files: [{ ...file0, statement: "import _ from 'lodash';", kind: 'esm-default' }, ...u.files.slice(1)] }), vuln()],
      ['import line', usage({ files: [{ ...file0, line: 8 }, ...u.files.slice(1)] }), vuln()],
      ['scopes', usage({ scopes: { source: 2, test: 1, config: 0, scripts: 0 } }), vuln()],
      ['members used', usage({ membersUsed: { merge: 1, get: 3, template: 1 } }), vuln()],
      ['member count', usage({ membersUsed: { merge: 2, get: 3 } }), vuln()],
      ['binding calls', usage({ bindingCalls: 1 }), vuln()],
      ['not imported', usage({ imported: false, files: [], scopes: { source: 0, test: 0, config: 0, scripts: 0 } }), vuln()],
      ['file cap', usage({ truncated: true }), vuln()],
      ['blamed symbol added', usage(), vuln({ blamedSymbols: [...vuln().blamedSymbols, { name: 'unset', kind: 'exported', via: 'member-access' }] })],
      ['blamed symbol class', usage(), vuln({ blamedSymbols: [{ name: 'template', kind: 'internal', via: 'call' }, { name: 'trim', kind: 'internal', via: 'call' }] })],
      ['fixed versions', usage(), vuln({ fixedVersions: ['4.17.21'] })],
      ['recommended fix', usage(), vuln({ recommendedFix: { version: '4.18.1', majorBump: false, skippedDeprecated: ['4.18.0'] } })],
      ['no fix', usage(), vuln({ recommendedFix: null })],
      ['dev-only', usage(), vuln({ isDevOnly: true })],
      ['transitive', usage(), vuln({ isDirect: false })],
      ['dependency paths', usage(), vuln({ dependencyPaths: [['vulnerable-app@1.0.0', 'x@1.0.0', 'lodash@4.17.20']] })],
      ['severity', usage(), vuln({ severity: { ghsa: 'CRITICAL', cvssScore: 9.1 } })],
      ['advisory text', usage(), vuln({ detailsExcerpt: 'Different details.' })],
    ];
    const hashes = new Set([base]);
    for (const [label, u2, v2] of changed) {
      const hash = usageEvidenceHash(u2, v2);
      assert.notEqual(hash, base, label);
      hashes.add(hash);
    }
    assert.equal(hashes.size, changed.length + 1, 'every change gives a distinct hash');
  });
});

describe('lookupVerdict and storeVerdict', () => {
  it('round-trips a verdict and marks the served copy as cached', () => {
    const cache: VerdictCacheFile = { version: VERDICT_CACHE_VERSION, entries: {} };
    const key = verdictCacheKey(KEY_INPUT);
    assert.equal(lookupVerdict(cache, key), null);
    const fresh = verdict();
    storeVerdict(cache, key, fresh);
    const hit = lookupVerdict(cache, key);
    assert.ok(hit);
    assert.equal(hit.investigation.cached, true);
    assert.deepEqual({ ...hit, investigation: { ...hit.investigation, cached: undefined } }, { ...fresh, investigation: { ...fresh.investigation, cached: undefined } });
    assert.equal(cache.entries[key]?.verdict.investigation.cached, undefined, 'the stored copy carries no cached flag');
    assert.match(cache.entries[key]?.storedAt ?? '', /^\d{4}-\d{2}-\d{2}T/);
    hit.risk = 'Noise';
    hit.evidence.push('mutated');
    assert.equal(lookupVerdict(cache, key)?.risk, 'High', 'callers get a copy');
    assert.equal(lookupVerdict(cache, key)?.evidence.length, 1);
    fresh.risk = 'Low';
    assert.equal(lookupVerdict(cache, key)?.risk, 'High', 'the cache keeps its own copy');
  });

  it('strips the cached flag when a served verdict is stored again', () => {
    const cache: VerdictCacheFile = { version: VERDICT_CACHE_VERSION, entries: {} };
    const key = verdictCacheKey(KEY_INPUT);
    storeVerdict(cache, key, verdict({}, { cached: true }));
    assert.equal(cache.entries[key]?.verdict.investigation.cached, undefined);
  });

  it('never stores a forced verdict', () => {
    const cache: VerdictCacheFile = { version: VERDICT_CACHE_VERSION, entries: {} };
    storeVerdict(cache, verdictCacheKey(KEY_INPUT), verdict({}, { forced: true }));
    assert.deepEqual(cache.entries, {});
  });

  it('never serves a mock verdict for a real model', () => {
    const cache: VerdictCacheFile = { version: VERDICT_CACHE_VERSION, entries: {} };
    const mockKey = verdictCacheKey({ ...KEY_INPUT, provider: 'mock', model: 'mock' });
    const realKey = verdictCacheKey(KEY_INPUT);
    const mockVerdict = verdict({ risk: 'Noise' }, { provider: 'mock', model: 'mock' });
    storeVerdict(cache, mockKey, mockVerdict);
    assert.equal(lookupVerdict(cache, realKey), null, 'different key');
    assert.throws(() => storeVerdict(cache, realKey, mockVerdict), /mock verdict cannot be stored under a ollama key/);
    // hand-edited mock verdict under a real key
    cache.entries[realKey] = { verdict: mockVerdict, storedAt: new Date().toISOString() };
    assert.equal(lookupVerdict(cache, realKey), null);
    assert.equal(lookupVerdict(cache, mockKey)?.risk, 'Noise');
  });

  it('rejects malformed keys and ignores prototype names', () => {
    const cache: VerdictCacheFile = { version: VERDICT_CACHE_VERSION, entries: {} };
    assert.throws(() => storeVerdict(cache, 'lodash', verdict()), /malformed cache key/);
    assert.equal(lookupVerdict(cache, 'constructor'), null);
    assert.equal(lookupVerdict(cache, '__proto__'), null);
    assert.equal(lookupVerdict(cache, 'toString'), null);
  });

  it(`keeps at most ${MAX_ENTRIES} entries, dropping the oldest`, () => {
    const cache: VerdictCacheFile = { version: VERDICT_CACHE_VERSION, entries: {} };
    const keys: string[] = [];
    for (let i = 0; i < MAX_ENTRIES + 5; i += 1) {
      const key = verdictCacheKey({ ...KEY_INPUT, vulnId: `GHSA-${i}` });
      keys.push(key);
      storeVerdict(cache, key, verdict({ vulnId: `GHSA-${i}` }));
      if (i < 5) {
        const entry = cache.entries[key];
        if (entry) entry.storedAt = `2020-01-0${i + 1}T00:00:00.000Z`;
      }
    }
    assert.equal(Object.keys(cache.entries).length, MAX_ENTRIES);
    for (const key of keys.slice(0, 5)) assert.equal(cache.entries[key], undefined);
    assert.ok(cache.entries[keys.at(-1) ?? '']);
  });
});

describe('loadVerdictCache and saveVerdictCache', () => {
  function collector(): { warn: (m: string, d?: string) => void; messages: string[] } {
    const messages: string[] = [];
    return { messages, warn: (m, d) => messages.push(d ? `${m} (${d})` : m) };
  }

  it('a missing file is an empty cache without a warning', async () => {
    const w = collector();
    const cache = await loadVerdictCache(path.join(dir, '.patch-pilot', 'verdict-cache.json'), { warn: w.warn });
    assert.deepEqual(cache, { version: VERDICT_CACHE_VERSION, entries: {} });
    assert.deepEqual(w.messages, []);
  });

  it('saves atomically and loads what it saved', async () => {
    const file = path.join(dir, '.patch-pilot', 'verdict-cache.json');
    const cache: VerdictCacheFile = { version: VERDICT_CACHE_VERSION, entries: {} };
    const key = verdictCacheKey(KEY_INPUT);
    storeVerdict(cache, key, verdict());
    await saveVerdictCache(file, cache);
    const text = await readFile(file, 'utf8');
    const parsed = JSON.parse(text) as VerdictCacheFile;
    assert.equal(parsed.version, VERDICT_CACHE_VERSION);
    assert.deepEqual(Object.keys(parsed.entries), [key]);
    assert.deepEqual(await readdir(path.dirname(file)), ['verdict-cache.json'], 'no temporary file left behind');
    const w = collector();
    const loaded = await loadVerdictCache(file, { warn: w.warn });
    assert.deepEqual(loaded, cache);
    assert.deepEqual(w.messages, []);
    assert.equal(lookupVerdict(loaded, key)?.investigation.cached, true);
  });

  it('a corrupt, foreign or wrongly shaped file gives an empty cache and one warning', async () => {
    const file = path.join(dir, 'verdict-cache.json');
    const cases: [string, string, RegExp][] = [
      ['{"version": 1, "entries": {', 'truncated JSON', /not valid JSON/],
      ['[1, 2, 3]', 'an array', /unexpected shape/],
      ['{"version": 99, "entries": {}}', 'another version', /another format \(version 99\)/],
      ['{"version": 1, "entries": []}', 'entries not an object', /no entries table/],
    ];
    for (const [content, label, expected] of cases) {
      await writeFile(file, content);
      const w = collector();
      const cache = await loadVerdictCache(file, { warn: w.warn });
      assert.deepEqual(cache, { version: VERDICT_CACHE_VERSION, entries: {} }, label);
      assert.equal(w.messages.length, 1, label);
      assert.match(w.messages[0] ?? '', expected, label);
    }
    await writeFile(file, '   \n');
    const w = collector();
    assert.deepEqual(await loadVerdictCache(file, { warn: w.warn }), { version: VERDICT_CACHE_VERSION, entries: {} });
    assert.deepEqual(w.messages, [], 'an empty file is simply empty');
  });

  it('drops malformed entries and keeps the good ones', async () => {
    const file = path.join(dir, 'verdict-cache.json');
    const good = verdictCacheKey(KEY_INPUT);
    const mockKey = verdictCacheKey({ ...KEY_INPUT, provider: 'mock' });
    const other = verdictCacheKey({ ...KEY_INPUT, vulnId: 'GHSA-2' });
    await writeFile(
      file,
      JSON.stringify({
        version: VERDICT_CACHE_VERSION,
        entries: {
          [good]: { verdict: verdict(), storedAt: '2026-09-24T10:00:00.000Z' },
          [mockKey]: { verdict: verdict(), storedAt: '2026-09-24T10:00:00.000Z' },
          [other]: { verdict: { ...verdict(), risk: 'Severe' }, storedAt: '2026-09-24T10:00:00.000Z' },
          'no-provider': { verdict: verdict(), storedAt: '2026-09-24T10:00:00.000Z' },
        },
      }),
    );
    const w = collector();
    const cache = await loadVerdictCache(file, { warn: w.warn });
    assert.deepEqual(Object.keys(cache.entries), [good]);
    assert.deepEqual(w.messages.length, 1);
    assert.match(w.messages[0] ?? '', /Ignored 3 malformed entries/);
  });

  it('an unreadable path warns and continues', async () => {
    const w = collector();
    const cache = await loadVerdictCache(dir, { warn: w.warn });
    assert.deepEqual(cache.entries, {});
    assert.equal(w.messages.length, 1);
    assert.match(w.messages[0] ?? '', /Cannot read the verdict cache/);
  });
});

describe('verdict cache in the investigation loop (mock provider)', () => {
  function setup() {
    const provider = new MockProvider({ rules: [] });
    const { ui, out, err } = captureUi();
    const audit = new MemoryAudit();
    const { registry } = fakeRegistry({
      get_usage: (a) => usageResult(String(a.package), typeof a.symbol === 'string' ? a.symbol : null, 0, [{ path: 'src/cli.js', line: 21, member: null }]),
      read_file: () => ({ ok: true, hint: 'src/cli.js:11-40 of 49 lines', text: 'code' }),
      check_deps: () => ({ ok: true, hint: 'direct production dependency', data: {} }),
    });
    return { provider, ui, out, err, audit, registry };
  }

  it('reuses verdicts on the second run, re-investigates with --no-cache and for another model', async () => {
    const lodash = lodashFixture();
    const minimist = minimistFixture();
    const cf = caseFileOf([lodash.pkg, minimist.pkg], [lodash.template, minimist.vuln], dir);
    const config = await testConfig(dir, { maxSteps: 3 });

    const first = setup();
    const a1 = await runPhase2(cf, config, { provider: first.provider, ui: first.ui, audit: first.audit, registry: first.registry, graph: null });
    assert.equal(a1.verdicts.length, 2);
    assert.deepEqual(first.audit.events('verdict.cached'), []);
    const saved = JSON.parse(await readFile(config.paths.verdictCacheFile, 'utf8')) as VerdictCacheFile;
    assert.equal(Object.keys(saved.entries).length, 2);
    assert.ok(Object.keys(saved.entries).every((k) => k.startsWith('mock:')), 'mock verdicts are filed under mock keys');

    const second = setup();
    const a2 = await runPhase2(cf, config, { provider: second.provider, ui: second.ui, audit: second.audit, registry: second.registry, graph: null });
    assert.deepEqual(a2.verdicts.map((v) => v.investigation.cached), [true, true]);
    assert.deepEqual(a2.verdicts.map((v) => [v.vulnId, v.risk]), a1.verdicts.map((v) => [v.vulnId, v.risk]));
    const cachedEvents = second.audit.events('verdict.cached');
    assert.deepEqual(cachedEvents.map((e) => e.vulnId).sort(), [lodash.template.id, minimist.vuln.id].sort());
    assert.ok(cachedEvents.every((e) => Object.keys(saved.entries).includes(e.key)));
    assert.equal(second.provider.calls.length, 0, 'no model call at all');
    assert.match(second.out(), /\[cached\] Same model, prompt and evidence as an earlier run/);

    const noCache = setup();
    const a3 = await runPhase2(cf, await testConfig(dir, { maxSteps: 3, cache: false }), {
      provider: noCache.provider,
      ui: noCache.ui,
      audit: noCache.audit,
      registry: noCache.registry,
      graph: null,
    });
    assert.deepEqual(a3.verdicts.map((v) => Boolean(v.investigation.cached)), [false, false]);
    assert.deepEqual(noCache.audit.events('verdict.cached'), []);
    assert.ok(noCache.provider.calls.some((c) => c.purpose === 'verdict'));

    const otherModel = setup();
    const provider = new MockProvider({ rules: [] }, { model: 'other-model' });
    const a4 = await runPhase2(cf, config, { provider, ui: otherModel.ui, audit: otherModel.audit, registry: otherModel.registry, graph: null });
    assert.deepEqual(a4.verdicts.map((v) => Boolean(v.investigation.cached)), [false, false]);
    assert.deepEqual(otherModel.audit.events('verdict.cached'), []);

    const changed = setup();
    const moved = { ...minimist.pkg, usage: { ...minimist.pkg.usage, bindingCalls: 2 } };
    const a5 = await runPhase2(caseFileOf([lodash.pkg, moved], [lodash.template, minimist.vuln], dir), config, {
      provider: changed.provider,
      ui: changed.ui,
      audit: changed.audit,
      registry: changed.registry,
      graph: null,
    });
    const byId = new Map(a5.verdicts.map((v) => [v.vulnId, Boolean(v.investigation.cached)]));
    assert.equal(byId.get(minimist.vuln.id), false, 'changed evidence is investigated again');
    assert.equal(byId.get(lodash.template.id), true, 'unchanged evidence still hits');
  });
});
