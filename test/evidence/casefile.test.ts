import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { describe, it } from 'node:test';
import { cvssScore, excerpt, mergeAliasedRecords, severityLabel, severityOf } from '../../src/evidence/casefile.ts';
import type { OsvRecord } from '../../src/types.ts';
import { fixtureData, recordById } from './helpers.ts';

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

describe('excerpt', async () => {
  const data = await fixtureData();

  it('cuts the details excerpt without code blocks or headings', () => {
    const text = excerpt(recordById(data, 'GHSA-9c47-m6qq-7p4h').details ?? '', 200);
    assert.ok(text.length <= 201);
    assert.ok(!text.includes('```'));
    assert.ok(text.startsWith('The `parse` method of the JSON5 library'));
    assert.equal(excerpt('### Impact\n\nShort text.'), 'Short text.');
  });
});
