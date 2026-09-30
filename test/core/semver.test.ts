import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import semver from 'semver';
import type { OsvRange } from '../../src/types.ts';
import {
  compareVersions,
  describeRanges,
  fixedVersionsFromRanges,
  isAffected,
  isAffectedByEntry,
  isMajorBump,
  isSameLine,
  pickFix,
  pickPackageFix,
  satisfiesRange,
  sortVersions,
  specStyle,
} from '../../src/util/semver.ts';

const range = (...events: Record<string, string>[]): OsvRange => ({ type: 'SEMVER', events: events as OsvRange['events'] });

// as osv.dev serves them
const LODASH: Record<string, OsvRange[]> = {
  'GHSA-29mw-wpgm-hmr9': [range({ introduced: '4.0.0' }, { fixed: '4.17.21' })],
  'GHSA-35jh-r3h4-6jhm': [range({ introduced: '0' }, { fixed: '4.17.21' })],
  'GHSA-f23m-r3pf-42rh': [range({ introduced: '0' }, { fixed: '4.18.0' })],
  'GHSA-r5fr-rjxr-66jc': [range({ introduced: '4.0.0' }, { fixed: '4.18.0' })],
  'GHSA-xxjr-mmjv-4gpg': [range({ introduced: '4.0.0' }, { fixed: '4.17.23' })],
};
const MINIMIST = [range({ introduced: '1.0.0' }, { fixed: '1.2.6' }), range({ introduced: '0' }, { fixed: '0.2.4' })];
const SEMVER_REDOS = [
  range({ introduced: '7.0.0' }, { fixed: '7.5.2' }),
  range({ introduced: '6.0.0' }, { fixed: '6.3.1' }),
  range({ introduced: '2.0.0-alpha' }, { fixed: '5.7.2' }),
];
const MARKED: Record<string, OsvRange[]> = {
  'GHSA-5v2h-r2cx-5xgj': [range({ introduced: '0' }, { fixed: '4.0.10' })],
  'GHSA-7px7-7xjx-hxm8': [range({ introduced: '0' }, { fixed: '0.3.7' })],
  'GHSA-p9wx-2529-fp83': [range({ introduced: '0' }, { fixed: '0.3.17' })],
  'GHSA-rrrm-qjm4-v8hf': [range({ introduced: '0' }, { fixed: '4.0.10' })],
  'GHSA-x5pg-88wf-qq4p': [range({ introduced: '0' }, { fixed: '0.3.9' })],
};
const DECODE: Record<string, OsvRange[]> = {
  'GHSA-w573-4hg7-7wgq': [range({ introduced: '0' }, { fixed: '0.2.1' })],
  'GHSA-vcc3-ghjq-m6fr': [range({ introduced: '0' }, { fixed: '0.5.0' })],
};

const inputs = (table: Record<string, OsvRange[]>) =>
  Object.entries(table).map(([id, ranges]) => ({ id, ranges, fixedVersions: fixedVersionsFromRanges(ranges) }));

describe('isAffected (OSV SEMVER events)', () => {
  it('evaluates introduced/fixed with introduced "0"', () => {
    for (const ranges of Object.values(LODASH)) assert.equal(isAffected('4.17.20', ranges), true);
    assert.equal(isAffected('4.17.21', LODASH['GHSA-29mw-wpgm-hmr9']!), false);
    assert.equal(isAffected('3.10.1', LODASH['GHSA-29mw-wpgm-hmr9']!), false, 'before introduced');
    assert.equal(isAffected('4.17.23', LODASH['GHSA-f23m-r3pf-42rh']!), true);
    assert.equal(isAffected('4.18.0', LODASH['GHSA-f23m-r3pf-42rh']!), false);
  });

  it('handles several ranges for one package (minimist 0.x and 1.x lines)', () => {
    assert.equal(isAffected('1.2.5', MINIMIST), true);
    assert.equal(isAffected('1.2.6', MINIMIST), false);
    assert.equal(isAffected('0.2.3', MINIMIST), true);
    assert.equal(isAffected('0.2.4', MINIMIST), false);
    assert.equal(isAffected('0.9.0', MINIMIST), false, 'between the ranges');
    assert.equal(isAffected('1.0.0', MINIMIST), true);
  });

  it('compares prereleases in events (semver introduced 2.0.0-alpha)', () => {
    assert.equal(isAffected('5.7.1', SEMVER_REDOS), true);
    assert.equal(isAffected('5.7.2', SEMVER_REDOS), false);
    assert.equal(isAffected('2.0.0-alpha', SEMVER_REDOS), true);
    assert.equal(isAffected('1.9.9', SEMVER_REDOS), false);
    assert.equal(isAffected('6.3.0', SEMVER_REDOS), true);
    assert.equal(isAffected('7.5.2', SEMVER_REDOS), false);
  });

  it('supports last_affected and limit', () => {
    const lastAffected = [range({ introduced: '4.0.0' }, { last_affected: '4.5.1' })];
    assert.equal(isAffected('4.5.1', lastAffected), true);
    assert.equal(isAffected('4.5.2', lastAffected), false);
    const limited = [range({ introduced: '0' }, { limit: '2.0.0' })];
    assert.equal(isAffected('1.9.9', limited), true);
    assert.equal(isAffected('2.0.0', limited), false);
  });

  it('sorts unsorted events, treats ECOSYSTEM like SEMVER and ignores GIT ranges', () => {
    assert.equal(isAffected('1.5.0', [range({ fixed: '2.0.0' }, { introduced: '1.0.0' })]), true);
    assert.equal(isAffected('1.5.0', [{ type: 'ECOSYSTEM', events: [{ introduced: '1.0.0' }, { fixed: '2.0.0' }] }]), true);
    assert.equal(isAffected('1.5.0', [{ type: 'GIT', repo: 'https://x', events: [{ introduced: '0' }] }]), false);
  });

  it('returns false for versions that are not semver and for empty ranges', () => {
    assert.equal(isAffected('github:user/repo', MINIMIST), false);
    assert.equal(isAffected('1.2.5', []), false);
  });

  it('accepts explicit versions lists in affected entries', () => {
    assert.equal(isAffectedByEntry('1.0.3', { versions: ['1.0.3'] }), true);
    assert.equal(isAffectedByEntry('1.2.5', { ranges: MINIMIST }), true);
    assert.equal(isAffectedByEntry('1.2.6', { versions: ['1.0.3'], ranges: MINIMIST }), false);
  });
});

describe('fixedVersionsFromRanges and describeRanges', () => {
  it('collects fixed events sorted', () => {
    assert.deepEqual(fixedVersionsFromRanges(MINIMIST), ['0.2.4', '1.2.6']);
    assert.deepEqual(fixedVersionsFromRanges(SEMVER_REDOS), ['5.7.2', '6.3.1', '7.5.2']);
  });

  it('describes ranges in npm range syntax', () => {
    assert.equal(describeRanges(LODASH['GHSA-29mw-wpgm-hmr9']!), '>=4.0.0 <4.17.21');
    assert.equal(describeRanges(LODASH['GHSA-35jh-r3h4-6jhm']!), '<4.17.21');
    assert.equal(describeRanges(MINIMIST), '<0.2.4 || >=1.0.0 <1.2.6');
    assert.equal(describeRanges([range({ introduced: '4.0.0' }, { last_affected: '4.5.1' })]), '>=4.0.0 <=4.5.1');
    assert.equal(describeRanges([range({ introduced: '1.0.0' })]), '>=1.0.0');
    assert.equal(describeRanges([range({ introduced: '0' })]), '*');
    assert.equal(describeRanges([]), 'unknown');
  });

  it('agrees with isAffected when the description is used as an npm range', () => {
    const samples = ['0.1.0', '0.2.3', '0.2.4', '0.9.0', '1.0.0', '1.2.5', '1.2.6', '3.0.0', '5.7.1', '5.7.2', '6.0.0', '6.3.1', '7.5.1'];
    for (const ranges of [MINIMIST, SEMVER_REDOS.slice(0, 2), LODASH['GHSA-29mw-wpgm-hmr9']!]) {
      const described = describeRanges(ranges);
      for (const v of samples) assert.equal(semver.satisfies(v, described), isAffected(v, ranges), `${v} vs ${described}`);
    }
  });
});

describe('isSameLine / isMajorBump (npm caret semantics)', () => {
  it('uses the major for >=1.0.0, the minor for 0.x and the patch for 0.0.x', () => {
    assert.equal(isSameLine('4.17.20', '4.18.1'), true);
    assert.equal(isSameLine('4.17.20', '5.0.0'), false);
    assert.equal(isSameLine('0.3.6', '0.3.17'), true);
    assert.equal(isSameLine('0.3.6', '0.4.0'), false);
    assert.equal(isSameLine('0.2.0', '0.5.0'), false);
    assert.equal(isSameLine('0.0.3', '0.0.4'), false);
    assert.equal(isMajorBump('0.3.6', '4.0.10'), true);
    assert.equal(isMajorBump('1.2.5', '1.2.6'), false);
  });
});

describe('pickFix', () => {
  const none = new Set<string>();

  it('picks the smallest fix in the installed line', () => {
    assert.deepEqual(pickFix(['4.17.21'], '4.17.20', none), { version: '4.17.21', majorBump: false });
    assert.deepEqual(pickFix(['1.2.6', '0.2.4'], '1.2.5', none), { version: '1.2.6', majorBump: false });
    assert.deepEqual(pickFix(['7.5.2', '6.3.1', '5.7.2'], '5.7.1', none), { version: '5.7.2', majorBump: false });
    assert.deepEqual(pickFix(['0.3.7'], '0.3.6', none), { version: '0.3.7', majorBump: false });
  });

  it('falls back to the smallest fix overall with majorBump', () => {
    assert.deepEqual(pickFix(['4.0.10'], '0.3.6', none), { version: '4.0.10', majorBump: true });
    assert.deepEqual(pickFix(['0.5.0'], '0.2.0', none), { version: '0.5.0', majorBump: true }, '0.x minor bumps are breaking');
  });

  it('skips a deprecated fix and replaces it from the available versions (lodash 4.18.0 -> 4.18.1)', () => {
    const available = ['4.17.20', '4.17.21', '4.17.23', '4.18.0', '4.18.1'];
    assert.deepEqual(pickFix(['4.18.0'], '4.17.20', new Set(['4.18.0']), { available }), {
      version: '4.18.1',
      majorBump: false,
      skippedDeprecated: ['4.18.0'],
    });
    assert.equal(pickFix(['4.18.0'], '4.17.20', new Set(['4.18.0'])), null, 'no replacement without the version list');
  });

  it('returns null when no fix is above the installed version', () => {
    assert.equal(pickFix(['1.0.0'], '2.0.0', none), null);
    assert.equal(pickFix([], '2.0.0', none), null);
    assert.equal(pickFix(['1.0.1'], 'not-a-version', none), null);
  });

  it('skips prerelease fixes unless the installed version is a prerelease', () => {
    assert.deepEqual(pickFix(['2.0.0-beta.1', '2.0.1'], '1.0.0', none), { version: '2.0.1', majorBump: true });
    assert.deepEqual(pickFix(['2.0.0-beta.2'], '2.0.0-beta.1', none), { version: '2.0.0-beta.2', majorBump: false });
  });

  it('skips candidates still affected by another range when ranges are given', () => {
    const ranges = [range({ introduced: '0' }, { fixed: '1.0.5' }), range({ introduced: '1.0.5' }, { fixed: '1.1.3' })];
    assert.deepEqual(pickFix(['1.0.5', '1.1.3'], '1.0.0', none), { version: '1.0.5', majorBump: false });
    assert.deepEqual(pickFix(['1.0.5', '1.1.3'], '1.0.0', none, { ranges }), { version: '1.1.3', majorBump: false });
  });
});

describe('pickPackageFix', () => {
  it('lodash: one bump to 4.18.1 closes all five CVEs, skipping deprecated 4.18.0', () => {
    const fix = pickPackageFix(inputs(LODASH), '4.17.20', ['4.17.19', '4.17.20', '4.17.21', '4.17.23', '4.18.0', '4.18.1'], new Set(['4.18.0']));
    assert.ok(fix);
    assert.equal(fix.version, '4.18.1');
    assert.equal(fix.majorBump, false);
    assert.equal(fix.clears.length, 5);
    assert.deepEqual(fix.remaining, []);
    assert.equal(fix.sameLineBest, undefined);
  });

  it('marked: clearing all five needs 4.0.10 (major); best same-line partial fix is 0.3.17', () => {
    const available = ['0.3.6', '0.3.7', '0.3.9', '0.3.17', '0.3.19', '0.4.0', '0.8.2', '1.0.0', '3.0.8', '4.0.0', '4.0.9', '4.0.10', '4.0.12'];
    const fix = pickPackageFix(inputs(MARKED), '0.3.6', available, new Set());
    assert.ok(fix);
    assert.equal(fix.version, '4.0.10');
    assert.equal(fix.majorBump, true);
    assert.deepEqual(fix.remaining, []);
    assert.equal(fix.sameLineBest?.version, '0.3.17');
    assert.deepEqual([...(fix.sameLineBest?.clears ?? [])].sort(), ['GHSA-7px7-7xjx-hxm8', 'GHSA-p9wx-2529-fp83', 'GHSA-x5pg-88wf-qq4p']);
  });

  it('decode-uri-component: 0.2.1 stays in the parent range but only 0.5.0 clears both', () => {
    const fix = pickPackageFix(inputs(DECODE), '0.2.0', ['0.1.0', '0.2.0', '0.2.1', '0.2.2', '0.3.0', '0.4.0', '0.4.1', '0.5.0'], new Set());
    assert.ok(fix);
    assert.equal(fix.version, '0.5.0');
    assert.equal(fix.majorBump, true);
    assert.equal(fix.sameLineBest?.version, '0.2.1');
    assert.deepEqual(fix.sameLineBest?.remaining, ['GHSA-vcc3-ghjq-m6fr']);
  });

  it('without a version list falls back to the fixed versions and reports what remains', () => {
    const fix = pickPackageFix(inputs(LODASH), '4.17.20', [], new Set(['4.18.0']));
    assert.ok(fix);
    assert.equal(fix.version, '4.17.23');
    assert.deepEqual([...fix.remaining].sort(), ['GHSA-f23m-r3pf-42rh', 'GHSA-r5fr-rjxr-66jc']);
  });

  it('returns null when nothing above the installed version clears anything', () => {
    const unfixed = [{ id: 'X', ranges: [range({ introduced: '0' })], fixedVersions: [] }];
    assert.equal(pickPackageFix(unfixed, '1.0.0', ['1.0.0', '1.1.0', '2.0.0'], new Set()), null);
  });
});

describe('specStyle, satisfiesRange, compareVersions', () => {
  it('classifies package.json specs', () => {
    assert.equal(specStyle('^4.17.20'), 'caret');
    assert.equal(specStyle('~1.2.5'), 'tilde');
    assert.equal(specStyle('0.3.6'), 'exact');
    assert.equal(specStyle('=1.2.3'), 'exact');
    for (const other of ['^1.2.3 || ^2', '>=1 <2', '*', 'latest', 'github:user/repo', 'npm:foo@^1.0.0', '1.x', 'file:../x']) {
      assert.equal(specStyle(other), 'other', other);
    }
  });

  it('checks npm ranges', () => {
    assert.equal(satisfiesRange('0.2.1', '^0.2.0'), true);
    assert.equal(satisfiesRange('0.5.0', '^0.2.0'), false);
    assert.equal(satisfiesRange('nope', '^1.0.0'), false);
    assert.equal(satisfiesRange('1.0.0', 'not a range at all'), false);
  });

  it('sorts versions ascending', () => {
    assert.deepEqual(sortVersions(['4.0.10', '0.3.17', '0.3.7', '4.0.9']), ['0.3.7', '0.3.17', '4.0.9', '4.0.10']);
    assert.ok(compareVersions('1.0.0-beta', '1.0.0') < 0);
  });
});
