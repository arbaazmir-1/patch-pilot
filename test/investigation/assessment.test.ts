import assert from 'node:assert/strict';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import {
  ASSESSMENT_VERSION,
  caseFileHash,
  createAssessment,
  findVerdict,
  loadAssessment,
  saveAssessment,
  upsertDossier,
  upsertVerdict,
} from '../../src/investigation/assessment.ts';
import type { Verdict } from '../../src/types.ts';
import { PatchPilotError } from '../../src/util/errors.ts';
import { hashJson } from '../../src/util/fs.ts';
import { caseFileOf, dossierFor, lodashFixture, tempDir } from './helpers.ts';

const META = { provider: 'mock' as const, model: 'mock', promptVersion: 'p1' };

function verdict(vulnId: string, risk: Verdict['risk']): Verdict {
  return {
    vulnId,
    package: 'lodash',
    installedVersion: '4.17.20',
    risk,
    reachable: 'no',
    confidence: 0.8,
    reasoning: 'r',
    evidence: [],
    recommendation: { action: 'upgrade', targetVersion: '4.17.21', majorBump: false },
    investigation: { provider: 'mock', model: 'mock', promptVersion: 'p1', steps: 1, toolCalls: [], durationMs: 1, forced: false },
  };
}

describe('assessment', () => {
  let tmp: Awaited<ReturnType<typeof tempDir>>;
  before(async () => {
    tmp = await tempDir('pp-assessment-');
  });
  after(async () => {
    await tmp.cleanup();
  });

  const { pkg, template, merge } = lodashFixture();
  const caseFile = caseFileOf([pkg], [template, merge]);

  it('hashes the case file with the stable JSON hash and starts incomplete', () => {
    const a = createAssessment(caseFile, META);
    assert.equal(a.caseFileHash, hashJson(caseFile));
    assert.equal(a.caseFileHash, caseFileHash(structuredClone(caseFile)));
    assert.equal(a.version, ASSESSMENT_VERSION);
    assert.equal(a.complete, false);
    assert.deepEqual([a.provider, a.model, a.promptVersion], ['mock', 'mock', 'p1']);
    assert.deepEqual([a.verdicts, a.dossiers], [[], []]);
  });

  it('upserts verdicts by (vulnId, package, installedVersion) and dossiers by (package, version)', () => {
    let a = createAssessment(caseFile, META);
    a = upsertVerdict(a, verdict(template.id, 'High'));
    a = upsertVerdict(a, verdict(merge.id, 'Low'));
    const replaced = upsertVerdict(a, verdict(template.id, 'Noise'));
    assert.equal(replaced.verdicts.length, 2);
    assert.equal(findVerdict(replaced, template.id, 'lodash', '4.17.20')?.risk, 'Noise');
    assert.equal(findVerdict(a, template.id, 'lodash', '4.17.20')?.risk, 'High', 'the input assessment is not mutated');
    let d = upsertDossier(a, dossierFor(pkg, { fixCost: 'one' }));
    d = upsertDossier(d, dossierFor(pkg, { fixCost: 'two' }));
    assert.equal(d.dossiers.length, 1);
    assert.equal(d.dossiers[0]?.fixCost, 'two');
  });

  it('saves atomically and loads it back; a missing file is null', async () => {
    const file = path.join(tmp.dir, '.patch-pilot', 'assessment.json');
    assert.equal(await loadAssessment(file), null);
    const a = upsertVerdict(createAssessment(caseFile, META), verdict(template.id, 'High'));
    await saveAssessment(file, a);
    assert.deepEqual(await loadAssessment(file), a);
    const leftovers = (await readdir(path.dirname(file))).filter((f) => f.endsWith('.tmp'));
    assert.deepEqual(leftovers, []);
    assert.ok((await readFile(file, 'utf8')).endsWith('\n'));
  });

  it('refuses another schema version and damaged files', async () => {
    const file = path.join(tmp.dir, 'old.json');
    await writeFile(file, JSON.stringify({ ...createAssessment(caseFile, META), version: 99 }));
    await assert.rejects(loadAssessment(file), (e: unknown) => e instanceof PatchPilotError && /version 99/.test(e.message) && e.exitCode === 2);
    await writeFile(file, '{"hello": 1}');
    await assert.rejects(loadAssessment(file), /not a PatchPilot assessment/);
    await writeFile(file, '{broken');
    await assert.rejects(loadAssessment(file), /Cannot read/);
  });
});
