import assert from 'node:assert/strict';
import { appendFile, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { AUDIT_EVENTS, AuditLog, captureIdentity, formatIdentity, MemoryAudit, readAuditFile, redactSecrets } from '../../src/audit.ts';

let tmp: string;
before(async () => {
  tmp = await mkdtemp(path.join(os.tmpdir(), 'pp-audit-'));
});
after(async () => {
  await rm(tmp, { recursive: true, force: true });
});

describe('audit log', () => {
  it('appends JSONL records with ts, run id and the event payload', async () => {
    const file = path.join(tmp, '.patch-pilot', 'audit.jsonl');
    const log = AuditLog.open(file, { runId: 'run-1', now: () => new Date('2026-09-24T10:00:00.000Z') });
    log.log({ event: 'report.written', md: 'a.md', json: 'a.json' });
    log.log({ event: 'error', message: 'boom', exitCode: 3 });
    await appendFile(file, 'not json\n');
    const records = readAuditFile(file);
    assert.equal(records.length, 2);
    assert.deepEqual(records[0], { ts: '2026-09-24T10:00:00.000Z', run: 'run-1', event: 'report.written', md: 'a.md', json: 'a.json' });
    assert.equal(records[1]?.event, 'error');
    assert.deepEqual(readAuditFile(path.join(tmp, 'none.jsonl')), []);
  });

  it('masks credentials but keeps token counts', () => {
    const out = redactSecrets({ options: { ollamaApiKey: 'sk-1', githubToken: 'ghp', promptTokens: 12, authorization: 'Bearer x', nested: [{ secret: 's' }] } }) as {
      options: Record<string, unknown>;
    };
    assert.equal(out.options.ollamaApiKey, '[redacted]');
    assert.equal(out.options.githubToken, '[redacted]');
    assert.equal(out.options.authorization, '[redacted]');
    assert.equal(out.options.promptTokens, 12);
    assert.deepEqual(out.options.nested, [{ secret: '[redacted]' }]);
  });

  it('lists every event name from the plan once', () => {
    assert.equal(AUDIT_EVENTS.length, 29);
    assert.equal(new Set(AUDIT_EVENTS).size, AUDIT_EVENTS.length);
    for (const name of ['preflight', 'trust.granted', 'approval', 'lockfile.diff', 'migration.search', 'verify.result', 'rollback']) {
      assert.ok(AUDIT_EVENTS.includes(name as (typeof AUDIT_EVENTS)[number]), name);
    }
  });

  it('keeps events in memory for tests', () => {
    const mem = new MemoryAudit();
    mem.log({ event: 'verdict.cached', vulnId: 'GHSA-1', package: 'a', risk: 'Low', key: 'k' });
    mem.log({ event: 'error', message: 'x' });
    assert.equal(mem.events('verdict.cached').length, 1);
    assert.equal(mem.events('verdict.cached')[0]?.risk, 'Low');
  });

  it('captures and formats identity', async () => {
    const id = await captureIdentity(tmp);
    assert.ok(id.osUser.length > 0);
    assert.equal(formatIdentity({ osUser: 'u', gitName: 'Ada', gitEmail: 'ada@example.com' }), 'Ada <ada@example.com>');
    assert.equal(formatIdentity({ osUser: 'u', gitName: null, gitEmail: null }), 'u');
  });
});
