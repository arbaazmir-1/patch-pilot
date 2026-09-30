// .patch-pilot/audit.jsonl, one event per line
import { randomBytes } from 'node:crypto';
import { appendFileSync, mkdirSync, readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { AuditEvent, AuditEventName, AuditRecord, AuditSink, Identity } from './types.ts';
import { gitConfig } from './util/proc.ts';

// pipeline order
export const AUDIT_EVENTS: readonly AuditEventName[] = [
  'preflight',
  'trust.granted',
  'scan.start',
  'discover.lockfile',
  'deps.parsed',
  'osv.query',
  'casefile.saved',
  'investigate.start',
  'tool.call',
  'tool.result',
  'gate.evidence',
  'verdict',
  'verdict.adjusted',
  'verdict.cached',
  'approval',
  'risk.accepted',
  'patch.backup',
  'patch.apply',
  'lockfile.diff',
  'migration.search',
  'migration.brief',
  'codemod.proposed',
  'codemod.applied',
  'verify.result',
  'rollback',
  'report.written',
  'provider.selected',
  'delegated.run',
  'error',
];

// promptTokens must not match
const SECRET_KEY = /(api[-_]?key|token|authorization|password|secret)$/i;

export function redactSecrets(value: unknown, depth = 0): unknown {
  if (depth > 12) return '[depth limit]';
  if (Array.isArray(value)) return value.map((v) => redactSecrets(v, depth + 1));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, v] of Object.entries(value as Record<string, unknown>)) {
      if (SECRET_KEY.test(key) && v !== null && v !== undefined && v !== false && v !== '') out[key] = '[redacted]';
      else out[key] = redactSecrets(v, depth + 1);
    }
    return out;
  }
  return value;
}

export function newRunId(now: Date = new Date()): string {
  return `${now.toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z')}-${randomBytes(3).toString('hex')}`;
}

export interface AuditLogOptions {
  runId?: string;
  now?: () => Date;
}

// append-only
export class AuditLog implements AuditSink {
  readonly file: string;
  readonly runId: string;
  private readonly now: () => Date;

  constructor(file: string, options: AuditLogOptions = {}) {
    this.file = file;
    this.now = options.now ?? (() => new Date());
    this.runId = options.runId ?? newRunId(this.now());
    mkdirSync(path.dirname(file), { recursive: true });
  }

  // creates the dir
  static open(file: string, options: AuditLogOptions = {}): AuditLog {
    return new AuditLog(file, options);
  }

  log(event: AuditEvent): AuditRecord {
    const record = { ts: this.now().toISOString(), run: this.runId, ...(redactSecrets(event) as AuditEvent) } as AuditRecord;
    let line: string;
    try {
      line = JSON.stringify(record);
    } catch (err) {
      line = JSON.stringify({
        ts: record.ts,
        run: this.runId,
        event: 'error',
        message: `Could not serialise audit event ${event.event}: ${(err as Error).message}`,
      });
    }
    appendFileSync(this.file, `${line}\n`, 'utf8');
    return record;
  }

  // across all runs
  read(): AuditRecord[] {
    return readAuditFile(this.file);
  }
}

// skips bad lines, missing file is []
export function readAuditFile(file: string): AuditRecord[] {
  let text: string;
  try {
    text = readFileSync(file, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw err;
  }
  const out: AuditRecord[] = [];
  for (const line of text.split('\n')) {
    if (line.trim() === '') continue;
    try {
      const parsed = JSON.parse(line) as AuditRecord;
      if (parsed && typeof parsed.event === 'string') out.push(parsed);
    } catch {
      // torn or edited line
    }
  }
  return out;
}

// tests
export class MemoryAudit implements AuditSink {
  readonly records: AuditRecord[] = [];
  readonly runId = 'memory';
  log(event: AuditEvent): AuditRecord {
    const record = { ts: new Date().toISOString(), run: this.runId, ...(redactSecrets(event) as AuditEvent) } as AuditRecord;
    this.records.push(record);
    return record;
  }
  events<N extends AuditEventName>(name: N): Extract<AuditRecord, { event: N }>[] {
    return this.records.filter((r): r is Extract<AuditRecord, { event: N }> => r.event === name);
  }
}

// before the trust gate
export const nullAudit: AuditSink = { log() {} };

function osUserName(): string {
  try {
    return os.userInfo().username;
  } catch {
    return process.env.USER ?? process.env.USERNAME ?? 'unknown';
  }
}

// null when unset
export async function captureIdentity(cwd: string): Promise<Identity> {
  const [gitName, gitEmail] = await Promise.all([gitConfig('user.name', cwd), gitConfig('user.email', cwd)]);
  return { osUser: osUserName(), gitName, gitEmail };
}

// OS user when git identity is unknown
export function formatIdentity(identity: Identity): string {
  if (identity.gitName && identity.gitEmail) return `${identity.gitName} <${identity.gitEmail}>`;
  if (identity.gitName) return identity.gitName;
  if (identity.gitEmail) return identity.gitEmail;
  return identity.osUser;
}
