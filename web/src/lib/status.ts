import fs from 'node:fs';
import path from 'node:path';
import { getDb } from './db.ts';
import { candidatePaths } from './discover.ts';
import { statusFileFor } from './paths.ts';

// cli writes this, see src/runStatus.ts
export type RunState = 'running' | 'done' | 'failed' | 'interrupted';

export interface RunPhase {
  title: string;
  state: 'done' | 'current' | 'pending';
}

export interface RunStatus {
  command: string;
  state: RunState;
  phases: RunPhase[];
  activity: string | null;
  detail: string | null;
  startedAt: string;
  updatedAt: string;
  finishedAt: string | null;
  error: string | null;
}

export interface ProjectRunStatus {
  root: string;
  name: string;
  projectId: number | null;
  status: RunStatus;
}

const STATES = new Set<RunState>(['running', 'done', 'failed', 'interrupted']);
const PHASE_STATES = new Set<RunPhase['state']>(['done', 'current', 'pending']);

function str(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

// killed runs never write a final state
function pidAlive(pid: unknown): boolean {
  if (typeof pid !== 'number' || !Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // EPERM: alive, not ours
    return (error as NodeJS.ErrnoException).code === 'EPERM';
  }
}

export function parseRunStatus(raw: unknown): RunStatus | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  if (r.schema !== 'patch-pilot.status') return null;
  let state = STATES.has(r.state as RunState) ? (r.state as RunState) : null;
  const startedAt = str(r.startedAt);
  if (!state || !startedAt) return null;
  if (state === 'running' && !pidAlive(r.pid)) state = 'interrupted';
  const phases = Array.isArray(r.phases)
    ? r.phases.flatMap((p): RunPhase[] => {
        const item = p as Record<string, unknown> | null;
        const title = str(item?.title);
        const phaseState = item?.state as RunPhase['state'];
        return title && PHASE_STATES.has(phaseState) ? [{ title, state: phaseState }] : [];
      })
    : [];
  return {
    command: str(r.command) ?? 'scan',
    state,
    phases,
    activity: str(r.activity),
    detail: str(r.detail),
    startedAt,
    updatedAt: str(r.updatedAt) ?? startedAt,
    finishedAt: str(r.finishedAt),
    error: str(r.error),
  };
}

export function readRunStatus(root: string): RunStatus | null {
  try {
    return parseRunStatus(JSON.parse(fs.readFileSync(statusFileFor(root), 'utf8')));
  } catch {
    return null;
  }
}

export function listRunStatuses(): ProjectRunStatus[] {
  const projects = new Map(
    (getDb().prepare('SELECT id, name, root FROM projects').all() as { id: number; name: string; root: string }[]).map((p) => [p.root, p]),
  );
  const hidden = new Set((getDb().prepare('SELECT root FROM hidden_projects').all() as { root: string }[]).map((r) => r.root));
  const out: ProjectRunStatus[] = [];
  for (const candidate of candidatePaths()) {
    if (hidden.has(candidate.path)) continue;
    const status = readRunStatus(candidate.path);
    if (!status) continue;
    const project = projects.get(candidate.path);
    out.push({ root: candidate.path, name: project?.name ?? path.basename(candidate.path), projectId: project?.id ?? null, status });
  }
  return out;
}
