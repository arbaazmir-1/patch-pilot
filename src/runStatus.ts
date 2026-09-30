// run status file for the dashboard
import { renameSync, unlinkSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import type { Config } from './types.ts';
import type { StatusSnapshot, Ui } from './ui.ts';

export const RUN_STATUS_SCHEMA = 'patch-pilot.status';

export type RunState = 'running' | 'done' | 'failed' | 'interrupted';

export interface RunStatusFile {
  schema: typeof RUN_STATUS_SCHEMA;
  version: 1;
  command: string;
  pid: number;
  state: RunState;
  phases: StatusSnapshot['phases'];
  activity: string | null;
  detail: string | null;
  startedAt: string;
  updatedAt: string;
  finishedAt: string | null;
  error: string | null;
}

export interface RunTracker {
  finish(state: Exclude<RunState, 'running'>, error?: unknown): void;
}

const WRITE_EVERY_MS = 250;

export function runStatusFile(config: Config): string {
  return path.join(config.paths.stateDir, 'status.json');
}

// mirrors the status bar, throttled
export function trackRun(config: Config, ui: Ui, command: string): RunTracker {
  const file = runStatusFile(config);
  const status: RunStatusFile = {
    schema: RUN_STATUS_SCHEMA,
    version: 1,
    command,
    pid: process.pid,
    state: 'running',
    phases: [],
    activity: null,
    detail: null,
    startedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    finishedAt: null,
    error: null,
  };
  let lastWrite = 0;
  let pending: ReturnType<typeof setTimeout> | null = null;
  let finished = false;

  const write = (): void => {
    if (pending) clearTimeout(pending);
    pending = null;
    lastWrite = Date.now();
    status.updatedAt = new Date(lastWrite).toISOString();
    writeQuietly(file, status);
  };
  const schedule = (): void => {
    if (pending) return;
    const wait = WRITE_EVERY_MS - (Date.now() - lastWrite);
    if (wait <= 0) return write();
    pending = setTimeout(write, wait);
    pending.unref?.();
  };

  const unsubscribe = ui.status.onChange((snapshot) => {
    if (finished) return;
    if (snapshot.phases.length > 0) status.phases = snapshot.phases;
    status.activity = snapshot.activity ?? null;
    status.detail = snapshot.detail ?? null;
    schedule();
  });

  // ctrl+c or hard exit
  const onExit = (): void => finish('interrupted');
  process.once('exit', onExit);

  function finish(state: Exclude<RunState, 'running'>, error?: unknown): void {
    if (finished) return;
    finished = true;
    unsubscribe();
    process.removeListener('exit', onExit);
    status.state = state;
    status.finishedAt = new Date().toISOString();
    if (state === 'done') status.phases = status.phases.map((item) => ({ ...item, state: 'done' }));
    if (error !== undefined) status.error = error instanceof Error ? error.message : String(error);
    status.activity = null;
    status.detail = null;
    write();
  }

  write();
  return { finish };
}

// sync for exit handlers, never throws
function writeQuietly(file: string, value: RunStatusFile): void {
  const tmp = `${file}.${process.pid}.tmp`;
  try {
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`);
    renameSync(tmp, file);
  } catch {
    try {
      unlinkSync(tmp);
    } catch {
      // nothing to clean
    }
  }
}
