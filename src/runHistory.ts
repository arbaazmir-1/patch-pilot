// run history: each scan archives the previous run before overwriting it
import { copyFile, mkdir, readFile, rm, stat } from 'node:fs/promises';
import path from 'node:path';
import { runStatusFile } from './runStatus.ts';
import type { Config } from './types.ts';

export const HISTORY_DIR = 'history';

export interface ArchivedRun {
  // .patch-pilot/history/<id>
  dir: string;
  files: string[];
}

async function exists(file: string): Promise<boolean> {
  return stat(file).then(
    () => true,
    () => false,
  );
}

// when the archived run happened: report time, then assessment, then file time
async function runTime(config: Config): Promise<Date> {
  const p = config.paths;
  for (const [file, key] of [
    [p.reportJson, 'generatedAt'],
    [p.assessmentFile, 'updatedAt'],
  ] as const) {
    try {
      const value = (JSON.parse(await readFile(file, 'utf8')) as Record<string, unknown>)[key];
      const date = typeof value === 'string' ? new Date(value) : null;
      if (date && !Number.isNaN(date.getTime())) return date;
    } catch {
      // missing or damaged
    }
  }
  for (const file of [p.reportJson, p.assessmentFile, p.caseFile]) {
    const info = await stat(file).catch(() => null);
    if (info) return info.mtime;
  }
  return new Date();
}

// "2026-10-01T10-22-33Z", safe as a folder name and sorts by time
export function runId(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z').replace(/:/g, '-');
}

// copy the last run into history/, null when there is nothing to keep
export async function archiveLastRun(config: Config, options: { withCache?: boolean } = {}): Promise<ArchivedRun | null> {
  const p = config.paths;
  const sources = [p.caseFile, p.assessmentFile, p.reportMd, p.reportJson, ...(options.withCache ? [p.verdictCacheFile] : [])];
  const present: string[] = [];
  for (const file of sources) if (await exists(file)) present.push(file);
  if (!present.some((file) => file === p.assessmentFile || file === p.reportJson)) return null;
  const dir = path.join(p.stateDir, HISTORY_DIR, runId(await runTime(config)));
  // already archived, e.g. the last scan stopped before writing new results
  if (await exists(dir)) return null;
  await mkdir(dir, { recursive: true });
  for (const file of present) await copyFile(file, path.join(dir, path.basename(file)));
  return { dir: path.relative(config.projectRoot, dir), files: present.map((file) => path.basename(file)) };
}

// --fresh: after archiving, drop the current results and the verdict cache
export async function clearProjectState(config: Config): Promise<string[]> {
  const p = config.paths;
  const targets = [p.caseFile, p.assessmentFile, p.verdictCacheFile, p.reportMd, p.reportJson, runStatusFile(config), p.tmpDir, p.debugLog];
  const removed: string[] = [];
  for (const target of targets) {
    if (!(await exists(target))) continue;
    await rm(target, { recursive: true, force: true });
    removed.push(path.relative(config.projectRoot, target));
  }
  return removed;
}
