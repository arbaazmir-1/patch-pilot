// --fresh: forget earlier results, keep backups and the audit log
import { rm, stat } from 'node:fs/promises';
import path from 'node:path';
import { runStatusFile } from './runStatus.ts';
import type { Config } from './types.ts';

export async function clearProjectState(config: Config): Promise<string[]> {
  const p = config.paths;
  const targets = [p.caseFile, p.assessmentFile, p.verdictCacheFile, p.reportMd, p.reportJson, runStatusFile(config), p.tmpDir, p.debugLog];
  const removed: string[] = [];
  for (const target of targets) {
    const exists = await stat(target).then(
      () => true,
      () => false,
    );
    if (!exists) continue;
    await rm(target, { recursive: true, force: true });
    removed.push(path.relative(config.projectRoot, target));
  }
  return removed;
}
