import fs from 'node:fs';
import path from 'node:path';
import { getDb } from './db.ts';
import { trustStoreFile } from './paths.ts';

export interface Candidate {
  path: string;
  source: 'trusted' | 'watch';
}

export function candidatePaths(): Candidate[] {
  const seen = new Set<string>();
  const out: Candidate[] = [];
  const add = (dir: string, source: Candidate['source']): void => {
    const abs = path.resolve(dir);
    if (seen.has(abs)) return;
    seen.add(abs);
    out.push({ path: abs, source });
  };

  for (const dir of trustedDirectories()) add(dir, 'trusted');

  const rows = getDb().prepare('SELECT path FROM watch_paths ORDER BY added_at').all() as { path: string }[];
  for (const row of rows) add(row.path, 'watch');

  return out;
}

export function trustedDirectories(): string[] {
  try {
    const raw = JSON.parse(fs.readFileSync(trustStoreFile(), 'utf8')) as { directories?: Record<string, { path?: string }> };
    if (!raw || typeof raw !== 'object' || !raw.directories || typeof raw.directories !== 'object') return [];
    const dirs: string[] = [];
    for (const [key, value] of Object.entries(raw.directories)) {
      const dir = typeof value?.path === 'string' ? value.path : key;
      if (dir) dirs.push(dir);
    }
    return dirs;
  } catch {
    return [];
  }
}

export function isDirectory(dir: string): boolean {
  try {
    return fs.statSync(dir).isDirectory();
  } catch {
    return false;
  }
}
