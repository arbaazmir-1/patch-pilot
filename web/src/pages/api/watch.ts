import path from 'node:path';
import type { APIRoute } from 'astro';
import { getDb } from '../../lib/db.ts';
import { isDirectory } from '../../lib/discover.ts';
import { syncReports } from '../../lib/sync.ts';

export const POST: APIRoute = async ({ request }) => {
  const form = await request.formData();
  const raw = String(form.get('path') ?? '').trim();
  const location = (msg: string): string => `/?flash=watch-error&path=${encodeURIComponent(raw)}&reason=${encodeURIComponent(msg)}`;

  if (!raw) return new Response(null, { status: 303, headers: { Location: location('no path given') } });
  if (!path.isAbsolute(raw)) return new Response(null, { status: 303, headers: { Location: location('the path must be absolute') } });
  if (!isDirectory(raw)) return new Response(null, { status: 303, headers: { Location: location('directory does not exist') } });

  getDb()
    .prepare('INSERT INTO watch_paths (path, added_at) VALUES (?, ?) ON CONFLICT(path) DO NOTHING')
    .run(path.resolve(raw), new Date().toISOString());
  syncReports();
  return new Response(null, { status: 303, headers: { Location: `/?flash=added&path=${encodeURIComponent(raw)}` } });
};
