import path from 'node:path';
import type { APIRoute } from 'astro';
import { getDb } from '../../lib/db.ts';

export const POST: APIRoute = async ({ request }) => {
  const form = await request.formData();
  const raw = String(form.get('path') ?? '').trim();
  if (raw) getDb().prepare('DELETE FROM watch_paths WHERE path = ?').run(path.resolve(raw));
  return new Response(null, { status: 303, headers: { Location: `/?flash=watch-removed&path=${encodeURIComponent(raw)}` } });
};
