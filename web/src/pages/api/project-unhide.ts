import type { APIRoute } from 'astro';
import { syncReports } from '../../lib/sync.ts';
import { unhideProject } from '../../lib/queries.ts';

export const POST: APIRoute = async ({ request }) => {
  const form = await request.formData();
  const root = String(form.get('root') ?? '').trim();
  if (root) unhideProject(root);
  syncReports();
  return new Response(null, { status: 303, headers: { Location: `/?flash=unhidden&path=${encodeURIComponent(root)}` } });
};
