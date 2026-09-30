import type { APIRoute } from 'astro';
import { listRunStatuses } from '../../lib/status.ts';

export const GET: APIRoute = () =>
  new Response(JSON.stringify({ runs: listRunStatuses() }), {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
