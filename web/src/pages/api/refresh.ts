import type { APIRoute } from 'astro';
import { syncReports } from '../../lib/sync.ts';

export const POST: APIRoute = async () => {
  const outcome = syncReports();
  const location = `/?flash=sync&updated=${outcome.updated}&unchanged=${outcome.unchanged}&missing=${outcome.missing}&errors=${outcome.errors.length}`;
  return new Response(null, { status: 303, headers: { Location: location } });
};
