import type { APIRoute } from 'astro';
import { deleteProject, getProject, hideProject } from '../../lib/queries.ts';

export const POST: APIRoute = async ({ request }) => {
  const form = await request.formData();
  const id = Number(form.get('id'));
  const project = Number.isInteger(id) ? getProject(id) : null;
  if (project) {
    // hide or the next sync re-imports it
    hideProject(project.root);
    deleteProject(project.id);
  }
  return new Response(null, { status: 303, headers: { Location: `/?flash=removed&name=${encodeURIComponent(project?.name ?? 'project')}` } });
};
