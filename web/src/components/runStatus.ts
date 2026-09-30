// shared by server render and the status poller
import type { RunStatus } from '../lib/status.ts';

export const PHASE_TITLES = ['Take in evidence', 'Investigate and decide', 'Act safely'];
export const PHASE_COLORS = ['#2f9e6f', '#8b6cf0', '#d0513a'];

// calm dot spinner, same frames as the cli
export const SPINNER_FRAMES = ['·  ', '·· ', '···', ' ··', '  ·', '   '];
export const SPINNER_MS = 110;

export function esc(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

export function ago(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return '';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '';
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 45) return 'just now';
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

function elapsed(fromIso: string, now: number): string {
  const s = Math.max(0, Math.round((now - new Date(fromIso).getTime()) / 1000));
  if (Number.isNaN(s)) return '';
  const m = Math.floor(s / 60);
  return `${m}:${String(s % 60).padStart(2, '0')}`;
}

export function phaseColor(title: string, index: number): string {
  const known = PHASE_TITLES.findIndex((t) => t.toLowerCase() === title.toLowerCase());
  return PHASE_COLORS[known >= 0 ? known : index % PHASE_COLORS.length] ?? PHASE_COLORS[1]!;
}

export function currentPhase(status: RunStatus): { n: number; total: number; title: string; color: string } | null {
  const i = status.phases.findIndex((p) => p.state === 'current');
  if (i < 0) return null;
  const title = status.phases[i]!.title;
  return { n: i + 1, total: status.phases.length, title, color: phaseColor(title, i) };
}

// one line: "··· phase 2/3 · Investigating lodash · CVE 3 of 12"
export function statusLineHtml(status: RunStatus, now = Date.now()): string {
  const cmd = esc(status.command);
  if (status.state === 'running') {
    const phase = currentPhase(status);
    const color = phase?.color ?? '#b48cff';
    const main = status.activity ?? phase?.title ?? `${status.command} running`;
    const parts = [
      `<span class="run-glyph" style="color:${color}">${SPINNER_FRAMES[2]}</span>`,
      phase ? `<span class="run-phase" style="color:${color}">phase ${phase.n}/${phase.total}</span>` : `<span class="run-phase">${cmd}</span>`,
      `<span class="run-main">${esc(main)}</span>`,
    ];
    if (status.detail) parts.push(`<span class="run-detail">${esc(status.detail)}</span>`);
    parts.push(`<span class="run-time">${elapsed(status.startedAt, now)}</span>`);
    return parts.join('<span class="sep"> · </span>');
  }
  const when = ago(status.finishedAt ?? status.updatedAt, now);
  if (status.state === 'done') {
    return `<span class="run-glyph ok">✓</span> <span class="run-main">${cmd} done</span>${when ? `<span class="sep"> · </span><span class="run-time">${when}</span>` : ''}`;
  }
  if (status.state === 'failed') {
    const err = status.error ? `<span class="sep"> · </span><span class="run-detail">${esc(status.error)}</span>` : '';
    return `<span class="run-glyph fail">✗</span> <span class="run-main">${cmd} failed</span>${err}${when ? `<span class="sep"> · </span><span class="run-time">${when}</span>` : ''}`;
  }
  return `<span class="run-glyph warn">!</span> <span class="run-main">${cmd} interrupted</span>${when ? `<span class="sep"> · </span><span class="run-time">${when}</span>` : ''}`;
}

// "⬢ Working on 3 phases" then ☒ ▣ ☐ rows, like ui.formatChecklist
export function checklistHtml(status: RunStatus, now = Date.now()): string {
  const count = status.phases.length;
  const head =
    status.state === 'running'
      ? `<b>Working</b> on ${count} phase${count === 1 ? '' : 's'}`
      : status.state === 'done'
        ? `<b>Finished</b> ${esc(status.command)}`
        : status.state === 'failed'
          ? `<b class="fail">Failed</b> ${esc(status.command)}`
          : `<b class="warn">Interrupted</b> ${esc(status.command)}`;
  const lines = [`<div class="cl-head"><span class="hex">⬢</span> ${head}<span class="cl-time">${status.state === 'running' ? elapsed(status.startedAt, now) : ago(status.finishedAt ?? status.updatedAt, now)}</span></div>`];
  status.phases.forEach((p, i) => {
    const color = phaseColor(p.title, i);
    const glyph = p.state === 'done' ? '☒' : p.state === 'current' ? '▣' : '☐';
    lines.push(
      `<div class="cl-item cl-${p.state}"><span class="cl-glyph" style="color:${p.state === 'pending' ? 'inherit' : color}">${glyph}</span> ${esc(p.title)}</div>`,
    );
  });
  if (status.state === 'running' && (status.activity || status.detail)) {
    lines.push(
      `<div class="cl-activity"><span class="hex">⬢</span> <b>${esc(status.activity ?? '')}</b>${status.detail ? `<span class="sep"> · </span><span class="run-detail">${esc(status.detail)}</span>` : ''}</div>`,
    );
  }
  if (status.state === 'failed' && status.error) lines.push(`<div class="cl-error">${esc(status.error)}</div>`);
  return lines.join('');
}
