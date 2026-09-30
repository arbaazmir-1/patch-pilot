import { cp, mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import type { AbbreviatedPackument, OsvRecord } from '../../src/types.ts';
import { Ui } from '../../src/ui.ts';

export const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url));
export const FIXTURE_APP = path.join(REPO_ROOT, 'examples', 'vulnerable-app');

export interface FixtureData {
  querybatch: Record<string, { id: string; modified: string }[]>;
  records: OsvRecord[];
  packuments: Record<string, AbbreviatedPackument>;
}

let cached: FixtureData | null = null;

// real responses for examples/vulnerable-app
export async function fixtureData(): Promise<FixtureData> {
  if (!cached) cached = JSON.parse(await readFile(new URL('./fixtures/fixture-data.json', import.meta.url), 'utf8')) as FixtureData;
  return cached;
}

export function recordById(data: FixtureData, id: string): OsvRecord {
  const record = data.records.find((r) => r.id === id);
  if (!record) throw new Error(`no fixture record ${id}`);
  return structuredClone(record);
}

export interface FetchCall {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | null;
}

export type FetchHandler = (call: FetchCall) => Response | Promise<Response>;

// records every call
export function stubFetch(handler: FetchHandler): { calls: FetchCall[]; restore: () => void } {
  const original = globalThis.fetch;
  const calls: FetchCall[] = [];
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const headers: Record<string, string> = {};
    const raw = init?.headers;
    if (raw instanceof Headers) raw.forEach((v, k) => (headers[k.toLowerCase()] = v));
    else if (Array.isArray(raw)) for (const [k, v] of raw) headers[String(k).toLowerCase()] = String(v);
    else if (raw) for (const [k, v] of Object.entries(raw)) headers[k.toLowerCase()] = String(v);
    const call: FetchCall = { url, method: init?.method ?? 'GET', headers, body: typeof init?.body === 'string' ? init.body : null };
    calls.push(call);
    return handler(call);
  }) as typeof fetch;
  return { calls, restore: () => void (globalThis.fetch = original) };
}

export function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
}

// undici's refused error
export function refused(): never {
  const err = new TypeError('fetch failed');
  (err as TypeError & { cause?: unknown }).cause = { code: 'ECONNREFUSED', message: 'connect ECONNREFUSED' };
  throw err;
}

export function fixtureServer(data: FixtureData, options: { osvDown?: boolean; registryDown?: boolean } = {}): FetchHandler {
  return (call) => {
    if (call.url.startsWith('https://api.osv.dev/')) {
      if (options.osvDown) refused();
      if (call.url === 'https://api.osv.dev/v1/querybatch') {
        const body = JSON.parse(call.body ?? '{}') as { queries: { package: { name: string }; version: string }[] };
        return jsonResponse({
          results: body.queries.map((q) => {
            const vulns = data.querybatch[`${q.package.name}@${q.version}`] ?? [];
            return vulns.length > 0 ? { vulns } : {};
          }),
        });
      }
      const m = /^https:\/\/api\.osv\.dev\/v1\/vulns\/(.+)$/.exec(call.url);
      if (m) {
        const record = data.records.find((r) => r.id === decodeURIComponent(m[1] as string));
        return record ? jsonResponse(record) : jsonResponse({ code: 5, message: 'Bug not found.' }, 404);
      }
    }
    if (call.url.startsWith('https://registry.npmjs.org/')) {
      if (options.registryDown) refused();
      const name = decodeURIComponent(call.url.slice('https://registry.npmjs.org/'.length));
      const packument = data.packuments[name];
      return packument ? jsonResponse(packument) : jsonResponse({ error: 'Not found' }, 404);
    }
    return jsonResponse({ error: `unexpected URL ${call.url}` }, 500);
  };
}

// no colours, not interactive
export function captureUi(): { ui: Ui; out: () => string; err: () => string } {
  let out = '';
  let err = '';
  const stdout = new Writable({
    write(chunk, _enc, cb) {
      out += String(chunk);
      cb();
    },
  });
  const stderr = new Writable({
    write(chunk, _enc, cb) {
      err += String(chunk);
      cb();
    },
  });
  const ui = new Ui({ stdout, stderr, color: false, unicode: true, interactive: false, env: {} });
  return { ui, out: () => out, err: () => err };
}

export async function tempDir(prefix = 'pp-phase1-'): Promise<{ dir: string; cleanup: () => Promise<void> }> {
  const dir = await mkdtemp(path.join(os.tmpdir(), prefix));
  return { dir, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

// fresh temp copy
export async function copyFixtureApp(): Promise<{ dir: string; cleanup: () => Promise<void> }> {
  const tmp = await tempDir('pp-app-');
  const dir = path.join(tmp.dir, 'vulnerable-app');
  await cp(FIXTURE_APP, dir, { recursive: true, filter: (src) => !src.split(path.sep).includes('.patch-pilot') && !src.split(path.sep).includes('node_modules') });
  return { dir, cleanup: tmp.cleanup };
}
