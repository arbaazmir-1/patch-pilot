// phase 3 test doubles
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { loadConfig, type CliFlags } from '../../src/config.ts';
import type { Assessment, CaseFile, Config, Identity } from '../../src/types.ts';
import { Ui } from '../../src/ui.ts';

const FIXTURES = fileURLToPath(new URL('./patch-fixtures/', import.meta.url));

export const IDENTITY: Identity = { osUser: 'tester', gitName: 'Test User', gitEmail: 'test@example.com' };

export async function loadFixtures(): Promise<{ caseFile: CaseFile; assessment: Assessment }> {
  const caseFile = JSON.parse(await readFile(path.join(FIXTURES, 'case-file.json'), 'utf8')) as CaseFile;
  const assessment = JSON.parse(await readFile(path.join(FIXTURES, 'assessment.json'), 'utf8')) as Assessment;
  return { caseFile, assessment };
}

export function captureUi(options: ConstructorParameters<typeof Ui>[0] = {}): { ui: Ui; out: () => string; err: () => string; all: () => string } {
  let out = '';
  let err = '';
  let all = '';
  const stream = (write: (s: string) => void): Writable =>
    new Writable({
      write(chunk, _enc, cb) {
        write(String(chunk));
        cb();
      },
    });
  const ui = new Ui({
    color: false,
    env: {},
    width: 100,
    stdout: stream((s) => {
      out += s;
      all += s;
    }) as never,
    stderr: stream((s) => {
      err += s;
      all += s;
    }) as never,
    ...options,
  });
  return { ui, out: () => out, err: () => err, all: () => all };
}

// tty makes it interactive
export async function projectConfig(dir: string, home: string, flags: CliFlags = {}, tty = false): Promise<Config> {
  return loadConfig({ dir, homeDir: home, env: {}, flags: { provider: 'mock', offline: true, ...flags }, stdinIsTTY: tty, stdoutIsTTY: tty });
}
