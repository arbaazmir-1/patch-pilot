import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Writable } from 'node:stream';
import { after, before, describe, it } from 'node:test';
import {
  checkTrust,
  ensureTrusted,
  loadTrustStore,
  sanitizeRemote,
  shellQuote,
  trustDirectory,
  trustPromptText,
  trustStorePath,
  untrustDirectory,
} from '../../src/trust.ts';
import { Ui } from '../../src/ui.ts';
import { EXIT, PatchPilotError } from '../../src/util/errors.ts';
import { run, which } from '../../src/util/proc.ts';

let tmp: string;
let home: string;
let output = '';
const sink = new Writable({
  write(chunk, _enc, cb) {
    output += String(chunk);
    cb();
  },
});
const ui = new Ui({ color: false, stdout: sink as never, stderr: sink as never });

async function newDir(name: string): Promise<string> {
  const dir = path.join(tmp, name);
  await mkdir(dir, { recursive: true });
  return dir;
}

before(async () => {
  tmp = await mkdtemp(path.join(os.tmpdir(), 'pp-trust-'));
  home = path.join(tmp, 'home');
  await mkdir(home);
});
after(async () => {
  await rm(tmp, { recursive: true, force: true });
});

const gate = { interactive: false, trustFlag: false, ollamaHost: 'http://localhost:11434', provider: 'ollama' as const };

describe('trust store (~/.patch-pilot/trusted.json)', () => {
  it('starts untrusted, trusts, and untrusts a directory keyed by its absolute path', async () => {
    const dir = await newDir('project-a');
    assert.equal((await checkTrust(dir, { homeDir: home, remote: null })).trusted, false);
    const entry = await trustDirectory(dir, { homeDir: home, remote: null, by: 'Tester <t@example.com>', method: 'command' });
    assert.equal(entry.remote, null);
    assert.equal(entry.method, 'command');
    const status = await checkTrust(dir, { homeDir: home, remote: null });
    assert.equal(status.trusted, true);
    const raw = JSON.parse(await readFile(trustStorePath(home), 'utf8'));
    assert.equal(raw.version, 1);
    assert.ok(raw.directories[status.dir], 'keyed by the canonical path');
    assert.equal(raw.directories[status.dir].by, 'Tester <t@example.com>');
    assert.equal(await untrustDirectory(dir, { homeDir: home }), true);
    assert.equal(await untrustDirectory(dir, { homeDir: home }), false);
    assert.equal((await checkTrust(dir, { homeDir: home, remote: null })).trusted, false);
  });

  it('asks again when the git remote changed since trust was granted', async () => {
    const dir = await newDir('project-remote');
    await trustDirectory(dir, { homeDir: home, remote: 'git@github.com:me/app.git' });
    assert.equal((await checkTrust(dir, { homeDir: home, remote: 'git@github.com:me/app.git' })).trusted, true);
    const moved = await checkTrust(dir, { homeDir: home, remote: 'git@github.com:someone-else/app.git' });
    assert.equal(moved.trusted, false);
    assert.equal(moved.reason, 'remote-changed');
    assert.equal((await checkTrust(dir, { homeDir: home, remote: null })).trusted, false);
  });

  it('resolves symlinks so a link and its target share one entry', async () => {
    const real = await newDir('project-real');
    const link = path.join(tmp, 'project-link');
    await symlink(real, link);
    await trustDirectory(link, { homeDir: home, remote: null });
    assert.equal((await checkTrust(real, { homeDir: home, remote: null })).trusted, true);
  });

  it('treats a corrupted store as empty instead of failing', async () => {
    const otherHome = await newDir('home-corrupt');
    await mkdir(path.join(otherHome, '.patch-pilot'), { recursive: true });
    await writeFile(trustStorePath(otherHome), '{ not json');
    assert.deepEqual(await loadTrustStore(otherHome), { version: 1, directories: {} });
    const dir = await newDir('project-corrupt');
    await trustDirectory(dir, { homeDir: otherHome, remote: null });
    assert.equal((await checkTrust(dir, { homeDir: otherHome, remote: null })).trusted, true);
  });

  it('records the real git remote without credentials', async (t) => {
    if (!(await which('git'))) {
      t.skip('git not installed');
      return;
    }
    const dir = await newDir('project-git');
    await run('git', ['init', '-q'], { cwd: dir });
    await run('git', ['remote', 'add', 'origin', 'https://user:secret@github.com/me/app.git'], { cwd: dir });
    const entry = await trustDirectory(dir, { homeDir: home });
    assert.equal(entry.remote, 'https://github.com/me/app.git');
  });

  it('sanitizes remotes and quotes paths for commands', () => {
    assert.equal(sanitizeRemote('https://user:tok@host.example/x.git'), 'https://host.example/x.git');
    assert.equal(sanitizeRemote('git@github.com:me/app.git'), 'git@github.com:me/app.git');
    assert.equal(sanitizeRemote(null), null);
    assert.equal(shellQuote('/Users/me/app'), '/Users/me/app');
    assert.equal(shellQuote('/Users/me/my app'), "'/Users/me/my app'");
    assert.equal(shellQuote("it's"), "'it'\\''s'");
  });
});

describe('ensureTrusted (the gate)', () => {
  it('without a TTY and without --trust exits 2 with a one-line instruction', async () => {
    const dir = await newDir('gate-noninteractive');
    await assert.rejects(ensureTrusted(dir, ui, { ...gate, homeDir: home, remote: null }), (err: unknown) => {
      assert.ok(err instanceof PatchPilotError);
      assert.equal(err.exitCode, EXIT.USAGE);
      assert.match(err.message, /Directory not trusted/);
      assert.match(err.hint ?? '', /patch-pilot trust .* once, or pass --trust/);
      return true;
    });
  });

  it('--trust pre-accepts and stores the decision', async () => {
    const dir = await newDir('gate-flag');
    const decision = await ensureTrusted(dir, ui, { ...gate, trustFlag: true, homeDir: home, remote: null });
    assert.equal(decision.via, 'flag');
    assert.equal(decision.entry.method, 'flag');
    const again = await ensureTrusted(dir, ui, { ...gate, homeDir: home, remote: null });
    assert.equal(again.via, 'stored');
  });

  it('asks once on a TTY, prints what PatchPilot will do, and remembers the answer', async () => {
    const dir = await newDir('gate-prompt');
    const questions: string[] = [];
    output = '';
    const decision = await ensureTrusted(dir, ui, {
      ...gate,
      interactive: true,
      homeDir: home,
      remote: null,
      identity: { osUser: 'me', gitName: 'Me', gitEmail: 'me@example.com' },
      ask: async (q) => {
        questions.push(q);
        return true;
      },
    });
    assert.equal(decision.via, 'prompt');
    assert.equal(decision.entry.by, 'Me <me@example.com>');
    assert.deepEqual(questions, ['Trust this directory?']);
    assert.match(output, /read the source files and the lockfile/);
    assert.match(output, /send code snippets only to your local Ollama model \(http:\/\/localhost:11434\)/);
    const second = await ensureTrusted(dir, ui, { ...gate, interactive: true, homeDir: home, remote: null, ask: async () => assert.fail('asked twice') });
    assert.equal(second.via, 'stored');
  });

  it('a "no" answer stops with exit 2 and stores nothing', async () => {
    const dir = await newDir('gate-no');
    await assert.rejects(
      ensureTrusted(dir, ui, { ...gate, interactive: true, homeDir: home, remote: null, ask: async () => false }),
      (err: unknown) => err instanceof PatchPilotError && err.exitCode === EXIT.USAGE && /Nothing was read/.test(err.message),
    );
    assert.equal((await checkTrust(dir, { homeDir: home, remote: null })).trusted, false);
  });
});

describe('trustPromptText', () => {
  it('states every promise from the plan', () => {
    const text = trustPromptText({ dir: '/work/app', remote: 'git@github.com:me/app.git', ollamaHost: 'http://localhost:11434', provider: 'ollama' });
    for (const phrase of [
      'PatchPilot has not been used in this directory before',
      '/work/app  (git remote: git@github.com:me/app.git)',
      'read the source files and the lockfile in this directory',
      'send code snippets only to your local Ollama model',
      'call OSV.dev, the npm registry and, for major-version migrations, public documentation pages',
      'write only under .patch-pilot/ in this directory',
      'never run npm or edit your code without asking for your approval first',
    ]) {
      assert.ok(text.includes(phrase), phrase);
    }
    assert.ok(!text.includes('\u2014'));
  });

  it('warns when the Ollama host is not this machine and explains a changed remote', () => {
    const remote = trustPromptText({ dir: '/w', remote: null, ollamaHost: 'http://gpu-box:11434', provider: 'ollama', hostSource: 'patch-pilot.config.json' });
    assert.match(remote, /Note: the Ollama host http:\/\/gpu-box:11434 is not on this machine \(set by patch-pilot\.config\.json\)/);
    const changed = trustPromptText({ dir: '/w', remote: 'new', ollamaHost: 'http://localhost:11434', provider: 'ollama', reason: 'remote-changed', previousRemote: 'old' });
    assert.match(changed, /git remote of this directory changed/);
    assert.match(changed, /was: old/);
    const mock = trustPromptText({ dir: '/w', remote: null, ollamaHost: 'http://localhost:11434', provider: 'mock' });
    assert.match(mock, /scripted mock model/);
  });
});
