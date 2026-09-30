// lockfile and package manager discovery
import { copyFile, mkdir, open, readFile, rm, stat } from 'node:fs/promises';
import path from 'node:path';
import type { DiscoverResult, LockfileKind, PackageManager, UnsupportedLockfileKind } from '../types.ts';
import { EnvironmentError } from '../util/errors.ts';
import { npmInvocation } from '../util/npm.ts';
import { run } from '../util/proc.ts';
import { yarnFlavor } from './lockfiles/yarn.ts';

// precedence order
export const LOCKFILES: readonly { file: string; kind: LockfileKind; tool: 'npm' | 'pnpm' | 'yarn' }[] = [
  { file: 'npm-shrinkwrap.json', kind: 'npm-shrinkwrap', tool: 'npm' },
  { file: 'package-lock.json', kind: 'package-lock', tool: 'npm' },
  { file: 'pnpm-lock.yaml', kind: 'pnpm', tool: 'pnpm' },
  { file: 'yarn.lock', kind: 'yarn', tool: 'yarn' },
];

const UNSUPPORTED_FILES: readonly { file: string; kind: UnsupportedLockfileKind }[] = [
  { file: 'bun.lock', kind: 'bun' },
  { file: 'bun.lockb', kind: 'bun' },
];

const TOOL_NAMES: Record<UnsupportedLockfileKind, string> = { yarn: 'Yarn', pnpm: 'pnpm', bun: 'Bun' };

export const MANAGER_NAMES: Record<PackageManager, string> = { npm: 'npm', yarn: 'yarn 1', 'yarn-berry': 'yarn 2+', pnpm: 'pnpm' };

// when yarn or pnpm won't start
export const MANAGER_INSTALL: Record<'yarn' | 'yarn-berry' | 'pnpm', { fix: string[]; links: string[] }> = {
  yarn: {
    fix: ['corepack enable   (corepack comes with Node.js up to version 24; otherwise: npm install -g corepack)', 'or install yarn 1 itself: npm install -g yarn'],
    links: ['https://yarnpkg.com/getting-started/install'],
  },
  'yarn-berry': {
    fix: ['corepack enable   (yarn then runs the version in "packageManager" in package.json)', 'or commit the yarn release and point yarnPath in .yarnrc.yml at it'],
    links: ['https://yarnpkg.com/getting-started/install'],
  },
  pnpm: {
    fix: ['npm install -g pnpm', 'or: corepack enable pnpm   (corepack comes with Node.js up to version 24)'],
    links: ['https://pnpm.io/installation'],
  },
};

// no install
export const LOCKFILE_COMMAND = 'npm install --package-lock-only --ignore-scripts';

export interface Discovery extends DiscoverResult {
  // not scanned
  otherLockfiles: { kind: LockfileKind; file: string }[];
  // as written, e.g. "pnpm@9.15.9+sha512..."
  packageManagerField: string | null;
  chosenBy: 'packageManager' | 'precedence' | null;
}

// "pnpm@9.15.9+sha512.abc" -> pnpm, 9.15.9
export function parsePackageManagerField(value: unknown): { name: string; version: string | null } | null {
  if (typeof value !== 'string') return null;
  const m = /^\s*(npm|yarn|pnpm|bun)(?:@([^+\s]+))?/.exec(value);
  if (!m) return null;
  return { name: m[1] as string, version: m[2] ?? null };
}

async function isFile(p: string): Promise<boolean> {
  try {
    return (await stat(p)).isFile();
  } catch {
    return false;
  }
}

// enough to tell yarn 1 from 2+
async function head(file: string, bytes = 4096): Promise<string> {
  let handle;
  try {
    handle = await open(file, 'r');
    const buffer = Buffer.alloc(bytes);
    const { bytesRead } = await handle.read(buffer, 0, bytes, 0);
    return buffer.subarray(0, bytesRead).toString('utf8');
  } catch {
    return '';
  } finally {
    await handle?.close().catch(() => {});
  }
}

// file first, then packageManager field
async function yarnManager(file: string, field: { name: string; version: string | null } | null): Promise<PackageManager> {
  const text = await head(file);
  if (text.trim() !== '') return yarnFlavor(text) === 'berry' ? 'yarn-berry' : 'yarn';
  if (field?.name === 'yarn' && field.version && Number.parseInt(field.version, 10) >= 2) return 'yarn-berry';
  return 'yarn';
}

export async function discoverProject(root: string): Promise<Discovery> {
  const abs = path.resolve(root);
  const packageJson = path.join(abs, 'package.json');
  const hasPackageJson = await isFile(packageJson);
  let field: string | null = null;
  if (hasPackageJson) {
    try {
      const pkg = JSON.parse(await readFile(packageJson, 'utf8')) as { packageManager?: unknown };
      field = typeof pkg?.packageManager === 'string' ? pkg.packageManager : null;
    } catch {
      field = null;
    }
  }
  const parsedField = parsePackageManagerField(field);
  const found: { file: string; kind: LockfileKind; tool: 'npm' | 'pnpm' | 'yarn' }[] = [];
  for (const candidate of LOCKFILES) if (await isFile(path.join(abs, candidate.file))) found.push(candidate);
  const unsupported: DiscoverResult['unsupported'] = [];
  for (const candidate of UNSUPPORTED_FILES) {
    if (await isFile(path.join(abs, candidate.file))) unsupported.push({ kind: candidate.kind, file: candidate.file });
  }
  const preferred = parsedField ? found.find((f) => f.tool === parsedField.name) : undefined;
  const chosen = preferred ?? found[0] ?? null;
  const lockfilePath = chosen ? path.join(abs, chosen.file) : null;
  let packageManager: PackageManager | undefined;
  if (chosen?.tool === 'npm') packageManager = 'npm';
  else if (chosen?.tool === 'pnpm') packageManager = 'pnpm';
  else if (chosen?.tool === 'yarn') packageManager = await yarnManager(path.join(abs, chosen.file), parsedField);
  else if (parsedField?.name === 'npm' || parsedField?.name === 'pnpm') packageManager = parsedField.name;
  else if (parsedField?.name === 'yarn') packageManager = parsedField.version && Number.parseInt(parsedField.version, 10) >= 2 ? 'yarn-berry' : 'yarn';
  const result: Discovery = {
    root: abs,
    packageJsonPath: hasPackageJson ? packageJson : null,
    lockfilePath,
    lockfileKind: chosen?.kind ?? null,
    unsupported,
    needsLockfile: hasPackageJson && lockfilePath === null,
    // npm's own precedence, no warning
    otherLockfiles: found.filter((f) => f !== chosen && f.tool !== chosen?.tool).map((f) => ({ kind: f.kind, file: f.file })),
    packageManagerField: field,
    chosenBy: chosen ? (preferred ? 'packageManager' : 'precedence') : null,
  };
  if (packageManager) result.packageManager = packageManager;
  return result;
}

function tail(text: string, lines = 6): string {
  return text
    .split('\n')
    .map((l) => l.trimEnd())
    .filter((l) => l.trim() !== '')
    .slice(-lines)
    .join('\n');
}

// scratch copy, project untouched
export async function generateScratchLockfile(root: string, tmpDir: string): Promise<string> {
  const source = path.join(root, 'package.json');
  if (!(await isFile(source))) {
    throw new EnvironmentError(`No package.json in ${root}`, { hint: 'Run patch-pilot inside an npm project.' });
  }
  let pkg: { workspaces?: unknown } = {};
  try {
    pkg = JSON.parse(await readFile(source, 'utf8')) as { workspaces?: unknown };
  } catch (err) {
    throw new EnvironmentError(`package.json in ${root} is not valid JSON: ${(err as Error).message}`, { hint: 'Fix package.json first.' });
  }
  if (pkg.workspaces !== undefined) {
    throw new EnvironmentError('This project uses workspaces, so a lockfile cannot be generated from a copy of package.json alone.', {
      hint: `Create it in the project instead: ${LOCKFILE_COMMAND}`,
    });
  }
  const dir = path.join(tmpDir, 'scratch');
  await rm(dir, { recursive: true, force: true });
  await mkdir(dir, { recursive: true });
  await copyFile(source, path.join(dir, 'package.json'));
  const npmrc = path.join(root, '.npmrc');
  const copiedNpmrc = path.join(dir, '.npmrc');
  const hasNpmrc = await isFile(npmrc);
  if (hasNpmrc) await copyFile(npmrc, copiedNpmrc);
  try {
    const npm = npmInvocation();
    const result = await run(npm.cmd, [...npm.prefix, 'install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund'], {
      cwd: dir,
      timeoutMs: 300_000,
      env: { ...process.env, npm_config_update_notifier: 'false' },
    });
    const lockfile = path.join(dir, 'package-lock.json');
    if (result.error && result.error.code === 'ENOENT') {
      throw new EnvironmentError('npm was not found on PATH, so no lockfile could be generated.', {
        hint: 'Install Node.js with npm (https://nodejs.org/en/download), then run patch-pilot again.',
      });
    }
    if (!result.ok || !(await isFile(lockfile))) {
      const detail = tail(result.stderr || result.stdout);
      throw new EnvironmentError(`npm could not generate a lockfile (exit ${result.code ?? result.signal ?? 'unknown'})${detail ? `:\n${detail}` : ''}`, {
        hint: `Run it yourself in the project: ${LOCKFILE_COMMAND}`,
      });
    }
    return lockfile;
  } finally {
    if (hasNpmrc) await rm(copiedNpmrc, { force: true });
  }
}

// "" when fine
export function unsupportedLockfileMessage(result: DiscoverResult | Discovery): string {
  if (!result.packageJsonPath && !result.lockfilePath) {
    return [
      `No package.json in ${result.root}.`,
      'PatchPilot scans npm, yarn and pnpm projects: run it in a directory with package.json and its lockfile (package-lock.json, yarn.lock or pnpm-lock.yaml).',
    ].join('\n');
  }
  const lines: string[] = [];
  const others = 'otherLockfiles' in result ? result.otherLockfiles : [];
  if (result.lockfilePath && others.length > 0) {
    const chosen = path.basename(result.lockfilePath);
    const why =
      'chosenBy' in result && result.chosenBy === 'packageManager' && result.packageManagerField
        ? `package.json says "packageManager": "${result.packageManagerField.split('+')[0]}"`
        : 'npm-shrinkwrap.json, then package-lock.json, then pnpm-lock.yaml, then yarn.lock';
    lines.push(
      `Found several lockfiles: ${[chosen, ...others.map((o) => o.file)].join(', ')}. Using ${chosen} (${why}); ${others.map((o) => o.file).join(' and ')} ${others.length === 1 ? 'is' : 'are'} not scanned.`,
      'Delete the lockfiles of package managers you no longer use, or set "packageManager" in package.json to pick one.',
    );
  }
  if (result.unsupported.length > 0) {
    const found = result.unsupported.map((u) => `${u.file} (${TOOL_NAMES[u.kind]})`).join(', ');
    const tools = [...new Set(result.unsupported.map((u) => TOOL_NAMES[u.kind]))].join(' and ');
    lines.push(`Found ${found}: ${tools} lockfiles are not supported yet (npm, yarn and pnpm lockfiles are).`);
    if (result.lockfilePath) {
      lines.push(`Using ${path.basename(result.lockfilePath)}, which may not match the ${tools} lockfile if they diverged.`);
      return lines.join('\n');
    }
    lines.push(
      'Workaround: scan an npm lockfile generated from package.json. PatchPilot can create one in .patch-pilot/tmp/ without touching the project,',
      `or you can run \`${LOCKFILE_COMMAND}\` yourself (it writes package-lock.json and installs nothing).`,
      `Note: npm resolves versions afresh, so they can differ from the ones pinned in the ${tools} lockfile.`,
    );
    return lines.join('\n');
  }
  if (!result.lockfilePath) {
    lines.push(
      `No package-lock.json, npm-shrinkwrap.json, yarn.lock or pnpm-lock.yaml in ${result.root}.`,
      `PatchPilot can generate a scratch lockfile in .patch-pilot/tmp/ (the project is not touched), or create one in the project with: ${LOCKFILE_COMMAND}`,
    );
  }
  return lines.join('\n');
}
