// version and install root
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

interface OwnPackage {
  root: string;
  version: string;
}

function findOwnPackage(start: string): OwnPackage {
  let dir = start;
  for (let i = 0; i < 8; i += 1) {
    try {
      const raw = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as { name?: string; version?: string };
      if (raw.name === 'patch-pilot' && typeof raw.version === 'string') return { root: dir, version: raw.version };
    } catch {
      // walk up
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return { root: start, version: '0.0.0' };
}

const own = findOwnPackage(import.meta.dirname);

export const VERSION: string = own.version;
export const PACKAGE_ROOT: string = own.root;
export const USER_AGENT = `patch-pilot/${VERSION}`;
