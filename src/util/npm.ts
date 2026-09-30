// how to spawn npm without a shell
import { existsSync } from 'node:fs';
import path from 'node:path';

export interface NpmInvocation {
  cmd: string;
  prefix: string[];
}

// node npm-cli.js on windows (npm.cmd needs a shell)
export function npmInvocation(platform: NodeJS.Platform = process.platform, execPath: string = process.execPath): NpmInvocation {
  if (platform !== 'win32') return { cmd: 'npm', prefix: [] };
  const cli = path.join(path.dirname(execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js');
  if (existsSync(cli)) return { cmd: execPath, prefix: [cli] };
  return { cmd: 'npm.cmd', prefix: [] };
}
