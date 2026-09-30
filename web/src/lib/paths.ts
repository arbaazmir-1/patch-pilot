import os from 'node:os';
import path from 'node:path';

// same as the cli's home
export function patchPilotHome(): string {
  return path.join(os.homedir(), '.patch-pilot');
}

export function dbFile(): string {
  return path.join(patchPilotHome(), 'web.db');
}

export function trustStoreFile(): string {
  return path.join(patchPilotHome(), 'trusted.json');
}

export function reportFileFor(projectRoot: string): string {
  return path.join(projectRoot, '.patch-pilot', 'report.json');
}

export function statusFileFor(projectRoot: string): string {
  return path.join(projectRoot, '.patch-pilot', 'status.json');
}
