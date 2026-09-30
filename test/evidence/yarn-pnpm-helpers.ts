// yarn and pnpm test helpers
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { dependencyPaths, parseLockfile, type LockfileJson } from '../../src/evidence/lockfile.ts';
import type { DependencyGraph, PackageJson } from '../../src/types.ts';

export const LOCKFILES = fileURLToPath(new URL('./fixtures/lockfiles/', import.meta.url));
export const APP = fileURLToPath(new URL('../../examples/vulnerable-app/', import.meta.url));

export async function text(...parts: string[]): Promise<string> {
  return readFile(path.join(LOCKFILES, ...parts), 'utf8');
}

export async function json<T>(file: string): Promise<T> {
  return JSON.parse(await readFile(file, 'utf8')) as T;
}

export async function appPackage(): Promise<PackageJson> {
  return json<PackageJson>(path.join(APP, 'package.json'));
}

// reference graph for every format
export async function appNpmGraph(): Promise<DependencyGraph> {
  return parseLockfile(await json<LockfileJson>(path.join(APP, 'package-lock.json')), await appPackage());
}

export async function workspacePackages(): Promise<{ root: PackageJson; workspaces: { path: string; pkg: PackageJson }[] }> {
  const dir = path.join(LOCKFILES, 'workspaces');
  return {
    root: await json<PackageJson>(path.join(dir, 'package.json')),
    workspaces: [
      { path: 'packages/a', pkg: await json<PackageJson>(path.join(dir, 'packages', 'a', 'package.json')) },
      { path: 'packages/b', pkg: await json<PackageJson>(path.join(dir, 'packages', 'b', 'package.json')) },
    ],
  };
}

export async function workspacesNpmGraph(): Promise<DependencyGraph> {
  const { root } = await workspacePackages();
  return parseLockfile(await json<LockfileJson>(path.join(LOCKFILES, 'workspaces', 'package-lock.json')), root);
}

export interface NodeSummary {
  flags: string;
  parents: string[];
  paths: string[];
}

// comparable across formats
export function summarize(graph: DependencyGraph): Record<string, NodeSummary> {
  const out: Record<string, NodeSummary> = {};
  for (const node of graph.nodes.values()) {
    const id = `${node.name}@${node.version}`;
    out[id] = {
      flags: [node.dev && 'dev', node.optional && 'optional', node.devOptional && 'devOptional', node.peer && 'peer', node.isDirect && 'direct'].filter(Boolean).join(','),
      parents: node.parents.map((p) => {
        const parent = graph.nodes.get(p);
        return parent ? `${parent.name}@${parent.version}` : p;
      }).sort(),
      paths: dependencyPaths(graph, node.key).map((p) => p.join(' > ')).sort(),
    };
  }
  return Object.fromEntries(Object.entries(out).sort(([a], [b]) => (a < b ? -1 : 1)));
}

export function rootEdges(graph: DependencyGraph): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, key] of Object.entries(graph.root.edges)) {
    const node = graph.nodes.get(key);
    out[name] = node ? `${node.name}@${node.version}` : key;
  }
  return Object.fromEntries(Object.entries(out).sort(([a], [b]) => (a < b ? -1 : 1)));
}
