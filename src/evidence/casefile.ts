// vuln matching, severity, fixes, phase 1
import path from 'node:path';
import type { ChatProvider } from '../llm/provider.ts';
import type {
  AuditSink,
  BlamedSymbol,
  CaseFile,
  CaseFileCounts,
  Config,
  DependencyGraph,
  DepType,
  FileScope,
  GhsaSeverity,
  OsvAffected,
  OsvRange,
  OsvRecord,
  OsvReference,
  PackageCase,
  PackageNode,
  PackageRef,
  SeverityLabel,
  UsageEvidence,
  VulnCase,
  VulnSeverity,
  VulnSourceInfo,
} from '../types.ts';
import { truncateLine, type Spinner, type Ui } from '../ui.ts';
import { EnvironmentError, errorMessage, EXIT, PatchPilotError } from '../util/errors.ts';
import { hashJson, readJsonIfExists, relativePosix, writeJsonAtomic } from '../util/fs.ts';
import {
  compareVersions,
  describeRanges,
  fixedVersionsFromRanges,
  isAffected,
  isAffectedByEntry,
  isMajorBump,
  isSameLine,
  parseVersion,
  pickFix,
  pickPackageFix,
  sortVersions,
} from '../util/semver.ts';
import { collectDependentUsage, collectUsageEvidence, extractBlamedSymbols, type DependentRef } from './codebase.ts';
import { normalizeTimestamp, openDb, type PatchPilotDb } from './db.ts';
import { discoverProject, generateScratchLockfile, LOCKFILE_COMMAND, MANAGER_NAMES, unsupportedLockfileMessage } from './discover.ts';
import { dependencyPaths, graphCounts, loadDependencyGraph } from './lockfile.ts';
import { formatDataAge, pairKey, queryOsv, type OsvQueryResult } from './osv.ts';
import { getPackument } from './registry.ts';

export const CASE_FILE_VERSION = 1;

export interface Phase1Deps {
  ui: Ui;
  audit: AuditSink;
  db?: PatchPilotDb | null;
  // warmed in phase 1, fire and forget
  provider?: ChatProvider | null;
  signal?: AbortSignal;
}

const GHSA_RANK: Record<SeverityLabel, number> = { UNKNOWN: 0, LOW: 1, MODERATE: 2, HIGH: 3, CRITICAL: 4 };
export const SEVERITY_ORDER: readonly SeverityLabel[] = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'UNKNOWN'];

function normalizeGhsa(value: unknown): GhsaSeverity | undefined {
  if (typeof value !== 'string') return undefined;
  const v = value.trim().toUpperCase();
  if (v === 'MEDIUM') return 'MODERATE';
  return v === 'LOW' || v === 'MODERATE' || v === 'HIGH' || v === 'CRITICAL' ? v : undefined;
}

// in GHSA words
export function severityFromScore(score: number | undefined): GhsaSeverity | undefined {
  if (score === undefined || !Number.isFinite(score) || score <= 0) return undefined;
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MODERATE';
  return 'LOW';
}

function parseMetrics(vector: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const part of vector.trim().split('/')) {
    const idx = part.indexOf(':');
    if (idx <= 0) continue;
    const key = part.slice(0, idx).trim();
    if (key === 'CVSS') continue;
    out.set(key, part.slice(idx + 1).trim());
  }
  return out;
}

function roundUp31(value: number): number {
  const int = Math.round(value * 100_000);
  return int % 10_000 === 0 ? int / 100_000 : (Math.floor(int / 10_000) + 1) / 10;
}

// null when a base metric is missing
function cvss3Score(vector: string): number | null {
  const m = parseMetrics(vector);
  const scope = m.get('S');
  const table = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { L: 0.77, H: 0.44 },
    UI: { N: 0.85, R: 0.62 },
    CIA: { H: 0.56, L: 0.22, N: 0 },
  } as const;
  const av = table.AV[m.get('AV') as keyof typeof table.AV];
  const ac = table.AC[m.get('AC') as keyof typeof table.AC];
  const ui = table.UI[m.get('UI') as keyof typeof table.UI];
  const prKey = m.get('PR');
  const pr = prKey === 'N' ? 0.85 : prKey === 'L' ? (scope === 'C' ? 0.68 : 0.62) : prKey === 'H' ? (scope === 'C' ? 0.5 : 0.27) : undefined;
  const c = table.CIA[m.get('C') as keyof typeof table.CIA];
  const i = table.CIA[m.get('I') as keyof typeof table.CIA];
  const a = table.CIA[m.get('A') as keyof typeof table.CIA];
  if ([av, ac, ui, pr, c, i, a].some((x) => x === undefined) || (scope !== 'U' && scope !== 'C')) return null;
  const iss = 1 - (1 - (c as number)) * (1 - (i as number)) * (1 - (a as number));
  const impact = scope === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
  const exploitability = 8.22 * (av as number) * (ac as number) * (pr as number) * (ui as number);
  if (impact <= 0) return 0;
  const raw = scope === 'U' ? Math.min(impact + exploitability, 10) : Math.min(1.08 * (impact + exploitability), 10);
  return vector.startsWith('CVSS:3.0/') ? Math.ceil(raw * 10 - 1e-9) / 10 : roundUp31(raw);
}

// AV:N/AC:L/Au:N/C:P/I:P/A:P
function cvss2Score(vector: string): number | null {
  const m = parseMetrics(vector.replace(/^\(|\)$/g, ''));
  const av = ({ L: 0.395, A: 0.646, N: 1.0 } as Record<string, number>)[m.get('AV') ?? ''];
  const ac = ({ H: 0.35, M: 0.61, L: 0.71 } as Record<string, number>)[m.get('AC') ?? ''];
  const au = ({ M: 0.45, S: 0.56, N: 0.704 } as Record<string, number>)[m.get('Au') ?? ''];
  const cia = { N: 0, P: 0.275, C: 0.66 } as Record<string, number>;
  const c = cia[m.get('C') ?? ''];
  const i = cia[m.get('I') ?? ''];
  const a = cia[m.get('A') ?? ''];
  if ([av, ac, au, c, i, a].some((x) => x === undefined)) return null;
  const impact = 10.41 * (1 - (1 - (c as number)) * (1 - (i as number)) * (1 - (a as number)));
  const exploitability = 20 * (av as number) * (ac as number) * (au as number);
  const f = impact === 0 ? 0 : 1.176;
  return Math.round((0.6 * impact + 0.4 * exploitability - 1.5) * f * 10) / 10;
}

// CVSS 4.0 tables and scoring from FIRST's reference calculator (license below)
//
//   Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors
//
//   Redistribution and use in source and binary forms, with or without modification, are
//   permitted provided that the following conditions are met:
//   1. Redistributions of source code must retain the above copyright notice, this list of
//      conditions and the following disclaimer.
//   2. Redistributions in binary form must reproduce the above copyright notice, this list
//      of conditions and the following disclaimer in the documentation and/or other
//      materials provided with the distribution.
//   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
//   EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
//   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
//   THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
//   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
//   BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
//   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
//   WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

const CVSS4_TABLE = [
  '000000:10 000001:9.9 000010:9.8 000011:9.5 000020:9.5 000021:9.2 000100:10 000101:9.6 000110:9.3 000111:8.7 000120:9.1 000121:8.1',
  '000200:9.3 000201:9 000210:8.9 000211:8 000220:8.1 000221:6.8 001000:9.8 001001:9.5 001010:9.5 001011:9.2 001020:9 001021:8.4',
  '001100:9.3 001101:9.2 001110:8.9 001111:8.1 001120:8.1 001121:6.5 001200:8.8 001201:8 001210:7.8 001211:7 001220:6.9 001221:4.8',
  '002001:9.2 002011:8.2 002021:7.2 002101:7.9 002111:6.9 002121:5 002201:6.9 002211:5.5 002221:2.7 010000:9.9 010001:9.7 010010:9.5',
  '010011:9.2 010020:9.2 010021:8.5 010100:9.5 010101:9.1 010110:9 010111:8.3 010120:8.4 010121:7.1 010200:9.2 010201:8.1 010210:8.2',
  '010211:7.1 010220:7.2 010221:5.3 011000:9.5 011001:9.3 011010:9.2 011011:8.5 011020:8.5 011021:7.3 011100:9.2 011101:8.2 011110:8',
  '011111:7.2 011120:7 011121:5.9 011200:8.4 011201:7 011210:7.1 011211:5.2 011220:5 011221:3 012001:8.6 012011:7.5 012021:5.2',
  '012101:7.1 012111:5.2 012121:2.9 012201:6.3 012211:2.9 012221:1.7 100000:9.8 100001:9.5 100010:9.4 100011:8.7 100020:9.1 100021:8.1',
  '100100:9.4 100101:8.9 100110:8.6 100111:7.4 100120:7.7 100121:6.4 100200:8.7 100201:7.5 100210:7.4 100211:6.3 100220:6.3 100221:4.9',
  '101000:9.4 101001:8.9 101010:8.8 101011:7.7 101020:7.6 101021:6.7 101100:8.6 101101:7.6 101110:7.4 101111:5.8 101120:5.9 101121:5',
  '101200:7.2 101201:5.7 101210:5.7 101211:5.2 101220:5.2 101221:2.5 102001:8.3 102011:7 102021:5.4 102101:6.5 102111:5.8 102121:2.6',
  '102201:5.3 102211:2.1 102221:1.3 110000:9.5 110001:9 110010:8.8 110011:7.6 110020:7.6 110021:7 110100:9 110101:7.7 110110:7.5',
  '110111:6.2 110120:6.1 110121:5.3 110200:7.7 110201:6.6 110210:6.8 110211:5.9 110220:5.2 110221:3 111000:8.9 111001:7.8 111010:7.6',
  '111011:6.7 111020:6.2 111021:5.8 111100:7.4 111101:5.9 111110:5.7 111111:5.7 111120:4.7 111121:2.3 111200:6.1 111201:5.2 111210:5.7',
  '111211:2.9 111220:2.4 111221:1.6 112001:7.1 112011:5.9 112021:3 112101:5.8 112111:2.6 112121:1.5 112201:2.3 112211:1.3 112221:0.6',
  '200000:9.3 200001:8.7 200010:8.6 200011:7.2 200020:7.5 200021:5.8 200100:8.6 200101:7.4 200110:7.4 200111:6.1 200120:5.6 200121:3.4',
  '200200:7 200201:5.4 200210:5.2 200211:4 200220:4 200221:2.2 201000:8.5 201001:7.5 201010:7.4 201011:5.5 201020:6.2 201021:5.1',
  '201100:7.2 201101:5.7 201110:5.5 201111:4.1 201120:4.6 201121:1.9 201200:5.3 201201:3.6 201210:3.4 201211:1.9 201220:1.9 201221:0.8',
  '202001:6.4 202011:5.1 202021:2 202101:4.7 202111:2.1 202121:1.1 202201:2.4 202211:0.9 202221:0.4 210000:8.8 210001:7.5 210010:7.3',
  '210011:5.3 210020:6 210021:5 210100:7.3 210101:5.5 210110:5.9 210111:4 210120:4.1 210121:2 210200:5.4 210201:4.3 210210:4.5',
  '210211:2.2 210220:2 210221:1.1 211000:7.5 211001:5.5 211010:5.8 211011:4.5 211020:4 211021:2.1 211100:6.1 211101:5.1 211110:4.8',
  '211111:1.8 211120:2 211121:0.9 211200:4.6 211201:1.8 211210:1.7 211211:0.7 211220:0.8 211221:0.2 212001:5.3 212011:2.4 212021:1.4',
  '212101:2.4 212111:1.2 212121:0.5 212201:1 212211:0.3 212221:0.1',
];

let cvss4Lookup: Map<string, number> | null = null;

function cvss4Table(): Map<string, number> {
  if (!cvss4Lookup) {
    cvss4Lookup = new Map();
    for (const line of CVSS4_TABLE) {
      for (const pair of line.split(' ')) {
        const [macro, score] = pair.split(':');
        if (macro && score) cvss4Lookup.set(macro, Number(score));
      }
    }
  }
  return cvss4Lookup;
}

const CVSS4_MAX_COMPOSED: Record<'eq1' | 'eq2' | 'eq4' | 'eq5', Record<number, string[]>> & { eq3: Record<number, Record<number, string[]>> } = {
  eq1: { 0: ['AV:N/PR:N/UI:N/'], 1: ['AV:A/PR:N/UI:N/', 'AV:N/PR:L/UI:N/', 'AV:N/PR:N/UI:P/'], 2: ['AV:P/PR:N/UI:N/', 'AV:A/PR:L/UI:P/'] },
  eq2: { 0: ['AC:L/AT:N/'], 1: ['AC:H/AT:N/', 'AC:L/AT:P/'] },
  eq3: {
    0: { 0: ['VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/'], 1: ['VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/', 'VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/'] },
    1: {
      0: ['VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/', 'VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/'],
      1: ['VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/', 'VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/', 'VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/', 'VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/', 'VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/'],
    },
    2: { 1: ['VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/'] },
  },
  eq4: { 0: ['SC:H/SI:S/SA:S/'], 1: ['SC:H/SI:H/SA:H/'], 2: ['SC:L/SI:L/SA:L/'] },
  eq5: { 0: ['E:A/'], 1: ['E:P/'], 2: ['E:U/'] },
};

const CVSS4_MAX_SEVERITY = {
  eq1: { 0: 1, 1: 4, 2: 5 } as Record<number, number>,
  eq2: { 0: 1, 1: 2 } as Record<number, number>,
  eq3eq6: { 0: { 0: 7, 1: 6 }, 1: { 0: 8, 1: 8 }, 2: { 1: 10 } } as Record<number, Record<number, number>>,
  eq4: { 0: 6, 1: 5, 2: 4 } as Record<number, number>,
};

const CVSS4_LEVELS: Record<string, Record<string, number>> = {
  AV: { N: 0, A: 0.1, L: 0.2, P: 0.3 },
  PR: { N: 0, L: 0.1, H: 0.2 },
  UI: { N: 0, P: 0.1, A: 0.2 },
  AC: { L: 0, H: 0.1 },
  AT: { N: 0, P: 0.1 },
  VC: { H: 0, L: 0.1, N: 0.2 },
  VI: { H: 0, L: 0.1, N: 0.2 },
  VA: { H: 0, L: 0.1, N: 0.2 },
  SC: { H: 0.1, L: 0.2, N: 0.3 },
  SI: { S: 0, H: 0.1, L: 0.2, N: 0.3 },
  SA: { S: 0, H: 0.1, L: 0.2, N: 0.3 },
  CR: { H: 0, M: 0.1, L: 0.2 },
  IR: { H: 0, M: 0.1, L: 0.2 },
  AR: { H: 0, M: 0.1, L: 0.2 },
};

const CVSS4_BASE = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'];

// base, threat and environmental
function cvss4Score(vector: string): number | null {
  const selected = parseMetrics(vector);
  if (CVSS4_BASE.some((k) => !selected.has(k))) return null;
  const m = (metric: string): string => {
    const value = selected.get(metric) ?? 'X';
    if (metric === 'E' && value === 'X') return 'A';
    if ((metric === 'CR' || metric === 'IR' || metric === 'AR') && value === 'X') return 'H';
    const modified = selected.get(`M${metric}`);
    if (modified !== undefined && modified !== 'X') return modified;
    return value;
  };
  if (['VC', 'VI', 'VA', 'SC', 'SI', 'SA'].every((k) => m(k) === 'N')) return 0;

  const eq1 = m('AV') === 'N' && m('PR') === 'N' && m('UI') === 'N' ? 0 : (m('AV') === 'N' || m('PR') === 'N' || m('UI') === 'N') && m('AV') !== 'P' ? 1 : 2;
  const eq2 = m('AC') === 'L' && m('AT') === 'N' ? 0 : 1;
  const eq3 = m('VC') === 'H' && m('VI') === 'H' ? 0 : m('VC') === 'H' || m('VI') === 'H' || m('VA') === 'H' ? 1 : 2;
  const eq4 = m('MSI') === 'S' || m('MSA') === 'S' ? 0 : m('SC') === 'H' || m('SI') === 'H' || m('SA') === 'H' ? 1 : 2;
  const eq5 = m('E') === 'A' ? 0 : m('E') === 'P' ? 1 : m('E') === 'U' ? 2 : -1;
  const eq6 = (m('CR') === 'H' && m('VC') === 'H') || (m('IR') === 'H' && m('VI') === 'H') || (m('AR') === 'H' && m('VA') === 'H') ? 0 : 1;
  if (eq5 < 0) return null;
  const lookup = cvss4Table();
  const macro = `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6}`;
  const value = lookup.get(macro);
  if (value === undefined) return null;
  const at = (a: number, b: number, c: number, d: number, e: number, f: number): number => lookup.get(`${a}${b}${c}${d}${e}${f}`) ?? Number.NaN;

  const scoreEq1 = at(eq1 + 1, eq2, eq3, eq4, eq5, eq6);
  const scoreEq2 = at(eq1, eq2 + 1, eq3, eq4, eq5, eq6);
  let scoreEq3eq6: number;
  if (eq3 === 1 && eq6 === 1) scoreEq3eq6 = at(eq1, eq2, eq3 + 1, eq4, eq5, eq6);
  else if (eq3 === 0 && eq6 === 1) scoreEq3eq6 = at(eq1, eq2, eq3 + 1, eq4, eq5, eq6);
  else if (eq3 === 1 && eq6 === 0) scoreEq3eq6 = at(eq1, eq2, eq3, eq4, eq5, eq6 + 1);
  else if (eq3 === 0 && eq6 === 0) {
    const left = at(eq1, eq2, eq3, eq4, eq5, eq6 + 1);
    const right = at(eq1, eq2, eq3 + 1, eq4, eq5, eq6);
    scoreEq3eq6 = left > right ? left : right;
  } else scoreEq3eq6 = at(eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1);
  const scoreEq4 = at(eq1, eq2, eq3, eq4 + 1, eq5, eq6);
  const scoreEq5 = at(eq1, eq2, eq3, eq4, eq5 + 1, eq6);

  const maxes: string[] = [];
  for (const a of CVSS4_MAX_COMPOSED.eq1[eq1] ?? []) {
    for (const b of CVSS4_MAX_COMPOSED.eq2[eq2] ?? []) {
      for (const c of CVSS4_MAX_COMPOSED.eq3[eq3]?.[eq6] ?? []) {
        for (const d of CVSS4_MAX_COMPOSED.eq4[eq4] ?? []) {
          for (const e of CVSS4_MAX_COMPOSED.eq5[eq5] ?? []) maxes.push(a + b + c + d + e);
        }
      }
    }
  }
  const metricsOrder = ['AV', 'PR', 'UI', 'AC', 'AT', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA', 'CR', 'IR', 'AR'];
  let distance: Record<string, number> = {};
  for (const max of maxes) {
    const maxMetrics = parseMetrics(max);
    distance = {};
    for (const k of metricsOrder) {
      distance[k] = (CVSS4_LEVELS[k]?.[m(k)] ?? Number.NaN) - (CVSS4_LEVELS[k]?.[maxMetrics.get(k) ?? ''] ?? Number.NaN);
    }
    if (metricsOrder.some((k) => (distance[k] as number) < 0)) continue;
    break;
  }
  const d = (k: string): number => distance[k] ?? 0;
  const current = {
    eq1: d('AV') + d('PR') + d('UI'),
    eq2: d('AC') + d('AT'),
    eq3eq6: d('VC') + d('VI') + d('VA') + d('CR') + d('IR') + d('AR'),
    eq4: d('SC') + d('SI') + d('SA'),
  };
  const step = 0.1;
  const maxSeverity = {
    eq1: (CVSS4_MAX_SEVERITY.eq1[eq1] ?? Number.NaN) * step,
    eq2: (CVSS4_MAX_SEVERITY.eq2[eq2] ?? Number.NaN) * step,
    eq3eq6: (CVSS4_MAX_SEVERITY.eq3eq6[eq3]?.[eq6] ?? Number.NaN) * step,
    eq4: (CVSS4_MAX_SEVERITY.eq4[eq4] ?? Number.NaN) * step,
  };
  let existing = 0;
  let total = 0;
  const addEq = (available: number, currentDistance: number, depth: number): void => {
    if (Number.isNaN(available)) return;
    existing += 1;
    total += available * (currentDistance / depth);
  };
  addEq(value - scoreEq1, current.eq1, maxSeverity.eq1);
  addEq(value - scoreEq2, current.eq2, maxSeverity.eq2);
  addEq(value - scoreEq3eq6, current.eq3eq6, maxSeverity.eq3eq6);
  addEq(value - scoreEq4, current.eq4, maxSeverity.eq4);
  if (!Number.isNaN(value - scoreEq5)) existing += 1; // always 0
  const mean = existing === 0 ? 0 : total / existing;
  const score = Math.min(10, Math.max(0, value - mean));
  // epsilon absorbs float noise (8.549999)
  return Math.round((score + 1e-6) * 10) / 10;
}

// also takes a bare numeric score
export function cvssScore(vector: string, type?: string): { score: number | null; version: string | null } {
  const v = vector.trim();
  const numeric = /^\d+(?:\.\d+)?$/.test(v) ? Number(v) : null;
  if (numeric !== null) return { score: numeric <= 10 ? numeric : null, version: type === 'CVSS_V4' ? '4.0' : type === 'CVSS_V2' ? '2.0' : type === 'CVSS_V3' ? '3.1' : null };
  const prefix = /^CVSS:(\d\.\d)\//.exec(v);
  if (prefix) {
    const version = prefix[1] as string;
    if (version === '3.0' || version === '3.1') return { score: cvss3Score(v), version };
    if (version === '4.0') return { score: cvss4Score(v), version };
    return { score: null, version };
  }
  if (type === 'CVSS_V2' || /(?:^|\/)Au:[MSN]/.test(v)) return { score: cvss2Score(v), version: '2.0' };
  return { score: null, version: null };
}

// missing arrays ok
export function severityOf(record: OsvRecord): VulnSeverity {
  const out: VulnSeverity = {};
  const entries = Array.isArray(record?.severity) ? record.severity.filter((e) => e && typeof e.score === 'string' && e.score.trim() !== '') : [];
  const byType = (type: string): (typeof entries)[number] | undefined => entries.find((e) => (e.type ?? '').toUpperCase() === type);
  const chosen = byType('CVSS_V3') ?? byType('CVSS_V4') ?? byType('CVSS_V2') ?? entries[0];
  if (chosen) {
    const { score, version } = cvssScore(chosen.score, (chosen.type ?? '').toUpperCase());
    if (!/^\d+(?:\.\d+)?$/.test(chosen.score.trim())) out.cvssVector = chosen.score.trim();
    if (score !== null) out.cvssScore = score;
    if (version) out.cvssVersion = version;
  }
  let ghsa = normalizeGhsa(record?.database_specific?.severity);
  if (!ghsa) {
    for (const affected of record?.affected ?? []) {
      ghsa = normalizeGhsa(affected?.database_specific?.severity) ?? normalizeGhsa(affected?.ecosystem_specific?.severity);
      if (ghsa) break;
    }
  }
  if (ghsa) out.ghsa = ghsa;
  return out;
}

// falls back to CVSS rating
export function severityLabel(severity: VulnSeverity, malware = false): SeverityLabel {
  return severity.ghsa ?? severityFromScore(severity.cvssScore) ?? (malware ? 'CRITICAL' : 'UNKNOWN');
}

function publishedTime(record: OsvRecord): number {
  const t = Date.parse(record.published ?? '');
  return Number.isFinite(t) ? t : Number.POSITIVE_INFINITY;
}

// osv returns dup ghsa ids per cve
export function mergeAliasedRecords(records: readonly OsvRecord[]): OsvRecord[][] {
  const byId = new Map<string, OsvRecord>();
  const order: string[] = [];
  for (const record of records) {
    if (!record || typeof record.id !== 'string' || record.id === '') continue;
    const existing = byId.get(record.id);
    if (!existing) {
      byId.set(record.id, record);
      order.push(record.id);
    } else if (normalizeTimestamp(record.modified ?? '') > normalizeTimestamp(existing.modified ?? '')) {
      byId.set(record.id, record);
    }
  }
  const parent = new Map<string, string>(order.map((id) => [id, id]));
  const find = (id: string): string => {
    let root = id;
    while (parent.get(root) !== root) root = parent.get(root) as string;
    let cur = id;
    while (parent.get(cur) !== root) {
      const next = parent.get(cur) as string;
      parent.set(cur, root);
      cur = next;
    }
    return root;
  };
  const union = (a: string, b: string): void => {
    const ra = find(a);
    const rb = find(b);
    if (ra !== rb) parent.set(rb, ra);
  };
  const idsUpper = new Map(order.map((id) => [id.toUpperCase(), id]));
  const aliasOwner = new Map<string, string>();
  for (const id of order) {
    const record = byId.get(id) as OsvRecord;
    for (const alias of record.aliases ?? []) {
      if (typeof alias !== 'string' || alias.trim() === '') continue;
      const key = alias.trim().toUpperCase();
      const other = idsUpper.get(key);
      if (other && other !== id) union(id, other);
      const owner = aliasOwner.get(key);
      if (owner) union(owner, id);
      else aliasOwner.set(key, id);
    }
  }
  const groups = new Map<string, OsvRecord[]>();
  for (const id of order) {
    const root = find(id);
    const list = groups.get(root);
    if (list) list.push(byId.get(id) as OsvRecord);
    else groups.set(root, [byId.get(id) as OsvRecord]);
  }
  return [...groups.values()].map((group) =>
    [...group].sort((a, b) => publishedTime(a) - publishedTime(b) || (a.id.startsWith('GHSA-') === b.id.startsWith('GHSA-') ? (a.id < b.id ? -1 : 1) : a.id.startsWith('GHSA-') ? -1 : 1)),
  );
}

export interface BuildCaseFileInput {
  projectRoot: string;
  projectName: string;
  lockfilePath: string;
  graph: DependencyGraph;
  osv: OsvQueryResult;
  usage: Map<string, UsageEvidence>;
  deprecated: Map<string, Set<string>>;
  available: Map<string, string[]>;
  // dist-tag
  latest?: Map<string, string>;
  scannedAt?: string;
  // "name@version" -> message
  deprecationMessages?: Map<string, string>;
}

function emptyUsage(pkg: string): UsageEvidence {
  return { package: pkg, imported: false, files: [], scopes: { source: 0, test: 0, config: 0, scripts: 0 }, membersUsed: {}, bindingCalls: 0, scannedFiles: 0 };
}

function npmEntries(record: OsvRecord, name: string): OsvAffected[] {
  return (record.affected ?? []).filter((a) => a?.package?.name === name && (a.package.ecosystem ?? '').toLowerCase() === 'npm');
}

function evaluableRanges(entry: OsvAffected): OsvRange[] {
  return (entry.ranges ?? []).filter((r) => r && (r.type === 'SEMVER' || r.type === 'ECOSYSTEM') && Array.isArray(r.events));
}

// trusted when nothing is evaluable
export function recordAffects(record: OsvRecord, name: string, version: string): boolean {
  const entries = npmEntries(record, name);
  if (entries.length === 0) return true;
  const evaluable = entries.some((e) => (e.versions?.length ?? 0) > 0 || evaluableRanges(e).length > 0);
  if (!evaluable) return true;
  return entries.some((e) => isAffectedByEntry(version, e));
}

// emphasis only at word edges, so __proto__ and snake_case survive
const STAR_EMPHASIS = /(^|[^\w*])(\*{1,3})(?=[^\s*])([^*\n]*?[^\s*])\2(?![\w*])/g;
const UNDERSCORE_EMPHASIS = /(^|[^\w])(_{1,3})(?=[^\s_])([^\n]*?[^\s_])\2(?!\w)/g;

function stripMarkdown(text: string): string {
  const spans: string[] = [];
  const shielded = text
    .replace(/^\s*(```|~~~)[^\n]*\n[\s\S]*?(?:^\s*\1[^\n]*$|$(?![\s\S]))/gm, ' ')
    .replace(/^\s{0,3}#{1,6}\s+[^\n]*$/gm, ' ')
    .replace(/`[^`\n]+`/g, (span) => `\u0000${spans.push(span) - 1}\u0000`)
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(STAR_EMPHASIS, '$1$3')
    .replace(UNDERSCORE_EMPHASIS, '$1$3');
  return shielded
    .replace(/\u0000(\d+)\u0000/g, (_, i: string) => spans[Number(i)] ?? '')
    .replace(/\s+/g, ' ')
    .trim();
}

// cut at a sentence or word
export function excerpt(details: string, max = 480): string {
  const text = stripMarkdown(details ?? '');
  if (text.length <= max) return text;
  const cut = text.slice(0, max);
  const sentence = cut.lastIndexOf('. ');
  if (sentence > max * 0.6) return cut.slice(0, sentence + 1);
  const space = cut.lastIndexOf(' ');
  return `${(space > max * 0.6 ? cut.slice(0, space) : cut).trimEnd()}…`;
}

function uniqueRefs(records: readonly OsvRecord[]): OsvReference[] {
  const seen = new Set<string>();
  const out: OsvReference[] = [];
  for (const record of records) {
    for (const ref of record.references ?? []) {
      if (!ref || typeof ref.url !== 'string' || seen.has(ref.url)) continue;
      seen.add(ref.url);
      out.push({ type: ref.type ?? 'WEB', url: ref.url });
    }
  }
  return out.slice(0, 25);
}

function worstSeverity(severities: readonly VulnSeverity[]): VulnSeverity {
  const out: VulnSeverity = {};
  let bestGhsa: GhsaSeverity | undefined;
  for (const s of severities) if (s.ghsa && (!bestGhsa || GHSA_RANK[s.ghsa] > GHSA_RANK[bestGhsa])) bestGhsa = s.ghsa;
  const scored = severities.filter((s) => s.cvssScore !== undefined).sort((a, b) => (b.cvssScore as number) - (a.cvssScore as number));
  const cvss = scored[0] ?? severities.find((s) => s.cvssVector);
  if (cvss?.cvssVector) out.cvssVector = cvss.cvssVector;
  if (cvss?.cvssScore !== undefined) out.cvssScore = cvss.cvssScore;
  if (cvss?.cvssVersion) out.cvssVersion = cvss.cvssVersion;
  if (bestGhsa) out.ghsa = bestGhsa;
  return out;
}

function sortAliases(aliases: Iterable<string>): string[] {
  return [...new Set(aliases)].sort((a, b) => {
    const ca = a.startsWith('CVE-') ? 0 : 1;
    const cb = b.startsWith('CVE-') ? 0 : 1;
    return ca - cb || (a < b ? -1 : a > b ? 1 : 0);
  });
}

function mergeBlamed(lists: readonly BlamedSymbol[][]): BlamedSymbol[] {
  const rank: Record<BlamedSymbol['via'], number> = { 'member-access': 0, 'default-callable': 1, call: 2, backticks: 3, summary: 4 };
  const out = new Map<string, BlamedSymbol>();
  for (const list of lists) {
    for (const s of list) {
      const existing = out.get(s.name);
      if (!existing) {
        out.set(s.name, { ...s });
        continue;
      }
      if (s.kind === 'exported') existing.kind = 'exported';
      if (rank[s.via] < rank[existing.via]) existing.via = s.via;
    }
  }
  const list = [...out.values()];
  return [...list.filter((s) => s.kind === 'exported'), ...list.filter((s) => s.kind === 'internal')].slice(0, 8);
}

interface Instance {
  name: string;
  version: string;
  keys: string[];
  alias?: string;
}

function depTypeOf(graph: DependencyGraph, importName: string): { depType: DepType; spec: string } | null {
  const sections: DepType[] = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
  for (const section of sections) {
    const spec = graph.root[section][importName];
    if (typeof spec === 'string') return { depType: section, spec };
  }
  return null;
}

function unionPaths(graph: DependencyGraph, keys: readonly string[]): string[][] {
  const out: string[][] = [];
  const seen = new Set<string>();
  for (const key of keys) {
    for (const p of dependencyPaths(graph, key, { maxPaths: 3, maxDepth: 10 })) {
      const text = p.join(' > ');
      if (seen.has(text)) continue;
      seen.add(text);
      out.push(p);
    }
  }
  return out.sort((a, b) => a.length - b.length).slice(0, 3);
}

// pure, no network
export function buildCaseFile(input: BuildCaseFileInput): CaseFile {
  const { graph, osv } = input;
  const scannedAt = input.scannedAt ?? new Date().toISOString();
  const instances = new Map<string, Instance>();
  for (const node of graph.nodes.values()) {
    const key = pairKey(node.name, node.version);
    const existing = instances.get(key);
    if (existing) existing.keys.push(node.key);
    else instances.set(key, { name: node.name, version: node.version, keys: [node.key], alias: node.alias });
  }

  const packages: PackageCase[] = [];
  const vulnerabilities: VulnCase[] = [];
  const osvRecords: Record<string, OsvRecord> = {};
  for (const [key, inst] of instances) {
    const ids = osv.idsByPackage.get(key) ?? [];
    if (ids.length === 0) continue;
    const records = ids.map((id) => osv.records.get(id)).filter((r): r is OsvRecord => r !== undefined && !r.withdrawn);
    const relevant = records.filter((r) => recordAffects(r, inst.name, inst.version));
    if (relevant.length === 0) continue;
    const nodes = inst.keys.map((k) => graph.nodes.get(k)).filter((n): n is PackageNode => n !== undefined);
    const isDirect = nodes.some((n) => n.isDirect);
    const isDevOnly = nodes.length > 0 && nodes.every((n) => n.dev);
    const paths = unionPaths(graph, inst.keys);
    const usage = input.usage.get(inst.name) ?? emptyUsage(inst.name);
    const deprecatedSet = input.deprecated.get(inst.name) ?? new Set<string>();
    const available = input.available.get(inst.name) ?? [];
    const cases: VulnCase[] = [];
    for (const group of mergeAliasedRecords(relevant)) {
      const primary = group[0] as OsvRecord;
      const others = group.slice(1);
      const ranges = group.flatMap((r) => npmEntries(r, inst.name).flatMap(evaluableRanges));
      const installed = parseVersion(inst.version);
      const fixedVersions = fixedVersionsFromRanges(ranges).filter((v) => {
        const parsed = parseVersion(v);
        return !installed || !parsed || parsed.compare(installed) > 0;
      });
      const malware = group.some((r) => r.id.startsWith('MAL-'));
      let recommendedFix = malware ? null : pickFix(fixedVersions, inst.version, deprecatedSet, { available, ranges });
      if (!recommendedFix && !malware && ranges.length > 0 && available.length > 0) {
        const derived = pickPackageFix([{ id: primary.id, ranges, fixedVersions }], inst.version, available, deprecatedSet);
        if (derived && derived.remaining.length === 0) recommendedFix = { version: derived.version, majorBump: derived.majorBump };
      }
      let affectedRange = describeRanges(ranges);
      if (affectedRange === 'unknown') {
        const listed = [...new Set(group.flatMap((r) => npmEntries(r, inst.name).flatMap((e) => e.versions ?? [])))];
        if (listed.length > 0) affectedRange = `versions ${sortVersions(listed).slice(0, 6).join(', ')}${listed.length > 6 ? `, and ${listed.length - 6} more` : ''}`;
      }
      const details = group.map((r) => r.details ?? '').filter(Boolean).join('\n\n');
      const summaries = group.map((r) => r.summary ?? '').filter(Boolean).join('. ');
      const blamedSymbols = mergeBlamed([extractBlamedSymbols(details, summaries, inst.name, usage)]);
      const aliases = sortAliases(
        [...group.flatMap((r) => r.aliases ?? []), ...others.map((r) => r.id)].filter((a) => typeof a === 'string' && a !== '' && a !== primary.id),
      );
      const modified = group.map((r) => r.modified ?? '').sort((a, b) => (normalizeTimestamp(a) < normalizeTimestamp(b) ? 1 : -1))[0] ?? '';
      const summary = primary.summary?.trim() || others.find((r) => r.summary?.trim())?.summary?.trim() || excerpt(primary.details ?? '', 140) || primary.id;
      const vuln: VulnCase = {
        id: primary.id,
        aliases,
        mergedIds: others.map((r) => r.id),
        package: inst.name,
        installedVersion: inst.version,
        summary,
        detailsExcerpt: excerpt(primary.details ?? summary),
        blamedSymbols,
        severity: worstSeverity(group.map(severityOf)),
        cweIds: [...new Set(group.flatMap((r) => (Array.isArray(r.database_specific?.cwe_ids) ? r.database_specific.cwe_ids : [])))].sort(),
        malware,
        affectedRange,
        ranges,
        fixedVersions,
        recommendedFix,
        isDirect,
        isDevOnly,
        dependencyPaths: paths,
        references: uniqueRefs(group),
        published: primary.published ?? '',
        modified,
      };
      cases.push(vuln);
      for (const r of group) osvRecords[r.id] = r;
    }
    cases.sort(
      (a, b) =>
        Number(b.malware) - Number(a.malware) ||
        GHSA_RANK[severityLabel(b.severity, b.malware)] - GHSA_RANK[severityLabel(a.severity, a.malware)] ||
        (b.severity.cvssScore ?? 0) - (a.severity.cvssScore ?? 0) ||
        (a.id < b.id ? -1 : 1),
    );
    const worst = cases.reduce<SeverityLabel>((w, c) => {
      const label = severityLabel(c.severity, c.malware);
      return GHSA_RANK[label] > GHSA_RANK[w] ? label : w;
    }, 'UNKNOWN');
    const dependents: PackageRef[] = [];
    const seenDependents = new Set<string>();
    for (const node of nodes) {
      for (const parentKey of node.parents) {
        const parent = graph.nodes.get(parentKey);
        if (!parent) continue;
        const ref = `${parent.name}@${parent.version}`;
        if (seenDependents.has(ref)) continue;
        seenDependents.add(ref);
        dependents.push({ name: parent.name, version: parent.version });
      }
    }
    dependents.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    const direct = isDirect ? depTypeOf(graph, inst.alias ?? inst.name) : null;
    const deprecation =
      nodes.find((n) => n.deprecated)?.deprecated ??
      input.deprecationMessages?.get(key) ??
      (deprecatedSet.has(inst.version) ? 'Deprecated in the npm registry' : null);
    packages.push({
      name: inst.name,
      version: inst.version,
      keys: [...inst.keys].sort(),
      isDirect,
      isDevOnly,
      depType: direct?.depType ?? null,
      spec: direct?.spec ?? null,
      dependencyPaths: paths,
      dependents,
      vulnIds: cases.map((c) => c.id),
      worstSeverity: worst,
      usage,
      deprecated: deprecation ?? null,
      latestVersion: input.latest?.get(inst.name) ?? null,
    });
    vulnerabilities.push(...cases);
  }

  packages.sort(
    (a, b) => GHSA_RANK[b.worstSeverity] - GHSA_RANK[a.worstSeverity] || b.vulnIds.length - a.vulnIds.length || (a.name < b.name ? -1 : a.name > b.name ? 1 : a.version < b.version ? -1 : 1),
  );
  const order = new Map(packages.map((p, i) => [pairKey(p.name, p.version), i]));
  const sortedVulns = vulnerabilities
    .map((v, i) => ({ v, i }))
    .sort((a, b) => (order.get(pairKey(a.v.package, a.v.installedVersion)) ?? 0) - (order.get(pairKey(b.v.package, b.v.installedVersion)) ?? 0) || a.i - b.i)
    .map((x) => x.v);

  const counts = graphCounts(graph);
  const bySeverity: Record<SeverityLabel, number> = { CRITICAL: 0, HIGH: 0, MODERATE: 0, LOW: 0, UNKNOWN: 0 };
  for (const v of sortedVulns) bySeverity[severityLabel(v.severity, v.malware)] += 1;
  const caseCounts: CaseFileCounts = {
    dependencies: counts.total,
    direct: counts.direct,
    dev: counts.dev,
    vulnerablePackages: packages.length,
    vulnerabilities: sortedVulns.length,
    bySeverity,
  };
  const lockRel = path.isAbsolute(input.lockfilePath) ? relativePosix(input.projectRoot, input.lockfilePath) : input.lockfilePath.replace(/\\/g, '/');
  return {
    version: CASE_FILE_VERSION,
    project: {
      root: input.projectRoot,
      name: input.projectName,
      lockfile: lockRel.startsWith('..') ? input.lockfilePath : lockRel,
      lockfileVersion: graph.lockfileVersion,
    },
    scannedAt,
    vulnSource: { ...osv.source },
    counts: caseCounts,
    packages,
    vulnerabilities: sortedVulns,
    osvRecords,
  };
}

// atomic, returns sha256
export async function saveCaseFile(file: string, caseFile: CaseFile): Promise<string> {
  await writeJsonAtomic(file, caseFile);
  return hashJson(caseFile);
}

// throws on another version
export async function loadCaseFile(file: string): Promise<CaseFile | null> {
  let data: CaseFile | null;
  try {
    data = await readJsonIfExists<CaseFile>(file);
  } catch (err) {
    throw new PatchPilotError(`The case file ${file} is unreadable: ${errorMessage(err)}`, {
      exitCode: EXIT.USAGE,
      hint: 'Run `patch-pilot scan` again to regenerate it.',
      cause: err,
    });
  }
  if (data === null) return null;
  if (!data || typeof data !== 'object' || typeof data.version !== 'number' || !Array.isArray(data.vulnerabilities) || !Array.isArray(data.packages)) {
    throw new PatchPilotError(`${file} is not a PatchPilot case file`, { exitCode: EXIT.USAGE, hint: 'Run `patch-pilot scan` again to regenerate it.' });
  }
  if (data.version !== CASE_FILE_VERSION) {
    throw new PatchPilotError(`The case file ${file} has version ${data.version}; this PatchPilot reads version ${CASE_FILE_VERSION}.`, {
      exitCode: EXIT.USAGE,
      hint: 'Run `patch-pilot scan` again to regenerate it.',
    });
  }
  if (!data.osvRecords || typeof data.osvRecords !== 'object') data.osvRecords = {};
  return data;
}

function plural(n: number, word: string, pluralWord = `${word}s`): string {
  return `${n} ${n === 1 ? word : pluralWord}`;
}

// "OSV.dev (cache, 3 h old)"
export function formatVulnSource(source: VulnSourceInfo): string {
  return `OSV.dev (${source.mode}, ${formatDataAge(source.ageHours)})`;
}

export interface SummaryOptions {
  // default true
  checks?: boolean;
  // default true
  table?: boolean;
  // default true, never with --quiet
  list?: boolean;
}

// [text, dim part] pairs
export function summaryCheckLines(caseFile: CaseFile): [string, string | undefined][] {
  const c = caseFile.counts;
  return [
    ['Discovered lockfile', caseFile.project.lockfile],
    [`Parsed ${plural(c.dependencies, 'dependency', 'dependencies')}`, `${c.direct} direct · ${c.dev} dev`],
    ['Vulnerability data', formatVulnSource(caseFile.vulnSource)],
    [`Found ${plural(c.vulnerabilities, 'CVE')} across ${plural(c.vulnerablePackages, 'package')}`, undefined],
  ];
}

export function renderCaseFileSummary(caseFile: CaseFile, ui: Ui, options: SummaryOptions = {}): string {
  const lines: string[] = [];
  if (options.checks !== false) for (const [text, dim] of summaryCheckLines(caseFile)) lines.push(ui.formatCheck(text, dim));
  if (options.table !== false && caseFile.counts.vulnerabilities > 0) {
    const rows = SEVERITY_ORDER.filter((label) => caseFile.counts.bySeverity[label] > 0).map((label) => {
      const names = [...new Set(caseFile.vulnerabilities.filter((v) => severityLabel(v.severity, v.malware) === label).map((v) => v.package))];
      return { severity: ui.severity(label), cves: caseFile.counts.bySeverity[label], packages: names.join(', ') };
    });
    if (lines.length > 0) lines.push('');
    lines.push(
      ui.table(
        [
          { key: 'severity', header: 'Severity', minWidth: 8 },
          { key: 'cves', header: 'CVEs', align: 'right' },
          { key: 'packages', header: 'Packages', maxWidth: 70 },
        ],
        rows,
        { indent: 2 },
      ),
    );
  }
  if (options.list !== false && !ui.quiet && caseFile.vulnerabilities.length > 0) {
    const list = renderVulnerabilityList(caseFile, ui);
    if (list !== '') {
      if (lines.length > 0) lines.push('');
      lines.push(list);
    }
  }
  return lines.join('\n');
}

const CVE_ALIAS = /^CVE-\d{4}-\d+$/i;
const naturalOrder = new Intl.Collator('en', { numeric: true, sensitivity: 'base' }).compare;
// longest label (CRITICAL)
const SEVERITY_COLUMN = 8;
// drop dim second id below this
const MIN_SUMMARY_ROOM = 20;

interface ListedVuln {
  vuln: VulnCase;
  label: SeverityLabel;
  // CVE alias, else OSV id
  primary: string;
  // set when primary is the CVE
  other: string | null;
}

function listedVuln(vuln: VulnCase): ListedVuln {
  const cve = (vuln.aliases ?? []).find((a) => CVE_ALIAS.test(a));
  return { vuln, label: severityLabel(vuln.severity, vuln.malware), primary: cve ?? vuln.id, other: cve && cve !== vuln.id ? vuln.id : null };
}

function plainInline(text: string): string {
  return text
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/`+/g, '')
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/\s+/g, ' ')
    .trim();
}

// keeps 4.17.21 whole
function firstSentenceOf(text: string): string {
  const match = /^.*?[.!?](?=\s|$)/.exec(text);
  return (match ? match[0] : text).trim();
}

// summary, else first sentence
export function advisorySentence(vuln: VulnCase, caseFile?: Pick<CaseFile, 'osvRecords'> | null): string {
  const summary = plainInline(vuln.summary ?? '');
  if (summary !== '' && summary !== vuln.id) return firstSentenceOf(summary);
  const details = (vuln.detailsExcerpt ?? '').trim() || caseFile?.osvRecords?.[vuln.id]?.details || '';
  return firstSentenceOf(plainInline(stripMarkdown(details))) || 'No description in the advisory';
}

// scope's @ stays
function hopName(hop: string): string {
  const at = hop.lastIndexOf('@');
  return at > 0 ? hop.slice(0, at) : hop;
}

// "transitive via vite and 3 more"
function relationText(pkg: PackageCase): string {
  if (pkg.isDirect) return 'direct';
  const parents: string[] = [];
  const add = (name: string | undefined): void => {
    if (name && name !== pkg.name && !parents.includes(name)) parents.push(name);
  };
  // shortest path parent first
  for (const route of pkg.dependencyPaths ?? []) add(route.length >= 2 ? hopName(route[route.length - 2] ?? '') : undefined);
  for (const dependent of pkg.dependents ?? []) add(dependent.name);
  if (parents.length === 0) return 'transitive';
  if (parents.length === 1) return `transitive via ${parents[0]}`;
  if (parents.length === 2) return `transitive via ${parents[0]} and ${parents[1]}`;
  return `transitive via ${parents[0]} and ${parents.length - 1} more`;
}

const SCOPE_WORDS: Record<FileScope, [string, string]> = {
  source: ['source file', 'source files'],
  test: ['test file', 'test files'],
  config: ['config file', 'config files'],
  scripts: ['script', 'scripts'],
};

function importText(usage: UsageEvidence | undefined): string {
  if (!usage?.imported) return 'not imported';
  const files = new Map<FileScope, Set<string>>();
  for (const site of usage.files ?? []) {
    const set = files.get(site.scope) ?? new Set<string>();
    set.add(site.path);
    files.set(site.scope, set);
  }
  const parts: string[] = [];
  for (const scope of ['source', 'test', 'config', 'scripts'] as const) {
    const n = files.size > 0 ? (files.get(scope)?.size ?? 0) : (usage.scopes?.[scope] ?? 0);
    if (n > 0) parts.push(plural(n, SCOPE_WORDS[scope][0], SCOPE_WORDS[scope][1]));
  }
  return parts.length > 0 ? `imported in ${parts.join(', ')}` : 'imported';
}

// same rule as vulnAffects
function stillAffected(vuln: VulnCase, version: string, caseFile: CaseFile): boolean {
  if (vuln.ranges.length > 0) return isAffected(version, vuln.ranges);
  const entries = [vuln.id, ...vuln.mergedIds].flatMap((id) => {
    const record = caseFile.osvRecords?.[id];
    return record ? npmEntries(record, vuln.package) : [];
  });
  if (entries.length === 0) return version === vuln.installedVersion;
  return entries.some((entry) => isAffectedByEntry(version, entry));
}

// same rule as chooseTarget
function packageTarget(pkg: PackageCase, vulns: readonly VulnCase[], caseFile: CaseFile): { version: string; majorBump: boolean } | null {
  const candidates = [
    ...new Set(vulns.map((v) => v.recommendedFix?.version).filter((v): v is string => typeof v === 'string' && parseVersion(v) !== null && compareVersions(v, pkg.version) > 0)),
  ].sort((a, b) => compareVersions(b, a));
  const cleared = (version: string): number => vulns.filter((v) => !stillAffected(v, version, caseFile)).length;
  let pick = candidates.find((version) => cleared(version) === vulns.length);
  if (!pick) {
    const scored = candidates.map((version) => ({ version, n: cleared(version) })).filter((s) => s.n > 0);
    const best = (list: typeof scored): string | undefined => [...list].sort((a, b) => b.n - a.n || compareVersions(b.version, a.version))[0]?.version;
    pick = best(scored.filter((s) => isSameLine(pkg.version, s.version))) ?? best(scored);
  }
  return pick ? { version: pick, majorBump: isMajorBump(pkg.version, pick) } : null;
}

// astro@5.1.2  direct · 12 CVEs · fix 5.14.1 (major)
function packageHeader(pkg: PackageCase, vulns: readonly VulnCase[], caseFile: CaseFile, ui: Ui, width: number): string {
  const target = packageTarget(pkg, vulns, caseFile);
  const parts = [relationText(pkg)];
  if (pkg.isDevOnly) parts.push('dev only');
  parts.push(importText(pkg.usage), plural(vulns.length, 'CVE'), target ? `fix ${target.version}${target.majorBump ? ' (major)' : ''}` : 'no fix');
  const name = `${pkg.name}@${pkg.version}`;
  const detail = truncateLine(parts.join(` ${ui.glyphs.dot} `), Math.max(8, width - name.length - 2), ui.glyphs.ellipsis);
  return `${ui.c.bold(name)}  ${ui.c.dim(detail)}`;
}

// recommended, else first fixed
function fixedInText(vuln: VulnCase, ui: Ui): string {
  const version = vuln.recommendedFix?.version ?? vuln.fixedVersions?.[0];
  return version ? `${ui.glyphs.arrow} fixed in ${version}` : 'no fix';
}

// one aligned line per CVE
function cveLines(listed: readonly ListedVuln[], caseFile: CaseFile, ui: Ui, width: number): string[] {
  const c = ui.c;
  const fixes = listed.map((l) => fixedInText(l.vuln, ui));
  const fixWidth = Math.max(0, ...fixes.map((f) => f.length));
  const idText = (l: ListedVuln, withOther: boolean): string => (withOther && l.other ? `${l.primary} (${l.other})` : l.primary);
  const layout = (withOther: boolean): { idWidth: number; room: number } => {
    const idWidth = Math.max(0, ...listed.map((l) => idText(l, withOther).length));
    return { idWidth, room: width - (2 + SEVERITY_COLUMN + 2 + idWidth + 2) - 2 - fixWidth };
  };
  const withOther = !(layout(true).room < MIN_SUMMARY_ROOM && listed.some((l) => l.other));
  const { idWidth, room } = layout(withOther);
  const summaries = listed.map((l) => truncateLine(ui.text(advisorySentence(l.vuln, caseFile)), Math.max(12, room), ui.glyphs.ellipsis));
  const summaryWidth = Math.max(0, ...summaries.map((s) => s.length));
  return listed.map((l, i) => {
    const id = withOther && l.other ? `${l.primary} ${c.dim(`(${l.other})`)}` : l.primary;
    const idPad = ' '.repeat(Math.max(0, idWidth - idText(l, withOther).length));
    const severity = `${ui.severity(l.label)}${' '.repeat(Math.max(0, SEVERITY_COLUMN - l.label.length))}`;
    return `  ${severity}  ${id}${idPad}  ${(summaries[i] ?? '').padEnd(summaryWidth)}  ${c.dim(fixes[i] ?? '')}`;
  });
}

// worst severity first
export function renderVulnerabilityList(caseFile: CaseFile, ui: Ui, width = ui.terminalWidth): string {
  const groups = caseFile.packages
    .map((pkg) => {
      const listed = caseFile.vulnerabilities
        .filter((v) => v.package === pkg.name && v.installedVersion === pkg.version)
        .map(listedVuln)
        .sort((a, b) => GHSA_RANK[b.label] - GHSA_RANK[a.label] || naturalOrder(a.primary, b.primary) || naturalOrder(a.vuln.id, b.vuln.id));
      const worst = listed.reduce((rank, l) => Math.max(rank, GHSA_RANK[l.label]), 0);
      return { pkg, listed, worst };
    })
    .filter((g) => g.listed.length > 0)
    .sort((a, b) => b.worst - a.worst || naturalOrder(a.pkg.name, b.pkg.name) || compareVersions(a.pkg.version, b.pkg.version));
  return groups
    .map(({ pkg, listed }) =>
      [
        packageHeader(
          pkg,
          listed.map((l) => l.vuln),
          caseFile,
          ui,
          width,
        ),
        ...cveLines(listed, caseFile, ui, width),
      ].join('\n'),
    )
    .join('\n\n');
}

async function mapPool<T, R>(items: readonly T[], concurrency: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(concurrency, items.length)) }, async () => {
    for (;;) {
      const index = next;
      next += 1;
      if (index >= items.length) return;
      out[index] = await fn(items[index] as T);
    }
  });
  await Promise.all(workers);
  return out;
}

function warmUp(provider: ChatProvider | null | undefined): void {
  if (!provider || typeof provider.warmup !== 'function') return;
  try {
    Promise.resolve(provider.warmup()).catch(() => {});
  } catch {
    // best effort
  }
}

async function readProjectName(root: string, fallback: string | null): Promise<string> {
  try {
    const pkg = await readJsonIfExists<{ name?: unknown }>(path.join(root, 'package.json'));
    if (pkg && typeof pkg.name === 'string' && pkg.name.trim() !== '') return pkg.name.trim();
  } catch {
    // fall through
  }
  return fallback && fallback !== '' ? fallback : path.basename(root);
}

function displayPath(root: string, file: string): string {
  const rel = relativePosix(root, file);
  return rel.startsWith('..') ? file : rel;
}

// discover, parse, osv, registry, usage, save
export async function runPhase1(config: Config, deps: Phase1Deps): Promise<CaseFile> {
  const { ui, audit, signal } = deps;
  warmUp(deps.provider);
  const root = config.projectRoot;
  let spinner: Spinner | null = null;
  const step = (text: string): Spinner => {
    spinner?.stop();
    spinner = ui.spinner(text);
    return spinner;
  };
  const done = (text: string, dim?: string): void => {
    spinner?.stop();
    spinner = null;
    ui.check(text, dim);
  };

  step('Looking for the lockfile...');
  const discovered = await discoverProject(root);
  const unsupportedKinds = discovered.unsupported.map((u) => u.kind);
  let lockfilePath = discovered.lockfilePath;
  let lockfileKind = discovered.lockfileKind;
  let generated = false;
  const failDiscovery = (message: string, hint: string): never => {
    (spinner as Spinner | null)?.stop();
    spinner = null;
    audit.log({ event: 'discover.lockfile', lockfile: null, kind: null, lockfileVersion: null, generated: false, unsupported: unsupportedKinds });
    throw new EnvironmentError(message, { hint });
  };
  if (!discovered.packageJsonPath && !lockfilePath) {
    failDiscovery(unsupportedLockfileMessage(discovered), 'Run patch-pilot inside an npm project (a directory with package.json).');
  }
  // bun beside a supported one, or several
  const discoveryNote = lockfilePath ? unsupportedLockfileMessage(discovered) : '';
  if (discoveryNote) {
    (spinner as Spinner | null)?.stop();
    spinner = null;
    ui.warn(discoveryNote);
  }
  if (!lockfilePath) {
    (spinner as Spinner | null)?.stop();
    spinner = null;
    const message = unsupportedLockfileMessage(discovered);
    if (!(config.interactive && ui.interactive)) failDiscovery(message, `Create a lockfile with: ${LOCKFILE_COMMAND}`);
    ui.warn(message);
    const answer = await ui.singleKeyPrompt('Generate a scratch lockfile in .patch-pilot/tmp/?', 'y/n');
    if (answer !== 'y') failDiscovery('No lockfile to scan.', `Create one with: ${LOCKFILE_COMMAND}`);
    step('Generating a scratch lockfile (npm install --package-lock-only)...');
    try {
      lockfilePath = await generateScratchLockfile(root, config.paths.tmpDir);
    } catch (err) {
      (spinner as Spinner | null)?.stop();
      spinner = null;
      audit.log({ event: 'discover.lockfile', lockfile: null, kind: null, lockfileVersion: null, generated: false, unsupported: unsupportedKinds });
      throw err;
    }
    lockfileKind = 'package-lock';
    generated = true;
  }
  const lockfile = lockfilePath as string;
  const lockDisplay = displayPath(root, lockfile);

  step(`Parsing ${lockDisplay}...`);
  let graph: DependencyGraph;
  try {
    graph = await loadDependencyGraph(generated ? path.dirname(lockfile) : root, lockfile);
  } catch (err) {
    (spinner as Spinner | null)?.stop();
    spinner = null;
    audit.log({ event: 'discover.lockfile', lockfile: lockDisplay, kind: lockfileKind, lockfileVersion: null, generated, unsupported: unsupportedKinds });
    const regenerate = generated ? LOCKFILE_COMMAND : lockfileKind === 'pnpm' ? 'pnpm install --lockfile-only' : lockfileKind === 'yarn' ? 'yarn install' : LOCKFILE_COMMAND;
    throw new EnvironmentError(errorMessage(err), { hint: `Regenerate the lockfile with: ${regenerate}`, cause: err });
  }
  audit.log({ event: 'discover.lockfile', lockfile: lockDisplay, kind: lockfileKind, lockfileVersion: graph.lockfileVersion, generated, unsupported: unsupportedKinds });
  const manager = graph.packageManager ?? 'npm';
  done('Discovered lockfile', generated ? `${lockDisplay} (generated from package.json)` : manager === 'npm' ? lockDisplay : `${lockDisplay} (${MANAGER_NAMES[manager]})`);
  const counts = graphCounts(graph);
  audit.log({ event: 'deps.parsed', total: counts.total, direct: counts.direct, dev: counts.dev, lockfileVersion: graph.lockfileVersion });
  done(`Parsed ${plural(counts.total, 'dependency', 'dependencies')}`, `${counts.direct} direct · ${counts.dev} dev`);

  const ownDb = deps.db === undefined;
  let db: PatchPilotDb | null = deps.db ?? null;
  if (ownDb) {
    try {
      db = openDb(config.paths.dbFile);
    } catch (err) {
      ui.warn('The local cache is unavailable, continuing without it', errorMessage(err));
      db = null;
    }
  }
  try {
    // non-semver matches every range from "0"
    const queryable = [...graph.nodes.values()].filter((n) => parseVersion(n.version) !== null);
    const pairs = [...new Map(queryable.map((n) => [pairKey(n.name, n.version), { name: n.name, version: n.version }])).values()];
    const unversioned = graph.nodes.size - queryable.length;
    if (unversioned > 0) {
      (spinner as Spinner | null)?.stop();
      spinner = null;
      ui.infoLine(`${plural(unversioned, 'package')} without a registry version (git, file or link) ${unversioned === 1 ? 'is' : 'are'} not checked against OSV.dev`);
    }
    const osvLabel = config.offline ? 'Reading cached vulnerability data' : `Checking ${plural(pairs.length, 'package')} against OSV.dev`;
    step(`${osvLabel}...`);
    const osv = await queryOsv(pairs, {
      db,
      offline: config.offline,
      timeoutMs: config.timeouts.osvMs,
      signal,
      onProgress: (n, total, label) => {
        (spinner as Spinner | null)?.update(label === 'querybatch' ? `${osvLabel} (${n} of ${total})...` : `Downloading advisories (${n} of ${total})...`);
      },
    }).catch((err: unknown) => {
      (spinner as Spinner | null)?.stop();
      spinner = null;
      throw err;
    });
    audit.log({
      event: 'osv.query',
      mode: osv.source.mode,
      queried: osv.stats.queried,
      vulnIds: osv.stats.vulnIds,
      hydrated: osv.stats.hydrated,
      cacheHits: osv.stats.cacheHits,
      ageHours: osv.source.ageHours,
      ...(osv.source.warning ? { warning: osv.source.warning } : {}),
      durationMs: osv.stats.durationMs,
    });
    done('Vulnerability data', formatVulnSource(osv.source));
    if (osv.source.warning) ui.warn(osv.source.warning);

    const vulnerable = new Map<string, Set<string>>();
    for (const node of graph.nodes.values()) {
      if ((osv.idsByPackage.get(pairKey(node.name, node.version)) ?? []).length === 0) continue;
      const versions = vulnerable.get(node.name) ?? new Set<string>();
      versions.add(node.version);
      vulnerable.set(node.name, versions);
    }
    const names = [...vulnerable.keys()].sort();
    const deprecated = new Map<string, Set<string>>();
    const available = new Map<string, string[]>();
    const latest = new Map<string, string>();
    const deprecationMessages = new Map<string, string>();
    let registryFailures = 0;
    if (names.length > 0) {
      step(config.offline ? 'Reading cached npm registry data...' : `Checking the npm registry for ${plural(names.length, 'package')}...`);
      await mapPool(names, 6, async (name) => {
        try {
          const packument = await getPackument(name, { db, offline: config.offline, timeoutMs: config.timeouts.registryMs, signal });
          if (!packument) {
            if (config.offline) registryFailures += 1;
            return;
          }
          const versions = sortVersions(Object.keys(packument.versions));
          available.set(name, versions);
          const dep = new Set<string>();
          for (const [v, info] of Object.entries(packument.versions)) if (typeof info.deprecated === 'string' && info.deprecated.trim() !== '') dep.add(v);
          deprecated.set(name, dep);
          const tag = packument['dist-tags']?.latest;
          if (typeof tag === 'string') latest.set(name, tag);
          for (const v of vulnerable.get(name) ?? []) {
            const message = packument.versions[v]?.deprecated;
            if (typeof message === 'string' && message.trim() !== '') deprecationMessages.set(pairKey(name, v), message);
          }
        } catch {
          registryFailures += 1;
        }
      });
      (spinner as Spinner | null)?.stop();
      spinner = null;
      if (registryFailures > 0) {
        ui.warn(
          `npm registry data is unavailable for ${plural(registryFailures, 'package')}`,
          'fix versions are not checked against deprecations for them',
        );
      }
    }

    // import names include npm aliases
    step('Locating usage in the project code...');
    const importNames = new Map<string, string>();
    for (const name of names) importNames.set(name, name);
    for (const node of graph.nodes.values()) if (node.alias && vulnerable.has(node.name)) importNames.set(node.alias, node.name);
    const rawUsage = await collectUsageEvidence(root, [...importNames.keys()], { exclude: config.exclude, signal });
    const usage = new Map<string, UsageEvidence>();
    for (const [importName, evidence] of rawUsage) {
      const real = importNames.get(importName) ?? importName;
      const existing = usage.get(real);
      if (!existing) {
        usage.set(real, { ...evidence, package: real });
        continue;
      }
      existing.imported = existing.imported || evidence.imported;
      existing.files.push(...evidence.files);
      for (const scope of ['source', 'test', 'config', 'scripts'] as const) existing.scopes[scope] += evidence.scopes[scope];
      for (const [member, n] of Object.entries(evidence.membersUsed)) existing.membersUsed[member] = (existing.membersUsed[member] ?? 0) + n;
      existing.bindingCalls += evidence.bindingCalls;
      if (evidence.truncated) existing.truncated = true;
      if (evidence.method && existing.method && evidence.method !== existing.method) existing.method = 'mixed';
      if (evidence.dynamicAccess?.length) existing.dynamicAccess = [...(existing.dynamicAccess ?? []), ...evidence.dynamicAccess];
      if (evidence.indirectPaths?.length) existing.indirectPaths = [...(existing.indirectPaths ?? []), ...evidence.indirectPaths];
    }
    // unimported transitive: check dependents' code
    for (const [real, evidence] of usage) {
      if (evidence.imported) continue;
      const dependents: DependentRef[] = [];
      for (const key of graph.byName.get(real) ?? []) {
        for (const parentKey of graph.nodes.get(key)?.parents ?? []) {
          const parent = parentKey === '' ? undefined : graph.nodes.get(parentKey);
          if (parent && !dependents.some((d) => d.name === parent.name && d.version === parent.version)) dependents.push({ name: parent.name, version: parent.version, dir: parent.key });
        }
      }
      if (dependents.length === 0) continue;
      const names = [...importNames.entries()].filter(([, r]) => r === real).map(([importName]) => importName);
      const found = await collectDependentUsage(root, names, dependents, { signal }).catch(() => undefined);
      if (found !== undefined) evidence.dependentUsage = found;
    }
    (spinner as Spinner | null)?.stop();
    spinner = null;

    const caseFile = buildCaseFile({
      projectRoot: root,
      projectName: await readProjectName(root, graph.root.name),
      lockfilePath: lockfile,
      graph,
      osv,
      usage,
      deprecated,
      available,
      latest,
      deprecationMessages,
    });
    done(`Found ${plural(caseFile.counts.vulnerabilities, 'CVE')} across ${plural(caseFile.counts.vulnerablePackages, 'package')}`);
    if (caseFile.packages.length > 0) {
      const scanned = [...usage.values()][0]?.scannedFiles ?? 0;
      const imported = caseFile.packages.filter((p) => p.usage.imported).length;
      done('Located usage evidence', `${plural(scanned, 'file')} scanned · ${imported} of ${caseFile.packages.length} vulnerable packages imported`);
      if ([...usage.values()].some((u) => u.truncated)) ui.warn('The file walker stopped at its file cap, so the usage evidence may be incomplete.');
    }
    const sha256 = await saveCaseFile(config.paths.caseFile, caseFile);
    audit.log({
      event: 'casefile.saved',
      path: displayPath(root, config.paths.caseFile),
      sha256,
      packages: caseFile.packages.length,
      vulnerabilities: caseFile.vulnerabilities.length,
    });
    const table = renderCaseFileSummary(caseFile, ui, { checks: false });
    if (table) {
      ui.info('');
      ui.info(table);
    }
    ui.info('');
    ui.infoLine('Case file', displayPath(root, config.paths.caseFile));
    return caseFile;
  } finally {
    (spinner as Spinner | null)?.stop();
    if (ownDb) db?.close();
  }
}
