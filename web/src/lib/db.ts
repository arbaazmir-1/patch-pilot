import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';
import { dbFile } from './paths.ts';

let db: Database.Database | null = null;

export function getDb(): Database.Database {
  if (db) return db;
  fs.mkdirSync(path.dirname(dbFile()), { recursive: true });
  db = new Database(dbFile());
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  migrate(db);
  return db;
}

const SCHEMA_VERSION = 2;

function migrate(database: Database.Database): void {
  const version = database.pragma('user_version', { simple: true }) as number;
  if (version < 2) {
    // v1 unique key broke on dup cves
    database.exec('DROP TABLE IF EXISTS findings');
    if (tableExists(database, 'projects')) database.exec('UPDATE projects SET report_mtime_ms = NULL');
  }
  database.exec(`
    CREATE TABLE IF NOT EXISTS projects (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      root TEXT NOT NULL UNIQUE,
      remote TEXT,
      lockfile TEXT,
      lockfile_version INTEGER,
      scanned_at TEXT,
      report_generated_at TEXT,
      patch_pilot_version TEXT,
      vuln_source_label TEXT,
      dependencies INTEGER,
      direct_deps INTEGER,
      dev_deps INTEGER,
      vulnerable_packages INTEGER,
      total_vulnerabilities INTEGER,
      investigated INTEGER,
      critical_count INTEGER NOT NULL DEFAULT 0,
      high_count INTEGER NOT NULL DEFAULT 0,
      medium_count INTEGER NOT NULL DEFAULT 0,
      low_count INTEGER NOT NULL DEFAULT 0,
      noise_count INTEGER NOT NULL DEFAULT 0,
      accepted_count INTEGER NOT NULL DEFAULT 0,
      findings_total INTEGER NOT NULL DEFAULT 0,
      report_json TEXT,
      report_mtime_ms INTEGER,
      imported_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS findings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      vuln_id TEXT NOT NULL,
      cve TEXT NOT NULL,
      package TEXT NOT NULL,
      version TEXT,
      summary TEXT,
      ghsa TEXT,
      cvss REAL,
      affected_range TEXT,
      fixed_versions TEXT,
      direct INTEGER,
      dev_only INTEGER,
      risk TEXT,
      reachable TEXT,
      confidence REAL,
      reasoning TEXT,
      evidence TEXT,
      recommendation_action TEXT,
      recommendation_text TEXT,
      target_version TEXT,
      major_bump INTEGER,
      badges TEXT,
      "references" TEXT,
      accepted INTEGER NOT NULL DEFAULT 0,
      sort_index INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
    CREATE INDEX IF NOT EXISTS idx_findings_risk ON findings(risk);

    CREATE TABLE IF NOT EXISTS watch_paths (
      path TEXT PRIMARY KEY,
      added_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS hidden_projects (
      root TEXT PRIMARY KEY,
      hidden_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS meta (
      key TEXT PRIMARY KEY,
      value TEXT
    );
  `);
  database.pragma(`user_version = ${SCHEMA_VERSION}`);
}

function tableExists(database: Database.Database, name: string): boolean {
  return database.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name) !== undefined;
}

export function setMeta(key: string, value: string): void {
  getDb()
    .prepare('INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
    .run(key, value);
}

export function getMeta(key: string): string | null {
  const row = getDb().prepare('SELECT value FROM meta WHERE key = ?').get(key) as { value: string } | undefined;
  return row?.value ?? null;
}
