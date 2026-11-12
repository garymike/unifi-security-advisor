import type { Finding } from '../audit/types.js';
import type { AnswerValue, Tier } from './schema.js';
import { applyAnswersAndTensions, type StoredAnswer } from '../wizard/reportAssembly.js';

/**
 * Names of the statements the backend will run (src-tauri/src/db.rs). The SQL
 * itself lives in Rust: the page can pick a statement and bind its
 * parameters, but cannot send SQL of its own.
 */
type WriteStatement = 'insertRun' | 'updateRunTier' | 'insertFinding' | 'insertSite' | 'upsertAnswer' | 'setKv';
type ReadStatement = 'getFindings' | 'getAnswers' | 'getSiteIds' | 'getApiGaps' | 'listRuns' | 'getKv';
type Param = string | number | boolean | null;

export interface DbInstance {
  /** Run a write once per parameter row, in one transaction. */
  write(name: WriteStatement, rows: Param[][]): Promise<number>;
  read<T>(name: ReadStatement, values?: Param[]): Promise<T>;
}

export async function openDb(): Promise<DbInstance> {
  // Imported lazily so Vitest and the Node CLI (no Tauri context) can load this module.
  const { invoke } = await import('@tauri-apps/api/core');
  return {
    write: (name, rows) => invoke<number>('db_write', { name, rows }),
    read: <T>(name: ReadStatement, values: Param[] = []) => invoke<T>('db_read', { name, values }),
  };
}

export interface RunRow {
  id: string;
  timestamp: string;
  host: string | null;
  profile: string;
  tier: Tier;
  site_count: number;
}

export async function insertRun(
  db: DbInstance,
  host: string,
  profile: string,
  siteCount: number,
  tier: Tier = 'standard',
): Promise<string> {
  const id = crypto.randomUUID();
  await db.write('insertRun', [[id, new Date().toISOString(), host, profile, tier, siteCount]]);
  return id;
}

export async function updateRunTier(db: DbInstance, runId: string, tier: Tier): Promise<void> {
  await db.write('updateRunTier', [[tier, runId]]);
}

export async function insertFindings(db: DbInstance, runId: string, findings: Finding[]): Promise<void> {
  if (!findings.length) return;
  await db.write('insertFinding', findings.map(f => [
    f.id, runId, f.section, f.severity, f.status, f.title, f.currentState,
    f.recommendation, f.intentQuestion,
    JSON.stringify(f.evidence), JSON.stringify(f.mapsTo),
    f.effort, f.impact, f.floatTop ? 1 : 0,
  ]));
}

export async function insertSites(
  db: DbInstance,
  runId: string,
  sites: Array<{ siteId: string; siteName: string; apiGaps: string[] }>,
): Promise<void> {
  if (!sites.length) return;
  await db.write('insertSite', sites.map(s => [runId, s.siteId, s.siteName, JSON.stringify(s.apiGaps)]));
}

export async function upsertAnswer(
  db: DbInstance,
  runId: string,
  findingId: string,
  answer: AnswerValue,
  freeText: string,
  tier: Tier,
): Promise<void> {
  await db.write('upsertAnswer', [[runId, findingId, answer, freeText, tier, new Date().toISOString()]]);
}

export async function getFindings(db: DbInstance, runId: string): Promise<Finding[]> {
  const rows = await db.read<Record<string, unknown>[]>('getFindings', [runId]);
  return rows.map(r => ({
    id: String(r['id']),
    section: String(r['section']),
    severity: r['severity'] as Finding['severity'],
    status: r['status'] as Finding['status'],
    title: String(r['title']),
    currentState: String(r['current_state']),
    recommendation: r['recommendation'] != null ? String(r['recommendation']) : null,
    intentQuestion: r['intent_question'] != null ? String(r['intent_question']) : null,
    evidence: JSON.parse(String(r['evidence'] ?? '{}')),
    mapsTo: JSON.parse(String(r['maps_to'] ?? '{}')),
    effort: r['effort'] as Finding['effort'],
    impact: r['impact'] as Finding['impact'],
    floatTop: r['float_top'] === 1,
  }));
}

export async function getAnswers(db: DbInstance, runId: string): Promise<StoredAnswer[]> {
  const rows = await db.read<Record<string, unknown>[]>('getAnswers', [runId]);
  return rows.map(r => ({
    findingId: String(r['finding_id']),
    answer: r['answer'] as AnswerValue,
    freeText: r['free_text'] != null ? String(r['free_text']) : '',
  }));
}

export async function getSiteIds(db: DbInstance, runId: string): Promise<string[]> {
  const rows = await db.read<Record<string, unknown>[]>('getSiteIds', [runId]);
  return rows.map(r => String(r['site_id']));
}

/**
 * The union of API-coverage gaps recorded across a run's sites. Empty means the
 * run came from a backup file (full coverage, no gaps); a live/API run always
 * gaps at least `port_forwards`/`traffic_routes` (never requested over the API),
 * so an empty set reliably identifies backup-file mode.
 */
export async function getApiGaps(db: DbInstance, runId: string): Promise<string[]> {
  const rows = await db.read<Record<string, unknown>[]>('getApiGaps', [runId]);
  const gaps = new Set<string>();
  for (const r of rows) {
    try {
      for (const g of JSON.parse(String(r['api_gaps'] ?? '[]')) as unknown[]) gaps.add(String(g));
    } catch { /* ignore malformed api_gaps */ }
  }
  return [...gaps];
}

/**
 * A run's findings with the wizard's answers applied and cross-answer tensions
 * recomputed — the canonical view used everywhere a score or finding list is
 * shown (report, history, home), so they never disagree. Raw `getFindings` is
 * only for internals that must not reflect answers.
 */
export async function getAnsweredFindings(db: DbInstance, runId: string): Promise<Finding[]> {
  const [raw, answers, siteIds] = await Promise.all([
    getFindings(db, runId),
    getAnswers(db, runId),
    getSiteIds(db, runId),
  ]);
  return applyAnswersAndTensions(raw, answers, siteIds);
}

export async function listRuns(db: DbInstance): Promise<RunRow[]> {
  return db.read<RunRow[]>('listRuns');
}

export async function getKv(key: string): Promise<string | null> {
  const db = await openDb();
  const rows = await db.read<{ value: string }[]>('getKv', [key]);
  return rows.length ? rows[0]!.value : null;
}

export async function setKv(key: string, value: string): Promise<void> {
  const db = await openDb();
  await db.write('setKv', [[key, value]]);
}
