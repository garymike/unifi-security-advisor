import type { Finding } from '../audit/types.js';
import type { AnswerValue, Tier } from './schema.js';
import type { StoredAnswer } from '../wizard/reportAssembly.js';
import { CREATE_TABLES } from './schema.js';

// Database instance type — imported lazily to avoid breaking Vitest (which has no Tauri context)
type DbInstance = Awaited<ReturnType<typeof import('@tauri-apps/plugin-sql').default.load>>;

export async function openDb(): Promise<DbInstance> {
  const Database = (await import('@tauri-apps/plugin-sql')).default;
  const db = await Database.load('sqlite:unifi-advisor.db');
  for (const sql of CREATE_TABLES) await db.execute(sql);
  return db;
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
): Promise<string> {
  const id = crypto.randomUUID();
  await db.execute(
    'INSERT INTO runs (id, timestamp, host, profile, tier, site_count) VALUES (?, ?, ?, ?, ?, ?)',
    [id, new Date().toISOString(), host, profile, 'standard', siteCount],
  );
  return id;
}

export async function updateRunTier(db: DbInstance, runId: string, tier: Tier): Promise<void> {
  await db.execute('UPDATE runs SET tier = ? WHERE id = ?', [tier, runId]);
}

export async function insertFindings(db: DbInstance, runId: string, findings: Finding[]): Promise<void> {
  for (const f of findings) {
    await db.execute(
      `INSERT INTO findings (id, run_id, section, severity, status, title, current_state,
        recommendation, intent_question, evidence, maps_to, effort, impact, float_top)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        f.id, runId, f.section, f.severity, f.status, f.title, f.currentState,
        f.recommendation, f.intentQuestion,
        JSON.stringify(f.evidence), JSON.stringify(f.mapsTo),
        f.effort, f.impact, f.floatTop ? 1 : 0,
      ],
    );
  }
}

export async function insertSites(
  db: DbInstance,
  runId: string,
  sites: Array<{ siteId: string; siteName: string; apiGaps: string[] }>,
): Promise<void> {
  for (const s of sites) {
    await db.execute(
      'INSERT INTO sites (run_id, site_id, site_name, api_gaps) VALUES (?, ?, ?, ?)',
      [runId, s.siteId, s.siteName, JSON.stringify(s.apiGaps)],
    );
  }
}

export async function upsertAnswer(
  db: DbInstance,
  runId: string,
  findingId: string,
  answer: AnswerValue,
  freeText: string,
  tier: Tier,
): Promise<void> {
  await db.execute(
    `INSERT INTO answers (run_id, finding_id, answer, free_text, tier, answered_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(run_id, finding_id) DO UPDATE SET
       answer = excluded.answer, free_text = excluded.free_text,
       tier = excluded.tier, answered_at = excluded.answered_at`,
    [runId, findingId, answer, freeText, tier, new Date().toISOString()],
  );
}

export async function getFindings(db: DbInstance, runId: string): Promise<Finding[]> {
  const rows = await db.select<Record<string, unknown>[]>(
    'SELECT * FROM findings WHERE run_id = ? ORDER BY float_top DESC, severity',
    [runId],
  );
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
  const rows = await db.select<Record<string, unknown>[]>(
    'SELECT finding_id, answer, free_text FROM answers WHERE run_id = ?',
    [runId],
  );
  return rows.map(r => ({
    findingId: String(r['finding_id']),
    answer: r['answer'] as AnswerValue,
    freeText: r['free_text'] != null ? String(r['free_text']) : '',
  }));
}

export async function getSiteIds(db: DbInstance, runId: string): Promise<string[]> {
  const rows = await db.select<Record<string, unknown>[]>(
    'SELECT site_id FROM sites WHERE run_id = ?',
    [runId],
  );
  return rows.map(r => String(r['site_id']));
}

export async function listRuns(db: DbInstance): Promise<RunRow[]> {
  return db.select<RunRow[]>('SELECT * FROM runs ORDER BY timestamp DESC');
}
