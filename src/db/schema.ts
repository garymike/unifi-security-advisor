export const CREATE_TABLES = [
  `CREATE TABLE IF NOT EXISTS runs (
    id          TEXT PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    host        TEXT,
    profile     TEXT,
    tier        TEXT,
    site_count  INTEGER
  )`,
  `CREATE TABLE IF NOT EXISTS findings (
    id              TEXT NOT NULL,
    run_id          TEXT NOT NULL REFERENCES runs(id),
    section         TEXT,
    severity        TEXT,
    status          TEXT,
    title           TEXT,
    current_state   TEXT,
    recommendation  TEXT,
    intent_question TEXT,
    evidence        TEXT,
    maps_to         TEXT,
    effort          TEXT,
    impact          TEXT,
    float_top       INTEGER DEFAULT 0
  )`,
  `CREATE TABLE IF NOT EXISTS answers (
    run_id      TEXT NOT NULL REFERENCES runs(id),
    finding_id  TEXT NOT NULL,
    answer      TEXT,
    free_text   TEXT,
    tier        TEXT,
    answered_at TEXT,
    PRIMARY KEY (run_id, finding_id)
  )`,
  `CREATE TABLE IF NOT EXISTS sites (
    run_id      TEXT NOT NULL REFERENCES runs(id),
    site_id     TEXT,
    site_name   TEXT,
    api_gaps    TEXT
  )`,
];

export type Tier = 'guided' | 'standard' | 'pro';
export type AnswerValue = 'yes' | 'no' | 'partially' | 'not_applicable' | 'deferred';
