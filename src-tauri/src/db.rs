//! The app's SQLite store, owned by Rust.
//!
//! The page used to reach SQLite through tauri-plugin-sql, which runs whatever
//! SQL the page sends against whatever database path it names. That is an
//! arbitrary file write: `load('sqlite:/any/path')` escapes the app directory
//! (the plugin joins the path with `PathBuf::push`), and `ATTACH` or
//! `VACUUM INTO` writes a file anywhere from any loaded database.
//!
//! Here the database path is fixed and the page can only run statements from
//! the catalog below, by name, with bound parameters.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::types::{Value as SqlValue, ValueRef};
use rusqlite::{params_from_iter, Connection};
use serde_json::{Map, Value as JsonValue};
use tauri::{command, State};

use crate::pinning::Fingerprint;

/// Same file name the SQL plugin used, in the same directory (app config dir),
/// so existing history carries over.
pub const DB_FILE: &str = "unifi-advisor.db";

const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS runs (
        id          TEXT PRIMARY KEY,
        timestamp   TEXT NOT NULL,
        host        TEXT,
        profile     TEXT,
        tier        TEXT,
        site_count  INTEGER
    )",
    "CREATE TABLE IF NOT EXISTS findings (
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
    )",
    "CREATE TABLE IF NOT EXISTS answers (
        run_id      TEXT NOT NULL REFERENCES runs(id),
        finding_id  TEXT NOT NULL,
        answer      TEXT,
        free_text   TEXT,
        tier        TEXT,
        answered_at TEXT,
        PRIMARY KEY (run_id, finding_id)
    )",
    "CREATE TABLE IF NOT EXISTS sites (
        run_id      TEXT NOT NULL REFERENCES runs(id),
        site_id     TEXT,
        site_name   TEXT,
        api_gaps    TEXT
    )",
    "CREATE TABLE IF NOT EXISTS app_kv (
        key   TEXT PRIMARY KEY,
        value TEXT
    )",
    // Certificate pins for local controllers, keyed by the same account name
    // as the controller's key (`local:<host>`). Not secret, but trusted: no
    // catalog statement below touches this table, so only Rust reads or
    // writes it (see `pin`, `pin_first_use`, `replace_pin`).
    "CREATE TABLE IF NOT EXISTS cert_pins (
        account    TEXT PRIMARY KEY,
        sha256     TEXT NOT NULL,
        pinned_at  INTEGER NOT NULL
    )",
];

#[derive(Debug, Clone, Copy, PartialEq)]
enum Kind {
    Write,
    Read,
}

/// Every statement the page may run. Names match the functions in
/// `src/db/queries.ts`.
const STATEMENTS: &[(&str, Kind, &str)] = &[
    ("insertRun", Kind::Write,
     "INSERT INTO runs (id, timestamp, host, profile, tier, site_count) VALUES (?, ?, ?, ?, ?, ?)"),
    ("updateRunTier", Kind::Write, "UPDATE runs SET tier = ? WHERE id = ?"),
    ("insertFinding", Kind::Write,
     "INSERT INTO findings (id, run_id, section, severity, status, title, current_state,
        recommendation, intent_question, evidence, maps_to, effort, impact, float_top)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
    ("insertSite", Kind::Write,
     "INSERT INTO sites (run_id, site_id, site_name, api_gaps) VALUES (?, ?, ?, ?)"),
    ("upsertAnswer", Kind::Write,
     "INSERT INTO answers (run_id, finding_id, answer, free_text, tier, answered_at)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(run_id, finding_id) DO UPDATE SET
        answer = excluded.answer, free_text = excluded.free_text,
        tier = excluded.tier, answered_at = excluded.answered_at"),
    ("setKv", Kind::Write,
     "INSERT INTO app_kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"),
    ("getFindings", Kind::Read,
     "SELECT * FROM findings WHERE run_id = ? ORDER BY float_top DESC, severity"),
    ("getAnswers", Kind::Read, "SELECT finding_id, answer, free_text FROM answers WHERE run_id = ?"),
    ("getSiteIds", Kind::Read, "SELECT site_id FROM sites WHERE run_id = ?"),
    ("getApiGaps", Kind::Read, "SELECT api_gaps FROM sites WHERE run_id = ?"),
    ("listRuns", Kind::Read, "SELECT * FROM runs ORDER BY timestamp DESC"),
    ("getKv", Kind::Read, "SELECT value FROM app_kv WHERE key = ?"),
];

pub struct Db(Mutex<Connection>);

impl Db {
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        Self::init(conn)
    }

    #[cfg(test)]
    pub(crate) fn in_memory() -> Self {
        Self::init(Connection::open_in_memory().unwrap()).unwrap()
    }

    fn init(conn: Connection) -> Result<Self, String> {
        for sql in SCHEMA {
            conn.execute(sql, []).map_err(|e| e.to_string())?;
        }
        Ok(Db(Mutex::new(conn)))
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, String> {
        self.0.lock().map_err(|_| "database lock poisoned".to_string())
    }

    fn write(&self, name: &str, rows: Vec<Vec<JsonValue>>) -> Result<usize, String> {
        let sql = lookup(name, Kind::Write)?;
        let mut conn = self.lock()?;
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let mut changed = 0;
        {
            let mut stmt = tx.prepare_cached(sql).map_err(|e| e.to_string())?;
            for row in rows {
                changed += stmt.execute(params_from_iter(bind(row)?)).map_err(|e| e.to_string())?;
            }
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(changed)
    }

    fn read(&self, name: &str, values: Vec<JsonValue>) -> Result<Vec<Map<String, JsonValue>>, String> {
        let sql = lookup(name, Kind::Read)?;
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached(sql).map_err(|e| e.to_string())?;
        let columns: Vec<String> = stmt.column_names().map(str::to_string).collect();
        let mut rows = stmt.query(params_from_iter(bind(values)?)).map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let mut obj = Map::new();
            for (i, col) in columns.iter().enumerate() {
                let v = row.get_ref(i).map_err(|e| e.to_string())?;
                obj.insert(col.clone(), to_json(v)?);
            }
            out.push(obj);
        }
        Ok(out)
    }

    /// The certificate pinned for a local controller's account, if any.
    pub fn pin(&self, account: &str) -> Result<Option<Fingerprint>, String> {
        let conn = self.lock()?;
        let stored: Option<String> = match conn.query_row(
            "SELECT sha256 FROM cert_pins WHERE account = ?",
            [account],
            |r| r.get(0),
        ) {
            Ok(v) => Some(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => return Err(e.to_string()),
        };
        match stored {
            None => Ok(None),
            // A row that does not parse is treated as a pin nothing matches,
            // so a damaged row refuses connections instead of re-pinning.
            Some(s) => Fingerprint::parse(&s)
                .map(Some)
                .ok_or_else(|| "The saved certificate pin for this controller is damaged.".to_string()),
        }
    }

    /// Pin on first use. Keeps an existing pin if one was written in the
    /// meantime, and returns whichever pin is now stored.
    pub fn pin_first_use(&self, account: &str, fp: Fingerprint) -> Result<Fingerprint, String> {
        self.lock()?
            .execute(
                "INSERT INTO cert_pins (account, sha256, pinned_at) VALUES (?, ?, ?)
                 ON CONFLICT(account) DO NOTHING",
                rusqlite::params![account, fp.to_string(), now_secs()],
            )
            .map_err(|e| e.to_string())?;
        self.pin(account)?.ok_or_else(|| "certificate pin was not stored".to_string())
    }

    /// Replace `old` with `new` after the user confirmed the change. Does
    /// nothing (returns false) if the stored pin is no longer `old`, so a
    /// confirmation for one change cannot overwrite a different one.
    pub fn replace_pin(&self, account: &str, old: Fingerprint, new: Fingerprint) -> Result<bool, String> {
        let changed = self
            .lock()?
            .execute(
                "UPDATE cert_pins SET sha256 = ?, pinned_at = ? WHERE account = ? AND sha256 = ?",
                rusqlite::params![new.to_string(), now_secs(), account, old.to_string()],
            )
            .map_err(|e| e.to_string())?;
        Ok(changed == 1)
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn lookup(name: &str, kind: Kind) -> Result<&'static str, String> {
    STATEMENTS
        .iter()
        .find(|(n, k, _)| *n == name && *k == kind)
        .map(|(_, _, sql)| *sql)
        .ok_or_else(|| format!("unknown statement: {name}"))
}

fn bind(values: Vec<JsonValue>) -> Result<Vec<SqlValue>, String> {
    values
        .into_iter()
        .map(|v| match v {
            JsonValue::Null => Ok(SqlValue::Null),
            JsonValue::Bool(b) => Ok(SqlValue::Integer(b as i64)),
            JsonValue::Number(n) => n
                .as_i64()
                .map(SqlValue::Integer)
                .or_else(|| n.as_f64().map(SqlValue::Real))
                .ok_or_else(|| "unsupported number".to_string()),
            JsonValue::String(s) => Ok(SqlValue::Text(s)),
            _ => Err("parameters must be strings, numbers, booleans, or null".to_string()),
        })
        .collect()
}

fn to_json(v: ValueRef<'_>) -> Result<JsonValue, String> {
    Ok(match v {
        ValueRef::Null => JsonValue::Null,
        ValueRef::Integer(i) => JsonValue::from(i),
        ValueRef::Real(f) => JsonValue::from(f),
        ValueRef::Text(t) => JsonValue::String(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(_) => return Err("unexpected blob column".to_string()),
    })
}

/// Run a catalog write once per row of parameters, in one transaction.
#[command(async)]
pub fn db_write(db: State<'_, Db>, name: String, rows: Vec<Vec<JsonValue>>) -> Result<usize, String> {
    db.write(&name, rows)
}

/// Run a catalog read.
#[command(async)]
pub fn db_read(
    db: State<'_, Db>,
    name: String,
    values: Vec<JsonValue>,
) -> Result<Vec<Map<String, JsonValue>>, String> {
    db.read(&name, values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run_row(id: &str, ts: &str) -> Vec<JsonValue> {
        vec![json!(id), json!(ts), json!("192.168.1.1"), json!("home"), json!("standard"), json!(1)]
    }

    #[test]
    fn schema_creates_the_six_tables() {
        let db = Db::in_memory();
        let conn = db.lock().unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table'
                 AND name IN ('runs','findings','answers','sites','app_kv','cert_pins')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 6);
    }

    #[test]
    fn the_page_has_no_statement_for_certificate_pins() {
        for (name, _, sql) in STATEMENTS {
            assert!(!sql.contains("cert_pins"), "{name} reaches cert_pins");
        }
    }

    #[test]
    fn pins_are_set_once_and_replaced_only_from_the_confirmed_value() {
        let db = Db::in_memory();
        let acct = "local:192.168.1.1";
        let a = Fingerprint::of(b"cert a");
        let b = Fingerprint::of(b"cert b");
        let c = Fingerprint::of(b"cert c");
        assert_eq!(db.pin(acct).unwrap(), None);
        assert_eq!(db.pin_first_use(acct, a).unwrap(), a);
        // A later first-use write does not move an existing pin.
        assert_eq!(db.pin_first_use(acct, b).unwrap(), a);
        // A replacement confirmed against a stale pin is ignored.
        assert!(!db.replace_pin(acct, c, b).unwrap());
        assert_eq!(db.pin(acct).unwrap(), Some(a));
        assert!(db.replace_pin(acct, a, b).unwrap());
        assert_eq!(db.pin(acct).unwrap(), Some(b));
        assert_eq!(db.pin("local:other").unwrap(), None);
    }

    #[test]
    fn a_damaged_pin_refuses_rather_than_re_pinning() {
        let db = Db::in_memory();
        db.lock()
            .unwrap()
            .execute("INSERT INTO cert_pins VALUES ('local:x', 'garbage', 0)", [])
            .unwrap();
        assert!(db.pin("local:x").is_err());
    }

    #[test]
    fn every_statement_prepares_against_the_schema() {
        let db = Db::in_memory();
        let conn = db.lock().unwrap();
        for (name, _, sql) in STATEMENTS {
            conn.prepare(sql).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }

    #[test]
    fn runs_round_trip_in_order() {
        let db = Db::in_memory();
        db.write("insertRun", vec![run_row("a", "2026-01-01T00:00:00Z"), run_row("b", "2026-02-01T00:00:00Z")])
            .unwrap();
        db.write("updateRunTier", vec![vec![json!("pro"), json!("a")]]).unwrap();
        let rows = db.read("listRuns", vec![]).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["id"], "b");
        assert_eq!(rows[1]["tier"], "pro");
        assert_eq!(rows[1]["site_count"], 1);
    }

    #[test]
    fn kv_upserts() {
        let db = Db::in_memory();
        db.write("setKv", vec![vec![json!("k"), json!("1")]]).unwrap();
        db.write("setKv", vec![vec![json!("k"), json!("2")]]).unwrap();
        let rows = db.read("getKv", vec![json!("k")]).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["value"], "2");
    }

    #[test]
    fn findings_and_answers_round_trip() {
        let db = Db::in_memory();
        db.write("insertRun", vec![run_row("r", "2026-01-01T00:00:00Z")]).unwrap();
        let finding = |id: &str, top: bool| {
            vec![
                json!(id), json!("r"), json!("Segmentation"), json!("high"), json!("gap"),
                json!("t"), json!("cs"), JsonValue::Null, json!("q?"), json!("{}"), json!("{}"),
                json!("quick"), json!("high"), json!(top),
            ]
        };
        db.write("insertFinding", vec![finding("F-1", false), finding("F-2", true)]).unwrap();
        let rows = db.read("getFindings", vec![json!("r")]).unwrap();
        assert_eq!(rows[0]["id"], "F-2");
        assert_eq!(rows[0]["float_top"], 1);
        assert!(rows[1]["recommendation"].is_null());

        let answer = |a: &str| vec![json!("r"), json!("F-1"), json!(a), json!(""), json!("standard"), json!("now")];
        db.write("upsertAnswer", vec![answer("no"), answer("yes")]).unwrap();
        let answers = db.read("getAnswers", vec![json!("r")]).unwrap();
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0]["answer"], "yes");
    }

    #[test]
    fn page_cannot_run_its_own_sql() {
        let db = Db::in_memory();
        for name in [
            "ATTACH DATABASE '/tmp/x.db' AS x",
            "VACUUM INTO '/tmp/x.db'",
            "SELECT * FROM runs",
            "DROP TABLE runs",
        ] {
            assert!(db.read(name, vec![]).is_err(), "{name}");
            assert!(db.write(name, vec![vec![]]).is_err(), "{name}");
        }
    }

    #[test]
    fn reads_and_writes_do_not_cross() {
        let db = Db::in_memory();
        assert!(db.read("insertRun", vec![]).is_err());
        assert!(db.write("listRuns", vec![vec![]]).is_err());
    }

    #[test]
    fn write_batch_is_atomic() {
        let db = Db::in_memory();
        // Second row has the wrong parameter count, so the whole batch rolls back.
        let bad = vec![run_row("a", "t"), vec![json!("b")]];
        assert!(db.write("insertRun", bad).is_err());
        assert!(db.read("listRuns", vec![]).unwrap().is_empty());
    }

    #[test]
    fn rejects_structured_parameters() {
        assert!(bind(vec![json!({"a": 1})]).is_err());
        assert!(bind(vec![json!([1])]).is_err());
        assert_eq!(bind(vec![json!(true), json!(1.5)]).unwrap(), vec![SqlValue::Integer(1), SqlValue::Real(1.5)]);
    }
}
