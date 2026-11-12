//! File I/O the page asks for. Rust opens the native dialog and acts on the
//! path the user picks, so the page never supplies a path: it can ask to save
//! a report or to pick a backup, and the user decides where.

use std::path::PathBuf;
use std::sync::Mutex;

use tauri::{command, AppHandle, State};
use tauri_plugin_dialog::DialogExt;

/// The backup the user picked in the open dialog, waiting to be parsed.
#[derive(Default)]
pub struct PendingBackup(Mutex<Option<PathBuf>>);

/// A file name safe to offer as the save dialog's default: letters, digits,
/// dot, dash, underscore; always ending in `.md`.
fn safe_report_name(requested: &str) -> String {
    let stem: String = requested
        .trim_end_matches(".md")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .take(64)
        .collect();
    let stem = stem.trim_matches('.');
    if stem.is_empty() {
        "unifi-report.md".to_string()
    } else {
        format!("{stem}.md")
    }
}

/// Ask where to save the report, then write it there. Returns false if the
/// user cancelled.
#[command(async)]
pub fn export_report(app: AppHandle, contents: String, default_name: String) -> Result<bool, String> {
    let Some(chosen) = app
        .dialog()
        .file()
        .set_title("Save report")
        .set_file_name(safe_report_name(&default_name))
        .add_filter("Markdown", &["md"])
        .blocking_save_file()
    else {
        return Ok(false);
    };
    let path = chosen.into_path().map_err(|e| e.to_string())?;
    std::fs::write(&path, contents).map_err(|e| format!("Cannot write the report: {e}"))?;
    Ok(true)
}

/// Ask the user to pick a backup file. Returns its file name for display, or
/// None if they cancelled. The path stays in Rust for `backup_parse`.
#[command(async)]
pub fn backup_choose(app: AppHandle, pending: State<'_, PendingBackup>) -> Result<Option<String>, String> {
    let Some(chosen) = app
        .dialog()
        .file()
        .set_title("Choose a UniFi backup")
        .add_filter("UniFi Backup", &["unf", "unifi"])
        .blocking_pick_file()
    else {
        return Ok(None);
    };
    let path = chosen.into_path().map_err(|e| e.to_string())?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "backup".to_string());
    *pending.0.lock().map_err(|_| "state poisoned".to_string())? = Some(path);
    Ok(Some(name))
}

/// Parse the backup the user picked with `backup_choose`.
#[command(async)]
pub fn backup_parse(pending: State<'_, PendingBackup>) -> Result<serde_json::Value, String> {
    let path = pending
        .0
        .lock()
        .map_err(|_| "state poisoned".to_string())?
        .clone()
        .ok_or_else(|| "Choose a backup file first.".to_string())?;
    crate::parse_backup_file(&path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_names_cannot_carry_a_path() {
        assert_eq!(safe_report_name("unifi-report-1a2b3c4d.md"), "unifi-report-1a2b3c4d.md");
        assert_eq!(safe_report_name("../../etc/passwd"), "etcpasswd.md");
        assert_eq!(safe_report_name("C:\\Windows\\x.md"), "CWindowsx.md");
        assert_eq!(safe_report_name(""), "unifi-report.md");
        assert_eq!(safe_report_name("..."), "unifi-report.md");
        assert!(safe_report_name(&"a".repeat(500)).len() <= 67);
    }
}
