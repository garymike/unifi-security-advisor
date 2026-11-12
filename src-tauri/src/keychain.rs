//! OS keychain access. Secrets are read and written only from Rust: the page
//! can delete a saved key, list account names, and see the last four
//! characters of a key, and nothing else. Commands that need a key look it up
//! themselves (see `connection.rs`).

use keyring::Entry;
use tauri::command;

pub const SERVICE: &str = "unifi-security-advisor";
const MAX_ACCOUNT_LEN: usize = 512;
/// Below this length, showing four characters reveals too much of the key.
const MIN_LEN_FOR_HINT: usize = 12;

fn entry(account: &str) -> Result<Entry, String> {
    if account.is_empty() || account.len() > MAX_ACCOUNT_LEN {
        return Err("invalid account name".into());
    }
    Entry::new(SERVICE, account).map_err(|e| e.to_string())
}

/// Store a secret. Rust-only; not a command.
pub fn set_secret(account: &str, secret: &str) -> Result<(), String> {
    entry(account)?.set_password(secret).map_err(|e| e.to_string())
}

/// Read a secret. Rust-only; not a command.
pub fn get_secret(account: &str) -> Result<Option<String>, String> {
    match entry(account)?.get_password() {
        Ok(secret) => Ok(Some(secret)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// The last four characters of a stored key, so the user can tell which key
/// is saved and match it against their Ubiquiti account
/// (docs/05-credential-handling.md, Revocation support). `None` when no key is
/// stored or the key is too short to show any of it safely.
fn hint_for(secret: &str) -> Option<String> {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() < MIN_LEN_FOR_HINT {
        return None;
    }
    Some(chars[chars.len() - 4..].iter().collect())
}

#[command(async)]
pub fn keychain_hint(account: String) -> Result<Option<String>, String> {
    Ok(get_secret(&account)?.as_deref().and_then(hint_for))
}

#[command(async)]
pub fn keychain_delete(account: String) -> Result<(), String> {
    match entry(&account)?.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Enumerate account identifiers stored under our service. Identifiers only —
/// never secret values. Returns an empty list on platforms without an
/// enumeration path rather than erroring.
#[command(async)]
pub fn keychain_scan() -> Result<Vec<String>, String> {
    scan_impl()
}

#[cfg(windows)]
fn scan_impl() -> Result<Vec<String>, String> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_NOT_FOUND;
    use windows::Win32::Security::Credentials::{
        CredEnumerateW, CredFree, CREDENTIALW, CRED_ENUMERATE_ALL_CREDENTIALS,
    };
    // keyring's windows-native backend stores the target name as
    // "{account}.{service}" (account first, service last — see keyring's
    // WinCredential::new_with_target). CredEnumerateW's filter only supports
    // prefix wildcards, so we can't filter by our (suffix) service name at
    // the API level; instead enumerate everything and filter by suffix here.
    // CredEnumerateW also surfaces generic credentials with a
    // "LegacyGeneric:target=" namespace prefix on the target name, which we
    // strip before comparing/returning. The Step-6 round-trip test validates
    // this mapping empirically.
    const LEGACY_GENERIC_PREFIX: &str = "LegacyGeneric:target=";
    let suffix = format!(".{}", SERVICE);
    let mut count: u32 = 0;
    let mut creds: *mut *mut CREDENTIALW = std::ptr::null_mut();
    let mut out: Vec<String> = Vec::new();
    unsafe {
        match CredEnumerateW(PCWSTR::null(), CRED_ENUMERATE_ALL_CREDENTIALS, &mut count, &mut creds) {
            Ok(()) => {
                let slice = std::slice::from_raw_parts(creds, count as usize);
                for &cred in slice {
                    let target = (*cred).TargetName;
                    if target.is_null() { continue; }
                    let s = target.to_string().unwrap_or_default();
                    let s = s.strip_prefix(LEGACY_GENERIC_PREFIX).unwrap_or(&s);
                    if let Some(account) = s.strip_suffix(&suffix) {
                        out.push(account.to_string());
                    }
                }
                CredFree(creds as *const _);
                Ok(out)
            }
            Err(e) if e.code() == ERROR_NOT_FOUND.to_hresult() => Ok(Vec::new()),
            Err(e) => Err(e.to_string()),
        }
    }
}

#[cfg(target_os = "macos")]
fn scan_impl() -> Result<Vec<String>, String> {
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit, SearchResult};
    let mut opts = ItemSearchOptions::new();
    opts.class(ItemClass::generic_password());
    opts.limit(Limit::All);
    opts.load_attributes(true);
    let results = match opts.search() {
        Ok(r) => r,
        Err(_) => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    for item in results {
        if let SearchResult::Dict(map) = item {
            let svc = map.get("svce").map(|v| v.to_string()).unwrap_or_default();
            if svc == SERVICE {
                if let Some(acct) = map.get("acct") {
                    out.push(acct.to_string());
                }
            }
        }
    }
    Ok(out)
}

#[cfg(target_os = "linux")]
fn scan_impl() -> Result<Vec<String>, String> {
    use secret_service::blocking::SecretService;
    use secret_service::EncryptionType;
    use std::collections::HashMap;
    let ss = match SecretService::connect(EncryptionType::Dh) {
        Ok(s) => s,
        Err(_) => return Ok(Vec::new()),
    };
    let mut attrs = HashMap::new();
    attrs.insert("service", SERVICE);
    let items = match ss.search_items(attrs) {
        Ok(i) => i,
        Err(_) => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    for item in items.unlocked.into_iter().chain(items.locked.into_iter()) {
        if let Ok(a) = item.get_attributes() {
            if let Some(account) = a.get("account") {
                out.push(account.clone());
            }
        }
    }
    Ok(out)
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn scan_impl() -> Result<Vec<String>, String> {
    Ok(Vec::new())
}

// NOTE on test strategy: keyring 3.6.3's mock credential store has
// `CredentialPersistence::EntryOnly` — `MockCredentialBuilder::build` returns
// a brand-new, unlinked `MockCredential` on every `Entry::new(..)` call (see
// keyring's mock.rs), so it cannot round-trip state across the separate
// `Entry::new` calls each of our keychain functions makes internally. That
// makes the mock unusable for testing cross-call persistence of our public
// command functions. Instead these tests exercise the real platform backend
// (same approach as `scan_lists_a_real_stored_account` below), using unique
// account names and cleaning up after themselves to stay hermetic in
// practice without depending on a shared external vault.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_delete_round_trip() {
        let acct = "local:__unit_test__";
        // Some environments (e.g. headless CI) have no usable OS keychain.
        // Skip the assertions there rather than failing spuriously — the
        // scan test's guard follows the same convention.
        if set_secret(acct, "secret-123-abcd").is_err() {
            eprintln!("SKIP set_get_delete_round_trip: no usable OS keychain backend in this environment");
            return;
        }
        // Capture results and delete unconditionally before asserting, so a
        // failed assertion below can't leave a stale credential behind.
        let got = get_secret(acct).unwrap();
        let hint = keychain_hint(acct.into()).unwrap();
        keychain_delete(acct.into()).unwrap();
        let after = get_secret(acct).unwrap();
        assert_eq!(got, Some("secret-123-abcd".to_string()));
        assert_eq!(hint, Some("abcd".to_string()));
        // after delete -> Ok(None)
        assert_eq!(after, None);
    }

    #[test]
    fn get_missing_returns_none() {
        // On a working keychain a missing account resolves to Ok(None). On a
        // backend-less environment (e.g. a headless CI runner with no Secret
        // Service / D-Bus) the backend connection itself errors — that's not a
        // NoEntry, so skip rather than panic, matching the other tests' guard.
        match get_secret("local:__absent__") {
            Ok(v) => assert_eq!(v, None),
            Err(_) => eprintln!(
                "SKIP get_missing_returns_none: no usable OS keychain backend in this environment"
            ),
        }
    }

    // scan uses the REAL platform store (not the mock), so run it against a
    // uniquely-named account and clean up. On the unsupported-platform arm this
    // still passes (empty list, account simply absent).
    #[test]
    fn scan_lists_a_real_stored_account() {
        let acct = "local:__scan_probe__";
        let entry = Entry::new(SERVICE, acct).unwrap();
        if entry.set_password("probe").is_err() {
            eprintln!("SKIP scan_lists_a_real_stored_account: no usable OS keychain backend in this environment");
            return; // no usable store in this environment; nothing to assert
        }
        let listed = keychain_scan().unwrap();
        let _ = entry.delete_credential();
        #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
        assert!(listed.contains(&acct.to_string()), "scan did not surface {acct}: {listed:?}");
    }

    #[test]
    fn hint_shows_only_the_last_four_of_a_long_key() {
        assert_eq!(hint_for("abcdefghijklmnop"), Some("mnop".into()));
        assert_eq!(hint_for("short-key"), None);
        assert_eq!(hint_for(""), None);
    }

    #[test]
    fn rejects_empty_or_huge_account_names() {
        assert!(get_secret("").is_err());
        assert!(keychain_delete("x".repeat(MAX_ACCOUNT_LEN + 1)).is_err());
    }
}
