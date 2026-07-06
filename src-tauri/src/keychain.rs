use keyring::Entry;
use tauri::command;

pub const SERVICE: &str = "unifi-security-advisor";

#[command]
pub fn keychain_set(account: String, secret: String) -> Result<(), String> {
    let entry = Entry::new(SERVICE, &account).map_err(|e| e.to_string())?;
    entry.set_password(&secret).map_err(|e| e.to_string())
}

#[command]
pub fn keychain_get(account: String) -> Result<Option<String>, String> {
    let entry = Entry::new(SERVICE, &account).map_err(|e| e.to_string())?;
    match entry.get_password() {
        Ok(secret) => Ok(Some(secret)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

#[command]
pub fn keychain_delete(account: String) -> Result<(), String> {
    let entry = Entry::new(SERVICE, &account).map_err(|e| e.to_string())?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Enumerate account identifiers stored under our service. Identifiers only —
/// never secret values. Returns an empty list on platforms without an
/// enumeration path rather than erroring.
#[command]
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
// `Entry::new` calls each of our `keychain_*` commands makes internally. That
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
        if keychain_set(acct.into(), "secret-123".into()).is_err() {
            eprintln!("SKIP set_get_delete_round_trip: no usable OS keychain backend in this environment");
            return;
        }
        // Capture results and delete unconditionally before asserting, so a
        // failed assertion below can't leave a stale credential behind.
        let got = keychain_get(acct.into()).unwrap();
        keychain_delete(acct.into()).unwrap();
        let after = keychain_get(acct.into()).unwrap();
        assert_eq!(got, Some("secret-123".to_string()));
        // after delete -> Ok(None)
        assert_eq!(after, None);
    }

    #[test]
    fn get_missing_returns_none() {
        assert_eq!(keychain_get("local:__absent__".into()).unwrap(), None);
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
}
