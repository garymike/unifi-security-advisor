//! The one place an API key is used.
//!
//! The page never holds a stored key and never chooses where a key is sent.
//! It opens a connection either with a key the user just pasted, or by naming
//! a saved account; Rust then keeps the key in memory, bound to the controller
//! that the account name describes, and `unifi_fetch` takes only a path on that
//! controller. A URL on any other origin is refused, and redirects are never
//! followed (reqwest would otherwise forward the custom `X-API-KEY` header to
//! whatever host a redirect names).
//!
//! The binding is structural: an account is `cloud` (the Site Manager API at
//! `api.ui.com`) or `local:<host>`, and the target is derived from that name
//! alone, so a key saved for one controller cannot be pointed at another.

use std::sync::Mutex;

use reqwest::header::{HeaderValue, ACCEPT};
use reqwest::Url;
use serde::Serialize;
use tauri::{command, AppHandle, State};

use crate::keychain;

pub const CLOUD_ACCOUNT: &str = "cloud";
const CLOUD_API_ORIGIN: &str = "https://api.ui.com";
const CLOUD_PORTAL_URL: &str = "https://unifi.ui.com";
const LOCAL_PREFIX: &str = "local:";
/// A DNS name is at most 253 characters; leave room for a scheme and port.
const MAX_HOST_LEN: usize = 300;
/// UniFi keys are short; anything this long is not a key.
const MAX_KEY_LEN: usize = 512;

/// Where a key may be sent: one https origin, plus whether its certificate is
/// verified. Built only from an account name, never from a page-supplied URL.
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    account: String,
    base: Url,
    /// Cloud has a valid public chain. Local consoles present self-signed
    /// certificates, so verification is off for them (unchanged behaviour).
    verify_tls: bool,
}

impl Target {
    pub fn cloud() -> Self {
        Target {
            account: CLOUD_ACCOUNT.to_string(),
            base: Url::parse(CLOUD_API_ORIGIN).expect("static URL"),
            verify_tls: true,
        }
    }

    /// A local controller as the user typed it: `192.168.1.1`,
    /// `unifi.local:8443`, or `https://10.0.0.1`. Only https is accepted, and
    /// only a bare origin (no path, query, fragment, or credentials).
    pub fn local(host: &str) -> Result<Self, String> {
        let host = host.trim();
        if host.is_empty() {
            return Err("Enter the controller's address.".into());
        }
        if host.len() > MAX_HOST_LEN || host.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err("That controller address is not valid.".into());
        }
        let lower = host.to_ascii_lowercase();
        if lower.starts_with("http://") {
            return Err("Use an https address; the API key must not travel unencrypted.".into());
        }
        let with_scheme = if lower.starts_with("https://") {
            host.to_string()
        } else if host.contains("://") {
            return Err("Use an https address for the controller.".into());
        } else {
            format!("https://{host}")
        };
        let url = Url::parse(&with_scheme).map_err(|_| "That controller address is not valid.".to_string())?;
        if url.scheme() != "https"
            || url.host_str().is_none_or(str::is_empty)
            || !url.username().is_empty()
            || url.password().is_some()
            || !(url.path().is_empty() || url.path() == "/")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("Enter only the controller's address, for example 192.168.1.1.".into());
        }
        let base = Url::parse(&url.origin().ascii_serialization())
            .map_err(|_| "That controller address is not valid.".to_string())?;
        Ok(Target { account: format!("{LOCAL_PREFIX}{host}"), base, verify_tls: false })
    }

    pub fn for_mode(mode: &str, host: Option<&str>) -> Result<Self, String> {
        match mode {
            "cloud" => Ok(Target::cloud()),
            "local" => Target::local(host.unwrap_or("")),
            _ => Err("Unknown connection mode.".into()),
        }
    }

    /// The target a saved account is bound to. This is the whole binding: the
    /// account name is the only input.
    pub fn from_account(account: &str) -> Result<Self, String> {
        if account == CLOUD_ACCOUNT {
            Ok(Target::cloud())
        } else if let Some(host) = account.strip_prefix(LOCAL_PREFIX) {
            Target::local(host)
        } else {
            Err("That saved key is not one this app created.".into())
        }
    }

    pub fn account(&self) -> &str {
        &self.account
    }

    pub fn is_cloud(&self) -> bool {
        self.account == CLOUD_ACCOUNT
    }

    /// Resolve a page-supplied path (or an absolute URL) against this target,
    /// refusing anything that lands on a different origin.
    pub fn resolve(&self, path_or_url: &str) -> Result<Url, String> {
        let refused = || "Refused: that address is not the controller this key belongs to.".to_string();
        let url = if path_or_url.starts_with('/') && !path_or_url.starts_with("//") {
            self.base.join(path_or_url).map_err(|_| refused())?
        } else if path_or_url.to_ascii_lowercase().starts_with("https://") {
            Url::parse(path_or_url).map_err(|_| refused())?
        } else {
            return Err(refused());
        };
        // The origin check is the guard; the prefix checks above only keep
        // the error early and readable.
        if url.origin() != self.base.origin() || !url.username().is_empty() || url.password().is_some() {
            return Err(refused());
        }
        Ok(url)
    }

    /// The page where the user mints a key for this target.
    pub fn portal_url(&self) -> String {
        if self.is_cloud() {
            CLOUD_PORTAL_URL.to_string()
        } else {
            format!("{}network/", self.base.as_str())
        }
    }
}

/// An open connection: a key and the one target it may be sent to. The key is
/// overwritten when the session is dropped.
#[derive(Clone)]
struct Session {
    target: Target,
    key: String,
}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: zero bytes are valid UTF-8, so the String stays well-formed.
        for b in unsafe { self.key.as_bytes_mut() } {
            unsafe { std::ptr::write_volatile(b, 0) };
        }
    }
}

#[derive(Default)]
pub struct ConnectionState(Mutex<Option<Session>>);

impl ConnectionState {
    fn set(&self, session: Session) -> Result<(), String> {
        *self.0.lock().map_err(|_| "connection state poisoned".to_string())? = Some(session);
        Ok(())
    }

    fn current(&self) -> Result<Session, String> {
        self.0
            .lock()
            .map_err(|_| "connection state poisoned".to_string())?
            .clone()
            .ok_or_else(|| "No open connection. Validate a key first.".to_string())
    }

    fn clear(&self) {
        if let Ok(mut s) = self.0.lock() {
            *s = None;
        }
    }
}

/// What the page learns about an open connection: never the key.
#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionInfo {
    account: String,
    mode: &'static str,
    host: Option<String>,
}

impl From<&Target> for ConnectionInfo {
    fn from(t: &Target) -> Self {
        ConnectionInfo {
            account: t.account.clone(),
            mode: if t.is_cloud() { "cloud" } else { "local" },
            host: t.account.strip_prefix(LOCAL_PREFIX).map(str::to_string),
        }
    }
}

fn check_key(key: &str) -> Result<String, String> {
    let key = key.trim();
    if key.is_empty() {
        return Err("Paste your API key first.".into());
    }
    if key.len() > MAX_KEY_LEN || HeaderValue::from_str(key).is_err() || key.contains(char::is_whitespace) {
        return Err("That does not look like an API key.".into());
    }
    Ok(key.to_string())
}

/// Open a connection with a key the user just entered.
#[command]
pub fn connection_open(
    state: State<'_, ConnectionState>,
    mode: String,
    host: Option<String>,
    api_key: String,
) -> Result<ConnectionInfo, String> {
    let target = Target::for_mode(&mode, host.as_deref())?;
    let key = check_key(&api_key)?;
    let info = ConnectionInfo::from(&target);
    state.set(Session { target, key })?;
    Ok(info)
}

/// Open a connection with a saved key. The key is read here and stays here.
#[command(async)]
pub fn connection_open_saved(
    state: State<'_, ConnectionState>,
    account: String,
) -> Result<ConnectionInfo, String> {
    let target = Target::from_account(&account)?;
    let key = keychain::get_secret(&account)?
        .ok_or_else(|| "That saved key could not be read; it may have been removed.".to_string())?;
    let key = check_key(&key)?;
    let info = ConnectionInfo::from(&target);
    state.set(Session { target, key })?;
    Ok(info)
}

/// Save the open connection's key to the keychain under its own account, so
/// it stays bound to the controller it was validated against.
#[command(async)]
pub fn connection_remember(state: State<'_, ConnectionState>) -> Result<ConnectionInfo, String> {
    let session = state.current()?;
    keychain::set_secret(session.target.account(), &session.key)?;
    Ok(ConnectionInfo::from(&session.target))
}

#[command]
pub fn connection_close(state: State<'_, ConnectionState>) {
    state.clear();
}

/// GET a path on the open connection's controller with its key.
#[command]
pub async fn unifi_fetch(
    state: State<'_, ConnectionState>,
    path: String,
) -> Result<serde_json::Value, String> {
    let session = state.current()?;
    let url = session.target.resolve(&path)?;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(!session.target.verify_tls)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;

    let mut key_header = HeaderValue::from_str(&session.key).map_err(|_| "invalid key".to_string())?;
    key_header.set_sensitive(true);

    let response = client
        .get(url)
        .header("X-API-KEY", key_header)
        .header(ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| e.without_url().to_string())?;

    let status = response.status().as_u16();
    let data: serde_json::Value = match response.json().await {
        Ok(v) => v,
        Err(_) => serde_json::json!({ "nonJsonResponse": true }),
    };
    Ok(serde_json::json!({ "status": status, "data": data }))
}

/// Open the key-minting page in the system browser. Rust builds the URL from
/// the mode and host, so the page cannot open arbitrary URLs.
#[command]
pub fn open_key_portal(app: AppHandle, mode: String, host: Option<String>) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    let target = Target::for_mode(&mode, host.as_deref())?;
    app.opener().open_url(target.portal_url(), None::<&str>).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_accepts_bare_hosts_and_https() {
        for (input, origin) in [
            ("192.168.1.1", "https://192.168.1.1"),
            ("  unifi.local  ", "https://unifi.local"),
            ("10.0.0.1:8443", "https://10.0.0.1:8443"),
            ("https://10.0.0.1/", "https://10.0.0.1"),
            ("HTTPS://Console.Lan", "https://console.lan"),
            ("[fe80::1]", "https://[fe80::1]"),
        ] {
            let t = Target::local(input).unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(t.base.origin().ascii_serialization(), origin, "{input}");
            assert!(!t.verify_tls);
        }
    }

    #[test]
    fn local_rejects_plaintext_paths_and_credentials() {
        for input in [
            "", "   ", "http://192.168.1.1", "ftp://x", "192.168.1.1/proxy",
            "192.168.1.1?x=1", "192.168.1.1#f", "user:pw@192.168.1.1", "a b",
        ] {
            assert!(Target::local(input).is_err(), "accepted {input:?}");
        }
    }

    #[test]
    fn account_name_is_the_binding() {
        assert_eq!(Target::from_account("cloud").unwrap(), Target::cloud());
        let t = Target::from_account("local:192.168.1.1").unwrap();
        assert_eq!(t.account(), "local:192.168.1.1");
        assert_eq!(t.base.host_str(), Some("192.168.1.1"));
        assert!(Target::from_account("evil").is_err());
        assert!(Target::from_account("local:http://evil.example").is_err());
    }

    #[test]
    fn account_round_trips_through_for_mode() {
        let t = Target::for_mode("local", Some(" 10.0.0.1:8443 ")).unwrap();
        assert_eq!(t.account(), "local:10.0.0.1:8443");
        assert_eq!(Target::from_account(t.account()).unwrap(), t);
        assert_eq!(Target::for_mode("cloud", Some("ignored")).unwrap(), Target::cloud());
        assert!(Target::for_mode("other", None).is_err());
    }

    #[test]
    fn resolve_keeps_requests_on_the_bound_origin() {
        let t = Target::local("192.168.1.1").unwrap();
        assert_eq!(
            t.resolve("/proxy/network/integration/v1/sites").unwrap().as_str(),
            "https://192.168.1.1/proxy/network/integration/v1/sites"
        );
        assert!(t.resolve("https://192.168.1.1/x").is_ok());
        for bad in [
            "https://evil.example/x",
            "//evil.example/x",
            "/\\evil.example/x",
            "http://192.168.1.1/x",
            "https://192.168.1.1:8443/x",
            "https://user@192.168.1.1/x",
            "relative/path",
            "javascript:alert(1)",
        ] {
            assert!(t.resolve(bad).is_err(), "resolved {bad:?}");
        }
    }

    #[test]
    fn cloud_key_only_reaches_api_ui_com() {
        let t = Target::cloud();
        assert!(t.verify_tls);
        assert!(t.resolve("https://api.ui.com/v1/hosts").is_ok());
        assert!(t.resolve("/v1/hosts").is_ok());
        assert!(t.resolve("https://unifi.ui.com/v1/hosts").is_err());
        assert!(t.resolve("https://api.ui.com.evil.example/v1/hosts").is_err());
    }

    #[test]
    fn portal_urls() {
        assert_eq!(Target::cloud().portal_url(), "https://unifi.ui.com");
        assert_eq!(Target::local("192.168.1.1").unwrap().portal_url(), "https://192.168.1.1/network/");
        assert_eq!(Target::local("https://10.0.0.1:8443/").unwrap().portal_url(), "https://10.0.0.1:8443/network/");
    }

    #[test]
    fn info_never_carries_the_key() {
        let info = ConnectionInfo::from(&Target::local("192.168.1.1").unwrap());
        let json = serde_json::to_string(&info).unwrap();
        assert_eq!(json, r#"{"account":"local:192.168.1.1","mode":"local","host":"192.168.1.1"}"#);
    }

    #[test]
    fn key_checks() {
        assert_eq!(check_key("  abc123  ").unwrap(), "abc123");
        assert!(check_key("").is_err());
        assert!(check_key("has space").is_err());
        assert!(check_key("line\nbreak").is_err());
        assert!(check_key(&"x".repeat(MAX_KEY_LEN + 1)).is_err());
    }

    #[test]
    fn state_requires_an_open_connection() {
        let state = ConnectionState::default();
        assert!(state.current().is_err());
        state.set(Session { target: Target::cloud(), key: "k".into() }).unwrap();
        assert_eq!(state.current().unwrap().target, Target::cloud());
        state.clear();
        assert!(state.current().is_err());
    }
}
