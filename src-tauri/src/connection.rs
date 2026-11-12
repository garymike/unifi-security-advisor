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
//!
//! TLS: cloud uses normal platform chain verification. A local console's
//! self-signed certificate is pinned on first use (`pinning.rs`): once a key
//! validates, the certificate's SHA-256 is stored against the account, and a
//! later handshake that presents any other certificate is aborted before the
//! request, and so the key, is written. The page sees that as a certificate
//! change it can ask the user to review; only a native confirmation dialog,
//! raised here, moves the pin, and only to the certificate Rust itself saw.

use std::sync::Mutex;

use reqwest::header::{HeaderValue, ACCEPT};
use reqwest::Url;
use serde::Serialize;
use tauri::{command, AppHandle, State};

use crate::db::Db;
use crate::keychain;
use crate::pinning::{self, Fingerprint};

pub const CLOUD_ACCOUNT: &str = "cloud";
const CLOUD_API_ORIGIN: &str = "https://api.ui.com";
const CLOUD_PORTAL_URL: &str = "https://unifi.ui.com";
const LOCAL_PREFIX: &str = "local:";
/// A DNS name is at most 253 characters; leave room for a scheme and port.
const MAX_HOST_LEN: usize = 300;
/// UniFi keys are short; anything this long is not a key.
const MAX_KEY_LEN: usize = 512;
/// The page matches on this prefix to offer the re-pin flow.
pub const CERT_CHANGED: &str =
    "certificate-changed: This controller presented a different certificate from the one pinned for it, so the key was not sent.";

/// Where a key may be sent: one https origin. Built only from an account
/// name, never from a page-supplied URL. Cloud has a valid public chain and is
/// verified normally; a local console's certificate is pinned (module docs).
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    account: String,
    base: Url,
}

impl Target {
    pub fn cloud() -> Self {
        Target {
            account: CLOUD_ACCOUNT.to_string(),
            base: Url::parse(CLOUD_API_ORIGIN).expect("static URL"),
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
        Ok(Target { account: format!("{LOCAL_PREFIX}{host}"), base })
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

/// A local controller presented `presented` where `pinned` was expected.
#[derive(Debug, Clone, Copy, PartialEq)]
struct CertChange {
    pinned: Fingerprint,
    presented: Fingerprint,
}

#[derive(Default)]
pub struct ConnectionState {
    session: Mutex<Option<Session>>,
    /// The last certificate change seen, and the account it was seen for,
    /// waiting for the user to review it. Cleared whenever the session changes.
    change: Mutex<Option<(String, CertChange)>>,
}

impl ConnectionState {
    fn set(&self, session: Session) -> Result<(), String> {
        *self.session.lock().map_err(|_| "connection state poisoned".to_string())? = Some(session);
        self.clear_change();
        Ok(())
    }

    fn current(&self) -> Result<Session, String> {
        self.session
            .lock()
            .map_err(|_| "connection state poisoned".to_string())?
            .clone()
            .ok_or_else(|| "No open connection. Validate a key first.".to_string())
    }

    fn clear(&self) {
        if let Ok(mut s) = self.session.lock() {
            *s = None;
        }
        self.clear_change();
    }

    fn note_change(&self, target: &Target, change: CertChange) {
        if let Ok(mut c) = self.change.lock() {
            *c = Some((target.account.clone(), change));
        }
    }

    /// The pending change for `target`, if one was seen on this connection.
    fn change_for(&self, target: &Target) -> Option<CertChange> {
        let c = self.change.lock().ok()?;
        c.as_ref().filter(|(account, _)| *account == target.account).map(|(_, ch)| *ch)
    }

    fn clear_change(&self) {
        if let Ok(mut c) = self.change.lock() {
            *c = None;
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
#[command(async)]
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

/// What one request produced.
#[derive(Debug)]
enum Outcome {
    /// The server answered. `presented` is the local controller's leaf
    /// certificate (None for cloud, or a resumed session).
    Response { status: u16, data: serde_json::Value, presented: Option<Fingerprint> },
    /// A local controller presented a certificate other than the pin. The
    /// handshake was aborted, so no request bytes, and no key, were sent.
    CertChanged(CertChange),
}

/// Send one GET with the key. For a local target the TLS handshake accepts
/// only `pin` (or, with no pin yet, any certificate, which the caller pins).
async fn send(target: &Target, key: &str, url: Url, pin: Option<Fingerprint>) -> Result<Outcome, String> {
    pinning::ensure_crypto_provider();
    let builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30));
    let (builder, verifier) = if target.is_cloud() {
        (builder, None)
    } else {
        let (config, verifier) = pinning::local_client_config(pin)?;
        (builder.tls_backend_preconfigured(config), Some(verifier))
    };
    let client = builder.build().map_err(|e| e.to_string())?;

    let mut key_header = HeaderValue::from_str(key).map_err(|_| "invalid key".to_string())?;
    key_header.set_sensitive(true);

    let response = match client
        .get(url)
        .header("X-API-KEY", key_header)
        .header(ACCEPT, "application/json")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            let presented = verifier.as_ref().and_then(|v| v.presented());
            if let (Some(pinned), Some(presented)) = (pin, presented) {
                if pinned != presented {
                    return Ok(Outcome::CertChanged(CertChange { pinned, presented }));
                }
            }
            return Err(e.without_url().to_string());
        }
    };

    let status = response.status().as_u16();
    let data: serde_json::Value = match response.json().await {
        Ok(v) => v,
        Err(_) => serde_json::json!({ "nonJsonResponse": true }),
    };
    let presented = verifier.as_ref().and_then(|v| v.presented());
    Ok(Outcome::Response { status, data, presented })
}

/// The certificate to pin after a response: only for a local target with no
/// pin yet, and only once the key has validated (a 2xx answer).
fn first_use_pin(target: &Target, pin: Option<Fingerprint>, status: u16, presented: Option<Fingerprint>) -> Option<Fingerprint> {
    if target.is_cloud() || pin.is_some() || !(200..300).contains(&status) {
        return None;
    }
    presented
}

/// GET a path on the open connection's controller with its key.
#[command]
pub async fn unifi_fetch(
    state: State<'_, ConnectionState>,
    db: State<'_, Db>,
    path: String,
) -> Result<serde_json::Value, String> {
    let session = state.current()?;
    let url = session.target.resolve(&path)?;
    let pin = if session.target.is_cloud() { None } else { db.pin(session.target.account())? };

    match send(&session.target, &session.key, url, pin).await? {
        Outcome::CertChanged(change) => {
            state.note_change(&session.target, change);
            Err(CERT_CHANGED.to_string())
        }
        Outcome::Response { status, data, presented } => {
            if let Some(fp) = first_use_pin(&session.target, pin, status, presented) {
                let stored = db.pin_first_use(session.target.account(), fp)?;
                // Two first requests raced and saw different certificates:
                // keep the first pin and surface the second as a change.
                if stored != fp {
                    state.note_change(&session.target, CertChange { pinned: stored, presented: fp });
                    return Err(CERT_CHANGED.to_string());
                }
            }
            Ok(serde_json::json!({ "status": status, "data": data }))
        }
    }
}

/// The open local connection's certificate pin and, after a refused
/// connection, the certificate the controller presented instead. Both are
/// SHA-256 fingerprints; neither is secret.
#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CertificateInfo {
    pinned: Option<String>,
    presented: Option<String>,
}

#[command(async)]
pub fn connection_certificate(
    state: State<'_, ConnectionState>,
    db: State<'_, Db>,
) -> Result<CertificateInfo, String> {
    let session = state.current()?;
    if session.target.is_cloud() {
        return Ok(CertificateInfo { pinned: None, presented: None });
    }
    let change = state.change_for(&session.target);
    let pinned = match change {
        Some(c) => Some(c.pinned),
        None => db.pin(session.target.account())?,
    };
    Ok(CertificateInfo {
        pinned: pinned.map(|f| f.to_string()),
        presented: change.map(|c| c.presented.to_string()),
    })
}

fn repin_prompt(host: &str, change: &CertChange) -> String {
    format!(
        "{host} presented a different certificate from the one this app pinned for it.\n\n\
         Pinned:\n{}\n\nPresented now:\n{}\n\n\
         This is expected after a console reset, restore, or certificate change. \
         If none of those happened, someone on your network may be intercepting the connection: \
         keep the old pin and check the console's certificate first.",
        change.pinned, change.presented
    )
}

/// Trust the certificate the controller presented, after the user confirms in
/// a native dialog. The page names no fingerprint: the new pin is the one Rust
/// observed in the refused handshake, and the dialog shows both values.
/// Returns false if the user kept the old pin.
#[command(async)]
pub fn connection_repin(
    app: AppHandle,
    state: State<'_, ConnectionState>,
    db: State<'_, Db>,
) -> Result<bool, String> {
    use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
    let session = state.current()?;
    let change = state
        .change_for(&session.target)
        .ok_or_else(|| "There is no certificate change to review for this controller.".to_string())?;
    let host = session.target.account().strip_prefix(LOCAL_PREFIX).unwrap_or_default();
    let confirmed = app
        .dialog()
        .message(repin_prompt(host, &change))
        .title("Controller certificate changed")
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(
            "Trust the new certificate".into(),
            "Keep the old pin".into(),
        ))
        .blocking_show();
    if !confirmed {
        return Ok(false);
    }
    if !db.replace_pin(session.target.account(), change.pinned, change.presented)? {
        return Err("The pinned certificate changed while you were deciding. Validate again.".into());
    }
    state.clear_change();
    Ok(true)
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
            assert!(!t.is_cloud());
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
        assert!(t.is_cloud());
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

    #[test]
    fn a_certificate_change_belongs_to_one_session() {
        let state = ConnectionState::default();
        let local = Target::local("192.168.1.1").unwrap();
        let change = CertChange { pinned: Fingerprint::of(b"a"), presented: Fingerprint::of(b"b") };
        state.set(Session { target: local.clone(), key: "k".into() }).unwrap();
        state.note_change(&local, change);
        assert_eq!(state.change_for(&local), Some(change));
        assert_eq!(state.change_for(&Target::local("10.0.0.1").unwrap()), None);
        // Opening any connection, even to the same controller, drops it.
        state.set(Session { target: local.clone(), key: "k".into() }).unwrap();
        assert_eq!(state.change_for(&local), None);
        state.note_change(&local, change);
        state.clear();
        assert_eq!(state.change_for(&local), None);
    }

    #[test]
    fn pins_only_after_a_local_key_validates() {
        let local = Target::local("192.168.1.1").unwrap();
        let fp = Some(Fingerprint::of(b"a"));
        assert_eq!(first_use_pin(&local, None, 200, fp), fp);
        assert_eq!(first_use_pin(&local, None, 204, fp), fp);
        assert_eq!(first_use_pin(&local, None, 401, fp), None, "a rejected key pins nothing");
        assert_eq!(first_use_pin(&local, None, 302, fp), None);
        assert_eq!(first_use_pin(&local, fp, 200, fp), None, "already pinned");
        assert_eq!(first_use_pin(&Target::cloud(), None, 200, fp), None, "cloud is never pinned");
    }

    #[test]
    fn the_repin_prompt_shows_both_fingerprints() {
        let change = CertChange { pinned: Fingerprint::of(b"a"), presented: Fingerprint::of(b"b") };
        let text = repin_prompt("192.168.1.1", &change);
        assert!(text.contains("192.168.1.1"));
        assert!(text.contains(&change.pinned.to_string()));
        assert!(text.contains(&change.presented.to_string()));
    }

    /// A one-shot HTTPS server on 127.0.0.1 presenting the given test
    /// certificate. Returns its port and a handle yielding every byte of
    /// application data it received (empty if the client aborted the
    /// handshake).
    fn tls_server(cert: &'static [u8], key: &'static [u8]) -> (u16, std::thread::JoinHandle<Vec<u8>>) {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use std::io::{Read, Write};
        use std::sync::Arc;

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
            )
            .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            tcp.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
            let conn = rustls::ServerConnection::new(Arc::new(config)).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, tcp);
            let mut received = Vec::new();
            let mut buf = [0u8; 4096];
            while !received.windows(4).any(|w| w == b"\r\n\r\n") {
                match tls.read(&mut buf) {
                    Ok(0) | Err(_) => return received,
                    Ok(n) => received.extend_from_slice(&buf[..n]),
                }
            }
            let body = br#"{"ok":true}"#;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = tls.write_all(head.as_bytes());
            let _ = tls.write_all(body);
            let _ = tls.flush();
            tls.conn.send_close_notify();
            let _ = tls.flush();
            received
        });
        (port, handle)
    }

    const CERT_A: &[u8] = include_bytes!("testdata/console-a.cert.der");
    const KEY_A: &[u8] = include_bytes!("testdata/console-a.key.der");
    const CERT_B: &[u8] = include_bytes!("testdata/console-b.cert.der");
    const KEY_B: &[u8] = include_bytes!("testdata/console-b.key.der");
    const TEST_KEY: &str = "test-api-key-0123456789";

    fn fetch(port: u16, pin: Option<Fingerprint>) -> Result<Outcome, String> {
        let target = Target::local(&format!("127.0.0.1:{port}")).unwrap();
        let url = target.resolve("/proxy/network/integration/v1/info").unwrap();
        tauri::async_runtime::block_on(send(&target, TEST_KEY, url, pin))
    }

    #[test]
    fn first_use_sends_the_key_and_reports_the_certificate_to_pin() {
        let (port, server) = tls_server(CERT_A, KEY_A);
        let outcome = fetch(port, None).unwrap();
        let received = String::from_utf8(server.join().unwrap()).unwrap();
        match outcome {
            Outcome::Response { status, presented, .. } => {
                assert_eq!(status, 200);
                assert_eq!(presented, Some(Fingerprint::of(CERT_A)));
            }
            other => panic!("expected a response, got {other:?}"),
        }
        assert!(received.to_ascii_lowercase().contains(&format!("x-api-key: {TEST_KEY}")));
    }

    #[test]
    fn a_matching_pin_sends_the_key() {
        let (port, server) = tls_server(CERT_A, KEY_A);
        let outcome = fetch(port, Some(Fingerprint::of(CERT_A))).unwrap();
        let received = String::from_utf8(server.join().unwrap()).unwrap();
        assert!(matches!(outcome, Outcome::Response { status: 200, .. }), "{outcome:?}");
        assert!(received.contains(TEST_KEY));
    }

    #[test]
    fn a_mismatched_certificate_is_refused_before_the_key_is_sent() {
        let (port, server) = tls_server(CERT_B, KEY_B);
        let pinned = Fingerprint::of(CERT_A);
        let outcome = fetch(port, Some(pinned)).unwrap();
        let received = server.join().unwrap();
        match outcome {
            Outcome::CertChanged(change) => {
                assert_eq!(change.pinned, pinned);
                assert_eq!(change.presented, Fingerprint::of(CERT_B));
            }
            other => panic!("expected a certificate change, got {other:?}"),
        }
        assert!(received.is_empty(), "server received {} bytes of request data", received.len());
    }
}
