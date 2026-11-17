//! Trust-on-first-use certificate pinning for local controllers.
//!
//! UniFi consoles present self-signed certificates, so a normal chain check
//! cannot tell the real console from anyone else on the LAN. Instead, the
//! first time a key validates against a `local:<host>` target we record the
//! SHA-256 of the certificate the console presented, and from then on the TLS
//! handshake itself fails unless the console presents that same certificate.
//! The check runs inside the handshake, before reqwest writes a single byte of
//! the request, so a mismatched console never receives the `X-API-KEY` header.
//!
//! The fingerprint is of the whole leaf certificate (DER), which is what
//! `openssl x509 -fingerprint -sha256` and browsers show, so a user can compare
//! it against the console by hand. Hostname and expiry are not checked: the
//! pin is the identity, and self-signed console certificates often carry
//! neither a matching name nor a sensible validity period. The handshake
//! signature is still verified, so presenting a copy of the pinned certificate
//! without its private key fails.
//!
//! Cloud (`api.ui.com`) does not use this module; it keeps reqwest's normal
//! platform chain verification.

use std::fmt;
use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};

/// SHA-256 of a DER certificate. Not a secret.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub fn of(der: &[u8]) -> Self {
        let digest = ring::digest::digest(&ring::digest::SHA256, der);
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        Fingerprint(out)
    }

    /// Parse the stored form (see `Display`). Separators and case are ignored
    /// so a value copied from another tool also parses.
    pub fn parse(s: &str) -> Option<Self> {
        let hex: Vec<u8> = s.bytes().filter(|b| b.is_ascii_hexdigit()).collect();
        if hex.len() != 64 || s.bytes().any(|b| !(b.is_ascii_hexdigit() || b == b':')) {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, pair) in hex.chunks(2).enumerate() {
            let pair = std::str::from_utf8(pair).ok()?;
            out[i] = u8::from_str_radix(pair, 16).ok()?;
        }
        Some(Fingerprint(out))
    }
}

/// Upper-case hex pairs separated by colons, as openssl prints them.
impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }
            write!(f, "{b:02X}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

/// The process-wide rustls provider. reqwest is built without a bundled
/// provider (see Cargo.toml), so this must run before any client is built;
/// tauri-plugin-updater installs the same one. Safe to call repeatedly.
pub fn ensure_crypto_provider() {
    if CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

/// Accepts exactly one certificate (or, on first use, any certificate) and
/// records what the server presented so the caller can pin it or report it.
#[derive(Debug)]
pub struct PinVerifier {
    expected: Option<Fingerprint>,
    presented: Mutex<Option<Fingerprint>>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl PinVerifier {
    /// The leaf the server presented in the most recent handshake, if any.
    pub fn presented(&self) -> Option<Fingerprint> {
        self.presented.lock().ok().and_then(|g| *g)
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let seen = Fingerprint::of(end_entity.as_ref());
        if let Ok(mut slot) = self.presented.lock() {
            *slot = Some(seen);
        }
        match self.expected {
            None => Ok(ServerCertVerified::assertion()),
            Some(pin) if pin == seen => Ok(ServerCertVerified::assertion()),
            Some(_) => Err(TlsError::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// A rustls config for one local request: accepts only `expected`, or on
/// first use (`None`) any certificate. Returns the verifier so the caller can
/// read what was presented after the request.
pub fn local_client_config(expected: Option<Fingerprint>) -> Result<(ClientConfig, Arc<PinVerifier>), String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinVerifier {
        expected,
        presented: Mutex::new(None),
        algorithms: provider.signature_verification_algorithms,
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    Ok((config, verifier))
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const CERT_A: &[u8] = include_bytes!("testdata/console-a.cert.der");

    #[test]
    fn fingerprint_matches_openssl_and_round_trips() {
        // `openssl x509 -inform DER -in console-a.cert.der -noout -fingerprint -sha256`
        let fp = Fingerprint::of(CERT_A);
        let shown = "D2:F4:1E:3A:4C:E6:45:5D:38:55:EA:61:EA:E4:18:F2:C5:4B:19:66:2A:1F:85:22:0F:D3:E8:E7:0A:7A:B5:D1";
        assert_eq!(fp.to_string(), shown);
        assert_eq!(Fingerprint::parse(shown), Some(fp));
        assert_eq!(Fingerprint::parse(&shown.replace(':', "").to_lowercase()), Some(fp));
    }

    #[test]
    fn parse_rejects_anything_that_is_not_one_sha256() {
        for bad in ["", "abc", &"0".repeat(62), &"0".repeat(66), &format!("{}zz", "0".repeat(62)), &format!("{} ", "0".repeat(64))] {
            assert_eq!(Fingerprint::parse(bad), None, "{bad:?}");
        }
    }

    fn verify(expected: Option<Fingerprint>, der: &[u8]) -> (bool, Option<Fingerprint>) {
        let (_, v) = local_client_config(expected).unwrap();
        let name = ServerName::try_from("192.168.1.1").unwrap();
        let ok = v
            .verify_server_cert(&CertificateDer::from(der.to_vec()), &[], &name, &[], UnixTime::now())
            .is_ok();
        (ok, v.presented())
    }

    #[test]
    fn verifier_accepts_the_pin_and_refuses_anything_else() {
        let a = Fingerprint::of(CERT_A);
        let b_der = include_bytes!("testdata/console-b.cert.der");
        assert_eq!(verify(Some(a), CERT_A), (true, Some(a)));
        let (ok, seen) = verify(Some(a), b_der);
        assert!(!ok, "a different certificate must fail the handshake");
        assert_eq!(seen, Some(Fingerprint::of(b_der)), "the new certificate is reported for re-pinning");
        // First use: nothing pinned yet, so the certificate is accepted and recorded.
        assert_eq!(verify(None, b_der), (true, Some(Fingerprint::of(b_der))));
    }
}
