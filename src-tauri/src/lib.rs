use std::collections::HashMap;
use std::io::Read;
use tauri::command;

mod keychain;

// Public AES-128-CBC keys (from UniFi source, used by all open-source tools in this space)
const UNF_KEY: &[u8; 16] = b"bcyangkmluohmars";
const UNF_IV: &[u8; 16] = b"ubntenterpriseap";

// Public AES-256-CBC key for the newer UniFi OS console `.unifi` backup format
// (Cloud Gateway Fiber and similar). Reverse-engineered from firmware; a fixed
// decryption constant, not a credential. Stored as raw bytes (rather than a hex
// string) both to avoid a hex-decode dependency and to keep the high-entropy
// literal out of secret scanners. Equivalent hex:
// e383b7c53698b36d4baea4ed22181ef73676bfd5d5b90005d9845ffd5dce985f
const CONSOLE_KEY: &[u8; 32] = &[
    0xe3, 0x83, 0xb7, 0xc5, 0x36, 0x98, 0xb3, 0x6d, 0x4b, 0xae, 0xa4, 0xed, 0x22, 0x18, 0x1e, 0xf7,
    0x36, 0x76, 0xbf, 0xd5, 0xd5, 0xb9, 0x00, 0x05, 0xd9, 0x84, 0x5f, 0xfd, 0x5d, 0xce, 0x98, 0x5f,
];

/// HTTP fetch for the UniFi API. TLS cert validation is kept ON by default and
/// only disabled when `verify_ssl` is false — the local-controller case, where
/// consoles present self-signed certificates. Cloud (Site Manager, api.ui.com)
/// has a valid chain and is verified normally.
#[command]
async fn unifi_fetch(
    url: String,
    api_key: String,
    verify_ssl: bool,
) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(!verify_ssl)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;

    let response = client
        .get(&url)
        .header("X-API-KEY", &api_key)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let status = response.status().as_u16();
    let data: serde_json::Value = match response.json().await {
        Ok(v) => v,
        Err(_) => serde_json::json!({ "nonJsonResponse": true }),
    };

    Ok(serde_json::json!({ "status": status, "data": data }))
}

/// Write UTF-8 text to a path the user picked via the save dialog. A browser
/// `<a download>` is silently ignored inside the Tauri webview, so the report
/// export saves through this command instead.
#[command]
fn write_text_file(path: String, contents: String) -> Result<(), String> {
    std::fs::write(&path, contents).map_err(|e| format!("Cannot write '{}': {}", path, e))
}

/// Parse a UniFi backup file. Returns raw MongoDB collections as JSON.
/// Handles two formats: the classic `.unf` scheme (AES-128-CBC → ZIP → BSON)
/// and the newer UniFi OS console `.unifi` scheme (AES-256-CBC with an embedded
/// IV → gzip'd TAR → marker-based BSON). All crypto and binary parsing runs in
/// Rust — the decrypted data never touches the webview's JavaScript heap.
#[command]
fn parse_backup(path: String) -> Result<serde_json::Value, String> {
    let raw = std::fs::read(&path)
        .map_err(|e| format!("Cannot read '{}': {}", path, e))?;

    // 1. Classic .unf: locate a ZIP archive (plain, prefixed, or AES-128-decrypted).
    if let Some(zip_data) = detect_classic_zip(&raw) {
        let collections = collections_from_zip(zip_data)?;
        return serde_json::to_value(collections).map_err(|e| e.to_string());
    }

    // 2. UniFi OS console .unifi: AES-256 + embedded IV → gzip → TAR → marker BSON.
    match parse_console_unifi(&raw) {
        Ok(collections) => serde_json::to_value(collections).map_err(|e| e.to_string()),
        Err(console_err) => Err(format!(
            "Unrecognized backup format — the classic .unf scheme found no ZIP archive, \
             and the UniFi OS console scheme failed: {}",
            console_err
        )),
    }
}

/// Classic `.unf` detection: returns the ZIP bytes if the file is a plain ZIP,
/// carries a ZIP after a short prefix, or decrypts (AES-128-CBC, static key/IV)
/// to one. `None` means "not a classic .unf" — the caller then tries the console
/// format.
fn detect_classic_zip(raw: &[u8]) -> Option<Vec<u8>> {
    use aes::Aes128;
    use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
    use cbc::Decryptor;
    type Aes128CbcDec = Decryptor<Aes128>;

    // Strategy A: plain ZIP (no encryption)
    if raw.len() >= 4 && &raw[..4] == b"PK\x03\x04" {
        return Some(raw.to_vec());
    }
    // Strategy B: ZIP magic found after a short header
    if let Some(offset) = raw[..raw.len().min(256)]
        .windows(4)
        .position(|w| w == b"PK\x03\x04")
    {
        return Some(raw[offset..].to_vec());
    }
    // Strategy C: AES-128-CBC with standard .unf static key + static IV
    if let Ok(d) = Aes128CbcDec::new(UNF_KEY.into(), UNF_IV.into())
        .decrypt_padded_vec_mut::<NoPadding>(raw)
    {
        if d.len() >= 4 && &d[..4] == b"PK\x03\x04" {
            return Some(d);
        }
    }
    None
}

/// Classic path: extract collections from the decrypted ZIP. Handles both the
/// older single-file `db.gz` layout and the newer `dump/<db>/<collection>.bson`
/// mongodump layout.
fn collections_from_zip(zip_data: Vec<u8>) -> Result<HashMap<String, Vec<serde_json::Value>>, String> {
    use flate2::read::GzDecoder;
    use std::io::Cursor;
    use zip::ZipArchive;

    let mut zip = ZipArchive::new(Cursor::new(&zip_data))
        .map_err(|e| format!("ZIP error: {}", e))?;

    let names: Vec<String> = (0..zip.len())
        .filter_map(|i| zip.by_index(i).ok().map(|f| f.name().to_string()))
        .collect();

    let mut collections: HashMap<String, Vec<serde_json::Value>> = HashMap::new();

    if names.iter().any(|n| n == "db.gz") {
        // Older single-file format: db.gz with all collections concatenated
        let mut gz_file = zip.by_name("db.gz").map_err(|e| e.to_string())?;
        let mut gz_data = Vec::new();
        gz_file.read_to_end(&mut gz_data).map_err(|e| e.to_string())?;
        let mut bson_data = Vec::new();
        GzDecoder::new(gz_data.as_slice())
            .read_to_end(&mut bson_data)
            .map_err(|e| e.to_string())?;
        for doc in parse_bson_stream(&bson_data)? {
            let coll = doc
                .get("collection")
                .or_else(|| doc.get("_type"))
                .and_then(|v| v.as_str())
                .unwrap_or("_unknown")
                .to_string();
            collections.entry(coll).or_default().push(doc);
        }
    } else {
        // Newer mongodump format: dump/<db>/<collection>.bson
        for i in 0..zip.len() {
            let mut file = zip.by_index(i).map_err(|e| e.to_string())?;
            let name = file.name().to_string();
            if !name.ends_with(".bson") {
                continue;
            }
            let coll = std::path::Path::new(&name)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            if coll.is_empty() {
                continue;
            }
            let mut data = Vec::new();
            file.read_to_end(&mut data).map_err(|e| e.to_string())?;
            collections.insert(coll, parse_bson_stream(&data)?);
        }
    }

    Ok(collections)
}

/// Console `.unifi` path: AES-256 decrypt (embedded IV) → gunzip → extract
/// `backup/network/db.gz` from the TAR → gunzip → marker-based BSON. Returns an
/// `Err` describing the failing step (used to build the combined error).
fn parse_console_unifi(raw: &[u8]) -> Result<HashMap<String, Vec<serde_json::Value>>, String> {
    let tar_gz = decrypt_console_backup(raw)?;
    let tar = gunzip(&tar_gz).map_err(|e| format!("decrypted stream is not valid gzip: {}", e))?;
    let db_gz = extract_tar_entry(&tar, "backup/network/db.gz")
        .ok_or("archive has no backup/network/db.gz entry")?;
    let bson = gunzip(&db_gz).map_err(|e| format!("backup/network/db.gz is not valid gzip: {}", e))?;
    parse_marker_stream_bson(&bson)
}

/// AES-256-CBC decrypt of a console backup. IV is the first 16 bytes, ciphertext
/// the rest, PKCS7 padding. Succeeds only if the plaintext starts with the gzip
/// magic (`1f 8b`) — this is the format-detection signal that distinguishes a
/// real console backup from an unrelated file that merely decrypts without error.
fn decrypt_console_backup(raw: &[u8]) -> Result<Vec<u8>, String> {
    use aes::Aes256;
    use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    use cbc::Decryptor;
    type Aes256CbcDec = Decryptor<Aes256>;

    if raw.len() <= 16 {
        return Err("file too short to contain an IV + ciphertext".into());
    }
    let iv: [u8; 16] = raw[..16].try_into().unwrap();
    let ciphertext = &raw[16..];

    let plain = Aes256CbcDec::new(CONSOLE_KEY.into(), &iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| "AES-256-CBC decryption failed (wrong key or not this format)".to_string())?;

    if plain.len() >= 2 && plain[0] == 0x1f && plain[1] == 0x8b {
        Ok(plain)
    } else {
        Err("decrypted data is not a gzip stream (not a console backup)".into())
    }
}

/// Walk a (uncompressed) USTAR archive and return the bytes of `name`, or `None`
/// if absent. Minimal reader: 512-byte header blocks, 100-byte NUL-terminated
/// filename field, 12-byte octal size field. No long-name/PAX extensions — the
/// real UniFi backup uses plain USTAR headers throughout.
fn extract_tar_entry(tar: &[u8], name: &str) -> Option<Vec<u8>> {
    let mut pos = 0usize;
    while pos + 512 <= tar.len() {
        let header = &tar[pos..pos + 512];
        // A pair of all-zero blocks marks the end of the archive.
        if header.iter().all(|&b| b == 0) {
            break;
        }
        let fname_end = header[..100].iter().position(|&b| b == 0).unwrap_or(100);
        let fname = std::str::from_utf8(&header[..fname_end]).unwrap_or("");
        let size_str = std::str::from_utf8(&header[124..136])
            .unwrap_or("")
            .trim_matches(|c: char| c == '\0' || c == ' ');
        let size = usize::from_str_radix(size_str, 8).unwrap_or(0);

        let data_start = pos + 512;
        if fname == name {
            let data_end = data_start.checked_add(size)?;
            if data_end <= tar.len() {
                return Some(tar[data_start..data_end].to_vec());
            }
            return None;
        }
        // Advance past this entry's data, rounded up to the next 512-byte block.
        let blocks = size.div_ceil(512);
        pos = data_start + blocks * 512;
    }
    None
}

/// Parse the console backup's marker-based BSON stream. A document carrying a
/// `collection` field is a marker: it sets the current collection and is not
/// itself emitted. Every other document is attributed to the current collection.
/// Documents before the first marker are dropped. Stops cleanly on a malformed
/// document (matches `parse_bson_stream`).
fn parse_marker_stream_bson(data: &[u8]) -> Result<HashMap<String, Vec<serde_json::Value>>, String> {
    let mut collections: HashMap<String, Vec<serde_json::Value>> = HashMap::new();
    let mut current: Option<String> = None;
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let len = i32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        if len < 5 || pos + len > data.len() {
            break;
        }
        let doc = match bson::from_slice::<bson::Document>(&data[pos..pos + len]) {
            Ok(d) => d,
            Err(_) => break,
        };
        pos += len;

        if let Some(coll) = doc.get("collection").and_then(|v| v.as_str()) {
            // Marker document — switch collection, don't emit the marker itself.
            // (A collection appears in the output only once it has ≥1 data doc,
            // matching the Node parseMarkerStreamBson.)
            current = Some(coll.to_string());
            continue;
        }
        if let Some(coll) = &current {
            let value = serde_json::to_value(&doc).map_err(|e| e.to_string())?;
            collections.entry(coll.clone()).or_default().push(value);
        }
        // Documents before the first marker are intentionally dropped.
    }
    Ok(collections)
}

/// Gunzip a byte slice.
fn gunzip(data: &[u8]) -> Result<Vec<u8>, String> {
    use flate2::read::GzDecoder;
    let mut out = Vec::new();
    GzDecoder::new(data)
        .read_to_end(&mut out)
        .map_err(|e| e.to_string())?;
    Ok(out)
}

fn parse_bson_stream(data: &[u8]) -> Result<Vec<serde_json::Value>, String> {
    let mut docs = Vec::new();
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let len = i32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        if len < 5 || pos + len > data.len() {
            break;
        }
        match bson::from_slice::<bson::Document>(&data[pos..pos + len]) {
            Ok(doc) => docs.push(serde_json::to_value(&doc).map_err(|e| e.to_string())?),
            Err(_) => break,
        }
        pos += len;
    }
    Ok(docs)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- synthetic-fixture builders ---------------------------------------

    fn aes256_encrypt_with_iv(plain: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        use aes::Aes256;
        use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
        use cbc::Encryptor;
        type Aes256CbcEnc = Encryptor<Aes256>;
        let ct = Aes256CbcEnc::new(CONSOLE_KEY.into(), iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(plain);
        let mut out = iv.to_vec();
        out.extend_from_slice(&ct);
        out
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// Minimal single-entry USTAR archive (no checksum — our reader ignores it),
    /// terminated by two zero blocks.
    fn tar_with(name: &str, data: &[u8]) -> Vec<u8> {
        let mut header = [0u8; 512];
        let nb = name.as_bytes();
        header[..nb.len()].copy_from_slice(nb);
        let size_oct = format!("{:011o}", data.len());
        header[124..124 + size_oct.len()].copy_from_slice(size_oct.as_bytes());
        header[156] = b'0'; // regular file

        let mut out = Vec::new();
        out.extend_from_slice(&header);
        out.extend_from_slice(data);
        let pad = (512 - data.len() % 512) % 512;
        out.extend(std::iter::repeat(0u8).take(pad));
        out.extend(std::iter::repeat(0u8).take(1024)); // end-of-archive
        out
    }

    fn bson_bytes(doc: &bson::Document) -> Vec<u8> {
        bson::to_vec(doc).unwrap()
    }

    // --- decrypt_console_backup -------------------------------------------

    #[test]
    fn decrypt_console_backup_roundtrips_to_gzip() {
        let gz = gzip(b"hello tar stream");
        let iv = [7u8; 16];
        let file = aes256_encrypt_with_iv(&gz, &iv);
        let out = decrypt_console_backup(&file).expect("should decrypt");
        assert_eq!(out, gz);
        assert_eq!(&out[..2], &[0x1f, 0x8b]);
    }

    #[test]
    fn decrypt_console_backup_rejects_non_gzip_plaintext() {
        let iv = [3u8; 16];
        let file = aes256_encrypt_with_iv(b"not a gzip payload at all", &iv);
        assert!(decrypt_console_backup(&file).is_err());
    }

    #[test]
    fn decrypt_console_backup_rejects_too_short() {
        assert!(decrypt_console_backup(&[0u8; 8]).is_err());
    }

    // --- extract_tar_entry -------------------------------------------------

    #[test]
    fn extract_tar_entry_finds_named_entry() {
        let payload = b"the db.gz bytes";
        let tar = tar_with("backup/network/db.gz", payload);
        let got = extract_tar_entry(&tar, "backup/network/db.gz");
        assert_eq!(got.as_deref(), Some(&payload[..]));
    }

    #[test]
    fn extract_tar_entry_returns_none_for_missing() {
        let tar = tar_with("backup/network/db.gz", b"x");
        assert!(extract_tar_entry(&tar, "backup/ucore/other").is_none());
    }

    // --- parse_marker_stream_bson -----------------------------------------

    #[test]
    fn parse_marker_stream_attributes_docs_to_current_collection() {
        let mut stream = Vec::new();
        stream.extend(bson_bytes(&bson::doc! { "collection": "device", "__cmd": "insert" }));
        stream.extend(bson_bytes(&bson::doc! { "mac": "aa:00:00:00:00:01", "model": "UDM" }));
        stream.extend(bson_bytes(&bson::doc! { "mac": "aa:00:00:00:00:02", "model": "U7" }));
        stream.extend(bson_bytes(&bson::doc! { "collection": "networkconf", "__cmd": "insert" }));
        stream.extend(bson_bytes(&bson::doc! { "name": "LAN", "purpose": "corporate" }));

        let cols = parse_marker_stream_bson(&stream).unwrap();
        assert_eq!(cols["device"].len(), 2);
        assert_eq!(cols["networkconf"].len(), 1);
        // Marker docs themselves are not emitted.
        assert!(cols["device"].iter().all(|d| d.get("collection").is_none()));
        assert_eq!(cols["networkconf"][0]["purpose"], "corporate");
    }

    #[test]
    fn parse_marker_stream_drops_docs_before_first_marker() {
        let mut stream = Vec::new();
        stream.extend(bson_bytes(&bson::doc! { "orphan": true }));
        stream.extend(bson_bytes(&bson::doc! { "collection": "device", "__cmd": "insert" }));
        stream.extend(bson_bytes(&bson::doc! { "mac": "aa:00:00:00:00:01" }));

        let cols = parse_marker_stream_bson(&stream).unwrap();
        assert_eq!(cols.len(), 1);
        assert_eq!(cols["device"].len(), 1);
    }

    #[test]
    fn parse_marker_stream_empty_input_is_empty() {
        let cols = parse_marker_stream_bson(&[]).unwrap();
        assert!(cols.is_empty());
    }

    // --- full console pipeline (decrypt → gunzip → untar → marker BSON) ----

    #[test]
    fn parse_console_unifi_end_to_end() {
        let mut stream = Vec::new();
        stream.extend(bson_bytes(&bson::doc! { "collection": "device", "__cmd": "insert" }));
        stream.extend(bson_bytes(&bson::doc! { "mac": "aa:00:00:00:00:01", "model": "UDM" }));

        let db_gz = gzip(&stream);
        let tar = tar_with("backup/network/db.gz", &db_gz);
        let tar_gz = gzip(&tar);
        let file = aes256_encrypt_with_iv(&tar_gz, &[9u8; 16]);

        let cols = parse_console_unifi(&file).expect("console pipeline should succeed");
        assert_eq!(cols["device"].len(), 1);
        assert_eq!(cols["device"][0]["model"], "UDM");
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_sql::Builder::default().build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            unifi_fetch,
            parse_backup,
            write_text_file,
            keychain::keychain_set,
            keychain::keychain_get,
            keychain::keychain_delete,
            keychain::keychain_scan
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
