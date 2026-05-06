use std::collections::HashMap;
use std::io::Read;
use tauri::command;

// Public AES-128-CBC keys (from UniFi source, used by all open-source tools in this space)
const UNF_KEY: &[u8; 16] = b"bcyangkmluohmars";
const UNF_IV: &[u8; 16] = b"ubntenterpriseap";

/// HTTP fetch with TLS cert validation disabled — required for local UniFi controllers
/// which use self-signed certificates.
#[command]
async fn unifi_fetch(url: String, api_key: String) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
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

/// Parse a UniFi .unf backup file. Returns raw MongoDB collections as JSON.
/// All crypto (AES-128-CBC) and binary parsing (ZIP, BSON) runs in Rust —
/// the decrypted data never touches the webview's JavaScript heap.
#[command]
fn parse_backup(path: String) -> Result<serde_json::Value, String> {
    use aes::Aes128;
    use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
    use cbc::Decryptor;
    use flate2::read::GzDecoder;
    use std::io::Cursor;
    use zip::ZipArchive;

    type Aes128CbcDec = Decryptor<Aes128>;

    // 1. Read file
    let raw = std::fs::read(&path)
        .map_err(|e| format!("Cannot read '{}': {}", path, e))?;

    // 2. Locate ZIP data using multiple strategies
    let zip_data: Vec<u8> = {
        // Strategy A: plain ZIP (no encryption)
        if raw.len() >= 4 && &raw[..4] == b"PK\x03\x04" {
            raw.clone()
        }
        // Strategy B: ZIP magic found after a header (some .unifi formats have a prefix)
        else if let Some(offset) = raw[..raw.len().min(256)]
            .windows(4)
            .position(|w| w == b"PK\x03\x04")
        {
            raw[offset..].to_vec()
        }
        // Strategy C: AES-128-CBC with standard .unf static key + static IV
        else if let Ok(d) = Aes128CbcDec::new(UNF_KEY.into(), UNF_IV.into())
            .decrypt_padded_vec_mut::<NoPadding>(&raw)
        {
            if d.len() >= 4 && &d[..4] == b"PK\x03\x04" { d }
            else { try_embedded_iv_strategies(&raw)? }
        }
        else {
            try_embedded_iv_strategies(&raw)?
        }
    };

    // 3. Open ZIP
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

    serde_json::to_value(collections).map_err(|e| e.to_string())
}

/// Try multiple AES-128-CBC strategies where the IV is embedded in the file.
/// Newer .unifi formats store a random per-file IV inside the backup instead of
/// using the static IV, making each backup uniquely encrypted.
fn try_embedded_iv_strategies(raw: &[u8]) -> Result<Vec<u8>, String> {
    use aes::Aes128;
    use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
    use cbc::Decryptor;
    type Aes128CbcDec = Decryptor<Aes128>;

    // Try each candidate (header_len, iv_offset): skip header bytes, read 16-byte IV, decrypt rest
    let candidates: &[(usize, usize)] = &[
        (0, 0),    // IV at bytes 0–15, data from 16
        (4, 4),    // 4-byte magic + IV at bytes 4–19, data from 20
        (8, 8),    // 8-byte header + IV at 8–23, data from 24
        (16, 0),   // 16-byte header, then static IV on remaining
        (32, 16),  // 32-byte header with IV embedded at 16–31
    ];

    for &(data_start, iv_start) in candidates {
        let iv_end = iv_start + 16;
        if raw.len() <= iv_end.max(data_start) { continue; }
        if iv_end > data_start && data_start < iv_start { continue; }

        let actual_data_start = data_start.max(iv_end);
        if raw.len() <= actual_data_start { continue; }

        let iv: [u8; 16] = raw[iv_start..iv_end].try_into().unwrap();
        let payload = &raw[actual_data_start..];

        if let Ok(d) = Aes128CbcDec::new(UNF_KEY.into(), &iv.into())
            .decrypt_padded_vec_mut::<NoPadding>(payload)
        {
            if d.len() >= 4 && &d[..4] == b"PK\x03\x04" {
                return Ok(d);
            }
        }
    }

    // Nothing worked — emit diagnostic hex for the first 32 bytes
    let header = raw.iter().take(32)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    Err(format!(
        "Unrecognised .unifi backup format (header: {}). \
         The Cloud Gateway Fiber may use device-specific encryption keys not yet \
         reverse-engineered by the community. \
         Try the Python CLI as a workaround: python src/parser.py analyze backup.unifi",
        header
    ))
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_sql::Builder::default().build())
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![unifi_fetch, parse_backup])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
