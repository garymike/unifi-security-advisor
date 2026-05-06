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

    // 2. Determine if file is a plain ZIP (.unifi from newer devices) or AES-encrypted (.unf)
    let zip_data: Vec<u8> = if raw.len() >= 4 && &raw[..4] == b"PK\x03\x04" {
        // Already a plain ZIP — .unifi files from newer devices skip encryption
        raw
    } else {
        // Try AES-128-CBC decryption (static public keys used by all UniFi tools)
        let decrypted = Aes128CbcDec::new(UNF_KEY.into(), UNF_IV.into())
            .decrypt_padded_vec_mut::<NoPadding>(&raw)
            .map_err(|e| format!("AES decryption failed: {:?}", e))?;

        if decrypted.len() < 4 || &decrypted[..4] != b"PK\x03\x04" {
            return Err(
                "Not a valid UniFi backup file (unrecognised format). \
                 Try downloading from UniFi Network → UCG Fiber → Control Plane → Backups."
                    .to_string(),
            );
        }
        decrypted
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
