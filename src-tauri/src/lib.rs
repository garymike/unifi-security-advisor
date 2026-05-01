use tauri::command;

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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_sql::Builder::default().build())
        .plugin(tauri_plugin_http::init())
        .invoke_handler(tauri::generate_handler![unifi_fetch])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
