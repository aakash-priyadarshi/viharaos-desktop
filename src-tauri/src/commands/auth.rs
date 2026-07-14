use crate::AppState;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Response from POST /auth/device/code (cloud API)
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_url: String,
    expires_in: u64,
    interval: u64,
}

/// Response from POST /auth/device/token (cloud API) on success
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceTokenResponse {
    access_token: String,
    refresh_token: String,
    user: CloudUser,
    remember_me: bool,
}

/// User object returned by the cloud API
#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CloudUser {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub property_id: Option<String>,
    pub organization_id: Option<String>,
    pub is_platform_admin: bool,
    pub can_manage_staff: bool,
    pub managed_hotel_ids: Vec<String>,
}

/// Result returned to the frontend after successful browser login
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserLoginResult {
    pub access_token: String,
    pub refresh_token: String,
    pub user: BrowserLoginUser,
    pub remember_me: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserLoginUser {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub property_id: Option<String>,
    pub organization_id: Option<String>,
    pub is_platform_admin: bool,
    pub can_manage_staff: bool,
    pub managed_hotel_ids: Vec<String>,
}

impl From<CloudUser> for BrowserLoginUser {
    fn from(u: CloudUser) -> Self {
        Self {
            id: u.id,
            email: u.email,
            name: u.name,
            role: u.role,
            property_id: u.property_id,
            organization_id: u.organization_id,
            is_platform_admin: u.is_platform_admin,
            can_manage_staff: u.can_manage_staff,
            managed_hotel_ids: u.managed_hotel_ids,
        }
    }
}

/// Get the cloud API server URL from sync_settings.
/// Falls back to the production API URL if not configured.
pub(crate) fn get_server_url(state: &AppState) -> String {
    if let Ok(conn) = state.db.conn() {
        if let Ok(url) = conn.query_row(
            "SELECT value FROM sync_settings WHERE key = 'server_url'",
            [],
            |row| row.get::<_, String>(0),
        ) {
            if !url.is_empty() {
                return url.trim_end_matches('/').to_string();
            }
        }
    }
    // Default to production API
    "https://api.viharaos.com/api".to_string()
}

/// Ensure the organization and property referenced by a cloud user exist
/// in the local SQLite cache so the `user` row can be inserted without
/// violating foreign-key constraints.
fn ensure_org_and_property_for_user(
    conn: &rusqlite::Connection,
    user: &CloudUser,
) -> Result<(), String> {
    if let Some(org_id) = &user.organization_id {
        conn.execute(
            "INSERT OR IGNORE INTO organization (id, name) VALUES (?1, ?1)",
            rusqlite::params![org_id],
        )
        .map_err(|e| e.to_string())?;
    }

    if let Some(prop_id) = &user.property_id {
        let org_id = user.organization_id.as_deref().unwrap_or("");
        // property.organization_id is NOT NULL; make sure the referenced
        // organization exists. Use an empty placeholder when the user has
        // no organization_id; it will be reconciled on the next sync.
        if org_id.is_empty() {
            conn.execute(
                "INSERT OR IGNORE INTO organization (id, name) VALUES ('', '')",
                [],
            )
            .map_err(|e| e.to_string())?;
        }
        conn.execute(
            "INSERT OR IGNORE INTO property (id, organization_id, name) VALUES (?1, ?2, ?1)",
            rusqlite::params![prop_id, org_id],
        )
        .map_err(|e| e.to_string())?;
    }

    Ok(())
}

/// Store cloud JWT tokens and user data in the local database.
/// Also creates a local session token for the embedded API server.
pub(crate) fn store_cloud_session(
    state: &AppState,
    user: &CloudUser,
    access_token: &str,
    refresh_token: &str,
    remember_me: bool,
) -> Result<String, String> {
    let conn = state.db.conn().map_err(|e| e.to_string())?;
    let session_ttl = if remember_me { "+15 days" } else { "+7 days" };

    // The local user table has foreign keys to organization and property.
    // If the sync cache hasn't pulled these rows yet, create stub rows so
    // the upsert succeeds. The real names will be filled in on the next sync.
    ensure_org_and_property_for_user(&conn, user)?;

    // Upsert the user in the local user table
    conn.execute(
        "INSERT INTO user (id, email, name, role, is_active, organization_id, property_id, auth_token, refresh_token, token_expires_at)
         VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7, ?8, datetime('now', ?9))
         ON CONFLICT(id) DO UPDATE SET
           email = ?2, name = ?3, role = ?4, organization_id = ?5, property_id = ?6,
           auth_token = ?7, refresh_token = ?8,
           token_expires_at = datetime('now', ?9),
           last_login_at = datetime('now')",
        rusqlite::params![
            &user.id,
            &user.email,
            &user.name,
            &user.role,
            &user.organization_id,
            &user.property_id,
            access_token,
            refresh_token,
            session_ttl,
        ],
    ).map_err(|e| e.to_string())?;

    // Generate a local session token for the embedded API server
    let session_token = format!("browser-{}", uuid::Uuid::new_v4());
    conn.execute(
        "INSERT INTO session_token (token, user_id, expires_at) VALUES (?1, ?2, datetime('now', ?3))",
        rusqlite::params![&session_token, &user.id, session_ttl],
    ).map_err(|e| e.to_string())?;

    // Clean up expired tokens
    let _ = conn.execute(
        "DELETE FROM session_token WHERE expires_at < datetime('now')",
        [],
    );

    // Store the auth token and server URL in sync_settings for the sync engine
    let _ = conn.execute(
        "INSERT OR REPLACE INTO sync_settings (key, value) VALUES ('auth_token', ?1)",
        rusqlite::params![access_token],
    );
    let _ = conn.execute(
        "INSERT OR REPLACE INTO sync_settings (key, value) VALUES ('server_url', ?1)",
        rusqlite::params![get_server_url(state)],
    );
    let _ = conn.execute(
        "INSERT OR REPLACE INTO sync_settings (key, value) VALUES ('remember_me', ?1)",
        rusqlite::params![if remember_me { "1" } else { "0" }],
    );

    Ok(session_token)
}

/// Return the newest non-expired local staff session, if any.
/// Used by the web AuthProvider on desktop cold start when cookies were lost.
#[tauri::command]
pub async fn get_active_session(
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<Option<BrowserLoginResult>, String> {
    let conn = state.db.conn().map_err(|e| e.to_string())?;

    let remember_me_flag: String = conn
        .query_row(
            "SELECT value FROM sync_settings WHERE key = 'remember_me'",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|_| "0".to_string());
    let remember_me = remember_me_flag == "1";

    let result = conn.query_row(
        "SELECT st.token, u.id, u.email, u.name, u.role, u.organization_id, u.property_id
         FROM session_token st
         JOIN user u ON u.id = st.user_id
         WHERE st.expires_at > datetime('now') AND u.is_active = 1
         ORDER BY st.expires_at DESC
         LIMIT 1",
        [],
        |row| {
            let token: String = row.get(0)?;
            let role: String = row.get(4)?;
            let is_platform_admin = role == "SYSTEM_ADMIN";
            let can_manage_staff = matches!(
                role.as_str(),
                "SYSTEM_ADMIN" | "HOTEL_ADMIN" | "OWNER" | "GENERAL_MANAGER"
            );
            Ok(BrowserLoginResult {
                access_token: token.clone(),
                refresh_token: token,
                user: BrowserLoginUser {
                    id: row.get(1)?,
                    email: row.get(2)?,
                    name: row.get(3)?,
                    role,
                    organization_id: row.get(5)?,
                    property_id: row.get(6)?,
                    is_platform_admin,
                    can_manage_staff,
                    managed_hotel_ids: Vec::new(),
                },
                remember_me,
            })
        },
    );

    match result {
        Ok(session) => {
            log::info!(
                "Restored active session for user {} ({})",
                session.user.email,
                session.user.id
            );
            Ok(Some(session))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// Explicit logout: wipe local session tokens and cached cloud JWTs.
#[tauri::command]
pub async fn clear_local_sessions(
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let conn = state.db.conn().map_err(|e| e.to_string())?;
    let _ = conn.execute("DELETE FROM session_token", []);
    let _ = conn.execute(
        "UPDATE user SET auth_token = NULL, refresh_token = NULL, token_expires_at = NULL",
        [],
    );
    let _ = conn.execute(
        "DELETE FROM sync_settings WHERE key IN ('auth_token', 'remember_me')",
        [],
    );
    log::info!("Cleared local staff sessions");
    Ok(())
}

/// Initiate browser-based login using the OAuth device authorization flow.
///
/// 1. Requests a device code from the cloud API
/// 2. Opens the verification URL in the system browser
/// 3. Polls the cloud API for tokens (every `interval` seconds)
/// 4. On success, stores tokens + user data locally and returns the session
///
/// The polling timeout is 5 minutes (matching the device code TTL).
#[tauri::command]
pub async fn login_with_browser(
    state: tauri::State<'_, Arc<AppState>>,
    provider_hint: Option<String>,
) -> Result<BrowserLoginResult, String> {
    let server_url = get_server_url(&state);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    // Step 1: Request a device code
    let code_url = format!("{}/auth/device/code", server_url);
    let code_resp = client
        .post(&code_url)
        .send()
        .await
        .map_err(|e| format!("Failed to request device code: {}", e))?;

    if !code_resp.status().is_success() {
        let status = code_resp.status();
        let body = code_resp.text().await.unwrap_or_default();
        return Err(format!("Device code request failed ({}): {}", status, body));
    }

    let device_code: DeviceCodeResponse = code_resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse device code response: {}", e))?;

    let mut verification_url = device_code.verification_url.clone();
    if provider_hint.as_deref() == Some("google") {
        let separator = if verification_url.contains('?') {
            "&"
        } else {
            "?"
        };
        verification_url = format!("{}{}provider=google", verification_url, separator);
    }

    log::info!(
        "Browser login: device code created, user_code={}, verification_url={}",
        device_code.user_code,
        verification_url
    );

    // Step 2: Open the verification URL in the system browser
    if let Err(e) = open::that(&verification_url) {
        log::error!("Failed to open browser: {}", e);
        return Err(format!("Failed to open browser: {}", e));
    }

    // Step 3: Poll for tokens
    let token_url = format!("{}/auth/device/token", server_url);
    let poll_interval = std::time::Duration::from_secs(device_code.interval.max(1));
    let max_polls = (device_code.expires_in / device_code.interval.max(1)).max(1);
    let mut last_error = String::new();

    for i in 0..max_polls {
        // Wait before polling (skip on first iteration to give the user time)
        if i > 0 {
            tokio::time::sleep(poll_interval).await;
        }

        let resp = client
            .post(&token_url)
            .json(&serde_json::json!({ "deviceCode": device_code.device_code }))
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status();
                if status.is_success() {
                    // Success — parse the token response
                    let token_resp: DeviceTokenResponse = r
                        .json()
                        .await
                        .map_err(|e| format!("Failed to parse token response: {}", e))?;

                    log::info!(
                        "Browser login: authorized for user {} ({})",
                        token_resp.user.email,
                        token_resp.user.id
                    );

                    // Step 4: Store tokens + user data locally
                    let session_token = store_cloud_session(
                        &state,
                        &token_resp.user,
                        &token_resp.access_token,
                        &token_resp.refresh_token,
                        token_resp.remember_me,
                    )
                    .map_err(|e| {
                        log::error!("Failed to store cloud session: {}", e);
                        e
                    })?;

                    return Ok(BrowserLoginResult {
                        access_token: session_token.clone(),
                        refresh_token: session_token,
                        user: token_resp.user.into(),
                        remember_me: token_resp.remember_me,
                    });
                } else if status.as_u16() == 400 {
                    // authorization_pending — keep polling
                    let body = r.text().await.unwrap_or_default();
                    if body.contains("authorization_pending") {
                        log::debug!(
                            "Browser login: still pending (poll {}/{})",
                            i + 1,
                            max_polls
                        );
                        continue;
                    }
                    // Other 400 errors (access_denied, etc.)
                    last_error = body;
                    log::warn!("Browser login: 400 error: {}", last_error);
                    continue;
                } else if status.as_u16() == 410 {
                    // expired_token
                    return Err("Device code expired. Please try again.".to_string());
                } else {
                    let body = r.text().await.unwrap_or_default();
                    last_error = format!("Unexpected status {}: {}", status, body);
                    log::warn!("Browser login: {}", last_error);
                }
            }
            Err(e) => {
                last_error = format!("Network error: {}", e);
                log::warn!("Browser login: {}", last_error);
            }
        }
    }

    Err(format!(
        "Browser login timed out after {} polls. {}",
        max_polls, last_error
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloud_user_to_browser_login_user_conversion() {
        let cloud_user = CloudUser {
            id: "user-123".to_string(),
            email: "test@example.com".to_string(),
            name: "Test User".to_string(),
            role: "RECEPTIONIST".to_string(),
            property_id: Some("prop-1".to_string()),
            organization_id: Some("org-1".to_string()),
            is_platform_admin: false,
            can_manage_staff: false,
            managed_hotel_ids: vec![],
        };

        let login_user: BrowserLoginUser = cloud_user.into();
        assert_eq!(login_user.id, "user-123");
        assert_eq!(login_user.email, "test@example.com");
        assert_eq!(login_user.name, "Test User");
        assert_eq!(login_user.role, "RECEPTIONIST");
        assert_eq!(login_user.property_id, Some("prop-1".to_string()));
        assert_eq!(login_user.organization_id, Some("org-1".to_string()));
        assert!(!login_user.is_platform_admin);
    }

    #[test]
    fn test_cloud_user_to_browser_login_user_with_null_fields() {
        let cloud_user = CloudUser {
            id: "user-456".to_string(),
            email: "admin@example.com".to_string(),
            name: "Admin".to_string(),
            role: "SYSTEM_ADMIN".to_string(),
            property_id: None,
            organization_id: None,
            is_platform_admin: true,
            can_manage_staff: true,
            managed_hotel_ids: vec!["hotel-1".to_string(), "hotel-2".to_string()],
        };

        let login_user: BrowserLoginUser = cloud_user.into();
        assert_eq!(login_user.property_id, None);
        assert_eq!(login_user.organization_id, None);
        assert!(login_user.is_platform_admin);
        assert!(login_user.can_manage_staff);
        assert_eq!(login_user.managed_hotel_ids.len(), 2);
    }
}
