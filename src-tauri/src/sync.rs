use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;

use crate::db::models::SyncStatus;
use crate::db::Database;

pub struct SyncEngine {
    db: Arc<Database>,
}

impl SyncEngine {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Check if sync is enabled in settings
    pub fn is_enabled(&self) -> bool {
        let conn = match self.db.conn() {
            Ok(c) => c,
            Err(_) => return false,
        };
        let value: String = conn
            .query_row(
                "SELECT value FROM sync_settings WHERE key = 'enabled'",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| "true".to_string());
        value == "true"
    }

    /// Enable or disable sync
    pub fn set_enabled(&self, enabled: bool) {
        if let Ok(conn) = self.db.conn() {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO sync_settings (key, value) VALUES ('enabled', ?1)",
                rusqlite::params![if enabled { "true" } else { "false" }],
            );
        }
    }

    /// Get the remote server URL from settings, falling back to the production
    /// cloud API if no server_url has been configured locally.
    fn get_server_url(&self) -> Option<String> {
        let conn = self.db.conn().ok()?;
        let url: String = conn
            .query_row(
                "SELECT value FROM sync_settings WHERE key = 'server_url'",
                [],
                |row| row.get(0),
            )
            .ok()?;
        if url.is_empty() {
            Some("https://api.viharaos.com/api".to_string())
        } else {
            Some(url)
        }
    }

    /// Get the auth token from settings
    fn get_auth_token(&self) -> Option<String> {
        let conn = self.db.conn().ok()?;
        let token: String = conn
            .query_row(
                "SELECT value FROM sync_settings WHERE key = 'auth_token'",
                [],
                |row| row.get(0),
            )
            .ok()?;
        if token.is_empty() {
            None
        } else {
            Some(token)
        }
    }

    /// Check network connectivity by pinging the remote server
    async fn check_online(&self) -> bool {
        let server_url = match self.get_server_url() {
            Some(u) => u,
            None => return false,
        };
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build();
        let client = match client {
            Ok(c) => c,
            Err(_) => return false,
        };
        let health_url = format!("{}/health", server_url.trim_end_matches('/'));
        client.get(&health_url).send().await.is_ok()
    }

    /// Persist the current online status to sync_settings so get_status()
    /// can return the real value without making a network call.
    fn set_online_status(&self, online: bool) {
        if let Ok(conn) = self.db.conn() {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO sync_settings (key, value) VALUES ('is_online', ?1)",
                rusqlite::params![if online { "true" } else { "false" }],
            );
        }
    }

    /// Read the persisted online status from sync_settings.
    /// Returns false if the key is missing or the value is not "true".
    fn get_online_status(&self) -> bool {
        let conn = match self.db.conn() {
            Ok(c) => c,
            Err(_) => return false,
        };
        let value: String = conn
            .query_row(
                "SELECT value FROM sync_settings WHERE key = 'is_online'",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| "false".to_string());
        value == "true"
    }

    /// Get current sync status
    pub fn get_status(&self) -> SyncStatus {
        let conn = match self.db.conn() {
            Ok(c) => c,
            Err(_) => {
                return SyncStatus {
                    enabled: false,
                    last_sync_at: None,
                    pending_count: 0,
                    failed_count: 0,
                    conflict_count: 0,
                    is_online: false,
                }
            }
        };

        let enabled = self.is_enabled();
        let last_sync_at: Option<String> = conn
            .query_row(
                "SELECT value FROM sync_settings WHERE key = 'last_sync_at'",
                [],
                |row| row.get(0),
            )
            .ok()
            .filter(|s: &String| !s.is_empty());

        let pending_count: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM sync_outbox WHERE status = 'PENDING'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        let failed_count: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM sync_outbox WHERE status = 'FAILED'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        let conflict_count: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM sync_conflict WHERE resolved_at IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        SyncStatus {
            enabled,
            last_sync_at,
            pending_count,
            failed_count,
            conflict_count,
            is_online: self.get_online_status(),
        }
    }

    /// Background worker that periodically syncs when online and enabled
    pub async fn start_worker(self: Arc<Self>, state: Arc<crate::AppState>) {
        let mut tick = interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
            if !self.is_enabled() {
                continue;
            }

            // Check network connectivity and persist the result so
            // get_status() returns the real online state.
            let online = self.check_online().await;
            self.set_online_status(online);
            if !online {
                log::debug!("Sync worker: offline, skipping");
                continue;
            }

            log::debug!("Sync worker tick — online, pushing pending operations");
            if let Err(e) = self.push_pending().await {
                log::warn!("Sync push error: {}", e);
            }

            if let Err(e) = self.pull_remote().await {
                log::warn!("Sync pull error: {}", e);
            }

            // Send a best-effort heartbeat to the cloud so admins can see
            // this device's sync status. Failure is logged but not fatal.
            if let Some(ref url) = self.get_server_url() {
                let token = self.get_auth_token();
                if let Err(e) = crate::commands::heartbeat::send_heartbeat_to_cloud(
                    &state,
                    url,
                    token.as_deref(),
                )
                .await
                {
                    log::debug!("Heartbeat send failed (best-effort): {}", e);
                }
            }

            // Update last sync timestamp
            if let Ok(conn) = self.db.conn() {
                let _ = conn.execute(
                    "INSERT OR REPLACE INTO sync_settings (key, value) VALUES ('last_sync_at', datetime('now'))",
                    [],
                );
            }
        }
    }

    /// Push pending outbox entries to the remote server
    async fn push_pending(&self) -> Result<(), String> {
        let server_url = self.get_server_url().ok_or("No server URL configured")?;
        let auth_token = self.get_auth_token();

        let entries = {
            let conn = self.db.conn().map_err(|e| e.to_string())?;
            let mut stmt = conn
                .prepare(
                    "SELECT id, idempotency_key, entity_type, entity_id, operation, payload, retry_count, property_id
                     FROM sync_outbox
                     WHERE status = 'PENDING' OR (status = 'FAILED' AND retry_count < 5)
                     ORDER BY created_at ASC
                     LIMIT 50",
                )
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([], |row| {
                    Ok(SyncOutboxEntry {
                        id: row.get(0)?,
                        idempotency_key: row.get(1)?,
                        entity_type: row.get(2)?,
                        entity_id: row.get(3)?,
                        operation: row.get(4)?,
                        payload: row.get(5)?,
                        retry_count: row.get::<_, i32>(6).unwrap_or(0),
                        property_id: row.get::<_, String>(7).unwrap_or_default(),
                    })
                })
                .map_err(|e| e.to_string())?;
            rows.filter_map(|r| r.ok()).collect::<Vec<_>>()
        };

        if entries.is_empty() {
            return Ok(());
        }

        log::info!("Sync: {} pending entries to push", entries.len());

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| e.to_string())?;

        let push_url = format!("{}/sync/push", server_url.trim_end_matches('/'));

        for entry in &entries {
            let mut req = client
                .post(&push_url)
                .header("Content-Type", "application/json")
                .header("X-Idempotency-Key", &entry.idempotency_key)
                .json(&serde_json::json!({
                    "entityType": entry.entity_type,
                    "entityId": entry.entity_id,
                    "operation": entry.operation,
                    "payload": serde_json::from_str::<serde_json::Value>(&entry.payload)
                        .unwrap_or(serde_json::Value::Null),
                }));

            if let Some(ref token) = auth_token {
                req = req.header("Authorization", format!("Bearer {}", token));
            }

            match req.send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        // Mark as synced
                        if let Ok(conn) = self.db.conn() {
                            let _ = conn.execute(
                                "UPDATE sync_outbox SET status = 'SYNCED', synced_at = datetime('now') WHERE id = ?1",
                                rusqlite::params![entry.id],
                            );
                        }
                        log::debug!(
                            "Sync push success: {} {} {}",
                            entry.operation,
                            entry.entity_type,
                            entry.entity_id
                        );
                    } else if resp.status().as_u16() == 409 {
                        // Conflict — parse server payload and record it
                        let server_payload: String = resp
                            .text()
                            .await
                            .ok()
                            .filter(|s| !s.trim().is_empty())
                            .and_then(|s| {
                                // Validate it's parseable JSON; if not, fall back to "{}"
                                serde_json::from_str::<serde_json::Value>(&s)
                                    .ok()
                                    .map(|_| s)
                            })
                            .unwrap_or_else(|| "{}".to_string());

                        if let Ok(conn) = self.db.conn() {
                            let _ = conn.execute(
                                "UPDATE sync_outbox SET status = 'CONFLICT' WHERE id = ?1",
                                rusqlite::params![entry.id],
                            );
                            let conflict_id = uuid::Uuid::new_v4().to_string();
                            match conn.execute(
                                "INSERT INTO sync_conflict
                                 (id, entity_type, entity_id, local_payload, server_payload,
                                  conflict_type, property_id, created_at)
                                 VALUES (?1, ?2, ?3, ?4, ?5, 'REMOTE_NEWER', ?6, datetime('now'))",
                                rusqlite::params![
                                    conflict_id,
                                    entry.entity_type,
                                    entry.entity_id,
                                    entry.payload,
                                    server_payload,
                                    entry.property_id,
                                ],
                            ) {
                                Ok(_) => log::debug!(
                                    "Conflict row inserted for {} {}",
                                    entry.entity_type,
                                    entry.entity_id
                                ),
                                Err(e) => {
                                    log::error!(
                                    "Failed to insert sync_conflict for {} {} (property={}): {}",
                                    entry.entity_type, entry.entity_id, entry.property_id, e,
                                )
                                }
                            }
                        }
                        log::warn!(
                            "Sync conflict: {} {} {}",
                            entry.operation,
                            entry.entity_type,
                            entry.entity_id
                        );
                    } else {
                        // Server error — increment retry count
                        let status = resp.status().as_u16();
                        if let Ok(conn) = self.db.conn() {
                            let _ = conn.execute(
                                "UPDATE sync_outbox SET status = 'FAILED', retry_count = retry_count + 1, last_error = ?2 WHERE id = ?1",
                                rusqlite::params![entry.id, format!("HTTP {}", status)],
                            );
                        }
                        log::warn!("Sync push failed (HTTP {}): {}", status, entry.entity_id);
                    }
                }
                Err(e) => {
                    // Network error — increment retry count
                    if let Ok(conn) = self.db.conn() {
                        let _ = conn.execute(
                            "UPDATE sync_outbox SET status = 'FAILED', retry_count = retry_count + 1, last_error = ?2 WHERE id = ?1",
                            rusqlite::params![entry.id, e.to_string()],
                        );
                    }
                    log::warn!("Sync push network error: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Pull remote changes from the server
    async fn pull_remote(&self) -> Result<(), String> {
        let server_url = self.get_server_url().ok_or("No server URL configured")?;
        let auth_token = self.get_auth_token();

        // Get last sync cursor
        let last_cursor: Option<String> = {
            let conn = self.db.conn().map_err(|e| e.to_string())?;
            conn.query_row(
                "SELECT value FROM sync_settings WHERE key = 'pull_cursor'",
                [],
                |row| row.get(0),
            )
            .ok()
            .filter(|s: &String| !s.is_empty())
        };

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| e.to_string())?;

        let mut pull_url = format!("{}/sync/pull", server_url.trim_end_matches('/'));
        if let Some(ref cursor) = last_cursor {
            pull_url = format!("{}?cursor={}", pull_url, urlencoding::encode(cursor));
        }

        let mut req = client.get(&pull_url);
        if let Some(token) = auth_token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }

        let resp = req.send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("Pull failed: HTTP {}", resp.status()));
        }

        let body: SyncPullResponse = resp.json().await.map_err(|e| e.to_string())?;

        // Apply changes to local DB
        let conn = self.db.conn().map_err(|e| e.to_string())?;
        for change in &body.changes {
            apply_remote_change(&conn, change)?;
        }

        // Update cursor
        if let Some(ref cursor) = body.next_cursor {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO sync_settings (key, value) VALUES ('pull_cursor', ?1)",
                rusqlite::params![cursor],
            );
        }

        log::info!("Sync pull: {} changes applied", body.changes.len());
        Ok(())
    }

    /// Manually trigger a full sync cycle
    pub async fn trigger_sync(&self) -> Result<(), String> {
        log::info!("Manual sync triggered");
        let online = self.check_online().await;
        self.set_online_status(online);
        if !online {
            return Err("Device is offline — cannot sync".to_string());
        }
        self.push_pending().await?;
        self.pull_remote().await?;

        // Update last sync timestamp
        if let Ok(conn) = self.db.conn() {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO sync_settings (key, value) VALUES ('last_sync_at', datetime('now'))",
                [],
            );
        }
        Ok(())
    }

    /// Send a best-effort heartbeat to the cloud.
    /// Called on startup, after login, after manual sync, and after local writes.
    /// Failure is logged at debug level and never propagated — heartbeat must
    /// never block local save or sync.
    pub async fn send_heartbeat(&self, state: &Arc<crate::AppState>) {
        if let Some(ref url) = self.get_server_url() {
            let token = self.get_auth_token();
            if let Err(e) =
                crate::commands::heartbeat::send_heartbeat_to_cloud(state, url, token.as_deref())
                    .await
            {
                log::debug!("Heartbeat send failed (best-effort): {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SyncEngine;
    use crate::db::Database;
    use std::sync::Arc;

    fn create_engine() -> SyncEngine {
        let db_path =
            std::env::temp_dir().join(format!("viharaos-sync-test-{}.db", uuid::Uuid::new_v4()));
        let db = Arc::new(Database::new(&db_path).expect("temp db should initialize"));
        SyncEngine::new(db)
    }

    #[test]
    fn sync_engine_defaults_to_enabled() {
        let engine = create_engine();
        assert!(engine.is_enabled());
    }

    #[test]
    fn sync_engine_persists_enabled_flag_changes() {
        let engine = create_engine();

        engine.set_enabled(false);
        assert!(!engine.is_enabled());

        engine.set_enabled(true);
        assert!(engine.is_enabled());
    }

    #[test]
    fn sync_engine_status_reflects_pending_failed_and_conflict_counts() {
        let engine = create_engine();
        let conn = engine.db.conn().expect("db connection");

        conn.execute(
            "INSERT INTO sync_outbox (id, idempotency_key, entity_type, entity_id, operation, payload, device_id, property_id, status)
             VALUES (?1, ?2, 'guest', 'guest-1', 'CREATE', '{}', 'desktop', 'prop-1', 'PENDING')",
            rusqlite::params![uuid::Uuid::new_v4().to_string(), "pending-key"],
        )
        .expect("insert pending row");
        conn.execute(
            "INSERT INTO sync_outbox (id, idempotency_key, entity_type, entity_id, operation, payload, device_id, property_id, status)
             VALUES (?1, ?2, 'guest', 'guest-2', 'UPDATE', '{}', 'desktop', 'prop-1', 'FAILED')",
            rusqlite::params![uuid::Uuid::new_v4().to_string(), "failed-key"],
        )
        .expect("insert failed row");
        conn.execute(
            "INSERT INTO sync_conflict (id, entity_type, entity_id, local_payload, server_payload, conflict_type, property_id)
             VALUES (?1, 'guest', 'guest-3', '{}', '{}', 'VERSION_MISMATCH', 'prop-1')",
            rusqlite::params![uuid::Uuid::new_v4().to_string()],
        )
        .expect("insert conflict row");

        let status = engine.get_status();
        assert!(status.enabled);
        assert_eq!(status.pending_count, 1);
        assert_eq!(status.failed_count, 1);
        assert_eq!(status.conflict_count, 1);
        assert!(!status.is_online);
    }

    #[test]
    fn sync_engine_persists_and_reads_online_status() {
        let engine = create_engine();

        // Default is offline
        assert!(!engine.get_status().is_online);

        // Persist online=true
        engine.set_online_status(true);
        assert!(engine.get_status().is_online);

        // Persist online=false
        engine.set_online_status(false);
        assert!(!engine.get_status().is_online);
    }

    #[test]
    fn sync_conflict_insert_matches_schema_with_server_payload_and_property_id() {
        let engine = create_engine();
        let conn = engine.db.conn().expect("db connection");

        // Insert a sync_outbox row with property_id (as push_pending would select)
        let outbox_id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO sync_outbox (id, idempotency_key, entity_type, entity_id, operation, payload, device_id, property_id, status)
             VALUES (?1, ?2, 'guest', 'guest-conflict', 'UPDATE', '{\"name\":\"Alice\"}', 'desktop', 'prop-42', 'PENDING')",
            rusqlite::params![outbox_id, "conflict-key"],
        )
        .expect("insert outbox row");

        // Simulate what the 409 handler does: insert a sync_conflict row
        // with all required schema fields.
        let conflict_id = uuid::Uuid::new_v4().to_string();
        let server_payload = "{\"name\":\"Alice (server)\"}";
        let property_id = "prop-42";

        conn.execute(
            "INSERT INTO sync_conflict
             (id, entity_type, entity_id, local_payload, server_payload,
              conflict_type, property_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'REMOTE_NEWER', ?6, datetime('now'))",
            rusqlite::params![
                conflict_id,
                "guest",
                "guest-conflict",
                "{\"name\":\"Alice\"}",
                server_payload,
                property_id,
            ],
        )
        .expect("conflict insert should succeed with full schema");

        // Verify the row was inserted with the correct fields
        let (id, entity_type, entity_id, local, server, conflict_type, prop_id): (
            String, String, String, String, String, String, String,
        ) = conn
            .query_row(
                "SELECT id, entity_type, entity_id, local_payload, server_payload, conflict_type, property_id
                 FROM sync_conflict WHERE id = ?1",
                rusqlite::params![conflict_id],
                |row| Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                )),
            )
            .expect("conflict row should be readable");

        assert_eq!(id, conflict_id);
        assert_eq!(entity_type, "guest");
        assert_eq!(entity_id, "guest-conflict");
        assert_eq!(local, "{\"name\":\"Alice\"}");
        assert_eq!(server, server_payload);
        assert_eq!(conflict_type, "REMOTE_NEWER");
        assert_eq!(prop_id, "prop-42");
    }
}

#[derive(Debug)]
struct SyncOutboxEntry {
    id: String,
    idempotency_key: String,
    entity_type: String,
    entity_id: String,
    operation: String,
    payload: String,
    retry_count: i32,
    property_id: String,
}

#[derive(Debug, serde::Deserialize)]
struct SyncPullResponse {
    changes: Vec<RemoteChange>,
    next_cursor: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct RemoteChange {
    entity_type: String,
    entity_id: String,
    operation: String,
    payload: serde_json::Value,
    server_updated_at: String,
}

/// Apply a remote change to the local SQLite database
fn apply_remote_change(conn: &rusqlite::Connection, change: &RemoteChange) -> Result<(), String> {
    match change.operation.as_str() {
        "CREATE" | "UPDATE" => {
            // Upsert the entity into the appropriate table
            // The payload is the full entity JSON
            let payload_str = serde_json::to_string(&change.payload).map_err(|e| e.to_string())?;

            // Store in a generic sync_entities table for now
            // In a full implementation, this would map to specific tables
            conn.execute(
                "INSERT OR REPLACE INTO sync_entity (entity_type, entity_id, payload, server_updated_at, local_updated_at)
                 VALUES (?1, ?2, ?3, ?4, datetime('now'))",
                rusqlite::params![change.entity_type, change.entity_id, payload_str, change.server_updated_at],
            )
            .map_err(|e| e.to_string())?;
        }
        "DELETE" => {
            conn.execute(
                "DELETE FROM sync_entity WHERE entity_type = ?1 AND entity_id = ?2",
                rusqlite::params![change.entity_type, change.entity_id],
            )
            .map_err(|e| e.to_string())?;
        }
        _ => {
            log::warn!("Unknown sync operation: {}", change.operation);
        }
    }
    Ok(())
}

// Minimal URL encoding for the cursor query parameter
mod urlencoding {
    pub fn encode(s: &str) -> String {
        s.chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
                    c.to_string()
                } else {
                    format!("%{:02X}", c as u8)
                }
            })
            .collect()
    }
}
