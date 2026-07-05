use std::sync::Arc;
use axum::{
    routing::{get, post, put, delete},
    Router,
    extract::{State as AxumState, Path, Query},
    response::Json,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Sha256, Digest};
use tower_http::cors::{CorsLayer, Any, AllowOrigin};
use axum::http::HeaderValue;
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};

use crate::AppState;
use crate::db::models::*;

/// Hash a password with Argon2id for offline verification.
/// Argon2id is the recommended password hashing algorithm (OWASP, PHC).
/// It uses a random salt and memory-hard key derivation to resist GPU/ASIC
/// brute-force attacks. The resulting PHC string is stored in the database.
fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .unwrap_or_else(|_| {
            // Fallback to SHA-256 if Argon2 fails (should never happen)
            let mut hasher = Sha256::new();
            hasher.update(password.as_bytes());
            hex::encode(hasher.finalize())
        })
}

/// Verify a password against a stored hash.
/// Supports both Argon2id (PHC format) and legacy SHA-256 hex (64 chars).
/// Legacy SHA-256 hashes are transparently upgraded to Argon2id on next login.
fn verify_password(password: &str, stored_hash: &str) -> bool {
    // Argon2id hashes start with "$argon2" (PHC format)
    if stored_hash.starts_with("$argon2") {
        if let Ok(parsed) = PasswordHash::new(stored_hash) {
            return Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok();
        }
        return false;
    }
    // Legacy SHA-256 fallback (64 hex chars, no salt)
    if stored_hash.len() == 64 && stored_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let input_hash = hex::encode(hasher.finalize());
        return input_hash == stored_hash;
    }
    false
}

/// Check if a stored hash is a legacy SHA-256 hash that should be upgraded.
fn is_legacy_hash(stored_hash: &str) -> bool {
    !stored_hash.starts_with("$argon2")
}

/// Map an error to a 500 response, logging the full error but returning
/// a generic message to the client. Prevents leaking internal error details
/// (e.g. SQL errors, file paths) in HTTP responses.
fn internal_error<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    log::error!("Internal error: {}", e);
    (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
}

/// Verify that a joined path stays within the allowed base directory.
/// Prevents path traversal attacks (e.g., `/images/../../etc/passwd`).
fn safe_join(base: &std::path::Path, relative: &str) -> Result<std::path::PathBuf, String> {
    let joined = base.join(relative);
    let canonical_base = base.canonicalize().map_err(|e| format!("Invalid base dir: {}", e))?;
    let canonical_joined = joined.canonicalize().map_err(|_| "Path not found".to_string())?;
    if !canonical_joined.starts_with(&canonical_base) {
        return Err("Path traversal denied".to_string());
    }
    Ok(canonical_joined)
}

/// Merge a serde_json::Value object with additional key-value pairs.
/// Returns a new JSON object containing all keys from `base` plus the overrides.
fn merge_json(mut base: Value, overrides: &[(&str, Value)]) -> Value {
    if let Some(obj) = base.as_object_mut() {
        for (key, val) in overrides {
            obj.insert((*key).to_string(), val.clone());
        }
    }
    base
}

/// Extract a Bearer token from the Authorization header.
fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    let auth_header = headers.get(axum::http::header::AUTHORIZATION)?;
    let auth_str = auth_header.to_str().ok()?;
    if auth_str.starts_with("Bearer ") {
        Some(auth_str[7..].to_string())
    } else {
        None
    }
}

/// Axum middleware that validates the Bearer token against the session_token table.
/// Requests to /api/auth/login and /api/health are exempt (no auth required).
async fn auth_middleware(
    AxumState(state): AxumState<Arc<AppState>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let path = request.uri().path();

    // Exempt routes that don't require authentication:
    // - /api/health: health check (no sensitive data)
    // - /api/auth/login: login endpoint (issues tokens)
    // - /api/auth/refresh: refresh endpoint (uses refresh token, not access token)
    // - /images/: static image serving (loaded via <img> tags without auth headers;
    //   CORS restriction already prevents other origins from accessing these)
    if path == "/api/health" || path == "/api/auth/login" || path == "/api/auth/refresh" || path.starts_with("/images/") {
        return Ok(next.run(request).await);
    }

    // Extract and validate the Bearer token
    let token = extract_bearer_token(request.headers())
        .ok_or((StatusCode::UNAUTHORIZED, "Missing or invalid Authorization header".to_string()))?;

    let conn = state.db.conn().map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, "Database unavailable".to_string())
    })?;

    let valid: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM session_token WHERE token = ?1 AND expires_at > datetime('now'))",
            rusqlite::params![token],
            |row| row.get(0),
        )
        .unwrap_or(false);

    if !valid {
        return Err((StatusCode::UNAUTHORIZED, "Invalid or expired session token".to_string()));
    }

    Ok(next.run(request).await)
}

/// Start the embedded local API server on localhost port 14000.
/// The frontend is hardcoded to talk to this port when in desktop mode.
pub async fn start_server(state: Arc<AppState>) -> Result<(), String> {
    let port = 14000;
    log::info!("Local API server starting on http://127.0.0.1:{}", port);

    // Store the port so it can be discovered if needed
    if let Ok(conn) = state.db.conn() {
        let _ = conn.execute(
            "INSERT OR REPLACE INTO sync_settings (key, value) VALUES ('local_api_port', ?1)",
            rusqlite::params![port.to_string()],
        );
    }

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .map_err(|e| format!("Failed to bind port {}: {}. Ensure no other application is using this port.", port, e))?;

    axum::serve(listener, app)
        .await
        .map_err(|e| format!("Server error: {}", e))?;

    Ok(())
}

fn build_router(state: Arc<AppState>) -> Router {
    let auth_state = state.clone();

    Router::new()
        // Health check
        .route("/api/health", get(health))
        // Auth
        .route("/api/auth/login", post(auth_login))
        .route("/api/auth/me", get(auth_me))
        .route("/api/auth/refresh", post(auth_refresh))
        // Guests
        .route("/api/guests", get(list_guests).post(create_guest))
        .route("/api/guests/:id", get(get_guest).put(update_guest).delete(delete_guest))
        // Rooms
        .route("/api/rooms", get(list_rooms))
        .route("/api/rooms/:id", get(get_room).put(update_room))
        .route("/api/rooms/:id/status", put(update_room_status))
        // Reservations
        .route("/api/reservations", get(list_reservations).post(create_reservation))
        .route("/api/reservations/:id", get(get_reservation).put(update_reservation).delete(delete_reservation))
        .route("/api/reservations/:id/check-in", post(check_in))
        .route("/api/reservations/:id/check-out", post(check_out))
        // Menu items
        .route("/api/menu-items", get(list_menu_items))
        .route("/api/menu-items/:id", get(get_menu_item).put(update_menu_item))
        // POS orders
        .route("/api/pos/orders", get(list_orders).post(create_order))
        .route("/api/pos/orders/:id", get(get_order).put(update_order))
        .route("/api/pos/orders/:id/items", post(add_order_item))
        // Folios
        .route("/api/folios", get(list_folios).post(create_folio))
        .route("/api/folios/:id", get(get_folio))
        .route("/api/folios/:id/charges", post(add_folio_charge))
        .route("/api/folios/:id/payments", post(add_folio_payment))
        // Housekeeping
        .route("/api/housekeeping/tasks", get(list_hk_tasks).post(create_hk_task))
        .route("/api/housekeeping/tasks/:id", put(update_hk_task))
        // Media
        .route("/api/media/quota", get(get_storage_quota))
        .route("/api/media/sync", post(sync_media))
        // Sync
        .route("/api/sync/status", get(get_sync_status))
        .route("/api/sync/trigger", post(trigger_sync))
        // Static image serving (local filesystem)
        .route("/images/{*path}", get(serve_image))
        .with_state(state)
        // Auth middleware: validates Bearer token against session_token table
        // for all routes except /api/health and /api/auth/login.
        .layer(axum::middleware::from_fn_with_state(auth_state, auth_middleware))
        // CORS: restrict to the Tauri webview origin and localhost dev server.
        // Without this, any web page in the user's browser can read local API
        // responses from http://127.0.0.1:14000, leaking hotel data.
        // Use AllowOrigin::list() instead of chained allow_origin() calls —
        // chained calls on CorsLayer overwrite (each call replaces the previous
        // value), so only the last origin would be allowed. list() sets all
        // origins in a single call.
        .layer(CorsLayer::new()
            .allow_origin(AllowOrigin::list([
                "tauri://localhost".parse::<HeaderValue>().unwrap(),
                "http://tauri.localhost".parse::<HeaderValue>().unwrap(),
                "http://localhost:3000".parse::<HeaderValue>().unwrap(),
            ]))
            .allow_methods(Any)
            .allow_headers(Any))
}

// ─── Handlers ───

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok", "mode": "desktop-offline" }))
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

async fn auth_login(
    AxumState(state): AxumState<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let conn = state.db.conn().map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, "Database unavailable".to_string())
    })?;

    let user: Option<(String, String, String, String, Option<String>, Option<String>, Option<String>)> = conn
        .query_row(
            "SELECT id, email, name, role, organization_id, property_id, password_hash
             FROM user WHERE email = ?1 AND is_active = 1",
            rusqlite::params![req.email],
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
        .ok();

    match user {
        Some((id, email, name, role, org_id, prop_id, password_hash)) => {
            // Verify password against stored hash if one exists.
            // If no hash is stored, the user hasn't logged in online from this
            // device yet — reject offline login to prevent auth bypass.
            if let Some(ref stored_hash) = password_hash {
                if !verify_password(&req.password, stored_hash) {
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        "Invalid credentials".to_string(),
                    ));
                }
                // Upgrade legacy SHA-256 hashes to Argon2id on successful login
                if is_legacy_hash(stored_hash) {
                    let new_hash = hash_password(&req.password);
                    let _ = conn.execute(
                        "UPDATE user SET password_hash = ?1 WHERE id = ?2",
                        rusqlite::params![new_hash, id],
                    );
                    log::info!("Upgraded password hash from SHA-256 to Argon2id for user '{}'", email);
                }
            } else {
                // No password hash stored — can't verify offline
                return Err((
                    StatusCode::UNAUTHORIZED,
                    "Offline login not available. Please log in online first to enable offline access.".to_string(),
                ));
            }

            // Update last_login_at
            let _ = conn.execute(
                "UPDATE user SET last_login_at = datetime('now') WHERE id = ?1",
                rusqlite::params![id],
            );

            // Generate a session token and store it for API auth
            let token = format!("offline-token-{}", uuid::Uuid::new_v4());
            let _ = conn.execute(
                "INSERT INTO session_token (token, user_id) VALUES (?1, ?2)",
                rusqlite::params![token, id],
            );
            // Clean up expired tokens
            let _ = conn.execute(
                "DELETE FROM session_token WHERE expires_at < datetime('now')",
                [],
            );

            Ok(Json(json!({
                "accessToken": token,
                "user": {
                    "id": id,
                    "email": email,
                    "name": name,
                    "role": role,
                    "organizationId": org_id,
                    "propertyId": prop_id,
                }
            })))
        }
        None => Err((
            StatusCode::UNAUTHORIZED,
            "Invalid credentials".to_string(),
        )),
    }
}

async fn auth_me(
    AxumState(state): AxumState<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Value>, (StatusCode, String)> {
    // Validate the Authorization header against the session_token table
    let token = extract_bearer_token(&headers)
        .ok_or((StatusCode::UNAUTHORIZED, "Missing or invalid Authorization header".to_string()))?;

    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    let user = conn
        .query_row(
            "SELECT u.id, u.email, u.name, u.role, u.organization_id, u.property_id
             FROM session_token st
             JOIN user u ON u.id = st.user_id
             WHERE st.token = ?1 AND st.expires_at > datetime('now') AND u.is_active = 1",
            rusqlite::params![token],
            |row| Ok(json!({
                "id": row.get::<_, String>(0)?,
                "email": row.get::<_, String>(1)?,
                "name": row.get::<_, String>(2)?,
                "role": row.get::<_, String>(3)?,
                "organizationId": row.get::<_, Option<String>>(4)?,
                "propertyId": row.get::<_, Option<String>>(5)?,
            })),
        )
        .ok();

    match user {
        Some(u) => Ok(Json(json!({ "user": u }))),
        None => Err((StatusCode::UNAUTHORIZED, "Not authenticated".to_string())),
    }
}

async fn auth_refresh() -> Json<Value> {
    Json(json!({ "accessToken": "offline-token-refreshed" }))
}

// ─── Guests ───

#[derive(Deserialize)]
struct ListQuery {
    #[serde(default)]
    property_id: Option<String>,
    #[serde(default)]
    search: Option<String>,
    #[serde(default)]
    limit: Option<i32>,
    #[serde(default)]
    offset: Option<i32>,
}

async fn list_guests(
    AxumState(state): AxumState<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    let limit = q.limit.unwrap_or(50).min(200);
    let offset = q.offset.unwrap_or(0);
    let property_id = q.property_id.unwrap_or_default();
    // Escape LIKE wildcard characters (% and _) in the search term so that
    // user input is treated as a literal substring, not a wildcard pattern.
    // The backslash is used as the ESCAPE character in the SQL below.
    let search = q.search.unwrap_or_default().replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");

    let mut stmt = conn
        .prepare(
            "SELECT id, property_id, first_name, last_name, email, phone,
                    id_type, id_number, nationality, vip, blacklisted, notes,
                    loyalty_points, created_at
             FROM guest
             WHERE (?1 = '' OR property_id = ?1)
             AND (?2 = '' OR first_name LIKE '%' || ?2 || '%' ESCAPE '\\' OR last_name LIKE '%' || ?2 || '%' ESCAPE '\\' OR phone LIKE '%' || ?2 || '%' ESCAPE '\\')
             ORDER BY created_at DESC
             LIMIT ?3 OFFSET ?4",
        )
        .map_err(|e| internal_error(e))?;

    let rows = stmt
        .query_map(
            rusqlite::params![property_id, search, limit, offset],
            |row| {
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "propertyId": row.get::<_, String>(1)?,
                    "firstName": row.get::<_, String>(2)?,
                    "lastName": row.get::<_, Option<String>>(3)?,
                    "email": row.get::<_, Option<String>>(4)?,
                    "phone": row.get::<_, Option<String>>(5)?,
                    "idType": row.get::<_, Option<String>>(6)?,
                    "idNumber": row.get::<_, Option<String>>(7)?,
                    "nationality": row.get::<_, Option<String>>(8)?,
                    "vip": row.get::<_, i32>(9)? != 0,
                    "blacklisted": row.get::<_, i32>(10)? != 0,
                    "notes": row.get::<_, Option<String>>(11)?,
                    "loyaltyPoints": row.get::<_, i32>(12)?,
                    "createdAt": row.get::<_, String>(13)?,
                }))
            },
        )
        .map_err(|e| internal_error(e))?;

    let guests: Vec<Value> = rows.filter_map(|r| r.ok()).collect();
    Ok(Json(json!({ "data": guests, "count": guests.len() })))
}

async fn create_guest(
    AxumState(state): AxumState<Arc<AppState>>,
    Json(req): Json<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let id = uuid::Uuid::new_v4().to_string();
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    conn.execute(
        "INSERT INTO guest (id, property_id, first_name, last_name, email, phone, id_type, id_number, nationality, notes)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        rusqlite::params![
            id,
            req["propertyId"].as_str().unwrap_or(""),
            req["firstName"].as_str().unwrap_or(""),
            req["lastName"].as_str(),
            req["email"].as_str(),
            req["phone"].as_str(),
            req["idType"].as_str(),
            req["idNumber"].as_str(),
            req["nationality"].as_str(),
            req["notes"].as_str(),
        ],
    )
    .map_err(|e| internal_error(e))?;

    // Queue sync
    queue_sync(&conn, "guest", &id, "CREATE", &req)?;

    Ok(Json(merge_json(req, &[("id", json!(id))])))
}

async fn get_guest(
    AxumState(state): AxumState<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    let guest = conn
        .query_row(
            "SELECT id, property_id, first_name, last_name, email, phone,
                    id_type, id_number, id_photo_path, photo_path, nationality,
                    date_of_birth, gender, address, city, state, country, pincode,
                    vip, blacklisted, notes, loyalty_points, created_at
             FROM guest WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "propertyId": row.get::<_, String>(1)?,
                    "firstName": row.get::<_, String>(2)?,
                    "lastName": row.get::<_, Option<String>>(3)?,
                    "email": row.get::<_, Option<String>>(4)?,
                    "phone": row.get::<_, Option<String>>(5)?,
                    "idType": row.get::<_, Option<String>>(6)?,
                    "idNumber": row.get::<_, Option<String>>(7)?,
                    "idPhotoPath": row.get::<_, Option<String>>(8)?,
                    "photoPath": row.get::<_, Option<String>>(9)?,
                    "nationality": row.get::<_, Option<String>>(10)?,
                    "dateOfBirth": row.get::<_, Option<String>>(11)?,
                    "gender": row.get::<_, Option<String>>(12)?,
                    "address": row.get::<_, Option<String>>(13)?,
                    "city": row.get::<_, Option<String>>(14)?,
                    "state": row.get::<_, Option<String>>(15)?,
                    "country": row.get::<_, Option<String>>(16)?,
                    "pincode": row.get::<_, Option<String>>(17)?,
                    "vip": row.get::<_, i32>(18)? != 0,
                    "blacklisted": row.get::<_, i32>(19)? != 0,
                    "notes": row.get::<_, Option<String>>(20)?,
                    "loyaltyPoints": row.get::<_, i32>(21)?,
                    "createdAt": row.get::<_, String>(22)?,
                }))
            },
        )
        .ok();

    match guest {
        Some(g) => Ok(Json(g)),
        None => Err((StatusCode::NOT_FOUND, "Guest not found".to_string())),
    }
}

async fn update_guest(
    AxumState(state): AxumState<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    // Dynamic update — build SET clause from provided fields
    // For safety, only update known fields
    if let Some(name) = req["firstName"].as_str() {
        conn.execute(
            "UPDATE guest SET first_name = ?1, local_updated_at = datetime('now') WHERE id = ?2",
            rusqlite::params![name, id],
        )
        .map_err(|e| internal_error(e))?;
    }
    if let Some(last) = req["lastName"].as_str() {
        conn.execute(
            "UPDATE guest SET last_name = ?1, local_updated_at = datetime('now') WHERE id = ?2",
            rusqlite::params![last, id],
        )
        .map_err(|e| internal_error(e))?;
    }
    if let Some(phone) = req["phone"].as_str() {
        conn.execute(
            "UPDATE guest SET phone = ?1, local_updated_at = datetime('now') WHERE id = ?2",
            rusqlite::params![phone, id],
        )
        .map_err(|e| internal_error(e))?;
    }
    if let Some(email) = req["email"].as_str() {
        conn.execute(
            "UPDATE guest SET email = ?1, local_updated_at = datetime('now') WHERE id = ?2",
            rusqlite::params![email, id],
        )
        .map_err(|e| internal_error(e))?;
    }

    queue_sync(&conn, "guest", &id, "UPDATE", &req)?;

    Ok(Json(json!({ "id": id, "updated": true })))
}

async fn delete_guest(
    AxumState(state): AxumState<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    conn.execute("DELETE FROM guest WHERE id = ?1", rusqlite::params![id])
        .map_err(|e| internal_error(e))?;

    queue_sync(&conn, "guest", &id, "DELETE", &json!({}))?;

    Ok(Json(json!({ "id": id, "deleted": true })))
}

// ─── Rooms ───

async fn list_rooms(
    AxumState(state): AxumState<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    let property_id = q.property_id.unwrap_or_default();
    let mut stmt = conn
        .prepare(
            "SELECT id, property_id, room_type_id, number, floor, status, is_active, photos, notes
             FROM room
             WHERE (?1 = '' OR property_id = ?1)
             ORDER BY number ASC",
        )
        .map_err(|e| internal_error(e))?;

    let rows = stmt
        .query_map(rusqlite::params![property_id], |row| {
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "propertyId": row.get::<_, String>(1)?,
                "roomTypeId": row.get::<_, Option<String>>(2)?,
                "number": row.get::<_, String>(3)?,
                "floor": row.get::<_, Option<i32>>(4)?,
                "status": row.get::<_, String>(5)?,
                "isActive": row.get::<_, i32>(6)? != 0,
                "photos": row.get::<_, Option<String>>(7)?,
                "notes": row.get::<_, Option<String>>(8)?,
            }))
        })
        .map_err(|e| internal_error(e))?;

    let rooms: Vec<Value> = rows.filter_map(|r| r.ok()).collect();
    Ok(Json(json!({ "data": rooms, "count": rooms.len() })))
}

async fn get_room(
    AxumState(state): AxumState<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    let room = conn
        .query_row(
            "SELECT id, property_id, room_type_id, number, floor, status, is_active, photos, notes
             FROM room WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "propertyId": row.get::<_, String>(1)?,
                    "roomTypeId": row.get::<_, Option<String>>(2)?,
                    "number": row.get::<_, String>(3)?,
                    "floor": row.get::<_, Option<i32>>(4)?,
                    "status": row.get::<_, String>(5)?,
                    "isActive": row.get::<_, i32>(6)? != 0,
                    "photos": row.get::<_, Option<String>>(7)?,
                    "notes": row.get::<_, Option<String>>(8)?,
                }))
            },
        )
        .ok();

    match room {
        Some(r) => Ok(Json(r)),
        None => Err((StatusCode::NOT_FOUND, "Room not found".to_string())),
    }
}

async fn update_room(
    AxumState(state): AxumState<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    if let Some(notes) = req["notes"].as_str() {
        conn.execute(
            "UPDATE room SET notes = ?1, local_updated_at = datetime('now') WHERE id = ?2",
            rusqlite::params![notes, id],
        )
        .map_err(|e| internal_error(e))?;
    }

    queue_sync(&conn, "room", &id, "UPDATE", &req)?;
    Ok(Json(json!({ "id": id, "updated": true })))
}

async fn update_room_status(
    AxumState(state): AxumState<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let status = req["status"].as_str().ok_or((
        StatusCode::BAD_REQUEST,
        "Missing status field".to_string(),
    ))?;

    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    conn.execute(
        "UPDATE room SET status = ?1, local_updated_at = datetime('now') WHERE id = ?2",
        rusqlite::params![status, id],
    )
    .map_err(|e| internal_error(e))?;

    queue_sync(&conn, "room", &id, "UPDATE", &req)?;
    Ok(Json(json!({ "id": id, "status": status })))
}

// ─── Reservations ───

async fn list_reservations(
    AxumState(state): AxumState<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    let property_id = q.property_id.unwrap_or_default();
    let mut stmt = conn
        .prepare(
            "SELECT r.id, r.property_id, r.guest_id, r.room_id, r.room_type_id,
                    r.status, r.source, r.check_in_date, r.check_out_date,
                    r.adults, r.children, r.rate_amount, r.currency,
                    r.special_requests, r.created_at, r.checked_in_at, r.checked_out_at,
                    g.first_name, g.last_name, g.phone,
                    rm.number as room_number
             FROM reservation r
             LEFT JOIN guest g ON r.guest_id = g.id
             LEFT JOIN room rm ON r.room_id = rm.id
             WHERE (?1 = '' OR r.property_id = ?1)
             ORDER BY r.check_in_date DESC",
        )
        .map_err(|e| internal_error(e))?;

    let rows = stmt
        .query_map(rusqlite::params![property_id], |row| {
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "propertyId": row.get::<_, String>(1)?,
                "guestId": row.get::<_, String>(2)?,
                "roomId": row.get::<_, Option<String>>(3)?,
                "roomTypeId": row.get::<_, Option<String>>(4)?,
                "status": row.get::<_, String>(5)?,
                "source": row.get::<_, Option<String>>(6)?,
                "checkInDate": row.get::<_, String>(7)?,
                "checkOutDate": row.get::<_, String>(8)?,
                "adults": row.get::<_, i32>(9)?,
                "children": row.get::<_, i32>(10)?,
                "rateAmount": row.get::<_, f64>(11)?,
                "currency": row.get::<_, String>(12)?,
                "specialRequests": row.get::<_, Option<String>>(13)?,
                "createdAt": row.get::<_, String>(14)?,
                "checkedInAt": row.get::<_, Option<String>>(15)?,
                "checkedOutAt": row.get::<_, Option<String>>(16)?,
                "guestFirstName": row.get::<_, Option<String>>(17)?,
                "guestLastName": row.get::<_, Option<String>>(18)?,
                "guestPhone": row.get::<_, Option<String>>(19)?,
                "roomNumber": row.get::<_, Option<String>>(20)?,
            }))
        })
        .map_err(|e| internal_error(e))?;

    let reservations: Vec<Value> = rows.filter_map(|r| r.ok()).collect();
    Ok(Json(json!({ "data": reservations, "count": reservations.len() })))
}

async fn create_reservation(
    AxumState(state): AxumState<Arc<AppState>>,
    Json(req): Json<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let id = uuid::Uuid::new_v4().to_string();
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    conn.execute(
        "INSERT INTO reservation (id, property_id, guest_id, room_id, room_type_id, status, source, check_in_date, check_out_date, adults, children, rate_amount, currency, special_requests, created_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        rusqlite::params![
            id,
            req["propertyId"].as_str().unwrap_or(""),
            req["guestId"].as_str().unwrap_or(""),
            req["roomId"].as_str(),
            req["roomTypeId"].as_str(),
            req["status"].as_str().unwrap_or("CONFIRMED"),
            req["source"].as_str(),
            req["checkInDate"].as_str().unwrap_or(""),
            req["checkOutDate"].as_str().unwrap_or(""),
            req["adults"].as_i64().unwrap_or(1),
            req["children"].as_i64().unwrap_or(0),
            req["rateAmount"].as_f64().unwrap_or(0.0),
            req["currency"].as_str().unwrap_or("INR"),
            req["specialRequests"].as_str(),
            req["createdBy"].as_str(),
        ],
    )
    .map_err(|e| internal_error(e))?;

    queue_sync(&conn, "reservation", &id, "CREATE", &req)?;
    Ok(Json(merge_json(req, &[("id", json!(id))])))
}

async fn get_reservation(
    AxumState(state): AxumState<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    let res = conn
        .query_row(
            "SELECT id, property_id, guest_id, room_id, room_type_id, status, source,
                    check_in_date, check_out_date, adults, children, rate_amount, currency,
                    special_requests, created_at, checked_in_at, checked_out_at
             FROM reservation WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "propertyId": row.get::<_, String>(1)?,
                    "guestId": row.get::<_, String>(2)?,
                    "roomId": row.get::<_, Option<String>>(3)?,
                    "roomTypeId": row.get::<_, Option<String>>(4)?,
                    "status": row.get::<_, String>(5)?,
                    "source": row.get::<_, Option<String>>(6)?,
                    "checkInDate": row.get::<_, String>(7)?,
                    "checkOutDate": row.get::<_, String>(8)?,
                    "adults": row.get::<_, i32>(9)?,
                    "children": row.get::<_, i32>(10)?,
                    "rateAmount": row.get::<_, f64>(11)?,
                    "currency": row.get::<_, String>(12)?,
                    "specialRequests": row.get::<_, Option<String>>(13)?,
                    "createdAt": row.get::<_, String>(14)?,
                    "checkedInAt": row.get::<_, Option<String>>(15)?,
                    "checkedOutAt": row.get::<_, Option<String>>(16)?,
                }))
            },
        )
        .ok();

    match res {
        Some(r) => Ok(Json(r)),
        None => Err((StatusCode::NOT_FOUND, "Reservation not found".to_string())),
    }
}

async fn update_reservation(
    AxumState(state): AxumState<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    if let Some(status) = req["status"].as_str() {
        conn.execute(
            "UPDATE reservation SET status = ?1, local_updated_at = datetime('now') WHERE id = ?2",
            rusqlite::params![status, id],
        )
        .map_err(|e| internal_error(e))?;
    }
    if let Some(room_id) = req["roomId"].as_str() {
        conn.execute(
            "UPDATE reservation SET room_id = ?1, local_updated_at = datetime('now') WHERE id = ?2",
            rusqlite::params![room_id, id],
        )
        .map_err(|e| internal_error(e))?;
    }

    queue_sync(&conn, "reservation", &id, "UPDATE", &req)?;
    Ok(Json(json!({ "id": id, "updated": true })))
}

async fn delete_reservation(
    AxumState(state): AxumState<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    conn.execute("DELETE FROM reservation WHERE id = ?1", rusqlite::params![id])
        .map_err(|e| internal_error(e))?;

    queue_sync(&conn, "reservation", &id, "DELETE", &json!({}))?;
    Ok(Json(json!({ "id": id, "deleted": true })))
}

async fn check_in(
    AxumState(state): AxumState<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE reservation SET status = 'CHECKED_IN', checked_in_at = ?1, local_updated_at = datetime('now') WHERE id = ?2",
        rusqlite::params![now, id],
    )
    .map_err(|e| internal_error(e))?;

    // Update room status to occupied
    if let Some(room_id) = req["roomId"].as_str() {
        conn.execute(
            "UPDATE room SET status = 'OCCUPIED', local_updated_at = datetime('now') WHERE id = ?1",
            rusqlite::params![room_id],
        )
        .map_err(|e| internal_error(e))?;
    }

    queue_sync(&conn, "reservation", &id, "UPDATE", &json!({ "status": "CHECKED_IN", "checkedInAt": now }))?;
    Ok(Json(json!({ "id": id, "status": "CHECKED_IN", "checkedInAt": now })))
}

async fn check_out(
    AxumState(state): AxumState<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE reservation SET status = 'CHECKED_OUT', checked_out_at = ?1, local_updated_at = datetime('now') WHERE id = ?2",
        rusqlite::params![now, id],
    )
    .map_err(|e| internal_error(e))?;

    // Update room status to dirty
    if let Some(room_id) = req["roomId"].as_str() {
        conn.execute(
            "UPDATE room SET status = 'DIRTY', local_updated_at = datetime('now') WHERE id = ?1",
            rusqlite::params![room_id],
        )
        .map_err(|e| internal_error(e))?;
    }

    queue_sync(&conn, "reservation", &id, "UPDATE", &json!({ "status": "CHECKED_OUT", "checkedOutAt": now }))?;
    Ok(Json(json!({ "id": id, "status": "CHECKED_OUT", "checkedOutAt": now })))
}

// ─── Menu Items ───

async fn list_menu_items(
    AxumState(state): AxumState<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    let property_id = q.property_id.unwrap_or_default();
    let mut stmt = conn
        .prepare(
            "SELECT id, property_id, name, description, category, price, tax_rate, is_veg, is_available, photo, prep_time_minutes
             FROM menu_item
             WHERE (?1 = '' OR property_id = ?1)
             ORDER BY name ASC",
        )
        .map_err(|e| internal_error(e))?;

    let rows = stmt
        .query_map(rusqlite::params![property_id], |row| {
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "propertyId": row.get::<_, String>(1)?,
                "name": row.get::<_, String>(2)?,
                "description": row.get::<_, Option<String>>(3)?,
                "category": row.get::<_, Option<String>>(4)?,
                "price": row.get::<_, f64>(5)?,
                "taxRate": row.get::<_, f64>(6)?,
                "isVeg": row.get::<_, i32>(7)? != 0,
                "isAvailable": row.get::<_, i32>(8)? != 0,
                "photo": row.get::<_, Option<String>>(9)?,
                "prepTimeMinutes": row.get::<_, Option<i32>>(10)?,
            }))
        })
        .map_err(|e| internal_error(e))?;

    let items: Vec<Value> = rows.filter_map(|r| r.ok()).collect();
    Ok(Json(json!({ "data": items, "count": items.len() })))
}

async fn get_menu_item(
    AxumState(state): AxumState<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    let item = conn
        .query_row(
            "SELECT id, property_id, name, description, category, price, tax_rate, is_veg, is_available, photo, prep_time_minutes
             FROM menu_item WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "propertyId": row.get::<_, String>(1)?,
                    "name": row.get::<_, String>(2)?,
                    "description": row.get::<_, Option<String>>(3)?,
                    "category": row.get::<_, Option<String>>(4)?,
                    "price": row.get::<_, f64>(5)?,
                    "taxRate": row.get::<_, f64>(6)?,
                    "isVeg": row.get::<_, i32>(7)? != 0,
                    "isAvailable": row.get::<_, i32>(8)? != 0,
                    "photo": row.get::<_, Option<String>>(9)?,
                    "prepTimeMinutes": row.get::<_, Option<i32>>(10)?,
                }))
            },
        )
        .ok();

    match item {
        Some(i) => Ok(Json(i)),
        None => Err((StatusCode::NOT_FOUND, "Menu item not found".to_string())),
    }
}

async fn update_menu_item(
    AxumState(state): AxumState<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    if let Some(price) = req["price"].as_f64() {
        conn.execute(
            "UPDATE menu_item SET price = ?1, local_updated_at = datetime('now') WHERE id = ?2",
            rusqlite::params![price, id],
        )
        .map_err(|e| internal_error(e))?;
    }
    if let Some(available) = req["isAvailable"].as_bool() {
        conn.execute(
            "UPDATE menu_item SET is_available = ?1, local_updated_at = datetime('now') WHERE id = ?2",
            rusqlite::params![available, id],
        )
        .map_err(|e| internal_error(e))?;
    }

    queue_sync(&conn, "menu-item", &id, "UPDATE", &req)?;
    Ok(Json(json!({ "id": id, "updated": true })))
}

// ─── POS Orders ───

async fn list_orders(
    AxumState(state): AxumState<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    let property_id = q.property_id.unwrap_or_default();
    let mut stmt = conn
        .prepare(
            "SELECT id, property_id, order_number, table_number, guest_id, reservation_id,
                    status, order_type, total_amount, tax_amount, discount_amount, final_amount,
                    currency, payment_status, served_by, created_at, updated_at
             FROM pos_order
             WHERE (?1 = '' OR property_id = ?1)
             ORDER BY created_at DESC",
        )
        .map_err(|e| internal_error(e))?;

    let rows = stmt
        .query_map(rusqlite::params![property_id], |row| {
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "propertyId": row.get::<_, String>(1)?,
                "orderNumber": row.get::<_, String>(2)?,
                "tableNumber": row.get::<_, Option<String>>(3)?,
                "guestId": row.get::<_, Option<String>>(4)?,
                "reservationId": row.get::<_, Option<String>>(5)?,
                "status": row.get::<_, String>(6)?,
                "orderType": row.get::<_, String>(7)?,
                "totalAmount": row.get::<_, f64>(8)?,
                "taxAmount": row.get::<_, f64>(9)?,
                "discountAmount": row.get::<_, f64>(10)?,
                "finalAmount": row.get::<_, f64>(11)?,
                "currency": row.get::<_, String>(12)?,
                "paymentStatus": row.get::<_, String>(13)?,
                "servedBy": row.get::<_, Option<String>>(14)?,
                "createdAt": row.get::<_, String>(15)?,
                "updatedAt": row.get::<_, String>(16)?,
            }))
        })
        .map_err(|e| internal_error(e))?;

    let orders: Vec<Value> = rows.filter_map(|r| r.ok()).collect();
    Ok(Json(json!({ "data": orders, "count": orders.len() })))
}

async fn create_order(
    AxumState(state): AxumState<Arc<AppState>>,
    Json(req): Json<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let id = uuid::Uuid::new_v4().to_string();
    let order_number = format!("ORD-{}", chrono::Utc::now().format("%Y%m%d%H%M%S"));
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    conn.execute(
        "INSERT INTO pos_order (id, property_id, order_number, table_number, guest_id, reservation_id, status, order_type, total_amount, tax_amount, discount_amount, final_amount, currency, payment_status, served_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        rusqlite::params![
            id,
            req["propertyId"].as_str().unwrap_or(""),
            order_number,
            req["tableNumber"].as_str(),
            req["guestId"].as_str(),
            req["reservationId"].as_str(),
            req["status"].as_str().unwrap_or("OPEN"),
            req["orderType"].as_str().unwrap_or("DINE_IN"),
            req["totalAmount"].as_f64().unwrap_or(0.0),
            req["taxAmount"].as_f64().unwrap_or(0.0),
            req["discountAmount"].as_f64().unwrap_or(0.0),
            req["finalAmount"].as_f64().unwrap_or(0.0),
            req["currency"].as_str().unwrap_or("INR"),
            req["paymentStatus"].as_str().unwrap_or("PENDING"),
            req["servedBy"].as_str(),
        ],
    )
    .map_err(|e| internal_error(e))?;

    queue_sync(&conn, "pos-order", &id, "CREATE", &req)?;
    Ok(Json(merge_json(req, &[("id", json!(id)), ("orderNumber", json!(order_number))])))
}

async fn get_order(
    AxumState(state): AxumState<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    let order = conn
        .query_row(
            "SELECT id, property_id, order_number, table_number, guest_id, reservation_id,
                    status, order_type, total_amount, tax_amount, discount_amount, final_amount,
                    currency, payment_status, served_by, created_at, updated_at
             FROM pos_order WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "propertyId": row.get::<_, String>(1)?,
                    "orderNumber": row.get::<_, String>(2)?,
                    "tableNumber": row.get::<_, Option<String>>(3)?,
                    "guestId": row.get::<_, Option<String>>(4)?,
                    "reservationId": row.get::<_, Option<String>>(5)?,
                    "status": row.get::<_, String>(6)?,
                    "orderType": row.get::<_, String>(7)?,
                    "totalAmount": row.get::<_, f64>(8)?,
                    "taxAmount": row.get::<_, f64>(9)?,
                    "discountAmount": row.get::<_, f64>(10)?,
                    "finalAmount": row.get::<_, f64>(11)?,
                    "currency": row.get::<_, String>(12)?,
                    "paymentStatus": row.get::<_, String>(13)?,
                    "servedBy": row.get::<_, Option<String>>(14)?,
                    "createdAt": row.get::<_, String>(15)?,
                    "updatedAt": row.get::<_, String>(16)?,
                }))
            },
        )
        .ok();

    match order {
        Some(o) => Ok(Json(o)),
        None => Err((StatusCode::NOT_FOUND, "Order not found".to_string())),
    }
}

async fn update_order(
    AxumState(state): AxumState<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    if let Some(status) = req["status"].as_str() {
        conn.execute(
            "UPDATE pos_order SET status = ?1, local_updated_at = datetime('now') WHERE id = ?2",
            rusqlite::params![status, id],
        )
        .map_err(|e| internal_error(e))?;
    }

    queue_sync(&conn, "pos-order", &id, "UPDATE", &req)?;
    Ok(Json(json!({ "id": id, "updated": true })))
}

async fn add_order_item(
    AxumState(state): AxumState<Arc<AppState>>,
    Path(order_id): Path<String>,
    Json(req): Json<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let id = uuid::Uuid::new_v4().to_string();
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    conn.execute(
        "INSERT INTO pos_order_item (id, order_id, menu_item_id, quantity, unit_price, total_price, notes, status)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            id,
            order_id,
            req["menuItemId"].as_str().unwrap_or(""),
            req["quantity"].as_i64().unwrap_or(1),
            req["unitPrice"].as_f64().unwrap_or(0.0),
            req["totalPrice"].as_f64().unwrap_or(0.0),
            req["notes"].as_str(),
            req["status"].as_str().unwrap_or("PENDING"),
        ],
    )
    .map_err(|e| internal_error(e))?;

    Ok(Json(merge_json(req, &[("id", json!(id)), ("orderId", json!(order_id))])))
}

// ─── Folios ───

async fn list_folios(
    AxumState(state): AxumState<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    let property_id = q.property_id.unwrap_or_default();
    let mut stmt = conn
        .prepare(
            "SELECT f.id, f.property_id, f.reservation_id, f.guest_id, f.folio_number,
                    f.status, f.total_charges, f.total_payments, f.balance, f.currency,
                    f.created_at, f.updated_at,
                    g.first_name, g.last_name
             FROM folio f
             LEFT JOIN guest g ON f.guest_id = g.id
             WHERE (?1 = '' OR f.property_id = ?1)
             ORDER BY f.created_at DESC",
        )
        .map_err(|e| internal_error(e))?;

    let rows = stmt
        .query_map(rusqlite::params![property_id], |row| {
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "propertyId": row.get::<_, String>(1)?,
                "reservationId": row.get::<_, Option<String>>(2)?,
                "guestId": row.get::<_, String>(3)?,
                "folioNumber": row.get::<_, String>(4)?,
                "status": row.get::<_, String>(5)?,
                "totalCharges": row.get::<_, f64>(6)?,
                "totalPayments": row.get::<_, f64>(7)?,
                "balance": row.get::<_, f64>(8)?,
                "currency": row.get::<_, String>(9)?,
                "createdAt": row.get::<_, String>(10)?,
                "updatedAt": row.get::<_, String>(11)?,
                "guestFirstName": row.get::<_, Option<String>>(12)?,
                "guestLastName": row.get::<_, Option<String>>(13)?,
            }))
        })
        .map_err(|e| internal_error(e))?;

    let folios: Vec<Value> = rows.filter_map(|r| r.ok()).collect();
    Ok(Json(json!({ "data": folios, "count": folios.len() })))
}

async fn create_folio(
    AxumState(state): AxumState<Arc<AppState>>,
    Json(req): Json<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let id = uuid::Uuid::new_v4().to_string();
    let folio_number = format!("FOL-{}", chrono::Utc::now().format("%Y%m%d%H%M%S"));
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    conn.execute(
        "INSERT INTO folio (id, property_id, reservation_id, guest_id, folio_number, status, currency)
         VALUES (?1, ?2, ?3, ?4, ?5, 'OPEN', ?6)",
        rusqlite::params![
            id,
            req["propertyId"].as_str().unwrap_or(""),
            req["reservationId"].as_str(),
            req["guestId"].as_str().unwrap_or(""),
            folio_number,
            req["currency"].as_str().unwrap_or("INR"),
        ],
    )
    .map_err(|e| internal_error(e))?;

    queue_sync(&conn, "folio", &id, "CREATE", &req)?;
    Ok(Json(merge_json(req, &[("id", json!(id)), ("folioNumber", json!(folio_number))])))
}

async fn get_folio(
    AxumState(state): AxumState<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    let folio = conn
        .query_row(
            "SELECT id, property_id, reservation_id, guest_id, folio_number, status,
                    total_charges, total_payments, balance, currency, created_at, updated_at
             FROM folio WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "propertyId": row.get::<_, String>(1)?,
                    "reservationId": row.get::<_, Option<String>>(2)?,
                    "guestId": row.get::<_, String>(3)?,
                    "folioNumber": row.get::<_, String>(4)?,
                    "status": row.get::<_, String>(5)?,
                    "totalCharges": row.get::<_, f64>(6)?,
                    "totalPayments": row.get::<_, f64>(7)?,
                    "balance": row.get::<_, f64>(8)?,
                    "currency": row.get::<_, String>(9)?,
                    "createdAt": row.get::<_, String>(10)?,
                    "updatedAt": row.get::<_, String>(11)?,
                }))
            },
        )
        .ok();

    match folio {
        Some(f) => Ok(Json(f)),
        None => Err((StatusCode::NOT_FOUND, "Folio not found".to_string())),
    }
}

async fn add_folio_charge(
    AxumState(state): AxumState<Arc<AppState>>,
    Path(folio_id): Path<String>,
    Json(req): Json<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let id = uuid::Uuid::new_v4().to_string();
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    let amount = req["amount"].as_f64().unwrap_or(0.0);
    let tax_rate = req["taxRate"].as_f64().unwrap_or(0.0);
    let tax_amount = amount * tax_rate / 100.0;
    let total = amount + tax_amount;

    conn.execute(
        "INSERT INTO folio_charge (id, folio_id, description, amount, tax_rate, tax_amount, total_amount, category, posted_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params![
            id,
            folio_id,
            req["description"].as_str().unwrap_or(""),
            amount,
            tax_rate,
            tax_amount,
            total,
            req["category"].as_str(),
            req["postedBy"].as_str(),
        ],
    )
    .map_err(|e| internal_error(e))?;

    // Update folio totals
    conn.execute(
        "UPDATE folio SET
            total_charges = (SELECT COALESCE(SUM(total_amount), 0) FROM folio_charge WHERE folio_id = ?1),
            balance = (SELECT COALESCE(SUM(total_amount), 0) FROM folio_charge WHERE folio_id = ?1) - total_payments,
            updated_at = datetime('now')
         WHERE id = ?1",
        rusqlite::params![folio_id],
    )
    .map_err(|e| internal_error(e))?;

    queue_sync(&conn, "folio-charge", &id, "CREATE", &req)?;
    Ok(Json(merge_json(req, &[("id", json!(id)), ("folioId", json!(folio_id)), ("totalAmount", json!(total))])))
}

async fn add_folio_payment(
    AxumState(state): AxumState<Arc<AppState>>,
    Path(folio_id): Path<String>,
    Json(req): Json<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let id = uuid::Uuid::new_v4().to_string();
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    let amount = req["amount"].as_f64().unwrap_or(0.0);

    conn.execute(
        "INSERT INTO folio_payment (id, folio_id, amount, method, reference, received_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            id,
            folio_id,
            amount,
            req["method"].as_str().unwrap_or("CASH"),
            req["reference"].as_str(),
            req["receivedBy"].as_str(),
        ],
    )
    .map_err(|e| internal_error(e))?;

    // Update folio totals
    conn.execute(
        "UPDATE folio SET
            total_payments = (SELECT COALESCE(SUM(amount), 0) FROM folio_payment WHERE folio_id = ?1),
            balance = total_charges - (SELECT COALESCE(SUM(amount), 0) FROM folio_payment WHERE folio_id = ?1),
            updated_at = datetime('now')
         WHERE id = ?1",
        rusqlite::params![folio_id],
    )
    .map_err(|e| internal_error(e))?;

    queue_sync(&conn, "folio-payment", &id, "CREATE", &req)?;
    Ok(Json(merge_json(req, &[("id", json!(id)), ("folioId", json!(folio_id)), ("amount", json!(amount))])))
}

// ─── Housekeeping ───

async fn list_hk_tasks(
    AxumState(state): AxumState<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    let property_id = q.property_id.unwrap_or_default();
    let mut stmt = conn
        .prepare(
            "SELECT t.id, t.property_id, t.room_id, t.task_type, t.status, t.assigned_to,
                    t.priority, t.notes, t.created_at, t.completed_at,
                    r.number as room_number
             FROM housekeeping_task t
             LEFT JOIN room r ON t.room_id = r.id
             WHERE (?1 = '' OR t.property_id = ?1)
             ORDER BY t.created_at DESC",
        )
        .map_err(|e| internal_error(e))?;

    let rows = stmt
        .query_map(rusqlite::params![property_id], |row| {
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "propertyId": row.get::<_, String>(1)?,
                "roomId": row.get::<_, String>(2)?,
                "taskType": row.get::<_, String>(3)?,
                "status": row.get::<_, String>(4)?,
                "assignedTo": row.get::<_, Option<String>>(5)?,
                "priority": row.get::<_, String>(6)?,
                "notes": row.get::<_, Option<String>>(7)?,
                "createdAt": row.get::<_, String>(8)?,
                "completedAt": row.get::<_, Option<String>>(9)?,
                "roomNumber": row.get::<_, Option<String>>(10)?,
            }))
        })
        .map_err(|e| internal_error(e))?;

    let tasks: Vec<Value> = rows.filter_map(|r| r.ok()).collect();
    Ok(Json(json!({ "data": tasks, "count": tasks.len() })))
}

async fn create_hk_task(
    AxumState(state): AxumState<Arc<AppState>>,
    Json(req): Json<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let id = uuid::Uuid::new_v4().to_string();
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    conn.execute(
        "INSERT INTO housekeeping_task (id, property_id, room_id, task_type, status, assigned_to, priority, notes)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            id,
            req["propertyId"].as_str().unwrap_or(""),
            req["roomId"].as_str().unwrap_or(""),
            req["taskType"].as_str().unwrap_or("CLEANING"),
            req["status"].as_str().unwrap_or("PENDING"),
            req["assignedTo"].as_str(),
            req["priority"].as_str().unwrap_or("NORMAL"),
            req["notes"].as_str(),
        ],
    )
    .map_err(|e| internal_error(e))?;

    queue_sync(&conn, "housekeeping-task", &id, "CREATE", &req)?;
    Ok(Json(merge_json(req, &[("id", json!(id))])))
}

async fn update_hk_task(
    AxumState(state): AxumState<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    if let Some(status) = req["status"].as_str() {
        let completed_at = if status == "COMPLETED" {
            Some(chrono::Utc::now().to_rfc3339())
        } else {
            None
        };
        conn.execute(
            "UPDATE housekeeping_task SET status = ?1, completed_at = COALESCE(?2, completed_at), local_updated_at = datetime('now') WHERE id = ?3",
            rusqlite::params![status, completed_at, id],
        )
        .map_err(|e| internal_error(e))?;
    }

    queue_sync(&conn, "housekeeping-task", &id, "UPDATE", &req)?;
    Ok(Json(json!({ "id": id, "updated": true })))
}

// ─── Media & Sync ───

async fn get_storage_quota(
    AxumState(state): AxumState<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let org_id = q.property_id.unwrap_or_default();
    let conn = state.db.conn().map_err(|e| {
        internal_error(e)
    })?;

    // Get or create quota
    let quota = conn
        .query_row(
            "SELECT id, organization_id, free_quota_bytes, addon_bytes, used_bytes
             FROM storage_quota WHERE organization_id = ?1",
            rusqlite::params![org_id],
            |row| Ok(json!({
                "id": row.get::<_, String>(0)?,
                "organizationId": row.get::<_, String>(1)?,
                "freeQuotaBytes": row.get::<_, i64>(2)?,
                "addonBytes": row.get::<_, i64>(3)?,
                "usedBytes": row.get::<_, i64>(4)?,
            })),
        )
        .unwrap_or_else(|_| json!({
            "organizationId": org_id,
            "freeQuotaBytes": 1073741824_i64,
            "addonBytes": 0_i64,
            "usedBytes": 0_i64,
        }));

    // Calculate actual usage
    let actual_used = crate::image::dir_size(&state.images_dir) as i64;
    let total_quota = quota["freeQuotaBytes"].as_i64().unwrap_or(1073741824) + quota["addonBytes"].as_i64().unwrap_or(0);
    Ok(Json(merge_json(quota, &[("usedBytes", json!(actual_used)), ("totalQuotaBytes", json!(total_quota))])))
}

async fn sync_media(
    AxumState(state): AxumState<Arc<AppState>>,
) -> Result<Json<Value>, (StatusCode, String)> {
    // TODO: Trigger actual R2 sync
    Ok(Json(json!({ "synced": true, "message": "Media sync queued" })))
}

async fn get_sync_status(
    AxumState(state): AxumState<Arc<AppState>>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let status = state.sync.get_status();
    Ok(Json(serde_json::to_value(status).unwrap_or_default()))
}

async fn trigger_sync(
    AxumState(state): AxumState<Arc<AppState>>,
) -> Result<Json<Value>, (StatusCode, String)> {
    state.sync.trigger_sync().await.map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, e)
    })?;
    Ok(Json(json!({ "triggered": true })))
}

// ─── Image serving ───

async fn serve_image(
    AxumState(state): AxumState<Arc<AppState>>,
    Path(path): Path<String>,
) -> Result<Vec<u8>, (StatusCode, String)> {
    let full_path = match safe_join(&state.images_dir, &path) {
        Ok(p) => p,
        Err(_) => return Err((StatusCode::NOT_FOUND, "Image not found".to_string())),
    };
    std::fs::read(&full_path)
        .map_err(|_,| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to read image".to_string()))
}

// ─── Helper ───

fn queue_sync(
    conn: &rusqlite::Connection,
    entity_type: &str,
    entity_id: &str,
    operation: &str,
    payload: &Value,
) -> Result<(), (StatusCode, String)> {
    let id = uuid::Uuid::new_v4().to_string();
    let idempotency_key = format!("{}_{}_{}_{}", entity_type, entity_id, operation, chrono::Utc::now().timestamp());
    conn.execute(
        "INSERT OR IGNORE INTO sync_outbox (id, idempotency_key, entity_type, entity_id, operation, payload, device_id, property_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            id,
            idempotency_key,
            entity_type,
            entity_id,
            operation,
            payload.to_string(),
            "desktop",
            "",
        ],
    )
    .map_err(|e| internal_error(e))?;
    Ok(())
}

// ─── Password hash storage (for offline auth) ───

/// Store a password hash for a user so offline login can verify credentials.
/// Called by the frontend after a successful online login.
/// The password is hashed with SHA-256 before storage — the plaintext password
/// is never stored.
#[tauri::command]
pub async fn store_password_hash(
    email: String,
    password: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let hash = hash_password(&password);
    let conn = state.db.conn().map_err(|e| e.to_string())?;
    let affected = conn.execute(
        "UPDATE user SET password_hash = ?1 WHERE email = ?2",
        rusqlite::params![hash, email],
    ).map_err(|e| e.to_string())?;
    if affected == 0 {
        // User not found in local DB — they may not be synced yet.
        // This is not an error; the hash will be stored after the next sync.
        log::debug!("store_password_hash: user '{}' not found in local DB yet", email);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // ─── hash_password / verify_password ───

    #[test]
    fn hash_password_produces_argon2_phc_format() {
        let hash = hash_password("mysecret123");
        assert!(
            hash.starts_with("$argon2"),
            "hash must be Argon2 PHC format, got: {}",
            &hash[..20.min(hash.len())]
        );
    }

    #[test]
    fn hash_password_is_non_deterministic() {
        // Argon2 uses a random salt, so two hashes of the same password differ.
        let h1 = hash_password("mysecret123");
        let h2 = hash_password("mysecret123");
        assert_ne!(h1, h2, "same password must produce different hashes (random salt)");
    }

    #[test]
    fn verify_password_succeeds_for_correct_password() {
        let hash = hash_password("correct-horse-battery-staple");
        assert!(verify_password("correct-horse-battery-staple", &hash), "correct password must verify");
    }

    #[test]
    fn verify_password_fails_for_wrong_password() {
        let hash = hash_password("correct-horse-battery-staple");
        assert!(!verify_password("wrong-password", &hash), "wrong password must not verify");
    }

    #[test]
    fn verify_password_supports_legacy_sha256() {
        // Legacy SHA-256 hashes (64 hex chars) must still verify for backward compat
        let mut hasher = Sha256::new();
        hasher.update(b"legacy-password");
        let legacy_hash = hex::encode(hasher.finalize());
        assert!(verify_password("legacy-password", &legacy_hash), "legacy SHA-256 hash must verify");
        assert!(!verify_password("wrong", &legacy_hash), "wrong password must not verify against legacy hash");
    }

    #[test]
    fn is_legacy_hash_detects_sha256_and_argon2() {
        let argon_hash = hash_password("test");
        assert!(!is_legacy_hash(&argon_hash), "Argon2 hash must not be detected as legacy");

        let mut hasher = Sha256::new();
        hasher.update(b"test");
        let sha_hash = hex::encode(hasher.finalize());
        assert!(is_legacy_hash(&sha_hash), "SHA-256 hash must be detected as legacy");
    }

    // ─── safe_join ───

    fn create_test_base() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("create temp dir");
        // Create a file inside so canonicalize works
        let mut f = std::fs::File::create(dir.path().join("placeholder.txt"))
            .expect("create placeholder");
        f.write_all(b"test").expect("write placeholder");
        // Create a subdirectory
        std::fs::create_dir_all(dir.path().join("guests")).expect("create subdir");
        // Create a file in the subdir
        let mut f2 = std::fs::File::create(dir.path().join("guests").join("img.webp"))
            .expect("create subdir file");
        f2.write_all(b"webp").expect("write subdir file");
        dir
    }

    #[test]
    fn safe_join_allows_path_within_base() {
        let base = create_test_base();
        let result = safe_join(base.path(), "guests/img.webp");
        assert!(result.is_ok(), "valid path within base should be allowed");
        let joined = result.unwrap();
        assert!(joined.starts_with(base.path().canonicalize().unwrap()));
    }

    #[test]
    fn safe_join_blocks_parent_traversal() {
        let base = create_test_base();
        let result = safe_join(base.path(), "../../etc/passwd");
        assert!(result.is_err(), "path traversal with .. must be blocked");
        let err = result.unwrap_err();
        assert!(err.contains("traversal") || err.contains("not found"),
            "error should mention traversal or not found, got: {}", err);
    }

    #[test]
    fn safe_join_blocks_nonexistent_path() {
        let base = create_test_base();
        let result = safe_join(base.path(), "nonexistent/file.webp");
        assert!(result.is_err(), "nonexistent path should fail canonicalize");
    }

    #[test]
    fn safe_join_blocks_absolute_path_outside_base() {
        let base = create_test_base();
        // On Windows, absolute paths like C:\Windows won't be under the temp dir
        // On Unix, /etc/hosts won't be under the temp dir
        let outside = if cfg!(windows) { "C:/Windows/System32/drivers/etc/hosts" } else { "/etc/passwd" };
        let result = safe_join(base.path(), outside);
        assert!(result.is_err(), "absolute path outside base must be blocked");
    }

    // ─── merge_json ───

    #[test]
    fn merge_json_adds_new_keys() {
        let base = json!({ "name": "Alice", "age": 30 });
        let result = merge_json(base, &[("id", json!("uuid-123")), ("active", json!(true))]);
        assert_eq!(result["name"], "Alice");
        assert_eq!(result["age"], 30);
        assert_eq!(result["id"], "uuid-123");
        assert_eq!(result["active"], true);
    }

    #[test]
    fn merge_json_overrides_existing_keys() {
        let base = json!({ "name": "Alice", "version": 1 });
        let result = merge_json(base, &[("name", json!("Bob"))]);
        assert_eq!(result["name"], "Bob", "override should replace existing value");
    }

    #[test]
    fn merge_json_preserves_non_object_base() {
        let base = json!([1, 2, 3]);
        let result = merge_json(base, &[("id", json!("x"))]);
        // Non-object base should be returned as-is (no panic)
        assert!(result.is_array(), "non-object base should remain unchanged");
    }

    #[test]
    fn merge_json_with_empty_overrides() {
        let base = json!({ "key": "value" });
        let result = merge_json(base, &[]);
        assert_eq!(result["key"], "value");
    }
}
