use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub last_active_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub organization_id: Option<String>,
    pub property_id: Option<String>,
    pub email: String,
    pub name: String,
    pub role: String,
    pub is_active: bool,
    pub avatar_url: Option<String>,
    pub phone: Option<String>,
    pub last_login_at: Option<String>,
    pub token_expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Guest {
    pub id: String,
    pub property_id: String,
    pub first_name: String,
    pub last_name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub id_type: Option<String>,
    pub id_number: Option<String>,
    pub id_photo_path: Option<String>,
    pub photo_path: Option<String>,
    pub nationality: Option<String>,
    pub date_of_birth: Option<String>,
    pub gender: Option<String>,
    pub address: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub pincode: Option<String>,
    pub vip: bool,
    pub blacklisted: bool,
    pub notes: Option<String>,
    pub loyalty_points: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Room {
    pub id: String,
    pub property_id: String,
    pub room_type_id: Option<String>,
    pub number: String,
    pub floor: Option<i32>,
    pub status: String,
    pub is_active: bool,
    pub photos: Option<String>, // JSON array
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reservation {
    pub id: String,
    pub property_id: String,
    pub guest_id: String,
    pub room_id: Option<String>,
    pub room_type_id: Option<String>,
    pub status: String,
    pub source: Option<String>,
    pub check_in_date: String,
    pub check_out_date: String,
    pub adults: i32,
    pub children: i32,
    pub rate_amount: f64,
    pub currency: String,
    pub special_requests: Option<String>,
    pub created_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub checked_in_at: Option<String>,
    pub checked_out_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MenuItem {
    pub id: String,
    pub property_id: String,
    pub name: String,
    pub description: Option<String>,
    pub category: Option<String>,
    pub price: f64,
    pub tax_rate: f64,
    pub is_veg: bool,
    pub is_available: bool,
    pub photo: Option<String>,
    pub prep_time_minutes: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PosOrder {
    pub id: String,
    pub property_id: String,
    pub order_number: String,
    pub table_number: Option<String>,
    pub guest_id: Option<String>,
    pub reservation_id: Option<String>,
    pub status: String,
    pub order_type: String,
    pub total_amount: f64,
    pub tax_amount: f64,
    pub discount_amount: f64,
    pub final_amount: f64,
    pub currency: String,
    pub payment_status: String,
    pub served_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Folio {
    pub id: String,
    pub property_id: String,
    pub reservation_id: Option<String>,
    pub guest_id: String,
    pub folio_number: String,
    pub status: String,
    pub total_charges: f64,
    pub total_payments: f64,
    pub balance: f64,
    pub currency: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaAsset {
    pub id: String,
    pub organization_id: String,
    pub property_id: String,
    pub entity: String,
    pub entity_id: String,
    pub variant: String,
    pub local_path: Option<String>,
    pub r2_key: Option<String>,
    pub url: Option<String>,
    pub mime_type: String,
    pub size_bytes: i64,
    pub width: Option<i32>,
    pub height: Option<i32>,
    pub is_synced: bool,
    pub is_always_cloud: bool,
    pub uploaded_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageQuota {
    pub id: String,
    pub organization_id: String,
    pub free_quota_bytes: i64,
    pub addon_bytes: i64,
    pub used_bytes: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncOutboxEntry {
    pub id: String,
    pub idempotency_key: String,
    pub entity_type: String,
    pub entity_id: String,
    pub operation: String,
    pub payload: String,
    pub local_version: i32,
    pub server_version: Option<i32>,
    pub device_id: String,
    pub property_id: String,
    pub created_at: String,
    pub updated_at: String,
    pub synced_at: Option<String>,
    pub sync_error: Option<String>,
    pub status: String,
    pub retry_count: i32,
}

/// IPC contract with the web UI — must serialize as camelCase (`isOnline`, not `is_online`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatus {
    pub enabled: bool,
    pub last_sync_at: Option<String>,
    pub pending_count: i32,
    pub failed_count: i32,
    pub conflict_count: i32,
    pub is_online: bool,
}
