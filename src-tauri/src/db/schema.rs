use rusqlite::Connection;
use crate::db::DbResult;

/// Run all database migrations to create the local SQLite schema.
/// This schema mirrors the subset of the PostgreSQL schema needed for
/// offline operations. It is NOT a 1:1 copy — SQLite has no arrays or
/// enums, so those are stored as JSON or TEXT with validation.
pub fn run_migrations(conn: &Connection) -> DbResult<()> {
    // Enable WAL mode and foreign keys
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")?;

    let migrations: &[(&str, &str)] = &[
        ("001_core", MIGRATION_001_CORE),
        ("002_sync", MIGRATION_002_SYNC),
        ("003_media", MIGRATION_003_MEDIA),
        ("004_rooms_reservations", MIGRATION_004_ROOMS_RESERVATIONS),
        ("005_pos_billing", MIGRATION_005_POS_BILLING),
        ("006_housekeeping", MIGRATION_006_HOUSEKEEPING),
        ("007_sync_entity", MIGRATION_007_SYNC_ENTITY),
        ("008_device_heartbeat", MIGRATION_008_DEVICE_HEARTBEAT),
    ];

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS _migrations (
            name TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )?;

    for (name, sql) in migrations {
        let applied: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM _migrations WHERE name = ?1)",
                rusqlite::params![name],
                |row| row.get(0),
            )
            .unwrap_or(false);

        if !applied {
            conn.execute_batch(sql)?;
            conn.execute(
                "INSERT INTO _migrations (name) VALUES (?1)",
                rusqlite::params![name],
            )?;
            log::info!("Applied migration: {}", name);
        }
    }

    Ok(())
}

// ─── Migration 001: Core tables (auth, properties, users, organizations) ───

const MIGRATION_001_CORE: &str = r#"
-- Device identity (generated on first install)
CREATE TABLE IF NOT EXISTS device (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT 'Desktop',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_active_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Organization (cached from server)
CREATE TABLE IF NOT EXISTS organization (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    code TEXT,
    contact_email TEXT,
    contact_phone TEXT,
    address TEXT,
    city TEXT,
    state TEXT,
    country TEXT,
    pincode TEXT,
    gstin TEXT,
    logo_url TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    server_updated_at TEXT,
    local_updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Property (cached from server)
CREATE TABLE IF NOT EXISTS property (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    name TEXT NOT NULL,
    code TEXT,
    address TEXT,
    city TEXT,
    state TEXT,
    country TEXT,
    pincode TEXT,
    phone TEXT,
    email TEXT,
    gstin TEXT,
    check_in_time TEXT DEFAULT '12:00',
    check_out_time TEXT DEFAULT '11:00',
    currency TEXT DEFAULT 'INR',
    timezone TEXT DEFAULT 'Asia/Kolkata',
    logo_url TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    server_updated_at TEXT,
    local_updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (organization_id) REFERENCES organization(id)
);
CREATE INDEX IF NOT EXISTS idx_property_org ON property(organization_id);

-- User (cached from server, for offline auth)
CREATE TABLE IF NOT EXISTS user (
    id TEXT PRIMARY KEY,
    organization_id TEXT,
    property_id TEXT,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'RECEPTIONIST',
    is_active INTEGER NOT NULL DEFAULT 1,
    avatar_url TEXT,
    phone TEXT,
    last_login_at TEXT,
    auth_token TEXT,          -- JWT for API calls (encrypted at rest)
    refresh_token TEXT,       -- JWT refresh token (encrypted at rest)
    token_expires_at TEXT,
    server_updated_at TEXT,
    local_updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (organization_id) REFERENCES organization(id),
    FOREIGN KEY (property_id) REFERENCES property(id)
);
CREATE INDEX IF NOT EXISTS idx_user_org ON user(organization_id);
CREATE INDEX IF NOT EXISTS idx_user_property ON user(property_id);

-- User property assignments (multi-property staff)
CREATE TABLE IF NOT EXISTS user_property (
    user_id TEXT NOT NULL,
    property_id TEXT NOT NULL,
    PRIMARY KEY (user_id, property_id),
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
    FOREIGN KEY (property_id) REFERENCES property(id) ON DELETE CASCADE
);
"#;

// ─── Migration 002: Sync tables (outbox, cursor, conflicts) ───

const MIGRATION_002_SYNC: &str = r#"
-- Sync outbox: pending mutations to push to server
CREATE TABLE IF NOT EXISTS sync_outbox (
    id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    operation TEXT NOT NULL,  -- CREATE, UPDATE, DELETE
    payload TEXT NOT NULL,    -- JSON
    local_version INTEGER NOT NULL DEFAULT 1,
    server_version INTEGER,
    device_id TEXT NOT NULL,
    property_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    synced_at TEXT,
    sync_error TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING',  -- PENDING, SYNCING, SYNCED, FAILED, CONFLICT
    retry_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_outbox_status ON sync_outbox(property_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_outbox_entity ON sync_outbox(entity_type, entity_id);

-- Sync cursor: last sync position per device/property
CREATE TABLE IF NOT EXISTS sync_cursor (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    property_id TEXT NOT NULL,
    last_synced_at TEXT NOT NULL,
    server_cursor TEXT,
    UNIQUE(device_id, property_id)
);

-- Sync conflicts: records needing manual resolution
CREATE TABLE IF NOT EXISTS sync_conflict (
    id TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    local_payload TEXT NOT NULL,
    server_payload TEXT NOT NULL,
    conflict_type TEXT NOT NULL,  -- VERSION_MISMATCH, DELETED_REMOTELY, etc.
    resolution TEXT,  -- KEEP_LOCAL, ACCEPT_SERVER, MERGED
    resolved_payload TEXT,
    resolved_by TEXT,
    resolved_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    property_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_conflict_property ON sync_conflict(property_id, resolved_at);

-- Sync settings
CREATE TABLE IF NOT EXISTS sync_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT OR IGNORE INTO sync_settings (key, value) VALUES ('enabled', 'true');
INSERT OR IGNORE INTO sync_settings (key, value) VALUES ('last_sync_at', '');
INSERT OR IGNORE INTO sync_settings (key, value) VALUES ('auto_sync_interval_seconds', '30');
INSERT OR IGNORE INTO sync_settings (key, value) VALUES ('server_url', '');
INSERT OR IGNORE INTO sync_settings (key, value) VALUES ('auth_token', '');
INSERT OR IGNORE INTO sync_settings (key, value) VALUES ('pull_cursor', '');
INSERT OR IGNORE INTO sync_settings (key, value) VALUES ('is_online', 'false');
"#;

// ─── Migration 003: Media storage tracking ───

const MIGRATION_003_MEDIA: &str = r#"
-- Media assets (local + cloud)
CREATE TABLE IF NOT EXISTS media_asset (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    property_id TEXT NOT NULL,
    entity TEXT NOT NULL,       -- menu-items, guests, employees, rooms, etc.
    entity_id TEXT NOT NULL,
    variant TEXT NOT NULL,      -- thumb, medium, original
    local_path TEXT,            -- relative path from images dir
    r2_key TEXT,                -- R2 storage key (when synced)
    url TEXT,                   -- public URL (R2 or imgproxy)
    mime_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    width INTEGER,
    height INTEGER,
    is_synced INTEGER NOT NULL DEFAULT 0,
    is_always_cloud INTEGER NOT NULL DEFAULT 0,  -- 1 for menu items, logo
    uploaded_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (organization_id) REFERENCES organization(id),
    FOREIGN KEY (property_id) REFERENCES property(id)
);
CREATE INDEX IF NOT EXISTS idx_media_entity ON media_asset(organization_id, property_id, entity, entity_id);
CREATE INDEX IF NOT EXISTS idx_media_synced ON media_asset(organization_id, is_synced);

-- Storage quota per organization
CREATE TABLE IF NOT EXISTS storage_quota (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL UNIQUE,
    free_quota_bytes INTEGER NOT NULL DEFAULT 1073741824,  -- 1 GB
    addon_bytes INTEGER NOT NULL DEFAULT 0,
    used_bytes INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Media folder permissions (role x folder)
CREATE TABLE IF NOT EXISTS media_folder_permission (
    id TEXT PRIMARY KEY,
    role TEXT NOT NULL,
    folder TEXT NOT NULL,
    can_view INTEGER NOT NULL DEFAULT 0,
    can_upload INTEGER NOT NULL DEFAULT 0,
    can_delete INTEGER NOT NULL DEFAULT 0,
    UNIQUE(role, folder)
);

-- Seed default permissions
INSERT OR IGNORE INTO media_folder_permission (id, role, folder, can_view, can_upload, can_delete) VALUES
-- OWNER: full access to all
('seed_owner_menu', 'OWNER', 'menu-items', 1, 1, 1),
('seed_owner_guests', 'OWNER', 'guests', 1, 1, 1),
('seed_owner_employees', 'OWNER', 'employees', 1, 1, 1),
('seed_owner_rooms', 'OWNER', 'rooms', 1, 1, 1),
('seed_owner_lost', 'OWNER', 'lost-found', 1, 1, 1),
('seed_owner_transport', 'OWNER', 'transport', 1, 1, 1),
('seed_owner_visitors', 'OWNER', 'visitors', 1, 1, 1),
('seed_owner_properties', 'OWNER', 'properties', 1, 1, 1),
-- HOTEL_ADMIN: full access to all
('seed_admin_menu', 'HOTEL_ADMIN', 'menu-items', 1, 1, 1),
('seed_admin_guests', 'HOTEL_ADMIN', 'guests', 1, 1, 1),
('seed_admin_employees', 'HOTEL_ADMIN', 'employees', 1, 1, 1),
('seed_admin_rooms', 'HOTEL_ADMIN', 'rooms', 1, 1, 1),
('seed_admin_lost', 'HOTEL_ADMIN', 'lost-found', 1, 1, 1),
('seed_admin_transport', 'HOTEL_ADMIN', 'transport', 1, 1, 1),
('seed_admin_visitors', 'HOTEL_ADMIN', 'visitors', 1, 1, 1),
('seed_admin_properties', 'HOTEL_ADMIN', 'properties', 1, 1, 1),
-- GENERAL_MANAGER: all except property settings
('seed_gm_menu', 'GENERAL_MANAGER', 'menu-items', 1, 1, 1),
('seed_gm_guests', 'GENERAL_MANAGER', 'guests', 1, 1, 1),
('seed_gm_employees', 'GENERAL_MANAGER', 'employees', 1, 1, 1),
('seed_gm_rooms', 'GENERAL_MANAGER', 'rooms', 1, 1, 1),
('seed_gm_lost', 'GENERAL_MANAGER', 'lost-found', 1, 1, 1),
('seed_gm_transport', 'GENERAL_MANAGER', 'transport', 1, 1, 1),
('seed_gm_visitors', 'GENERAL_MANAGER', 'visitors', 1, 1, 1),
-- SUPERVISOR: view/upload most, no property settings
('seed_sup_menu', 'SUPERVISOR', 'menu-items', 1, 1, 1),
('seed_sup_guests', 'SUPERVISOR', 'guests', 1, 1, 1),
('seed_sup_employees', 'SUPERVISOR', 'employees', 1, 0, 0),
('seed_sup_rooms', 'SUPERVISOR', 'rooms', 1, 1, 1),
('seed_sup_lost', 'SUPERVISOR', 'lost-found', 1, 1, 1),
('seed_sup_transport', 'SUPERVISOR', 'transport', 1, 1, 1),
('seed_sup_visitors', 'SUPERVISOR', 'visitors', 1, 1, 1),
-- RECEPTIONIST: guests, rooms, transport, visitors
('seed_rec_guests', 'RECEPTIONIST', 'guests', 1, 1, 1),
('seed_rec_rooms', 'RECEPTIONIST', 'rooms', 1, 1, 1),
('seed_rec_transport', 'RECEPTIONIST', 'transport', 1, 1, 1),
('seed_rec_visitors', 'RECEPTIONIST', 'visitors', 1, 1, 1),
-- HOUSEKEEPING: rooms, lost-found
('seed_hk_rooms', 'HOUSEKEEPING', 'rooms', 1, 1, 1),
('seed_hk_lost', 'HOUSEKEEPING', 'lost-found', 1, 1, 1),
-- KITCHEN: menu-items only
('seed_kit_menu', 'KITCHEN', 'menu-items', 1, 1, 1),
-- WAITER: menu-items only (view)
('seed_wtr_menu', 'WAITER', 'menu-items', 1, 0, 0);
"#;

// ─── Migration 004: Rooms & Reservations ───

const MIGRATION_004_ROOMS_RESERVATIONS: &str = r#"
-- Room types
CREATE TABLE IF NOT EXISTS room_type (
    id TEXT PRIMARY KEY,
    property_id TEXT NOT NULL,
    name TEXT NOT NULL,
    code TEXT,
    description TEXT,
    base_price REAL NOT NULL DEFAULT 0,
    max_occupancy INTEGER NOT NULL DEFAULT 2,
    amenities TEXT,  -- JSON array
    is_active INTEGER NOT NULL DEFAULT 1,
    server_updated_at TEXT,
    local_updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (property_id) REFERENCES property(id)
);
CREATE INDEX IF NOT EXISTS idx_room_type_property ON room_type(property_id);

-- Rooms
CREATE TABLE IF NOT EXISTS room (
    id TEXT PRIMARY KEY,
    property_id TEXT NOT NULL,
    room_type_id TEXT,
    number TEXT NOT NULL,
    floor INTEGER,
    status TEXT NOT NULL DEFAULT 'AVAILABLE',  -- AVAILABLE, OCCUPIED, RESERVED, MAINTENANCE, DIRTY, CLEAN
    is_active INTEGER NOT NULL DEFAULT 1,
    photos TEXT,  -- JSON array of local paths
    notes TEXT,
    server_updated_at TEXT,
    local_updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (property_id) REFERENCES property(id),
    FOREIGN KEY (room_type_id) REFERENCES room_type(id)
);
CREATE INDEX IF NOT EXISTS idx_room_property ON room(property_id);
CREATE INDEX IF NOT EXISTS idx_room_status ON room(property_id, status);

-- Guests
CREATE TABLE IF NOT EXISTS guest (
    id TEXT PRIMARY KEY,
    property_id TEXT NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT,
    email TEXT,
    phone TEXT,
    id_type TEXT,  -- PASSPORT, AADHAAR, DRIVING_LICENSE, etc.
    id_number TEXT,
    id_photo_path TEXT,  -- local path to ID card photo
    photo_path TEXT,     -- local path to guest photo
    nationality TEXT,
    date_of_birth TEXT,
    gender TEXT,
    address TEXT,
    city TEXT,
    state TEXT,
    country TEXT,
    pincode TEXT,
    vip INTEGER NOT NULL DEFAULT 0,
    blacklisted INTEGER NOT NULL DEFAULT 0,
    notes TEXT,
    loyalty_points INTEGER NOT NULL DEFAULT 0,
    server_updated_at TEXT,
    local_updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (property_id) REFERENCES property(id)
);
CREATE INDEX IF NOT EXISTS idx_guest_property ON guest(property_id);
CREATE INDEX IF NOT EXISTS idx_guest_name ON guest(property_id, first_name, last_name);
CREATE INDEX IF NOT EXISTS idx_guest_phone ON guest(property_id, phone);

-- Reservations
CREATE TABLE IF NOT EXISTS reservation (
    id TEXT PRIMARY KEY,
    property_id TEXT NOT NULL,
    guest_id TEXT NOT NULL,
    room_id TEXT,
    room_type_id TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING',  -- PENDING, CONFIRMED, CHECKED_IN, CHECKED_OUT, CANCELLED, NO_SHOW
    source TEXT,  -- DIRECT, BOOKING_COM, AGODA, etc.
    check_in_date TEXT NOT NULL,
    check_out_date TEXT NOT NULL,
    adults INTEGER NOT NULL DEFAULT 1,
    children INTEGER NOT NULL DEFAULT 0,
    rate_plan TEXT,
    rate_amount REAL NOT NULL DEFAULT 0,
    currency TEXT DEFAULT 'INR',
    special_requests TEXT,
    created_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    checked_in_at TEXT,
    checked_out_at TEXT,
    server_updated_at TEXT,
    local_updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (property_id) REFERENCES property(id),
    FOREIGN KEY (guest_id) REFERENCES guest(id),
    FOREIGN KEY (room_id) REFERENCES room(id),
    FOREIGN KEY (room_type_id) REFERENCES room_type(id)
);
CREATE INDEX IF NOT EXISTS idx_res_property ON reservation(property_id, status);
CREATE INDEX IF NOT EXISTS idx_res_dates ON reservation(property_id, check_in_date, check_out_date);
CREATE INDEX IF NOT EXISTS idx_res_guest ON reservation(guest_id);
"#;

// ─── Migration 005: POS & Billing ───

const MIGRATION_005_POS_BILLING: &str = r#"
-- Menu items (for POS)
CREATE TABLE IF NOT EXISTS menu_item (
    id TEXT PRIMARY KEY,
    property_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    category TEXT,
    price REAL NOT NULL DEFAULT 0,
    tax_rate REAL NOT NULL DEFAULT 0,
    is_veg INTEGER NOT NULL DEFAULT 1,
    is_available INTEGER NOT NULL DEFAULT 1,
    photo TEXT,  -- local path or R2 URL
    prep_time_minutes INTEGER,
    server_updated_at TEXT,
    local_updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (property_id) REFERENCES property(id)
);
CREATE INDEX IF NOT EXISTS idx_menu_property ON menu_item(property_id, is_available);

-- POS orders
CREATE TABLE IF NOT EXISTS pos_order (
    id TEXT PRIMARY KEY,
    property_id TEXT NOT NULL,
    order_number TEXT NOT NULL,
    table_number TEXT,
    guest_id TEXT,
    reservation_id TEXT,
    status TEXT NOT NULL DEFAULT 'OPEN',  -- OPEN, KOT_PRINTED, SERVED, BILLED, PAID, CANCELLED
    order_type TEXT NOT NULL DEFAULT 'DINE_IN',  -- DINE_IN, TAKEAWAY, DELIVERY, ROOM_SERVICE
    total_amount REAL NOT NULL DEFAULT 0,
    tax_amount REAL NOT NULL DEFAULT 0,
    discount_amount REAL NOT NULL DEFAULT 0,
    final_amount REAL NOT NULL DEFAULT 0,
    currency TEXT DEFAULT 'INR',
    payment_status TEXT NOT NULL DEFAULT 'PENDING',
    served_by TEXT,  -- waiter/staff user id
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    kot_printed_at TEXT,
    billed_at TEXT,
    server_updated_at TEXT,
    local_updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (property_id) REFERENCES property(id),
    FOREIGN KEY (guest_id) REFERENCES guest(id),
    FOREIGN KEY (reservation_id) REFERENCES reservation(id)
);
CREATE INDEX IF NOT EXISTS idx_order_property ON pos_order(property_id, status);
CREATE INDEX IF NOT EXISTS idx_order_number ON pos_order(property_id, order_number);

-- POS order items
CREATE TABLE IF NOT EXISTS pos_order_item (
    id TEXT PRIMARY KEY,
    order_id TEXT NOT NULL,
    menu_item_id TEXT NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1,
    unit_price REAL NOT NULL DEFAULT 0,
    total_price REAL NOT NULL DEFAULT 0,
    notes TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING',  -- PENDING, PREPARING, READY, SERVED, CANCELLED
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (order_id) REFERENCES pos_order(id) ON DELETE CASCADE,
    FOREIGN KEY (menu_item_id) REFERENCES menu_item(id)
);
CREATE INDEX IF NOT EXISTS idx_orderitem_order ON pos_order_item(order_id);

-- Folios (guest billing)
CREATE TABLE IF NOT EXISTS folio (
    id TEXT PRIMARY KEY,
    property_id TEXT NOT NULL,
    reservation_id TEXT,
    guest_id TEXT NOT NULL,
    folio_number TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN',  -- OPEN, CLOSED, SETTLED
    total_charges REAL NOT NULL DEFAULT 0,
    total_payments REAL NOT NULL DEFAULT 0,
    balance REAL NOT NULL DEFAULT 0,
    currency TEXT DEFAULT 'INR',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    closed_at TEXT,
    server_updated_at TEXT,
    local_updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (property_id) REFERENCES property(id),
    FOREIGN KEY (reservation_id) REFERENCES reservation(id),
    FOREIGN KEY (guest_id) REFERENCES guest(id)
);
CREATE INDEX IF NOT EXISTS idx_folio_property ON folio(property_id, status);
CREATE INDEX IF NOT EXISTS idx_folio_guest ON folio(guest_id);

-- Folio charges
CREATE TABLE IF NOT EXISTS folio_charge (
    id TEXT PRIMARY KEY,
    folio_id TEXT NOT NULL,
    description TEXT NOT NULL,
    amount REAL NOT NULL DEFAULT 0,
    tax_rate REAL NOT NULL DEFAULT 0,
    tax_amount REAL NOT NULL DEFAULT 0,
    total_amount REAL NOT NULL DEFAULT 0,
    category TEXT,  -- ROOM, FNB, LAUNDRY, TRANSPORT, MISC
    posted_by TEXT,
    posted_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (folio_id) REFERENCES folio(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_charge_folio ON folio_charge(folio_id);

-- Folio payments
CREATE TABLE IF NOT EXISTS folio_payment (
    id TEXT PRIMARY KEY,
    folio_id TEXT NOT NULL,
    amount REAL NOT NULL DEFAULT 0,
    method TEXT NOT NULL,  -- CASH, CARD, UPI, BANK_TRANSFER, etc.
    reference TEXT,
    received_by TEXT,
    received_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (folio_id) REFERENCES folio(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_payment_folio ON folio_payment(folio_id);
"#;

// ─── Migration 006: Housekeeping ───

const MIGRATION_006_HOUSEKEEPING: &str = r#"
-- Housekeeping tasks
CREATE TABLE IF NOT EXISTS housekeeping_task (
    id TEXT PRIMARY KEY,
    property_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    task_type TEXT NOT NULL DEFAULT 'CLEANING',  -- CLEANING, INSPECTION, MAINTENANCE, DEEP_CLEAN
    status TEXT NOT NULL DEFAULT 'PENDING',  -- PENDING, IN_PROGRESS, COMPLETED, SKIPPED
    assigned_to TEXT,  -- user id
    priority TEXT NOT NULL DEFAULT 'NORMAL',  -- LOW, NORMAL, HIGH, URGENT
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at TEXT,
    server_updated_at TEXT,
    local_updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (property_id) REFERENCES property(id),
    FOREIGN KEY (room_id) REFERENCES room(id)
);
CREATE INDEX IF NOT EXISTS idx_hk_property ON housekeeping_task(property_id, status);
CREATE INDEX IF NOT EXISTS idx_hk_room ON housekeeping_task(room_id);
CREATE INDEX IF NOT EXISTS idx_hk_assigned ON housekeeping_task(assigned_to, status);

-- Lost & found items
CREATE TABLE IF NOT EXISTS lost_found_item (
    id TEXT PRIMARY KEY,
    property_id TEXT NOT NULL,
    description TEXT NOT NULL,
    found_location TEXT,
    found_date TEXT NOT NULL,
    found_by TEXT,  -- user id
    status TEXT NOT NULL DEFAULT 'STORED',  -- STORED, CLAIMED, DISPOSED, RETURNED
    photo_path TEXT,  -- local path
    claimed_by TEXT,
    claimed_date TEXT,
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    server_updated_at TEXT,
    local_updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (property_id) REFERENCES property(id)
);
CREATE INDEX IF NOT EXISTS idx_lf_property ON lost_found_item(property_id, status);

-- Employees (staff)
CREATE TABLE IF NOT EXISTS employee (
    id TEXT PRIMARY KEY,
    property_id TEXT NOT NULL,
    name TEXT NOT NULL,
    email TEXT,
    phone TEXT,
    role TEXT,
    department TEXT,
    photo_path TEXT,  -- local path
    is_active INTEGER NOT NULL DEFAULT 1,
    join_date TEXT,
    server_updated_at TEXT,
    local_updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (property_id) REFERENCES property(id)
);
CREATE INDEX IF NOT EXISTS idx_emp_property ON employee(property_id, is_active);
"#;

// ─── Migration 007: Sync entity store + outbox additions ───

const MIGRATION_007_SYNC_ENTITY: &str = r#"
-- Generic entity store for pulled remote changes
CREATE TABLE IF NOT EXISTS sync_entity (
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    payload TEXT NOT NULL,          -- full entity JSON
    server_updated_at TEXT,
    local_updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (entity_type, entity_id)
);
CREATE INDEX IF NOT EXISTS idx_sync_entity_type ON sync_entity(entity_type);

-- Add last_error column to sync_outbox for error tracking
ALTER TABLE sync_outbox ADD COLUMN last_error TEXT;
"#;

// ─── Migration 008: Device heartbeat tracking ───

const MIGRATION_008_DEVICE_HEARTBEAT: &str = r#"
-- Local device heartbeat state (mirrors what we send to the cloud)
CREATE TABLE IF NOT EXISTS device_heartbeat (
    device_id TEXT PRIMARY KEY,
    user_id TEXT,
    user_name TEXT,
    role TEXT,
    property_id TEXT,
    app_version TEXT,
    platform TEXT,
    is_online INTEGER NOT NULL DEFAULT 0,
    sync_status TEXT NOT NULL DEFAULT 'SYNCED',
    pending_count INTEGER NOT NULL DEFAULT 0,
    failed_count INTEGER NOT NULL DEFAULT 0,
    conflict_count INTEGER NOT NULL DEFAULT 0,
    last_local_write_at TEXT,
    last_push_at TEXT,
    last_pull_at TEXT,
    last_heartbeat_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Ensure the device table has a stable row we can reference
INSERT OR IGNORE INTO device (id, name) VALUES ('local', 'This Desktop');
"#;
