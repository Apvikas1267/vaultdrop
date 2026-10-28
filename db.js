const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

// Ensure data and uploads directory exist
const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'uploads');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

const dbPath = path.join(DATA_DIR, 'vault.db');
const db = new Database(dbPath);

// Enable WAL mode for high performance and concurrency
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Initialize database schema
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    storage_used INTEGER DEFAULT 0,
    storage_limit INTEGER DEFAULT 52428800, -- 50 MB in bytes
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    original_name TEXT NOT NULL,
    stored_filename TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    download_count INTEGER DEFAULT 0,
    expires_at DATETIME NOT NULL,
    is_revoked INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id);
  CREATE INDEX IF NOT EXISTS idx_files_expires ON files(expires_at);
  CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
`);

console.log('✅ SQLite database initialized at:', dbPath);

module.exports = {
  db,
  DATA_DIR,
  UPLOADS_DIR
};
