/**
 * VaultDrop Database Viewer Utility
 * Run with: node view_db.js
 */

const { db } = require('./db');

console.log('\n================================================================');
console.log('📊 VAULTDROP LIVE DATABASE INSPECTOR');
console.log('================================================================\n');

// 1. Fetch all users
const users = db.prepare(`
  SELECT 
    id, 
    email, 
    ROUND(storage_used / (1024.0 * 1024.0), 2) || ' MB' AS storage_used, 
    ROUND(storage_limit / (1024.0 * 1024.0), 0) || ' MB' AS storage_limit,
    created_at
  FROM users
  ORDER BY created_at DESC
`).all();

console.log(`👤 REGISTERED USERS (${users.length} total):`);
if (users.length === 0) {
  console.log('   (No registered users found yet.)\n');
} else {
  console.table(users);
  console.log('');
}

// 2. Fetch all files with owner email
const files = db.prepare(`
  SELECT 
    f.id,
    f.original_name,
    u.email AS owner_email,
    ROUND(f.file_size / (1024.0 * 1024.0), 2) || ' MB' AS size,
    f.download_count AS downloads,
    CASE 
      WHEN f.is_revoked = 1 THEN 'REVOKED'
      WHEN datetime('now') > datetime(f.expires_at) THEN 'EXPIRED'
      ELSE 'ACTIVE'
    END AS status,
    f.expires_at,
    f.created_at
  FROM files f
  LEFT JOIN users u ON f.owner_id = u.id
  ORDER BY f.created_at DESC
`).all();

console.log(`📁 UPLOADED DOCUMENTS (${files.length} total):`);
if (files.length === 0) {
  console.log('   (No uploaded documents found yet.)\n');
} else {
  console.table(files);
  console.log('');
}

console.log('🔒 Zero-Knowledge Security Notice:');
console.log('   - Passwords are one-way hashed with bcrypt (never readable in plaintext).');
console.log('   - File payloads on disk are AES-256 encrypted ciphertext (the server never has the decryption key).\n');
console.log('================================================================\n');
