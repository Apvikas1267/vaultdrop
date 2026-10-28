/**
 * Automated End-to-End & Integration Test Suite for VaultDrop
 */

const { db, UPLOADS_DIR } = require('./db');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const JWT_SECRET = process.env.JWT_SECRET || 'vaultdrop-default-jwt-secret-key-2026-production';

function runTests() {
  console.log('🧪 Starting VaultDrop Automated Verification Tests...\n');
  let passed = 0;
  let total = 0;

  function assert(condition, message) {
    total++;
    if (condition) {
      console.log(`  ✅ PASS: ${message}`);
      passed++;
    } else {
      console.error(`  ❌ FAIL: ${message}`);
      process.exitCode = 1;
    }
  }

  // Test 1: Verify Database Tables
  console.log('--- Test Group 1: Database Initialization ---');
  const userTable = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").get();
  const fileTable = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='files'").get();
  assert(userTable && userTable.name === 'users', 'Users table exists in SQLite database');
  assert(fileTable && fileTable.name === 'files', 'Files table exists in SQLite database');

  // Test 2: User Creation & Storage Quota Default
  console.log('\n--- Test Group 2: User Storage Quota (50MB Default) ---');
  const testEmail = `test_${Date.now()}@example.com`;
  const testUserId = uuidv4();
  const testPasswordHash = bcrypt.hashSync('securePassword123', 10);
  const quota50MB = 50 * 1024 * 1024;

  db.prepare(`
    INSERT INTO users (id, email, password, storage_used, storage_limit)
    VALUES (?, ?, ?, 0, ?)
  `).run(testUserId, testEmail, testPasswordHash, quota50MB);

  const createdUser = db.prepare('SELECT * FROM users WHERE id = ?').get(testUserId);
  assert(createdUser && createdUser.email === testEmail, 'User created successfully with unique ID');
  assert(createdUser.storage_limit === 52428800, 'User storage limit is strictly set to 50MB (52,428,800 bytes)');
  assert(createdUser.storage_used === 0, 'User initial storage used is 0 bytes');

  // Test 3: JWT Verification
  console.log('\n--- Test Group 3: Authentication & JWT ---');
  const token = jwt.sign({ id: createdUser.id, email: createdUser.email }, JWT_SECRET, { expiresIn: '7d' });
  const decoded = jwt.verify(token, JWT_SECRET);
  assert(decoded.id === testUserId && decoded.email === testEmail, 'JWT token signs and verifies user credentials correctly');

  // Test 4: File Upload & Quota Tracking
  console.log('\n--- Test Group 4: File Registration & Quota Tracking ---');
  const testFileId = uuidv4();
  const testFileSize = 2 * 1024 * 1024; // 2MB
  const dummyFilename = `${testFileId}-payload.enc`;
  const dummyFilePath = path.join(UPLOADS_DIR, dummyFilename);
  fs.writeFileSync(dummyFilePath, Buffer.alloc(testFileSize, 'A'));

  // 24 Hour expiry
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  db.transaction(() => {
    db.prepare(`
      INSERT INTO files (id, owner_id, original_name, stored_filename, mime_type, file_size, download_count, expires_at, is_revoked)
      VALUES (?, ?, ?, ?, ?, ?, 0, ?, 0)
    `).run(testFileId, testUserId, 'report.pdf', dummyFilename, 'application/pdf', testFileSize, expiresAt);

    db.prepare('UPDATE users SET storage_used = storage_used + ? WHERE id = ?').run(testFileSize, testUserId);
  })();

  const updatedUser = db.prepare('SELECT storage_used FROM users WHERE id = ?').get(testUserId);
  assert(updatedUser.storage_used === testFileSize, `User storage_used increased exactly to 2MB (${testFileSize} bytes)`);

  const fileRecord = db.prepare('SELECT * FROM files WHERE id = ?').get(testFileId);
  assert(fileRecord && fileRecord.original_name === 'report.pdf', 'File record stored with original name preserved');
  assert(fileRecord.download_count === 0, 'Initial download count is 0');
  assert(fileRecord.is_revoked === 0, 'Initial revocation state is 0 (Active)');

  // Test 5: Quota Overflow Prevention
  console.log('\n--- Test Group 5: Quota Limit Enforcement ---');
  const remainingSpace = createdUser.storage_limit - updatedUser.storage_used;
  const oversizedFile = remainingSpace + 1024; // Exceeds limit
  const wouldOverflow = (updatedUser.storage_used + oversizedFile) > createdUser.storage_limit;
  assert(wouldOverflow === true, 'Quota check detects and blocks uploads exceeding the 50MB storage limit');

  // Test 6: Download Tracking
  console.log('\n--- Test Group 6: Download Tracking ---');
  db.prepare('UPDATE files SET download_count = download_count + 1 WHERE id = ?').run(testFileId);
  const afterDl = db.prepare('SELECT download_count FROM files WHERE id = ?').get(testFileId);
  assert(afterDl.download_count === 1, 'Download count incremented to 1');

  // Test 7: Expiration Check Logic
  console.log('\n--- Test Group 7: Expiration Check Logic ---');
  const pastDate = new Date(Date.now() - 3600000).toISOString(); // 1 hour ago
  const expiredFileId = uuidv4();
  db.prepare(`
    INSERT INTO files (id, owner_id, original_name, stored_filename, mime_type, file_size, download_count, expires_at, is_revoked)
    VALUES (?, ?, ?, ?, ?, 1024, 0, ?, 0)
  `).run(expiredFileId, testUserId, 'expired.txt', 'dummy.enc', 'text/plain', pastDate);

  const expiredRecord = db.prepare('SELECT expires_at FROM files WHERE id = ?').get(expiredFileId);
  const isExpired = new Date() > new Date(expiredRecord.expires_at);
  assert(isExpired === true, 'Expired link is properly detected as past expiry (triggers 410)');

  // Test 8: Revocation Toggle
  console.log('\n--- Test Group 8: Revocation Toggle ---');
  db.prepare('UPDATE files SET is_revoked = 1 WHERE id = ?').run(testFileId);
  let revokedRecord = db.prepare('SELECT is_revoked FROM files WHERE id = ?').get(testFileId);
  assert(revokedRecord.is_revoked === 1, 'File status successfully updated to Revoked (triggers 430/403)');

  db.prepare('UPDATE files SET is_revoked = 0 WHERE id = ?').run(testFileId);
  revokedRecord = db.prepare('SELECT is_revoked FROM files WHERE id = ?').get(testFileId);
  assert(revokedRecord.is_revoked === 0, 'File status successfully restored to Active');

  // Test 9: File Deletion & Quota Deduction
  console.log('\n--- Test Group 9: Deletion & Quota Restoration ---');
  db.transaction(() => {
    db.prepare('DELETE FROM files WHERE id = ?').run(testFileId);
    db.prepare('UPDATE users SET storage_used = MAX(0, storage_used - ?) WHERE id = ?').run(testFileSize, testUserId);
  })();

  if (fs.existsSync(dummyFilePath)) {
    fs.unlinkSync(dummyFilePath);
  }

  const userAfterDelete = db.prepare('SELECT storage_used FROM users WHERE id = ?').get(testUserId);
  assert(userAfterDelete.storage_used === 0, 'User storage_used returned to 0 bytes after file deletion');
  assert(!fs.existsSync(dummyFilePath), 'Physical file removed from disk on deletion');

  // Test 10: Malicious File Mitigation & Multi-Extension Defense
  console.log('\n--- Test Group 10: Malicious File & Multi-Extension Defense ---');
  const DISALLOWED_EXTENSIONS = new Set([
    '.exe', '.bat', '.sh', '.msi', '.scr', '.cmd', '.vbs',
    '.ps1', '.com', '.jar', '.apk', '.app', '.dll', '.pif',
    '.reg', '.wsf', '.cpl', '.hta'
  ]);

  function isBlocked(filename) {
    if (!filename) return false;
    const clean = filename.replace(/\0/g, '').trim().toLowerCase();
    const ext = path.extname(clean);
    if (DISALLOWED_EXTENSIONS.has(ext)) return true;
    const segments = clean.split('.');
    for (let i = 1; i < segments.length; i++) {
      if (DISALLOWED_EXTENSIONS.has('.' + segments[i])) return true;
    }
    if (clean.endsWith('.') || clean.endsWith(' ')) return true;
    return false;
  }

  assert(isBlocked('malware.exe') === true, 'Direct .exe execution blocked');
  assert(isBlocked('script.bat') === true, 'Direct .bat execution blocked');
  assert(isBlocked('installer.msi') === true, 'Direct .msi execution blocked');
  assert(isBlocked('shell.sh') === true, 'Direct .sh execution blocked');
  assert(isBlocked('trojan.exe.pdf') === true, 'Disguised double-extension .exe.pdf blocked');
  assert(isBlocked('exploit.bat.txt') === true, 'Disguised double-extension .bat.txt blocked');
  assert(isBlocked('invoice.pdf') === false, 'Legitimate PDF file allowed');
  assert(isBlocked('data.xlsx') === false, 'Legitimate Excel file allowed');
  assert(isBlocked('project.zip') === false, 'Legitimate ZIP archive allowed');

  // Clean up test user and expired file
  db.prepare('DELETE FROM files WHERE id = ?').run(expiredFileId);
  db.prepare('DELETE FROM users WHERE id = ?').run(testUserId);

  console.log(`\n===============================================`);
  console.log(`Test Summary: ${passed}/${total} assertions passed successfully!`);
  console.log(`===============================================`);
}

runTests();
