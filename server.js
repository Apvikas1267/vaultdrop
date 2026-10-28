require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');

const { db, UPLOADS_DIR } = require('./db');
const { authenticate, JWT_SECRET } = require('./middleware/auth');

const app = express();
const PORT = process.env.PORT || 3000;

// Security Headers Middleware
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// Parsers & Helpers
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Static Files
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// Disallowed executable extensions & scripts
const DISALLOWED_EXTENSIONS = new Set([
  '.exe', '.bat', '.sh', '.msi', '.scr', '.cmd', '.vbs',
  '.ps1', '.com', '.jar', '.apk', '.app', '.dll', '.pif',
  '.reg', '.wsf', '.cpl', '.hta'
]);

function isExtensionBlocked(filename) {
  if (!filename) return false;
  // Strip null bytes and normalize
  const clean = filename.replace(/\0/g, '').trim().toLowerCase();
  
  // 1. Direct extension check
  const ext = path.extname(clean);
  if (DISALLOWED_EXTENSIONS.has(ext)) return true;

  // 2. Double extension mitigation (e.g. file.exe.pdf, script.bat.txt)
  const segments = clean.split('.');
  for (let i = 1; i < segments.length; i++) {
    if (DISALLOWED_EXTENSIONS.has('.' + segments[i])) {
      return true;
    }
  }

  // 3. Trailing dot or space spoofing
  if (clean.endsWith('.') || clean.endsWith(' ')) {
    return true;
  }

  return false;
}

// Multer Storage Configuration (Store locally in ./uploads)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOADS_DIR);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = uuidv4() + '-' + Date.now() + '.enc';
    cb(null, uniqueSuffix);
  }
});

// Multer upload handler (Max 10MB per file)
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB strict limit
  },
  fileFilter: (req, file, cb) => {
    const originalName = req.body.original_name || file.originalname || '';
    if (isExtensionBlocked(originalName) || isExtensionBlocked(file.originalname)) {
      return cb(new Error('Executable and potentially malicious file extensions (.exe, .bat, .sh, etc.) are strictly prohibited.'));
    }
    cb(null, true);
  }
});

// Helper: Calculate expiration ISO timestamp
function calculateExpiry(expiryOption) {
  const now = Date.now();
  let ms;
  switch (expiryOption) {
    case '1h':
      ms = 1 * 60 * 60 * 1000;
      break;
    case '6h':
      ms = 6 * 60 * 60 * 1000;
      break;
    case '24h':
      ms = 24 * 60 * 60 * 1000;
      break;
    case '7d':
      ms = 7 * 24 * 60 * 60 * 1000;
      break;
    default:
      ms = 24 * 60 * 60 * 1000; // default 24h
  }
  return new Date(now + ms).toISOString();
}

// ==========================================
// HTML PAGE ROUTES
// ==========================================

// Landing Page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Dashboard Page (Protected)
app.get('/dashboard', authenticate, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Shareable download page (Serves share.html so URL hash #key=... is retained in browser)
app.get('/share/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'share.html'));
});

// Direct share.html access
app.get('/share', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'share.html'));
});

// Admin Live Database Viewer Page
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ==========================================
// AUTHENTICATION API ROUTES
// ==========================================

// Sign Up
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const cleanEmail = email.toLowerCase().trim();
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
    }

    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(cleanEmail);
    if (existing) {
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();
    const storageLimit = 50 * 1024 * 1024; // 50MB

    db.prepare(`
      INSERT INTO users (id, email, password, storage_used, storage_limit)
      VALUES (?, ?, ?, 0, ?)
    `).run(userId, cleanEmail, hashedPassword, storageLimit);

    console.log(`[AUTH] 👤 New user registered: ${cleanEmail}`);

    const token = jwt.sign({ id: userId, email: cleanEmail }, JWT_SECRET, { expiresIn: '7d' });

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.status(201).json({
      message: 'Account created successfully.',
      user: {
        id: userId,
        email: cleanEmail,
        storage_used: 0,
        storage_limit: storageLimit
      }
    });
  } catch (err) {
    console.error('Signup error:', err);
    return res.status(500).json({ error: 'Internal server error during registration.' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const cleanEmail = email.toLowerCase().trim();
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(cleanEmail);

    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.json({
      message: 'Logged in successfully.',
      user: {
        id: user.id,
        email: user.email,
        storage_used: user.storage_used,
        storage_limit: user.storage_limit
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Internal server error during login.' });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  return res.json({ message: 'Logged out successfully.' });
});

// Current User Profile
app.get('/api/auth/me', authenticate, (req, res) => {
  return res.json({
    user: {
      id: req.user.id,
      email: req.user.email,
      storage_used: req.user.storage_used,
      storage_limit: req.user.storage_limit,
      created_at: req.user.created_at
    }
  });
});

// ==========================================
// FILE MANAGEMENT & UPLOAD API ROUTES
// ==========================================

// Upload Encrypted File
app.post('/api/upload', authenticate, upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No encrypted payload uploaded.' });
    }

    const originalName = (req.body.original_name || 'unnamed-file').trim();
    const mimeType = (req.body.mime_type || 'application/octet-stream').trim();
    const expiry = req.body.expiry || '24h';
    const fileSize = req.file.size;

    // Check disallowed extensions again
    if (isExtensionBlocked(originalName)) {
      // Remove uploaded file from disk immediately
      try { fs.unlinkSync(req.file.path); } catch (e) {}
      return res.status(400).json({
        error: 'Security violation: Disallowed executable file extension detected.'
      });
    }

    // Storage Quota Enforcement
    // Check user's current storage_used + file_size <= 50MB
    const currentUser = db.prepare('SELECT storage_used, storage_limit FROM users WHERE id = ?').get(req.user.id);
    if (!currentUser) {
      try { fs.unlinkSync(req.file.path); } catch (e) {}
      return res.status(404).json({ error: 'User not found.' });
    }

    const availableSpace = currentUser.storage_limit - currentUser.storage_used;
    if (fileSize > availableSpace) {
      // Delete temporary uploaded payload
      try { fs.unlinkSync(req.file.path); } catch (e) {}
      const usedMb = (currentUser.storage_used / (1024 * 1024)).toFixed(1);
      const limitMb = (currentUser.storage_limit / (1024 * 1024)).toFixed(0);
      const neededMb = (fileSize / (1024 * 1024)).toFixed(1);
      return res.status(400).json({
        error: `Storage quota exceeded. You have used ${usedMb} MB of ${limitMb} MB limit. File requires ${neededMb} MB.`
      });
    }

    const fileId = uuidv4();
    const expiresAt = calculateExpiry(expiry);
    const storedFilename = req.file.filename;

    // Insert file and update user storage_used in a transaction
    const insertTransaction = db.transaction(() => {
      db.prepare(`
        INSERT INTO files (id, owner_id, original_name, stored_filename, mime_type, file_size, download_count, expires_at, is_revoked)
        VALUES (?, ?, ?, ?, ?, ?, 0, ?, 0)
      `).run(fileId, req.user.id, originalName, storedFilename, mimeType, fileSize, expiresAt);

      db.prepare(`
        UPDATE users
        SET storage_used = storage_used + ?
        WHERE id = ?
      `).run(fileSize, req.user.id);
    });

    insertTransaction();

    console.log(`[FILE] 📤 Encrypted upload: "${originalName}" (${(fileSize / (1024 * 1024)).toFixed(2)} MB) by ${req.user.email}`);

    return res.status(201).json({
      message: 'Encrypted payload secured successfully.',
      file: {
        id: fileId,
        original_name: originalName,
        mime_type: mimeType,
        file_size: fileSize,
        expires_at: expiresAt,
        download_count: 0,
        is_revoked: 0
      }
    });
  } catch (err) {
    if (req.file && req.file.path) {
      try { fs.unlinkSync(req.file.path); } catch (e) {}
    }
    console.error('Upload error:', err);
    return res.status(500).json({ error: err.message || 'Error saving file payload.' });
  }
});

// List User's Uploaded Files
app.get('/api/files', authenticate, (req, res) => {
  try {
    const files = db.prepare(`
      SELECT id, original_name, mime_type, file_size, download_count, expires_at, is_revoked, created_at
      FROM files
      WHERE owner_id = ?
      ORDER BY created_at DESC
    `).all(req.user.id);

    return res.json({ files });
  } catch (err) {
    console.error('Fetch files error:', err);
    return res.status(500).json({ error: 'Failed to retrieve files.' });
  }
});

// Revoke or Unrevoke File Access
app.post('/api/files/:id/revoke', authenticate, (req, res) => {
  try {
    const file = db.prepare('SELECT id, is_revoked FROM files WHERE id = ? AND owner_id = ?').get(req.params.id, req.user.id);
    if (!file) {
      return res.status(404).json({ error: 'File not found or unauthorized.' });
    }

    const newRevokedState = file.is_revoked === 1 ? 0 : 1;
    db.prepare('UPDATE files SET is_revoked = ? WHERE id = ?').run(newRevokedState, req.params.id);

    return res.json({
      message: newRevokedState === 1 ? 'Link access revoked.' : 'Link access restored.',
      is_revoked: newRevokedState
    });
  } catch (err) {
    console.error('Revoke toggle error:', err);
    return res.status(500).json({ error: 'Failed to toggle revocation state.' });
  }
});

// Delete File
app.delete('/api/files/:id', authenticate, (req, res) => {
  try {
    const file = db.prepare('SELECT id, stored_filename, file_size FROM files WHERE id = ? AND owner_id = ?').get(req.params.id, req.user.id);
    if (!file) {
      return res.status(404).json({ error: 'File not found or unauthorized.' });
    }

    // Delete record and deduct storage from user
    const deleteTransaction = db.transaction(() => {
      db.prepare('DELETE FROM files WHERE id = ?').run(req.params.id);
      db.prepare(`
        UPDATE users
        SET storage_used = MAX(0, storage_used - ?)
        WHERE id = ?
      `).run(file.file_size, req.user.id);
    });

    deleteTransaction();

    // Remove file from disk
    const filePath = path.join(UPLOADS_DIR, file.stored_filename);
    if (fs.existsSync(filePath)) {
      try {
        fs.unlinkSync(filePath);
      } catch (err) {
        console.error('Could not delete disk file:', err);
      }
    }

    return res.json({ message: 'File deleted and quota updated.' });
  } catch (err) {
    console.error('Delete file error:', err);
    return res.status(500).json({ error: 'Failed to delete file.' });
  }
});

// ==========================================
// PUBLIC SHARING & DECRYPTION API ROUTES
// ==========================================

// Get File Public Metadata (for share page validation)
app.get('/api/share/:id/meta', (req, res) => {
  try {
    const file = db.prepare(`
      SELECT id, original_name, mime_type, file_size, download_count, expires_at, is_revoked, created_at
      FROM files
      WHERE id = ?
    `).get(req.params.id);

    if (!file) {
      return res.status(404).json({
        error: 'File Not Found',
        code: 'NOT_FOUND',
        message: 'The requested file does not exist or may have been permanently removed.'
      });
    }

    // Check revocation
    if (file.is_revoked === 1) {
      return res.status(403).json({
        error: 'Access Revoked',
        code: 'REVOKED',
        message: 'The owner has revoked public access to this document.'
      });
    }

    // Check expiry
    const now = new Date();
    const expiry = new Date(file.expires_at);
    if (now > expiry) {
      return res.status(410).json({
        error: 'Link Expired',
        code: 'EXPIRED',
        expires_at: file.expires_at,
        message: 'This secure sharing link has expired and is no longer accessible.'
      });
    }

    return res.json({
      id: file.id,
      original_name: file.original_name,
      mime_type: file.mime_type,
      file_size: file.file_size,
      download_count: file.download_count,
      expires_at: file.expires_at,
      created_at: file.created_at
    });
  } catch (err) {
    console.error('Meta fetch error:', err);
    return res.status(500).json({ error: 'Error inspecting file metadata.' });
  }
});

// Download Encrypted File Payload
app.get('/api/share/:id/download', (req, res) => {
  try {
    const file = db.prepare(`
      SELECT id, original_name, stored_filename, file_size, expires_at, is_revoked
      FROM files
      WHERE id = ?
    `).get(req.params.id);

    if (!file) {
      return res.status(404).json({ error: 'File Not Found', code: 'NOT_FOUND' });
    }

    if (file.is_revoked === 1) {
      return res.status(403).json({ error: 'Link Revoked', code: 'REVOKED' });
    }

    const now = new Date();
    if (now > new Date(file.expires_at)) {
      return res.status(410).json({ error: 'Link Expired', code: 'EXPIRED' });
    }

    const filePath = path.join(UPLOADS_DIR, file.stored_filename);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Payload missing on disk.', code: 'NOT_FOUND' });
    }

    // Increment download count
    db.prepare('UPDATE files SET download_count = download_count + 1 WHERE id = ?').run(file.id);

    console.log(`[FILE] 📥 File payload downloaded: "${file.original_name}" (Total downloads: ${file.download_count + 1})`);

    // Enforce strict security headers
    res.setHeader('Content-Disposition', 'attachment; filename="vault_payload.bin"');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');

    const fileStream = fs.createReadStream(filePath);
    fileStream.pipe(res);
  } catch (err) {
    console.error('Download stream error:', err);
    return res.status(500).json({ error: 'Error streaming encrypted file.' });
  }
});

// ==========================================
// ADMIN DATABASE INSPECTOR API
// ==========================================

const ADMIN_KEY = process.env.ADMIN_KEY || 'vaultadmin2026';

app.post('/api/admin/db', (req, res) => {
  try {
    const providedKey = req.headers['x-admin-key'] || req.body.admin_key;
    if (!providedKey || providedKey !== ADMIN_KEY) {
      return res.status(401).json({ error: 'Unauthorized: Invalid Admin Key' });
    }

    const users = db.prepare(`
      SELECT id, email, storage_used, storage_limit, created_at
      FROM users
      ORDER BY created_at DESC
    `).all();

    const files = db.prepare(`
      SELECT f.id, f.original_name, u.email AS owner_email, f.file_size, f.download_count, f.expires_at, f.is_revoked, f.created_at
      FROM files f
      LEFT JOIN users u ON f.owner_id = u.id
      ORDER BY f.created_at DESC
    `).all();

    return res.json({ users, files });
  } catch (err) {
    console.error('Admin DB fetch error:', err);
    return res.status(500).json({ error: 'Failed to query database.' });
  }
});

// ==========================================
// ERROR HANDLING MIDDLEWARE
// ==========================================

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File exceeds maximum allowed size of 10 MB.' });
    }
    return res.status(400).json({ error: `Upload error: ${err.message}` });
  }
  if (err) {
    return res.status(400).json({ error: err.message || 'An unexpected error occurred.' });
  }
  next();
});

// 404 handler for unknown routes
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found.' });
});

// Start Server
app.listen(PORT, () => {
  console.log(`===============================================`);
  console.log(`🔒 VaultDrop Service running on port ${PORT}`);
  console.log(`🌐 Local URL: http://localhost:${PORT}`);
  console.log(`===============================================`);
});
