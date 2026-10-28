const jwt = require('jsonwebtoken');
const { db } = require('../db');

const JWT_SECRET = process.env.JWT_SECRET || 'vaultdrop-default-jwt-secret-key-2026-production';

function authenticate(req, res, next) {
  const token = req.cookies.token || (req.headers.authorization && req.headers.authorization.split(' ')[1]);

  if (!token) {
    if (req.originalUrl.startsWith('/api/')) {
      return res.status(401).json({ error: 'Unauthorized: Authentication required.' });
    }
    return res.redirect('/?redirect=' + encodeURIComponent(req.originalUrl));
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = db.prepare('SELECT id, email, storage_used, storage_limit, created_at FROM users WHERE id = ?').get(decoded.id);

    if (!user) {
      res.clearCookie('token');
      if (req.originalUrl.startsWith('/api/')) {
        return res.status(401).json({ error: 'User account not found.' });
      }
      return res.redirect('/');
    }

    req.user = user;
    next();
  } catch (err) {
    res.clearCookie('token');
    if (req.originalUrl.startsWith('/api/')) {
      return res.status(401).json({ error: 'Invalid or expired session. Please log in again.' });
    }
    return res.redirect('/');
  }
}

module.exports = {
  authenticate,
  JWT_SECRET
};
