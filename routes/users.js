const express  = require('express');
const bcrypt   = require('bcryptjs');
const { pool } = require('../db');
const router   = express.Router();

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin')
    return res.status(403).json({ error: 'Admin only' });
  next();
}

const COLORS = ['#00d4aa','#7c5cfc','#f5c842','#ff6b6b','#45b7d1','#4ecdc4','#ff9a3c','#a8e063'];

// GET /api/users
router.get('/', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id,username,name,role,color,created_at FROM users ORDER BY id');
    res.json(rows);
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// POST /api/users  (admin only)
router.post('/', requireAdmin, async (req, res) => {
  const { username, name, password, role } = req.body;
  if (!username || !name || !password) return res.status(400).json({ error: 'All fields required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  try {
    const hash  = await bcrypt.hash(password, 10);
    const color = COLORS[Math.floor(Math.random() * COLORS.length)];
    const { rows } = await pool.query(
      'INSERT INTO users (username,name,password_hash,role,color) VALUES ($1,$2,$3,$4,$5) RETURNING id,username,name,role,color',
      [username, name, hash, role || 'agent', color]
    );
    res.json(rows[0]);
  } catch(err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Username already exists' });
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/users/:id  (admin only)
router.delete('/:id', requireAdmin, async (req, res) => {
  if (parseInt(req.params.id) === req.session.user.id)
    return res.status(400).json({ error: 'Cannot delete yourself' });
  try {
    await pool.query('DELETE FROM users WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
