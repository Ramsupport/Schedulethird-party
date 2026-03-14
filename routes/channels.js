const express  = require('express');
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

// GET /api/channels
router.get('/', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM channels ORDER BY id');
    res.json(rows);
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// POST /api/channels  (admin only)
router.post('/', requireAdmin, async (req, res) => {
  const { name, description, icon } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  try {
    const { rows } = await pool.query(
      'INSERT INTO channels (name,description,icon,created_by) VALUES ($1,$2,$3,$4) RETURNING *',
      [name.toLowerCase().replace(/\s+/g,'-'), description||'', icon||'💬', req.session.user.id]
    );
    res.json(rows[0]);
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// GET /api/channels/:id/messages
router.get('/:id/messages', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM messages WHERE channel_id=$1 ORDER BY created_at ASC LIMIT 200',
      [req.params.id]
    );
    res.json(rows);
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// POST /api/channels/:id/messages
router.post('/:id/messages', requireAuth, async (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: 'Text required' });
  const user = req.session.user;
  try {
    const { rows } = await pool.query(
      'INSERT INTO messages (channel_id,author_id,author_name,text) VALUES ($1,$2,$3,$4) RETURNING *',
      [req.params.id, user.id, user.name, text]
    );
    const msg = rows[0];
    const io  = req.app.get('io');
    if (io) io.to(`channel_${req.params.id}`).emit('new_message', { ...msg, author_color: user.color });
    res.json(msg);
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// DELETE /api/channels/messages/:id
router.delete('/messages/:id', requireAuth, async (req, res) => {
  const user = req.session.user;
  try {
    const { rows } = await pool.query('SELECT * FROM messages WHERE id=$1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Message not found' });
    if (user.role !== 'admin' && rows[0].author_id !== user.id)
      return res.status(403).json({ error: 'You can only delete your own messages' });
    await pool.query('DELETE FROM messages WHERE id=$1', [req.params.id]);
    // Notify all users in that channel
    const io = req.app.get('io');
    if (io) io.to(`channel_${rows[0].channel_id}`).emit('message_deleted', {
      message_id: parseInt(req.params.id),
      channel_id: rows[0].channel_id
    });
    res.json({ ok: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
