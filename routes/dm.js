const express  = require('express');
const { pool } = require('../db');
const router   = express.Router();

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  next();
}

function dmKey(a, b) { return [a, b].sort((x,y) => x-y).join(':'); }

// GET /api/dm/conversations
router.get('/conversations', requireAuth, async (req, res) => {
  const user = req.session.user;
  try {
    let userIds;
    if (user.role === 'admin') {
      // Admin sees all agents
      const { rows } = await pool.query(`SELECT id FROM users WHERE role='agent' ORDER BY name`);
      userIds = rows.map(r => r.id);
    } else {
      // Agent sees only admin
      const { rows } = await pool.query(`SELECT id FROM users WHERE role='admin' LIMIT 1`);
      userIds = rows.map(r => r.id);
    }

    const conversations = await Promise.all(userIds.map(async (otherId) => {
      const key = dmKey(user.id, otherId);
      const [userRow, lastMsg, unread] = await Promise.all([
        pool.query('SELECT id,name,role,color FROM users WHERE id=$1', [otherId]),
        pool.query(`SELECT text FROM direct_messages WHERE dm_key=$1 ORDER BY created_at DESC LIMIT 1`, [key]),
        pool.query(`SELECT COUNT(*) FROM direct_messages WHERE dm_key=$1 AND receiver_id=$2 AND is_read=false`, [key, user.id]),
      ]);
      if (!userRow.rows.length) return null;
      return {
        ...userRow.rows[0],
        last_message:  lastMsg.rows[0]?.text || null,
        unread_count:  parseInt(unread.rows[0].count),
      };
    }));
    res.json(conversations.filter(Boolean));
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// GET /api/dm/:userId/messages
router.get('/:userId/messages', requireAuth, async (req, res) => {
  const user    = req.session.user;
  const other   = parseInt(req.params.userId);
  // Agents can only DM admin
  if (user.role === 'agent') {
    const { rows } = await pool.query(`SELECT id FROM users WHERE id=$1 AND role='admin'`, [other]);
    if (!rows.length) return res.status(403).json({ error: 'Agents can only message Admin' });
  }
  const key = dmKey(user.id, other);
  try {
    const { rows } = await pool.query(
      'SELECT * FROM direct_messages WHERE dm_key=$1 ORDER BY created_at ASC LIMIT 200', [key]
    );
    // Mark as read
    await pool.query(`UPDATE direct_messages SET is_read=true WHERE dm_key=$1 AND receiver_id=$2`, [key, user.id]);
    res.json(rows);
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// POST /api/dm/:userId
router.post('/:userId', requireAuth, async (req, res) => {
  const { text }  = req.body;
  if (!text) return res.status(400).json({ error: 'Text required' });
  const user  = req.session.user;
  const other = parseInt(req.params.userId);
  // Agents can only DM admin
  if (user.role === 'agent') {
    const { rows } = await pool.query(`SELECT id FROM users WHERE id=$1 AND role='admin'`, [other]);
    if (!rows.length) return res.status(403).json({ error: 'Agents can only message Admin' });
  }
  const key = dmKey(user.id, other);
  try {
    const { rows } = await pool.query(
      `INSERT INTO direct_messages (dm_key,sender_id,sender_name,sender_color,receiver_id,text)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [key, user.id, user.name, user.color, other, text]
    );
    const msg = rows[0];
    const io  = req.app.get('io');
    if (io) {
      io.to(`dm_${key}`).emit('dm_message', msg);
      io.to(`user_${other}`).emit('dm_notification', { from_id: user.id, from_name: user.name, text });
    }
    res.json(msg);
  } catch(err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
