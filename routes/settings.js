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

// PATCH /api/settings/password  — change own password
router.patch('/password', requireAuth, async (req, res) => {
  const { current_password, new_password } = req.body;
  if (!current_password || !new_password)
    return res.status(400).json({ error: 'Both fields required' });
  if (new_password.length < 6)
    return res.status(400).json({ error: 'New password must be at least 6 characters' });
  try {
    const { rows } = await pool.query('SELECT password_hash FROM users WHERE id=$1', [req.session.user.id]);
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    const valid = await bcrypt.compare(current_password, rows[0].password_hash);
    if (!valid) return res.status(400).json({ error: 'Current password is incorrect' });
    const hash = await bcrypt.hash(new_password, 10);
    await pool.query('UPDATE users SET password_hash=$1 WHERE id=$2', [hash, req.session.user.id]);
    res.json({ ok: true });
  } catch(err) { res.status(500).json({ error: 'Server error' }); }
});

// PATCH /api/settings/user-password/:id  — admin resets any user's password
router.patch('/user-password/:id', requireAdmin, async (req, res) => {
  const { new_password } = req.body;
  if (!new_password || new_password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  try {
    const hash = await bcrypt.hash(new_password, 10);
    await pool.query('UPDATE users SET password_hash=$1 WHERE id=$2', [hash, req.params.id]);
    res.json({ ok: true });
  } catch(err) { res.status(500).json({ error: 'Server error' }); }
});

// GET /api/settings/backup  — full JSON backup (admin only)
router.get('/backup', requireAdmin, async (req, res) => {
  try {
    const [tokens, users, channels, messages, dms] = await Promise.all([
      pool.query('SELECT * FROM tokens ORDER BY created_at'),
      pool.query('SELECT id,username,name,role,color,created_at FROM users ORDER BY id'),
      pool.query('SELECT * FROM channels ORDER BY id'),
      pool.query('SELECT * FROM messages ORDER BY created_at'),
      pool.query('SELECT * FROM direct_messages ORDER BY created_at'),
    ]);
    const backup = {
      version:     '2.0',
      exported_at: new Date().toISOString(),
      app:         'Token Management Master System',
      data: {
        users:           users.rows,
        tokens:          tokens.rows,
        channels:        channels.rows,
        messages:        messages.rows,
        direct_messages: dms.rows,
      }
    };
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition',
      `attachment; filename="tmms-backup-${new Date().toISOString().slice(0,10)}.json"`);
    res.send(JSON.stringify(backup, null, 2));
  } catch(err) { res.status(500).json({ error: 'Backup failed: ' + err.message }); }
});

// POST /api/settings/restore  — restore from JSON backup (admin only)
router.post('/restore', requireAdmin, async (req, res) => {
  const { data, restore_tokens, restore_messages, restore_users } = req.body;
  if (!data) return res.status(400).json({ error: 'No backup data provided' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const summary = { tokens: 0, messages: 0, direct_messages: 0, channels: 0, users: 0 };

    if (restore_tokens && data.tokens?.length) {
      for (const t of data.tokens) {
        await client.query(`
          INSERT INTO tokens (id,token_ref,details,charge,status,author_id,author_name,
            created_at,completed_at,kyc_image_url,kyc_public_id,kyc_uploaded_at,kyc_uploaded_by)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
          ON CONFLICT (id) DO UPDATE SET
            details=EXCLUDED.details, charge=EXCLUDED.charge, status=EXCLUDED.status,
            completed_at=EXCLUDED.completed_at, kyc_image_url=EXCLUDED.kyc_image_url`,
          [t.id,t.token_ref,t.details,t.charge,t.status,t.author_id,t.author_name,
           t.created_at,t.completed_at,t.kyc_image_url,t.kyc_public_id,t.kyc_uploaded_at,t.kyc_uploaded_by]);
        summary.tokens++;
      }
      await client.query(`SELECT setval('tokens_id_seq', COALESCE((SELECT MAX(id) FROM tokens),1))`);
    }

    if (restore_messages && data.channels?.length) {
      for (const ch of data.channels) {
        await client.query(
          `INSERT INTO channels (id,name,description,icon,created_by,created_at)
           VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (id) DO NOTHING`,
          [ch.id,ch.name,ch.description,ch.icon,ch.created_by,ch.created_at]);
        summary.channels++;
      }
      await client.query(`SELECT setval('channels_id_seq', COALESCE((SELECT MAX(id) FROM channels),1))`);
    }

    if (restore_messages && data.messages?.length) {
      for (const m of data.messages) {
        await client.query(
          `INSERT INTO messages (id,channel_id,author_id,author_name,text,is_token_alert,created_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO NOTHING`,
          [m.id,m.channel_id,m.author_id,m.author_name,m.text,m.is_token_alert,m.created_at]);
        summary.messages++;
      }
      await client.query(`SELECT setval('messages_id_seq', COALESCE((SELECT MAX(id) FROM messages),1))`);
    }

    if (restore_messages && data.direct_messages?.length) {
      for (const d of data.direct_messages) {
        await client.query(
          `INSERT INTO direct_messages (id,dm_key,sender_id,sender_name,sender_color,receiver_id,text,is_read,created_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (id) DO NOTHING`,
          [d.id,d.dm_key,d.sender_id,d.sender_name,d.sender_color,d.receiver_id,d.text,d.is_read,d.created_at]);
        summary.direct_messages++;
      }
      await client.query(`SELECT setval('direct_messages_id_seq', COALESCE((SELECT MAX(id) FROM direct_messages),1))`);
    }

    if (restore_users && data.users?.length) {
      for (const u of data.users) {
        if (u.role === 'admin') continue; // never overwrite admin account
        await client.query('UPDATE users SET name=$1, color=$2 WHERE id=$3', [u.name, u.color, u.id]);
        summary.users++;
      }
    }

    await client.query('COMMIT');
    res.json({ ok: true, summary });
  } catch(err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Restore failed: ' + err.message });
  } finally { client.release(); }
});

// GET /api/settings/stats
router.get('/stats', requireAuth, async (req, res) => {
  try {
    const [tokenStats, userCount, msgCount, dmCount] = await Promise.all([
      pool.query(`SELECT COUNT(*) as total,
                         COUNT(*) FILTER(WHERE status='active') as active,
                         COUNT(*) FILTER(WHERE status='completed') as completed,
                         COALESCE(SUM(charge) FILTER(WHERE status='active'),0) as total_due
                  FROM tokens`),
      pool.query('SELECT COUNT(*) as total FROM users'),
      pool.query('SELECT COUNT(*) as total FROM messages'),
      pool.query('SELECT COUNT(*) as total FROM direct_messages'),
    ]);
    res.json({
      tokens:          tokenStats.rows[0],
      users:           parseInt(userCount.rows[0].total),
      messages:        parseInt(msgCount.rows[0].total),
      direct_messages: parseInt(dmCount.rows[0].total),
    });
  } catch(err) { res.status(500).json({ error: 'Server error' }); }
});

module.exports = router;
