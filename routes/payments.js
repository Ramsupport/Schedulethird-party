const express    = require('express');
const multer     = require('multer');
const cloudinary = require('cloudinary').v2;
const { pool }   = require('../db');
const router     = express.Router();
const upload     = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  next();
}

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// GET /api/payments
router.get('/', requireAuth, async (req, res) => {
  const user = req.session.user;
  try {
    let query  = 'SELECT * FROM payments WHERE 1=1';
    const params = [];
    if (user.role !== 'admin') {
      query += ' AND submitted_by=$1';
      params.push(user.id);
    }
    query += ' ORDER BY created_at DESC';
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// POST /api/payments  (with optional screenshot upload)
router.post('/', requireAuth, upload.single('screenshot'), async (req, res) => {
  const { details, amount, payment_date } = req.body;
  if (!details || !amount) return res.status(400).json({ error: 'Details and amount are required' });
  const user = req.session.user;

  let screenshot_url       = null;
  let screenshot_public_id = null;

  // Upload screenshot to Cloudinary if provided
  if (req.file) {
    try {
      const result = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { folder: 'token-tracker/payments', resource_type: 'image' },
          (err, result) => err ? reject(err) : resolve(result)
        );
        stream.end(req.file.buffer);
      });
      screenshot_url       = result.secure_url;
      screenshot_public_id = result.public_id;
    } catch(e) { /* screenshot upload failed — still save the payment */ }
  }

  try {
    // Generate payment ref
    const { rows: countRows } = await pool.query('SELECT COUNT(*) FROM payments');
    const ref = 'PAY' + String(parseInt(countRows[0].count) + 1).padStart(4, '0');

    const pdate = payment_date || new Date().toISOString().slice(0, 10);

    const { rows } = await pool.query(
      `INSERT INTO payments
         (payment_ref, details, amount, payment_date, screenshot_url, screenshot_public_id, submitted_by, submitted_name)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [ref, details, parseFloat(amount), pdate, screenshot_url, screenshot_public_id, user.id, user.name]
    );
    res.json(rows[0]);
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// DELETE /api/payments/:id  (admin or own)
router.delete('/:id', requireAuth, async (req, res) => {
  const user = req.session.user;
  try {
    const { rows } = await pool.query('SELECT * FROM payments WHERE id=$1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Payment not found' });
    if (user.role !== 'admin' && rows[0].submitted_by !== user.id)
      return res.status(403).json({ error: 'Not allowed' });
    if (rows[0].screenshot_public_id) {
      await cloudinary.uploader.destroy(rows[0].screenshot_public_id).catch(() => {});
    }
    await pool.query('DELETE FROM payments WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;

// POST /api/payments/:id/screenshot  — upload/replace screenshot for existing payment
router.post('/:id/screenshot', requireAuth, upload.single('screenshot'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const user = req.session.user;
  try {
    const { rows } = await pool.query('SELECT * FROM payments WHERE id=$1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Payment not found' });
    if (user.role !== 'admin' && rows[0].submitted_by !== user.id)
      return res.status(403).json({ error: 'Not allowed' });
    // Remove old screenshot
    if (rows[0].screenshot_public_id) {
      await cloudinary.uploader.destroy(rows[0].screenshot_public_id).catch(() => {});
    }
    const result = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        { folder: 'token-tracker/payments', resource_type: 'image' },
        (err, result) => err ? reject(err) : resolve(result)
      );
      stream.end(req.file.buffer);
    });
    const updated = await pool.query(
      'UPDATE payments SET screenshot_url=$1, screenshot_public_id=$2 WHERE id=$3 RETURNING *',
      [result.secure_url, result.public_id, req.params.id]
    );
    res.json(updated.rows[0]);
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// DELETE /api/payments/:id/screenshot
router.delete('/:id/screenshot', requireAuth, async (req, res) => {
  const user = req.session.user;
  try {
    const { rows } = await pool.query('SELECT * FROM payments WHERE id=$1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Payment not found' });
    if (user.role !== 'admin' && rows[0].submitted_by !== user.id)
      return res.status(403).json({ error: 'Not allowed' });
    if (rows[0].screenshot_public_id) {
      await cloudinary.uploader.destroy(rows[0].screenshot_public_id).catch(() => {});
    }
    await pool.query(
      'UPDATE payments SET screenshot_url=NULL, screenshot_public_id=NULL WHERE id=$1', [req.params.id]
    );
    res.json({ ok: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});
