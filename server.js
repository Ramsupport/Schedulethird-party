require('dotenv').config();
const express        = require('express');
const http           = require('http');
const { Server }     = require('socket.io');
const session        = require('express-session');
const pgSession      = require('connect-pg-simple')(session);
const path           = require('path');
const { pool, initSchema } = require('./db');

// ── Routes ───────────────────────────────────
const authRoutes     = require('./routes/auth');
const tokenRoutes    = require('./routes/tokens');
const channelRoutes  = require('./routes/channels');
const dmRoutes       = require('./routes/dm');
const userRoutes     = require('./routes/users');
const settingsRoutes  = require('./routes/settings');
const paymentRoutes   = require('./routes/payments');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*', credentials: true } });

// ── Session ──────────────────────────────────
const sessionMiddleware = session({
  store:  new pgSession({ pool, tableName: 'session' }),
  secret: process.env.SESSION_SECRET || 'tmms-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure:   process.env.NODE_ENV === 'production',
    maxAge:   7 * 24 * 60 * 60 * 1000,
    httpOnly: true,
  }
});

// ── Middleware ────────────────────────────────
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(sessionMiddleware);
app.use(express.static(path.join(__dirname, 'public')));

// Share session with Socket.IO
io.use((socket, next) => sessionMiddleware(socket.request, {}, next));

// ── API Routes ────────────────────────────────
app.use('/api/auth',     authRoutes);
app.use('/api/tokens',   tokenRoutes);
app.use('/api/channels', channelRoutes);
app.use('/api/dm',       dmRoutes);
app.use('/api/users',    userRoutes);
app.use('/api/settings', settingsRoutes);
app.use('/api/payments', paymentRoutes);

// Pass io to routes that need it
app.set('io', io);

// ── Socket.IO ─────────────────────────────────
io.on('connection', (socket) => {
  const user = socket.request.session?.user;
  if (!user) return;

  socket.join(`user_${user.id}`);

  socket.on('join_channel', (channelId) => {
    socket.join(`channel_${channelId}`);
  });

  socket.on('join_dm', (dmKey) => {
    socket.join(`dm_${dmKey}`);
  });

  socket.on('disconnect', () => {});
});

// ── SPA fallback ─────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start ─────────────────────────────────────
const PORT = process.env.PORT || 3000;

initSchema().then(() => {
  server.listen(PORT, () => {
    console.log(`🚀 Token Management Master System running on port ${PORT}`);
  });
}).catch(err => {
  console.error('❌ Failed to init schema:', err);
  process.exit(1);
});
