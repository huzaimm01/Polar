'use strict';
// Polar v2 server.
//
// Deploy = one key in one file:
//   cp .env.example .env   # paste your free Atlas MONGODB_URI
//   npm install && npm start
//
// If MONGODB_URI is missing the server refuses to boot — Polar never silently
// falls back to localStorage or an insecure store. For local testing without
// Atlas: `npm run dev:memory` (in-memory Mongo, test/dev only).
require('dotenv').config();
const crypto = require('node:crypto');
const express = require('express');
const http = require('node:http');
const path = require('node:path');
const cors = require('cors');
const mongoose = require('mongoose');
const { initAuth, requireAuth } = require('./server/auth');
const apiRoutes = require('./server/routes');
const { attachSocket } = require('./server/socket');

const PORT = parseInt(process.env.PORT, 10) || 3000;
const USE_MEMORY = process.argv.includes('--memory');

async function boot() {
  let mongoUri = process.env.MONGODB_URI;

  if (USE_MEMORY) {
    // Dev/test only: ephemeral in-memory Mongo. Never used in production.
    const { MongoMemoryServer } = require('mongodb-memory-server');
    const mongod = await MongoMemoryServer.create();
    mongoUri = mongod.getUri();
    console.log('[polar] dev:memory — using ephemeral in-memory MongoDB (data is lost on exit).');
  }

  if (!mongoUri) {
    console.error('');
    console.error('  Polar cannot start: MONGODB_URI is not set.');
    console.error('');
    console.error('  1. Create a free MongoDB Atlas cluster (M0) at https://cloud.mongodb.com');
    console.error('  2. cp .env.example .env');
    console.error('  3. Paste your Atlas connection string as MONGODB_URI in .env');
    console.error('  4. npm install && npm start');
    console.error('');
    console.error('  Just testing locally? Run: npm run dev:memory');
    console.error('');
    process.exit(1);
  }

  // JWT secret: optional. Without one, sessions are signed with an ephemeral
  // random secret and everyone is logged out on restart. Loud on purpose.
  let jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) {
    jwtSecret = crypto.randomBytes(32).toString('hex');
    console.warn('[polar] WARNING: JWT_SECRET is not set. Using a random ephemeral secret —');
    console.warn('[polar] all sessions will be invalidated when the server restarts.');
    console.warn('[polar] Set JWT_SECRET in .env for a real deployment.');
  }
  initAuth(jwtSecret);

  await mongoose.connect(mongoUri);
  console.log('[polar] MongoDB connected.');

  const app = express();
  app.use(cors());
  app.use(express.json({ limit: '100kb' }));

  // Client config (public): STUN servers only, plus whether the friends-only
  // signup gate is on. TURN credentials are secrets and are NEVER served
  // here — they live on the authenticated /api/config/ice endpoint below,
  // so an anonymous visitor cannot harvest them.
  app.get('/api/config', (req, res) => {
    res.json({
      iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
      ],
      maxCallPeers: 5,
      // Friends-only signup gate: true when SIGNUP_CODE is set. Read at
      // request time so the frontend always reflects the current setting.
      // The code value itself is never exposed here.
      signupCodeRequired: Boolean(process.env.SIGNUP_CODE),
    });
  });

  // Authenticated ICE config: the full server list, including TURN when the
  // deployer configured one. Only logged-in users get TURN credentials
  // (voice calls happen post-login — see public/voice.js loadConfig).
  app.get('/api/config/ice', requireAuth, (req, res) => {
    const iceServers = [
      { urls: 'stun:stun.l.google.com:19302' },
      { urls: 'stun:stun1.l.google.com:19302' },
    ];
    if (process.env.TURN_URL) {
      const turn = { urls: process.env.TURN_URL };
      if (process.env.TURN_USERNAME) turn.username = process.env.TURN_USERNAME;
      if (process.env.TURN_PASSWORD) turn.credential = process.env.TURN_PASSWORD;
      iceServers.push(turn);
    }
    res.json({ iceServers, maxCallPeers: 5 });
  });

  app.get('/health', (req, res) => {
    res.json({
      ok: true,
      db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    });
  });

  app.use('/api', apiRoutes);

  // Frontend (public/) — includes the logo/favicon images copied from old/.
  // Note: the repo root itself is NOT served statically — that would expose
  // .env (your MongoDB credentials) to anyone who asks for it.
  app.use(express.static(path.join(__dirname, 'public')));
  app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

  // JSON error handler (incl. malformed JSON bodies).
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err.type === 'entity.parse.failed' || err instanceof SyntaxError) {
      return res.status(400).json({ error: 'Invalid JSON body' });
    }
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  });

  const server = http.createServer(app);
  attachSocket(server);
  server.listen(PORT, () => {
    console.log(`[polar] Listening on http://localhost:${PORT}`);
    console.log('[polar] Health: GET /health');
  });
  return server;
}

// Allow `require('./server')` in tests without auto-booting.
if (require.main === module) {
  boot().catch((err) => {
    console.error('[polar] Failed to start:', err.message);
    process.exit(1);
  });
}

module.exports = { boot };
