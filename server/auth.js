'use strict';
// Auth helpers: JWT signing/verification and the Express + Socket.io guards.
const jwt = require('jsonwebtoken');

let secret = null;

function initAuth(jwtSecret) {
  secret = jwtSecret;
}

function signToken(user) {
  return jwt.sign(
    { sub: user._id.toString(), username: user.username },
    secret,
    { expiresIn: '7d' },
  );
}

function verifyToken(token) {
  return jwt.verify(token, secret);
}

// Express middleware: requires `Authorization: Bearer <jwt>`, sets req.user.
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing auth token' });
  try {
    req.user = verifyToken(token);
    return next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Public user shape — never includes passwordHash or anything private.
function publicUser(user) {
  return {
    id: user._id.toString(),
    username: user.username,
    displayName: user.displayName,
    bio: user.bio || '',
    avatarUrl: user.avatarUrl || '',
    publicKeyJwk: user.publicKeyJwk || null,
    createdAt: user.createdAt,
  };
}

module.exports = { initAuth, signToken, verifyToken, requireAuth, publicUser };
