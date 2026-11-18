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

// Owner check: the user whose username matches OWNER_USERNAME is the
// instance owner (the person running/hosting it). Read at request time,
// like the SIGNUP_CODE gate, so it can be set without a restart. Usernames
// are stored lowercase, so the env value is lowercased too. Unset = nobody
// is owner (the default for anyone cloning the repo to self-host).
function isOwnerUser(username) {
  const owner = process.env.OWNER_USERNAME;
  return Boolean(owner) && typeof username === 'string' &&
    username.toLowerCase() === owner.trim().toLowerCase();
}

// Express middleware: requires a valid JWT (via requireAuth) AND the owner.
// 401 for no/bad token, 403 for a logged-in non-owner.
function requireOwner(req, res, next) {
  requireAuth(req, res, () => {
    if (!isOwnerUser(req.user.username)) {
      return res.status(403).json({ error: 'Owner access required.' });
    }
    return next();
  });
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
    isOwner: isOwnerUser(user.username),
  };
}

module.exports = { initAuth, signToken, verifyToken, requireAuth, requireOwner, isOwnerUser, publicUser };
