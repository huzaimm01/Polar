'use strict';
// REST API for Polar v2. Every route except signup/login and /health requires
// a JWT. Message bodies are ciphertext only — the server never sees plaintext.
const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('node:crypto');
const { User, Room, Message } = require('./models');
const { requireAuth, signToken, publicUser, requireOwner, isOwnerUser } = require('./auth');

const router = express.Router();

function isValidUsername(name) {
  return typeof name === 'string' && /^[a-z0-9_]{3,20}$/.test(name);
}

function inviteCode() {
  // 6 chars from an unambiguous alphabet (no 0/O, 1/I/l).
  const alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  return Array.from({ length: 6 }, () =>
    alphabet[crypto.randomInt(alphabet.length)]).join('');
}

async function loadRoomOr404(req, res) {
  const room = await Room.findById(req.params.id).populate('members.user', 'username displayName avatarUrl publicKeyJwk');
  if (!room) { res.status(404).json({ error: 'Room not found' }); return null; }
  return room;
}

function isMember(room, userId) {
  return room.members.some((m) => m.user._id.toString() === userId);
}

function roomShape(room, myUserId) {
  const mine = room.members.find((m) => m.user._id.toString() === myUserId);
  return {
    id: room._id.toString(),
    name: room.name,
    inviteCode: room.inviteCode,
    inviteWrappedRoomKey: room.inviteWrappedRoomKey,
    createdAt: room.createdAt,
    // This member's wrapped room key — only they can unwrap it client-side.
    wrappedRoomKey: mine ? mine.wrappedRoomKey : null,
    wrappedBy: mine && mine.wrappedBy ? mine.wrappedBy.toString() : null,
    members: room.members.map((m) => ({
      id: m.user._id.toString(),
      username: m.user.username,
      displayName: m.user.displayName,
      avatarUrl: m.user.avatarUrl || '',
      publicKeyJwk: m.user.publicKeyJwk || null,
      joinedAt: m.joinedAt,
    })),
  };
}

// ---------------------------------------------------------------- auth ------
// Friends-only signup gate: if SIGNUP_CODE is set (hosted instances only),
// signup requires the matching code. Unset = open signup, so anyone cloning
// the repo to self-host is never locked out. Read at request time so the
// gate can be toggled without rebooting.
router.post('/auth/signup', async (req, res) => {
  const { username, displayName, password, bio, avatarUrl, publicKeyJwk, signupCode } = req.body || {};
  const requiredCode = process.env.SIGNUP_CODE;
  if (requiredCode && signupCode !== requiredCode) {
    return res.status(403).json({ error: 'Invite code required' });
  }
  const name = typeof username === 'string' ? username.toLowerCase().trim() : '';
  if (!isValidUsername(name)) {
    return res.status(400).json({ error: 'Username must be 3-20 chars: lowercase letters, digits, underscore.' });
  }
  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }
  if (typeof displayName !== 'string' || !displayName.trim()) {
    return res.status(400).json({ error: 'Display name is required.' });
  }
  if (publicKeyJwk && (typeof publicKeyJwk !== 'object' || publicKeyJwk.kty !== 'EC')) {
    return res.status(400).json({ error: 'publicKeyJwk must be an EC JWK object.' });
  }
  if (await User.findOne({ username: name })) {
    return res.status(409).json({ error: 'Username is already taken.' });
  }
  const passwordHash = await bcrypt.hash(password, 12);
  const user = await User.create({
    username: name,
    displayName: displayName.trim().slice(0, 60),
    bio: typeof bio === 'string' ? bio.slice(0, 280) : '',
    avatarUrl: typeof avatarUrl === 'string' ? avatarUrl.slice(0, 500) : '',
    passwordHash,
    publicKeyJwk: publicKeyJwk || null,
  });
  return res.status(201).json({ token: signToken(user), user: publicUser(user) });
});

router.post('/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  const name = typeof username === 'string' ? username.toLowerCase().trim() : '';
  const user = await User.findOne({ username: name }).select('+passwordHash');
  if (!user || typeof password !== 'string' ||
      !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }
  return res.json({ token: signToken(user), user: publicUser(user) });
});

router.get('/auth/me', requireAuth, async (req, res) => {
  const user = await User.findById(req.user.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  return res.json({ user: publicUser(user) });
});

// Key rotation: a user on a new device generates a fresh ECDH keypair and
// uploads the new public key here. Old rooms' wrapped keys were made for the
// old key, so a room member must re-wrap the room key for them (re-invite).
// Losing the old private key means old history cannot be decrypted — see README.
router.post('/auth/public-key', requireAuth, async (req, res) => {
  const { publicKeyJwk } = req.body || {};
  if (!publicKeyJwk || typeof publicKeyJwk !== 'object' || publicKeyJwk.kty !== 'EC') {
    return res.status(400).json({ error: 'publicKeyJwk must be an EC JWK object.' });
  }
  const user = await User.findByIdAndUpdate(
    req.user.sub, { publicKeyJwk }, { new: true },
  );
  if (!user) return res.status(404).json({ error: 'User not found' });
  return res.json({ user: publicUser(user) });
});

// ------------------------------------------------------- users (lookup) ----
// Needed for inviting: fetch someone's public key so the client can wrap the
// room key for them. Only public key material is ever returned.
router.get('/users/:username', requireAuth, async (req, res) => {
  const user = await User.findOne({ username: req.params.username.toLowerCase() });
  if (!user) return res.status(404).json({ error: 'User not found' });
  return res.json({ user: publicUser(user) });
});

// ---------------------------------------------------------------- rooms -----
router.get('/rooms', requireAuth, async (req, res) => {
  const rooms = await Room.find({ 'members.user': req.user.sub })
    .populate('members.user', 'username displayName avatarUrl publicKeyJwk')
    .sort({ createdAt: 1 });
  return res.json({ rooms: rooms.map((r) => roomShape(r, req.user.sub)) });
});

router.post('/rooms', requireAuth, async (req, res) => {
  const { name, wrappedRoomKey, inviteWrappedRoomKey } = req.body || {};
  if (typeof name !== 'string' || !name.trim()) {
    return res.status(400).json({ error: 'Room name is required.' });
  }
  if (typeof wrappedRoomKey !== 'string' || !wrappedRoomKey ||
      typeof inviteWrappedRoomKey !== 'string' || !inviteWrappedRoomKey) {
    return res.status(400).json({
      error: 'wrappedRoomKey and inviteWrappedRoomKey are required (generated in your browser).',
    });
  }
  // Retry on the (very unlikely) invite-code collision.
  let room = null;
  for (let attempt = 0; attempt < 5 && !room; attempt++) {
    try {
      room = await Room.create({
        name: name.trim().slice(0, 80),
        inviteCode: inviteCode(),
        inviteWrappedRoomKey,
        members: [{ user: req.user.sub, wrappedRoomKey, wrappedBy: req.user.sub }],
        createdBy: req.user.sub,
      });
    } catch (err) {
      if (err.code !== 11000) throw err;
    }
  }
  if (!room) return res.status(500).json({ error: 'Could not create room, please try again.' });
  await room.populate('members.user', 'username displayName avatarUrl publicKeyJwk');
  return res.status(201).json({ room: roomShape(room, req.user.sub) });
});

// Set the invite-code-wrapped room key. The invite code is generated by the
// server at creation, so the creator computes this wrap right after creating
// the room and posts it here. Creator only.
router.post('/rooms/:id/invite-key', requireAuth, async (req, res) => {
  const { inviteWrappedRoomKey } = req.body || {};
  const room = await Room.findById(req.params.id);
  if (!room) return res.status(404).json({ error: 'Room not found' });
  if (room.createdBy.toString() !== req.user.sub) {
    return res.status(403).json({ error: 'Only the room creator can set the invite key.' });
  }
  if (typeof inviteWrappedRoomKey !== 'string' || !inviteWrappedRoomKey) {
    return res.status(400).json({ error: 'inviteWrappedRoomKey is required.' });
  }
  room.inviteWrappedRoomKey = inviteWrappedRoomKey;
  await room.save();
  return res.json({ ok: true });
});

router.post('/rooms/join', requireAuth, async (req, res) => {
  const { inviteCode: code } = req.body || {};
  if (typeof code !== 'string' || !code.trim()) {
    return res.status(400).json({ error: 'Invite code is required.' });
  }
  const room = await Room.findOne({ inviteCode: code.trim().toUpperCase() });
  if (!room) return res.status(404).json({ error: 'No room with that invite code.' });
  if (isMember(room, req.user.sub)) {
    await room.populate('members.user', 'username displayName avatarUrl publicKeyJwk');
    return res.json({ room: roomShape(room, req.user.sub), alreadyMember: true });
  }
  // Membership first; the client unwraps the room key from
  // inviteWrappedRoomKey (it knows the code) and stores its own wrapped key
  // via POST /rooms/:id/wrapped-key.
  room.members.push({ user: req.user.sub, wrappedRoomKey: '', wrappedBy: null });
  await room.save();
  await room.populate('members.user', 'username displayName avatarUrl publicKeyJwk');
  return res.json({ room: roomShape(room, req.user.sub) });
});

router.get('/rooms/:id', requireAuth, async (req, res) => {
  const room = await loadRoomOr404(req, res);
  if (!room) return;
  if (!isMember(room, req.user.sub)) return res.status(403).json({ error: 'You are not a member of this room.' });
  return res.json({ room: roomShape(room, req.user.sub) });
});

router.get('/rooms/:id/members', requireAuth, async (req, res) => {
  const room = await loadRoomOr404(req, res);
  if (!room) return;
  if (!isMember(room, req.user.sub)) return res.status(403).json({ error: 'You are not a member of this room.' });
  return res.json({ members: roomShape(room, req.user.sub).members });
});

// Add a member by username. The caller wraps the room key for the new member
// in their browser first — the server just stores the wrapped key.
router.post('/rooms/:id/members', requireAuth, async (req, res) => {
  const { username, wrappedRoomKey } = req.body || {};
  const room = await loadRoomOr404(req, res);
  if (!room) return;
  if (!isMember(room, req.user.sub)) return res.status(403).json({ error: 'You are not a member of this room.' });
  if (typeof username !== 'string' || typeof wrappedRoomKey !== 'string' || !wrappedRoomKey) {
    return res.status(400).json({ error: 'username and wrappedRoomKey are required.' });
  }
  const target = await User.findOne({ username: username.toLowerCase().trim() });
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (isMember(room, target._id.toString())) {
    return res.status(409).json({ error: 'That user is already a member.' });
  }
  room.members.push({ user: target._id, wrappedRoomKey, wrappedBy: req.user.sub });
  await room.save();
  await room.populate('members.user', 'username displayName avatarUrl publicKeyJwk');
  return res.status(201).json({ room: roomShape(room, req.user.sub) });
});

// Store / replace my own wrapped room key (e.g. after re-wrapping on a new
// device, or if I joined before my keypair existed).
router.post('/rooms/:id/wrapped-key', requireAuth, async (req, res) => {
  const { wrappedRoomKey } = req.body || {};
  const room = await loadRoomOr404(req, res);
  if (!room) return;
  const member = room.members.find((m) => m.user._id.toString() === req.user.sub);
  if (!member) return res.status(403).json({ error: 'You are not a member of this room.' });
  if (typeof wrappedRoomKey !== 'string' || !wrappedRoomKey) {
    return res.status(400).json({ error: 'wrappedRoomKey is required.' });
  }
  member.wrappedRoomKey = wrappedRoomKey;
  member.wrappedBy = req.user.sub; // self-wrapped from here on
  await room.save();
  return res.json({ ok: true });
});

// ------------------------------------------------------------- messages -----
// Bodies are { ciphertext, iv } — both base64. No plaintext field exists.
router.get('/rooms/:id/messages', requireAuth, async (req, res) => {
  const room = await Room.findById(req.params.id);
  if (!room) return res.status(404).json({ error: 'Room not found' });
  if (!isMember(room, req.user.sub)) return res.status(403).json({ error: 'You are not a member of this room.' });
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), 200);
  const messages = await Message.find({ room: room._id })
    .sort({ createdAt: 1 })
    .limit(limit)
    .populate('sender', 'username displayName');
  return res.json({
    messages: messages.map((m) => ({
      id: m._id.toString(),
      room: m.room.toString(),
      sender: { id: m.sender._id.toString(), username: m.sender.username, displayName: m.sender.displayName },
      ciphertext: m.ciphertext,
      iv: m.iv,
      createdAt: m.createdAt,
    })),
  });
});

router.post('/rooms/:id/messages', requireAuth, async (req, res) => {
  const { ciphertext, iv } = req.body || {};
  const room = await Room.findById(req.params.id);
  if (!room) return res.status(404).json({ error: 'Room not found' });
  if (!isMember(room, req.user.sub)) return res.status(403).json({ error: 'You are not a member of this room.' });
  if (typeof ciphertext !== 'string' || !ciphertext || typeof iv !== 'string' || !iv) {
    return res.status(400).json({ error: 'ciphertext and iv are required.' });
  }
  if (ciphertext.length > 20000 || iv.length > 64) {
    return res.status(413).json({ error: 'Message too large.' });
  }
  const message = await Message.create({ room: room._id, sender: req.user.sub, ciphertext, iv });
  const sender = await User.findById(req.user.sub);
  return res.status(201).json({
    message: {
      id: message._id.toString(),
      room: room._id.toString(),
      sender: { id: sender._id.toString(), username: sender.username, displayName: sender.displayName },
      ciphertext: message.ciphertext,
      iv: message.iv,
      createdAt: message.createdAt,
    },
  });
});

// ---------------------------------------------------------------- admin -----
// Owner-only controls. The owner is the user whose username matches the
// OWNER_USERNAME env var (see server/auth.js). Every endpoint here is 403
// for anyone else, including logged-in non-owners; 401 with no/bad token.
router.get('/admin/users', requireOwner, async (req, res) => {
  const users = await User.find().sort({ createdAt: 1 });
  return res.json({
    users: users.map((u) => ({
      id: u._id.toString(),
      username: u.username,
      displayName: u.displayName,
      createdAt: u.createdAt,
      isOwner: isOwnerUser(u.username),
    })),
  });
});

router.get('/admin/rooms', requireOwner, async (req, res) => {
  const rooms = await Room.find().sort({ createdAt: 1 });
  return res.json({
    rooms: rooms.map((r) => ({
      id: r._id.toString(),
      name: r.name,
      inviteCode: r.inviteCode,
      memberCount: r.members.length,
      createdAt: r.createdAt,
    })),
  });
});

// Delete a room and all of its messages. Members just lose the room.
router.delete('/admin/rooms/:id', requireOwner, async (req, res) => {
  const room = await Room.findById(req.params.id);
  if (!room) return res.status(404).json({ error: 'Room not found' });
  await Message.deleteMany({ room: room._id });
  await room.deleteOne();
  return res.json({ ok: true });
});

// Delete a user, their room memberships, and the messages they sent.
// (Their messages are removed too — otherwise room history would hold
// messages from a sender that no longer exists.) The owner cannot delete
// their own account.
router.delete('/admin/users/:id', requireOwner, async (req, res) => {
  if (req.params.id === req.user.sub) {
    return res.status(403).json({ error: 'You cannot delete your own account.' });
  }
  const user = await User.findById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  await Message.deleteMany({ sender: user._id });
  await Room.updateMany(
    { 'members.user': user._id },
    { $pull: { members: { user: user._id } } },
  );
  await user.deleteOne();
  return res.json({ ok: true });
});

module.exports = router;
