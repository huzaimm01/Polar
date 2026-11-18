'use strict';
// Socket.io layer for Polar v2: realtime messages, typing, presence, and
// WebRTC voice-call signalling. Media is peer-to-peer — audio never passes
// through this server; only signalling (offers/answers/ICE) does.
const { Server } = require('socket.io');
const { verifyToken } = require('./auth');
const { Room, Message, User } = require('./models');

const MAX_CALL_PEERS = 5;

// roomId -> Map(userId -> { username, displayName, socketId })
const presence = new Map();
// roomId -> Set(userId) currently in a voice call
const calls = new Map();

function roomPresence(roomId) {
  const map = presence.get(roomId);
  if (!map) return [];
  return [...map.values()].map((p) => ({ id: p.userId, username: p.username, displayName: p.displayName }));
}

function callPeers(roomId) {
  const set = calls.get(roomId);
  if (!set) return [];
  return [...set].map((userId) => {
    const p = presence.get(roomId)?.get(userId);
    return p ? { id: userId, username: p.username, displayName: p.displayName } : { id: userId };
  });
}

async function isRoomMember(roomId, userId) {
  if (!roomId || typeof roomId !== 'string') return false;
  const room = await Room.findOne({ _id: roomId, 'members.user': userId }).select('_id');
  return !!room;
}

function attachSocket(httpServer) {
  const io = new Server(httpServer, { cors: { origin: true } });

  // JWT auth on handshake.
  io.use((socket, next) => {
    const token = socket.handshake.auth?.token;
    if (!token) return next(new Error('Missing auth token'));
    try {
      socket.user = verifyToken(token);
      return next();
    } catch {
      return next(new Error('Invalid or expired token'));
    }
  });

  io.on('connection', (socket) => {
    const userId = socket.user.sub;
    const username = socket.user.username;

    // ------------------------------------------------------------ rooms ----
    socket.on('room:join', async (roomId, ack) => {
      if (!(await isRoomMember(roomId, userId))) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Not a member of this room' });
        return;
      }
      socket.join(roomId);
      let map = presence.get(roomId);
      if (!map) { map = new Map(); presence.set(roomId, map); }
      const user = await User.findById(userId).select('displayName');
      map.set(userId, { userId, username, displayName: user?.displayName || username, socketId: socket.id });
      io.to(roomId).emit('presence', { roomId, users: roomPresence(roomId) });
      if (typeof ack === 'function') ack({ ok: true, users: roomPresence(roomId) });
    });

    socket.on('room:leave', (roomId) => {
      socket.leave(roomId);
      const map = presence.get(roomId);
      if (map) {
        map.delete(userId);
        io.to(roomId).emit('presence', { roomId, users: roomPresence(roomId) });
      }
    });

    // --------------------------------------------------------- messages ----
    // Client sends ciphertext only; the server stores it and relays it.
    socket.on('message:send', async (payload, ack) => {
      const { roomId, ciphertext, iv } = payload || {};
      if (!(await isRoomMember(roomId, userId))) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Not a member of this room' });
        return;
      }
      if (typeof ciphertext !== 'string' || !ciphertext || typeof iv !== 'string' || !iv ||
          ciphertext.length > 20000 || iv.length > 64) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Invalid message payload' });
        return;
      }
      const message = await Message.create({ room: roomId, sender: userId, ciphertext, iv });
      const sender = await User.findById(userId).select('username displayName');
      const out = {
        id: message._id.toString(),
        room: roomId,
        sender: { id: userId, username: sender.username, displayName: sender.displayName },
        ciphertext, iv,
        createdAt: message.createdAt,
      };
      io.to(roomId).emit('message:new', out);
      if (typeof ack === 'function') ack({ ok: true, message: out });
    });

    // ----------------------------------------------------------- typing ----
    socket.on('typing:start', async ({ roomId } = {}) => {
      if (await isRoomMember(roomId, userId)) {
        socket.to(roomId).emit('typing:start', { roomId, userId, username });
      }
    });
    socket.on('typing:stop', async ({ roomId } = {}) => {
      if (await isRoomMember(roomId, userId)) {
        socket.to(roomId).emit('typing:stop', { roomId, userId, username });
      }
    });

    // ------------------------------------------------------ voice calls ----
    // Mesh, audio-only. Signalling only — media flows directly peer to peer.
    socket.on('call:join', async ({ roomId } = {}, ack) => {
      if (!(await isRoomMember(roomId, userId))) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Not a member of this room' });
        return;
      }
      let set = calls.get(roomId);
      if (!set) { set = new Set(); calls.set(roomId, set); }
      if (!set.has(userId) && set.size >= MAX_CALL_PEERS) {
        if (typeof ack === 'function') ack({ ok: false, error: `Call is full (${MAX_CALL_PEERS} people max in v1)` });
        return;
      }
      const isNew = !set.has(userId);
      set.add(userId);
      socket.join(`call:${roomId}`);
      if (isNew) {
        socket.to(`call:${roomId}`).emit('call:peer-joined', { roomId, peer: { id: userId, username } });
      }
      if (typeof ack === 'function') ack({ ok: true, peers: callPeers(roomId) });
    });

    socket.on('call:leave', ({ roomId } = {}) => {
      const set = calls.get(roomId);
      if (set && set.delete(userId)) {
        socket.leave(`call:${roomId}`);
        socket.to(`call:${roomId}`).emit('call:peer-left', { roomId, peer: { id: userId, username } });
      }
    });

    // Relay offer/answer/ICE to one peer in the same call room.
    for (const event of ['call:offer', 'call:answer', 'call:ice']) {
      socket.on(event, async (payload = {}) => {
        const { roomId, to, data } = payload;
        if (!(await isRoomMember(roomId, userId))) return;
        const set = calls.get(roomId);
        if (!set || !set.has(userId) || !set.has(to)) return;
        const target = presence.get(roomId)?.get(to);
        if (target) io.to(target.socketId).emit(event, { roomId, from: { id: userId, username }, data });
      });
    }

    socket.on('disconnect', () => {
      for (const [roomId, map] of presence.entries()) {
        if (map.delete(userId)) {
          io.to(roomId).emit('presence', { roomId, users: roomPresence(roomId) });
        }
        const callSet = calls.get(roomId);
        if (callSet && callSet.delete(userId)) {
          io.to(`call:${roomId}`).emit('call:peer-left', { roomId, peer: { id: userId, username } });
        }
      }
    });
  });

  return io;
}

module.exports = { attachSocket, MAX_CALL_PEERS };
