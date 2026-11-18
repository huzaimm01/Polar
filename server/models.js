'use strict';
// Mongoose models for Polar v2.
//
// What the server stores — and what it never sees:
//  - Users: bcrypt password hashes + public ECDH keys. No plaintext passwords,
//    no private keys, ever.
//  - Rooms: membership + each member's *wrapped* (encrypted) room key.
//  - Messages: ciphertext + IV only. The server never receives plaintext.
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: {
    type: String, required: true, unique: true, lowercase: true, trim: true,
    minlength: 3, maxlength: 20, match: /^[a-z0-9_]+$/,
  },
  displayName: { type: String, required: true, trim: true, maxlength: 60 },
  bio: { type: String, default: '', maxlength: 280 },
  avatarUrl: { type: String, default: '' },
  passwordHash: { type: String, required: true, select: false },
  // Public ECDH P-256 key (JWK) for wrapping room keys. The matching private
  // key lives only in the user's browser, encrypted with their password.
  publicKeyJwk: { type: mongoose.Schema.Types.Mixed, default: null },
  createdAt: { type: Date, default: Date.now },
});

const memberSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  // Room AES-GCM key, wrapped (encrypted) for this member with ECDH+HKDF+AES-KW.
  // Base64. The server cannot unwrap it. Empty until the member stores theirs
  // (invite-code joiners unwrap via the invite key first, then store this).
  wrappedRoomKey: { type: String, default: '' },
  // Who wrapped the key for this member (their public key unwraps it).
  // Null for invite-code joiners until they store their own self-wrapped key.
  wrappedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  joinedAt: { type: Date, default: Date.now },
}, { _id: false });

const roomSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 80 },
  // 6-char invite code, e.g. "K7Q2XA". Share it with friends; anyone with it
  // can join (and then receives the room key wrapped for them).
  inviteCode: { type: String, required: true, unique: true, index: true },
  // Room key wrapped with a key derived from the invite code (PBKDF2).
  // Lets a new member get the room key by knowing the code alone. Only ever
  // sent to room members. Anyone with the code can unwrap it — see README.
  inviteWrappedRoomKey: { type: String, required: true },
  members: { type: [memberSchema], default: [] },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now },
});

const messageSchema = new mongoose.Schema({
  room: { type: mongoose.Schema.Types.ObjectId, ref: 'Room', required: true, index: true },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  // AES-GCM ciphertext of the message, base64. Plaintext never reaches the server.
  ciphertext: { type: String, required: true },
  // 12-byte random IV, base64.
  iv: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});
messageSchema.index({ room: 1, createdAt: 1 });

module.exports = {
  User: mongoose.model('User', userSchema),
  Room: mongoose.model('Room', roomSchema),
  Message: mongoose.model('Message', messageSchema),
};
