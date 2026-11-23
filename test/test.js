'use strict';
/* Polar v2 tests — run with `npm test` (uses mongodb-memory-server, no Atlas).
 *
 * Covers: health, auth validation, signup/login, room create + invite-code
 * join, ECDH invite-by-username, ciphertext-only storage (server never sees
 * plaintext), both members decrypting, socket delivery to members, and
 * rejection for non-members / unauthenticated sockets. Also verifies the
 * friends-only signup gate (SIGNUP_CODE), the owner admin role
 * (OWNER_USERNAME), and the fail-fast boot when MONGODB_URI is missing
 * (child process).
 */
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { MongoMemoryServer } = require('mongodb-memory-server');
const { io } = require('socket.io-client');

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();
const b64e = (buf) => Buffer.from(buf).toString('base64');
const b64d = (s) => Buffer.from(s, 'base64');

// --- client-crypto mirror (same algorithms as public/crypto.js) -------------
async function genIdentity() {
  const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
  return { privateKey: kp.privateKey, publicJwk: await subtle.exportKey('jwk', kp.publicKey) };
}
async function deriveKwKey(myPrivate, theirPublicJwk) {
  const theirPublic = await subtle.importKey('jwk', theirPublicJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
  const shared = await subtle.deriveKey(
    { name: 'ECDH', public: theirPublic }, myPrivate,
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('polar-room-key-v1') },
    false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('polar-room-key-v1') },
    shared, { name: 'AES-KW', length: 256 }, false, ['wrapKey', 'unwrapKey']);
}
async function wrapRoomKey(roomKey, myPrivate, theirPublicJwk) {
  const kw = await deriveKwKey(myPrivate, theirPublicJwk);
  return b64e(await subtle.wrapKey('raw', roomKey, kw, 'AES-KW'));
}
async function unwrapRoomKey(wrappedB64, myPrivate, wrapperPublicJwk) {
  const kw = await deriveKwKey(myPrivate, wrapperPublicJwk);
  return subtle.unwrapKey('raw', b64d(wrappedB64), kw, 'AES-KW', { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}
async function deriveInviteKwKey(code, roomId) {
  const base = await subtle.importKey('raw', enc.encode(code), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode(`polar-invite:${roomId}`), iterations: 100000, hash: 'SHA-256' },
    base, { name: 'AES-KW', length: 256 }, false, ['wrapKey', 'unwrapKey']);
}
async function wrapForInvite(roomKey, code, roomId) {
  return b64e(await subtle.wrapKey('raw', roomKey, await deriveInviteKwKey(code, roomId), 'AES-KW'));
}
async function unwrapFromInvite(wrappedB64, code, roomId) {
  return subtle.unwrapKey('raw', b64d(wrappedB64), await deriveInviteKwKey(code, roomId), 'AES-KW', { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}
async function encryptMessage(roomKey, text) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, roomKey, enc.encode(text));
  return { ciphertext: b64e(ct), iv: b64e(iv) };
}
async function decryptMessage(roomKey, ciphertextB64, ivB64) {
  const plain = await subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(b64d(ivB64)) }, roomKey, b64d(ciphertextB64));
  return dec.decode(plain);
}

// --- server harness ----------------------------------------------------------
let mongod;
let server;
let base;

async function api(path, { method = 'GET', token, body } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(`${base}${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const data = await res.json().catch(() => ({}));
  return { status: res.status, data };
}

async function signup(username, displayName) {
  const id = await genIdentity();
  const { status, data } = await api('/api/auth/signup', {
    method: 'POST',
    body: { username, displayName, password: 'testpass123', publicKeyJwk: id.publicJwk },
  });
  assert.equal(status, 201, `signup ${username}: ${JSON.stringify(data)}`);
  return { ...data, identity: id };
}

// Signup without asserting — for gate tests that expect 403s. `extra` merges
// into the request body (e.g. { signupCode }). Uses a dummy code only.
async function rawSignup(username, extra = {}) {
  const id = await genIdentity();
  return api('/api/auth/signup', {
    method: 'POST',
    body: { username, displayName: 'Gate Test', password: 'testpass123', publicKeyJwk: id.publicJwk, ...extra },
  });
}

before(async () => {
  // mongodb-memory-server's mongod binds a unix socket at /tmp/mongodb-<port>.sock.
  // If a previous run was killed, the stale socket makes mongod die with an
  // fassert() failure on startup. Clear them before starting.
  const fs = require('node:fs');
  for (const f of fs.readdirSync('/tmp')) {
    if (f.startsWith('mongodb-') && f.endsWith('.sock')) {
      try { fs.unlinkSync(`/tmp/${f}`); } catch { /* already gone */ }
    }
  }
  mongod = await MongoMemoryServer.create();
  process.env.MONGODB_URI = mongod.getUri();
  process.env.PORT = '0';
  process.env.JWT_SECRET = 'test-secret-for-tests-only';
  const { boot } = require('../server');
  server = await boot();
  const port = server.address().port;
  base = `http://127.0.0.1:${port}`;
});

after(async () => {
  if (server) await new Promise((resolve) => server.close(resolve));
  const mongoose = require('mongoose');
  await mongoose.disconnect();
  if (mongod) await mongod.stop();
});

test('health reports ok + connected db', async () => {
  const { status, data } = await api('/health');
  assert.equal(status, 200);
  assert.equal(data.ok, true);
  assert.equal(data.db, 'connected');
});

test('auth validation rejects bad usernames and short passwords', async () => {
  const badUser = await api('/api/auth/signup', {
    method: 'POST',
    body: { username: 'Bad Name!', displayName: 'X', password: 'testpass123' },
  });
  assert.equal(badUser.status, 400);
  const shortPass = await api('/api/auth/signup', {
    method: 'POST',
    body: { username: 'validuser', displayName: 'X', password: 'short' },
  });
  assert.equal(shortPass.status, 400);
});

test('full E2EE flow: create room, invite-code join, ciphertext-only storage, both members decrypt', async () => {
  const alice = await signup('alice', 'Alice A');
  const bob = await signup('bob', 'Bob B');

  // Wrong password must fail.
  const badLogin = await api('/api/auth/login', { method: 'POST', body: { username: 'alice', password: 'nope-nope-nope' } });
  assert.equal(badLogin.status, 401);

  // Alice creates a room (app flow: create, then post the invite wrap).
  const roomKey = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const selfWrapped = await wrapRoomKey(roomKey, alice.identity.privateKey, alice.identity.publicJwk);
  const created = await api('/api/rooms', {
    method: 'POST', token: alice.token,
    body: { name: 'test room', wrappedRoomKey: selfWrapped, inviteWrappedRoomKey: selfWrapped },
  });
  assert.equal(created.status, 201, JSON.stringify(created.data));
  const room = created.data.room;
  assert.equal(room.inviteCode.length, 6);
  const inviteWrapped = await wrapForInvite(roomKey, room.inviteCode, room.id);
  const fixed = await api(`/api/rooms/${room.id}/invite-key`, {
    method: 'POST', token: alice.token, body: { inviteWrappedRoomKey: inviteWrapped },
  });
  assert.equal(fixed.status, 200);

  // Bob joins with the invite code and unwraps the room key from the code.
  const joined = await api('/api/rooms/join', {
    method: 'POST', token: bob.token, body: { inviteCode: room.inviteCode },
  });
  assert.equal(joined.status, 200, JSON.stringify(joined.data));
  const bobRoomKey = await unwrapFromInvite(joined.data.room.inviteWrappedRoomKey, room.inviteCode, room.id);
  const bobSelfWrapped = await wrapRoomKey(bobRoomKey, bob.identity.privateKey, bob.identity.publicJwk);
  const stored = await api(`/api/rooms/${room.id}/wrapped-key`, {
    method: 'POST', token: bob.token, body: { wrappedRoomKey: bobSelfWrapped },
  });
  assert.equal(stored.status, 200);

  // Alice sends a message (ciphertext only).
  const plaintext = 'hello bob, this is secret 12345';
  const payload = await encryptMessage(roomKey, plaintext);
  const sent = await api(`/api/rooms/${room.id}/messages`, {
    method: 'POST', token: alice.token, body: payload,
  });
  assert.equal(sent.status, 201, JSON.stringify(sent.data));

  // The server stored ciphertext, never the plaintext.
  const history = await api(`/api/rooms/${room.id}/messages`, { token: bob.token });
  assert.equal(history.status, 200);
  assert.equal(history.data.messages.length, 1);
  const storedMsg = history.data.messages[0];
  assert.equal('plaintext' in storedMsg, false);
  assert.ok(!storedMsg.ciphertext.includes('secret'));
  assert.notEqual(storedMsg.ciphertext, plaintext);

  // Bob decrypts with the room key he unwrapped from the invite code.
  assert.equal(await decryptMessage(bobRoomKey, storedMsg.ciphertext, storedMsg.iv), plaintext);
  // Alice decrypts with her own room key too.
  assert.equal(await decryptMessage(roomKey, storedMsg.ciphertext, storedMsg.iv), plaintext);

  // ECDH invite-by-username: Alice wraps the room key for Carol.
  const carol = await signup('carol', 'Carol C');
  const forCarol = await wrapRoomKey(roomKey, alice.identity.privateKey, carol.identity.publicJwk);
  const added = await api(`/api/rooms/${room.id}/members`, {
    method: 'POST', token: alice.token, body: { username: 'carol', wrappedRoomKey: forCarol },
  });
  assert.equal(added.status, 201, JSON.stringify(added.data));
  const carolEntry = added.data.room.members.find((m) => m.username === 'carol');
  assert.ok(carolEntry);
  const carolRoomKey = await unwrapRoomKey(forCarol, carol.identity.privateKey, alice.identity.publicJwk);
  assert.equal(await decryptMessage(carolRoomKey, storedMsg.ciphertext, storedMsg.iv), plaintext);

  // Non-member cannot read, write, or list the room.
  const dave = await signup('dave', 'Dave D');
  assert.equal((await api(`/api/rooms/${room.id}/messages`, { token: dave.token })).status, 403);
  assert.equal((await api(`/api/rooms/${room.id}/messages`, {
    method: 'POST', token: dave.token, body: payload,
  })).status, 403);
  assert.equal((await api(`/api/rooms/${room.id}`, { token: dave.token })).status, 403);
  // No token at all -> 401.
  assert.equal((await api('/api/rooms')).status, 401);
});

test('socket: message delivered to a member, rejected for a non-member, auth required', async () => {
  const alice = await signup('alice2', 'Alice Two');
  const bob = await signup('bob2', 'Bob Two');
  const dave = await signup('dave2', 'Dave Two');

  const roomKey = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const selfWrapped = await wrapRoomKey(roomKey, alice.identity.privateKey, alice.identity.publicJwk);
  const created = await api('/api/rooms', {
    method: 'POST', token: alice.token,
    body: { name: 'socket room', wrappedRoomKey: selfWrapped, inviteWrappedRoomKey: selfWrapped },
  });
  const room = created.data.room;
  const inviteWrapped = await wrapForInvite(roomKey, room.inviteCode, room.id);
  await api(`/api/rooms/${room.id}/invite-key`, {
    method: 'POST', token: alice.token, body: { inviteWrappedRoomKey: inviteWrapped },
  });
  await api('/api/rooms/join', { method: 'POST', token: bob.token, body: { inviteCode: room.inviteCode } });

  const connectSocket = (token) => new Promise((resolve, reject) => {
    const s = io(base, { auth: token ? { token } : {}, reconnection: false });
    s.once('connect', () => resolve(s));
    s.once('connect_error', (err) => reject(err));
  });

  // Unauthenticated socket must be rejected.
  await assert.rejects(connectSocket(null), /Missing auth token/);

  const bobSocket = await connectSocket(bob.token);
  const daveSocket = await connectSocket(dave.token);
  try {
    // Bob joins the room channel.
    const bobJoin = await new Promise((resolve) => bobSocket.emit('room:join', room.id, resolve));
    assert.equal(bobJoin.ok, true);

    // Dave (non-member) is refused the room channel and cannot send.
    const daveJoin = await new Promise((resolve) => daveSocket.emit('room:join', room.id, resolve));
    assert.equal(daveJoin.ok, false);
    const daveSend = await new Promise((resolve) => {
      daveSocket.emit('message:send', { roomId: room.id, ciphertext: 'AAAA', iv: 'BBBB' }, resolve);
    });
    assert.equal(daveSend.ok, false);

    // Bob receives a realtime message Alice sends over the socket.
    const received = new Promise((resolve) => bobSocket.once('message:new', resolve));
    const payload = await encryptMessage(roomKey, 'realtime secret');
    const aliceSocket = await connectSocket(alice.token);
    try {
      const aliceJoin = await new Promise((resolve) => aliceSocket.emit('room:join', room.id, resolve));
      assert.equal(aliceJoin.ok, true);
      const ack = await new Promise((resolve) => {
        aliceSocket.emit('message:send', { roomId: room.id, ...payload }, resolve);
      });
      assert.equal(ack.ok, true);
      const msg = await received;
      assert.equal(msg.room, room.id);
      assert.equal(await decryptMessage(roomKey, msg.ciphertext, msg.iv), 'realtime secret');
    } finally {
      aliceSocket.disconnect();
    }
  } finally {
    bobSocket.disconnect();
    daveSocket.disconnect();
  }
});

test('signup gate: SIGNUP_CODE required when set, open when unset', async () => {
  const prev = process.env.SIGNUP_CODE; // undefined in this suite
  try {
    // Unset: open signup, and /api/config says so.
    delete process.env.SIGNUP_CODE;
    assert.equal((await api('/api/config')).data.signupCodeRequired, false);
    assert.equal((await rawSignup('gateopen')).status, 201);

    // Set: config says required; no code -> 403, wrong code -> 403.
    process.env.SIGNUP_CODE = 'TESTCODE123';
    assert.equal((await api('/api/config')).data.signupCodeRequired, true);
    const noCode = await rawSignup('gatenone');
    assert.equal(noCode.status, 403);
    assert.match(noCode.data.error || '', /Invite code/);
    const wrongCode = await rawSignup('gatewrong', { signupCode: 'NOTTHECODE' });
    assert.equal(wrongCode.status, 403);
    assert.match(wrongCode.data.error || '', /Invite code/);

    // Correct test code -> 201.
    assert.equal((await rawSignup('gateright', { signupCode: 'TESTCODE123' })).status, 201);
  } finally {
    // Restore exactly what was there before, so later tests are unaffected.
    if (prev === undefined) delete process.env.SIGNUP_CODE;
    else process.env.SIGNUP_CODE = prev;
  }
  // And signup is open again after the restore.
  assert.equal((await api('/api/config')).data.signupCodeRequired, false);
});

test('owner admin role: OWNER_USERNAME gates admin endpoints, owner can manage users/rooms', async () => {
  const prev = process.env.OWNER_USERNAME; // undefined in this suite
  try {
    // Unset: nobody is owner, admin endpoints are 403 even for a real user.
    delete process.env.OWNER_USERNAME;
    const plain = await signup('plainuser', 'Plain User');
    assert.equal(plain.user.isOwner, false);
    assert.equal((await api('/api/admin/users', { token: plain.token })).status, 403);
    assert.equal((await api('/api/admin/rooms', { token: plain.token })).status, 403);
    assert.equal((await api('/api/admin/users')).status, 401);

    // Set the owner (dummy username only).
    process.env.OWNER_USERNAME = 'owneruser';
    const owner = await signup('owneruser', 'Owner User');
    const regular = await signup('regularuser', 'Regular User');
    assert.equal(owner.user.isOwner, true);
    assert.equal((await api('/api/auth/me', { token: owner.token })).data.user.isOwner, true);
    assert.equal(regular.user.isOwner, false);
    assert.equal((await api('/api/auth/me', { token: regular.token })).data.user.isOwner, false);

    // Owner lists users and rooms; the shape is what the Admin panel needs.
    const users = await api('/api/admin/users', { token: owner.token });
    assert.equal(users.status, 200);
    const ownerRow = users.data.users.find((u) => u.username === 'owneruser');
    assert.ok(ownerRow && ownerRow.isOwner === true && ownerRow.displayName === 'Owner User' && ownerRow.createdAt);
    const regularRow = users.data.users.find((u) => u.username === 'regularuser');
    assert.ok(regularRow && regularRow.isOwner === false);
    assert.equal((await api('/api/admin/rooms', { token: owner.token })).status, 200);

    // Non-owner is 403 on every admin endpoint, even with a fake id.
    assert.equal((await api('/api/admin/users', { token: regular.token })).status, 403);
    assert.equal((await api('/api/admin/rooms', { token: regular.token })).status, 403);
    assert.equal((await api('/api/admin/rooms/fakeid', { method: 'DELETE', token: regular.token })).status, 403);
    assert.equal((await api(`/api/admin/users/${regular.user.id}`, { method: 'DELETE', token: regular.token })).status, 403);

    // Owner deletes a room: create one as regular, post a message, delete as owner.
    const roomKey = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    const selfWrapped = await wrapRoomKey(roomKey, regular.identity.privateKey, regular.identity.publicJwk);
    const created = await api('/api/rooms', {
      method: 'POST', token: regular.token,
      body: { name: 'owner test room', wrappedRoomKey: selfWrapped, inviteWrappedRoomKey: selfWrapped },
    });
    assert.equal(created.status, 201);
    const roomId = created.data.room.id;
    const payload = await encryptMessage(roomKey, 'bye room');
    assert.equal((await api(`/api/rooms/${roomId}/messages`, { method: 'POST', token: regular.token, body: payload })).status, 201);
    assert.equal((await api(`/api/admin/rooms/${roomId}`, { method: 'DELETE', token: owner.token })).status, 200);
    assert.equal((await api(`/api/rooms/${roomId}`, { token: owner.token })).status, 404);
    // Deleting a missing room -> 404.
    assert.equal((await api(`/api/admin/rooms/${roomId}`, { method: 'DELETE', token: owner.token })).status, 404);
    const roomsAfter = await api('/api/admin/rooms', { token: owner.token });
    assert.equal(roomsAfter.data.rooms.some((r) => r.id === roomId), false);

    // Owner cannot delete their own account.
    assert.equal((await api(`/api/admin/users/${owner.user.id}`, { method: 'DELETE', token: owner.token })).status, 403);

    // Owner deletes a user: invite them into the owner's room, have them post,
    // then delete — membership and their messages go away, and they can't log in.
    const ownerRoomKey = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    const ownerSelfWrapped = await wrapRoomKey(ownerRoomKey, owner.identity.privateKey, owner.identity.publicJwk);
    const ownerRoom = await api('/api/rooms', {
      method: 'POST', token: owner.token,
      body: { name: 'owner room', wrappedRoomKey: ownerSelfWrapped, inviteWrappedRoomKey: ownerSelfWrapped },
    });
    assert.equal(ownerRoom.status, 201);
    const ownerRoomId = ownerRoom.data.room.id;
    const forRegular = await wrapRoomKey(ownerRoomKey, owner.identity.privateKey, regular.identity.publicJwk);
    assert.equal((await api(`/api/rooms/${ownerRoomId}/members`, {
      method: 'POST', token: owner.token, body: { username: 'regularuser', wrappedRoomKey: forRegular },
    })).status, 201);
    const regPayload = await encryptMessage(ownerRoomKey, 'from regular');
    assert.equal((await api(`/api/rooms/${ownerRoomId}/messages`, { method: 'POST', token: regular.token, body: regPayload })).status, 201);
    assert.equal((await api(`/api/admin/users/${regular.user.id}`, { method: 'DELETE', token: owner.token })).status, 200);
    assert.equal((await api('/api/auth/login', { method: 'POST', body: { username: 'regularuser', password: 'testpass123' } })).status, 401);
    const roomNow = await api(`/api/rooms/${ownerRoomId}`, { token: owner.token });
    assert.equal(roomNow.status, 200);
    assert.equal(roomNow.data.room.members.some((m) => m.username === 'regularuser'), false);
    const historyNow = await api(`/api/rooms/${ownerRoomId}/messages`, { token: owner.token });
    assert.equal(historyNow.data.messages.length, 0);
    // Deleting a missing user -> 404.
    assert.equal((await api(`/api/admin/users/${regular.user.id}`, { method: 'DELETE', token: owner.token })).status, 404);
  } finally {
    // Restore exactly what was there before, so later tests are unaffected.
    if (prev === undefined) delete process.env.OWNER_USERNAME;
    else process.env.OWNER_USERNAME = prev;
  }
  // And nobody is owner again after the restore.
  const after = await signup('afterrestore', 'After Restore');
  assert.equal(after.user.isOwner, false);
});

test('avatarUrl: rejects attribute-breakout and non-http URLs, accepts https', async () => {
  // Stored-XSS vector: avatarUrl is rendered into <img src="..."> for every
  // user who sees the profile, so a quote must never reach storage.
  const breakout = await rawSignup('avatarxss', { avatarUrl: 'x" onerror="alert(1)' });
  assert.equal(breakout.status, 400);
  assert.match(breakout.data.error || '', /Avatar/);
  const jsScheme = await rawSignup('avatarjs', { avatarUrl: 'javascript:alert(1)' });
  assert.equal(jsScheme.status, 400);
  const withSpace = await rawSignup('avatarspace', { avatarUrl: 'https://example.com/a b.png' });
  assert.equal(withSpace.status, 400);
  const ok = await rawSignup('avatarok', { avatarUrl: 'https://example.com/a.png' });
  assert.equal(ok.status, 201, JSON.stringify(ok.data));
  assert.equal(ok.data.user.avatarUrl, 'https://example.com/a.png');
});

test('config: TURN credentials are never served anonymously, only to logged-in users', async () => {
  const prev = {
    url: process.env.TURN_URL,
    user: process.env.TURN_USERNAME,
    pass: process.env.TURN_PASSWORD,
  };
  try {
    process.env.TURN_URL = 'turn:turn.example.test:3478';
    process.env.TURN_USERNAME = 'turnuser';
    process.env.TURN_PASSWORD = 'turnpass-for-test-only';
    // Public config: no TURN anywhere, signup-gate flag still present.
    const pub = await api('/api/config');
    assert.equal(pub.status, 200);
    assert.equal('signupCodeRequired' in pub.data, true);
    assert.equal(JSON.stringify(pub.data).includes('turn.example.test'), false);
    assert.equal(JSON.stringify(pub.data).includes('turnpass-for-test-only'), false);
    // Authenticated ICE config: 401 without a token, TURN present with one.
    assert.equal((await api('/api/config/ice')).status, 401);
    const alice = await signup('iceuser', 'Ice User');
    const authed = await api('/api/config/ice', { token: alice.token });
    assert.equal(authed.status, 200);
    const turn = authed.data.iceServers.find((s) => s.urls === 'turn:turn.example.test:3478');
    assert.ok(turn, JSON.stringify(authed.data));
    assert.equal(turn.username, 'turnuser');
    assert.equal(turn.credential, 'turnpass-for-test-only');
  } finally {
    for (const [key, val] of [['TURN_URL', prev.url], ['TURN_USERNAME', prev.user], ['TURN_PASSWORD', prev.pass]]) {
      if (val === undefined) delete process.env[key];
      else process.env[key] = val;
    }
  }
});

test('boot fails fast with a clear message when MONGODB_URI is missing', async () => {
  const { code, stdout, stderr } = await new Promise((resolve) => {
    execFile(process.execPath, ['server.js'], {
      cwd: path.join(__dirname, '..'),
      env: { ...process.env, MONGODB_URI: '', PORT: '0' },
      timeout: 15000,
    }, (err, stdout, stderr) => resolve({ code: err?.code, stdout, stderr }));
  });
  assert.notEqual(code, 0);
  assert.match(stdout + stderr, /MONGODB_URI is not set/);
});
