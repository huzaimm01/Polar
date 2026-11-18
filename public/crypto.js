'use strict';
/* Polar v2 client crypto — WebCrypto only, no extra dependencies.
 *
 * How it works (honest version):
 *  - Each user has an ECDH P-256 keypair. The public key is uploaded on signup.
 *    The private key NEVER leaves the browser: it is encrypted with a key
 *    derived from the user's password (PBKDF2, 100k iterations) via AES-GCM
 *    and stored in localStorage.
 *  - Each room has a random 256-bit AES-GCM room key, made in the creator's
 *    browser. It reaches members in two ways:
 *      a) Invite by username: an existing member wraps it for the new member
 *         with ECDH (my private + their public) -> HKDF -> AES-KW. Only the
 *         new member can unwrap it (ECDH with their private + the
 *         wrapper's public). The server stores the wrapped key + who
 *         wrapped it, and cannot unwrap it.
 *      b) Join by invite code: the creator also wraps the room key with a key
 *         derived from the invite code itself (PBKDF2). Anyone who knows the
 *         code can unwrap the room key — treat the code like a password and
 *         only share it with people you trust (see README Security notes).
 *         After joining, the member re-wraps the key for themselves
 *         (self-ECDH) and stores that, so they no longer need the code.
 *  - Messages are encrypted in the browser with the room key (fresh random
 *    12-byte IV per message). The server only ever sees ciphertext + IV.
 *
 * Limits (see README "Security notes"): the server operator could serve
 * malicious JS or add a member; losing your password loses your private key
 * and your old history on a new device; no forward secrecy in v1.
 */
const PolarCrypto = (() => {
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  const b64 = {
    encode(buf) {
      const bytes = new Uint8Array(buf);
      let s = '';
      for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
      return btoa(s);
    },
    decode(str) {
      const s = atob(str);
      const bytes = new Uint8Array(s.length);
      for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
      return bytes.buffer;
    },
  };

  const LS_KEYS = {
    privateKey: 'polar:privateKey', // AES-GCM-encrypted JWK {ciphertext, iv, salt}
    publicKey: 'polar:publicKey',   // plain JWK (public — fine to store)
  };

  // --- password-derived key wrapping for the private key -------------------
  async function derivePasswordKey(password, salt) {
    const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  }

  async function generateIdentity(password) {
    const keypair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey'],
    );
    const publicJwk = await crypto.subtle.exportKey('jwk', keypair.publicKey);
    const privateJwk = await crypto.subtle.exportKey('jwk', keypair.privateKey);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const wrapKey = await derivePasswordKey(password, salt);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, wrapKey, enc.encode(JSON.stringify(privateJwk)),
    );
    localStorage.setItem(LS_KEYS.privateKey, JSON.stringify({
      ciphertext: b64.encode(ciphertext), iv: b64.encode(iv), salt: b64.encode(salt),
    }));
    localStorage.setItem(LS_KEYS.publicKey, JSON.stringify(publicJwk));
    return { publicJwk, privateKey: keypair.privateKey };
  }

  async function loadPrivateKey(password) {
    const stored = localStorage.getItem(LS_KEYS.privateKey);
    if (!stored) return null;
    const { ciphertext, iv, salt } = JSON.parse(stored);
    const wrapKey = await derivePasswordKey(password, b64.decode(salt));
    let plain;
    try {
      plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(b64.decode(iv)) },
        wrapKey, b64.decode(ciphertext),
      );
    } catch {
      return null; // wrong password
    }
    const jwk = JSON.parse(dec.decode(plain));
    return crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
  }

  function hasIdentity() {
    return !!localStorage.getItem(LS_KEYS.privateKey);
  }

  function storedPublicJwk() {
    const raw = localStorage.getItem(LS_KEYS.publicKey);
    return raw ? JSON.parse(raw) : null;
  }

  function clearIdentity() {
    localStorage.removeItem(LS_KEYS.privateKey);
    localStorage.removeItem(LS_KEYS.publicKey);
  }

  // --- room keys ------------------------------------------------------------
  async function generateRoomKey() {
    return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  }

  async function importRoomKey(rawB64) {
    return crypto.subtle.importKey('raw', b64.decode(rawB64), { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  }

  // Shared ECDH -> HKDF -> AES-KW derivation. Both sides derive the same key:
  // wrap uses (myPrivate, theirPublic); unwrap uses (theirPrivate, myPublic).
  async function deriveKwKey(myPrivateKey, theirPublicJwk) {
    const theirPublic = await crypto.subtle.importKey(
      'jwk', theirPublicJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, [],
    );
    const shared = await crypto.subtle.deriveKey(
      { name: 'ECDH', public: theirPublic }, myPrivateKey,
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('polar-room-key-v1') },
      false, ['deriveKey'],
    );
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('polar-room-key-v1') },
      shared, { name: 'AES-KW', length: 256 }, false, ['wrapKey', 'unwrapKey'],
    );
  }

  // Wrap a room key for another member (inviting by username).
  async function wrapRoomKey(roomKey, myPrivateKey, theirPublicJwk) {
    const kwKey = await deriveKwKey(myPrivateKey, theirPublicJwk);
    return b64.encode(await crypto.subtle.wrapKey('raw', roomKey, kwKey, 'AES-KW'));
  }

  // Unwrap a room key that was wrapped for me. `wrapperPublicJwk` is the
  // public key of whoever wrapped it (for a self-wrap, my own public key).
  async function unwrapRoomKey(wrappedB64, myPrivateKey, wrapperPublicJwk) {
    const kwKey = await deriveKwKey(myPrivateKey, wrapperPublicJwk);
    return crypto.subtle.unwrapKey(
      'raw', b64.decode(wrappedB64), kwKey, 'AES-KW',
      { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'],
    );
  }

  // Wrap the room key for myself (creator at creation, or after joining by
  // invite code). Self-wrap = ECDH(myPrivate, myPublic).
  async function wrapRoomKeyForSelf(roomKey, myPrivateKey, myPublicJwk) {
    return wrapRoomKey(roomKey, myPrivateKey, myPublicJwk);
  }

  // --- invite-code wrapping ---------------------------------------------------
  // The invite code doubles as a shared secret: the room key wrapped with a
  // key derived from the code. Anyone with the code can unwrap it — that is
  // the documented tradeoff that makes code-joining possible without an
  // online member. Salt is the room id, so codes are not reusable across rooms.
  async function deriveInviteKwKey(inviteCode, roomId) {
    const base = await crypto.subtle.importKey('raw', enc.encode(inviteCode), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: enc.encode(`polar-invite:${roomId}`), iterations: 100000, hash: 'SHA-256' },
      base, { name: 'AES-KW', length: 256 }, false, ['wrapKey', 'unwrapKey'],
    );
  }

  async function wrapRoomKeyForInvite(roomKey, inviteCode, roomId) {
    const kwKey = await deriveInviteKwKey(inviteCode, roomId);
    return b64.encode(await crypto.subtle.wrapKey('raw', roomKey, kwKey, 'AES-KW'));
  }

  async function unwrapRoomKeyFromInvite(wrappedB64, inviteCode, roomId) {
    const kwKey = await deriveInviteKwKey(inviteCode, roomId);
    return crypto.subtle.unwrapKey(
      'raw', b64.decode(wrappedB64), kwKey, 'AES-KW',
      { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'],
    );
  }

  // --- messages ---------------------------------------------------------------
  async function encryptMessage(roomKey, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, roomKey, enc.encode(plaintext),
    );
    return { ciphertext: b64.encode(ciphertext), iv: b64.encode(iv) };
  }

  async function decryptMessage(roomKey, ciphertextB64, ivB64) {
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(b64.decode(ivB64)) },
      roomKey, b64.decode(ciphertextB64),
    );
    return dec.decode(plain);
  }

  return {
    b64,
    generateIdentity, loadPrivateKey, hasIdentity, storedPublicJwk, clearIdentity,
    generateRoomKey, importRoomKey,
    wrapRoomKey, unwrapRoomKey, wrapRoomKeyForSelf,
    wrapRoomKeyForInvite, unwrapRoomKeyFromInvite,
    encryptMessage, decryptMessage,
  };
})();
