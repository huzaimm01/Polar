'use strict';
/* Polar v2 frontend — talks to the real API + Socket.io, decrypts locally.
 * No default users, no localStorage user/message stores. The server only ever
 * receives ciphertext; plaintext lives in this browser only.
 */
(() => {
  const $ = (id) => document.getElementById(id);
  const api = {
    async call(path, { method = 'GET', body, auth = true } = {}) {
      const headers = { 'Content-Type': 'application/json' };
      if (auth && state.token) headers.Authorization = `Bearer ${state.token}`;
      const res = await fetch(`/api${path}`, {
        method, headers, body: body ? JSON.stringify(body) : undefined,
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
      return data;
    },
  };

  const state = {
    token: localStorage.getItem('polar:token') || null,
    user: null,
    privateKey: null,
    rooms: [],
    activeRoom: null,      // room object from API
    roomKey: null,         // CryptoKey (AES-GCM) for the active room
    socket: null,
    onlineUsers: [],
    typingUsers: new Map(), // userId -> timeout
    inCall: false,
  };

  // ---------------------------------------------------------------- helpers
  function notify(message, type = 'success') {
    const n = $('notification');
    n.className = `notification ${type}`;
    $('notification-message').textContent = message;
    n.classList.add('show');
    setTimeout(() => n.classList.remove('show'), 3500);
  }

  function escapeHtml(s) {
    return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  // Inline SVG icons (no emoji anywhere in the UI). All stroke icons use
  // currentColor so they follow the theme; the star is a filled mark.
  const svgIcon = (inner) => `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${inner}</svg>`;
  const LOCK_SVG = svgIcon('<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>');
  const PHONE_SVG = svgIcon('<path d="M22 16.9v3a2 2 0 0 1-2.2 2 19.8 19.8 0 0 1-8.6-3.1 19.5 19.5 0 0 1-6-6A19.8 19.8 0 0 1 2.1 4.2 2 2 0 0 1 4.1 2h3a2 2 0 0 1 2 1.7c.13.96.36 1.9.7 2.8a2 2 0 0 1-.45 2.1L8.1 9.9a16 16 0 0 0 6 6l1.3-1.3a2 2 0 0 1 2.1-.45c.9.34 1.84.57 2.8.7A2 2 0 0 1 22 16.9Z"/>');
  const MIC_SVG = svgIcon('<rect x="9" y="2" width="6" height="12" rx="3"/><path d="M5 10a7 7 0 0 0 14 0"/><path d="M12 19v3"/>');
  const MIC_OFF_SVG = svgIcon('<path d="M2 2l20 20"/><path d="M9 5v6a3 3 0 0 0 5.1 2.1M15 9.5V5a3 3 0 0 0-5.7-1.3"/><path d="M17 16.9A7 7 0 0 1 5 10"/><path d="M12 19v3"/>');
  const MOON_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8Z"/></svg>';
  const SUN_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>';
  const STAR_SVG = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 1.5l2 7.8 7.8 2-7.8 2-2 7.8-2-7.8-7.8-2 7.8-2z"/></svg>';

  function avatarFor(user, size = 40) {
    if (user.avatarUrl) return user.avatarUrl;
    const initial = (user.displayName || user.username || '?').charAt(0).toUpperCase();
    const svg = `<svg xmlns='http://www.w3.org/2000/svg' width='${size}' height='${size}'><rect width='100%' height='100%' fill='#002137'/><text x='50%' y='68%' font-size='${Math.round(size * 0.55)}' font-family='sans-serif' fill='#FFFCF5' text-anchor='middle'>${initial}</text></svg>`;
    return `data:image/svg+xml,${encodeURIComponent(svg)}`;
  }

  function fmtTime(iso) {
    return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function fmtDate(iso) {
    return new Date(iso).toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric' });
  }

  // ------------------------------------------------------------- identity --
  async function ensureIdentity(password) {
    // Signup created the identity; login unlocks it with the password.
    if (PolarCrypto.hasIdentity()) {
      const key = await PolarCrypto.loadPrivateKey(password);
      if (!key) throw new Error('Wrong password, or this device has no saved key. (Your private key is locked with your password — if it is lost, old messages cannot be decrypted on a new device.)');
      state.privateKey = key;
      return;
    }
    // No identity on this device (e.g. signed up elsewhere): generate a fresh
    // one and upload the new public key. Old rooms' wrapped keys were made
    // for the old public key, so a member will need to re-invite this user.
    const { publicJwk, privateKey } = await PolarCrypto.generateIdentity(password);
    state.privateKey = privateKey;
    await api.call('/auth/public-key', { method: 'POST', body: { publicKeyJwk: publicJwk } });
    state.user.publicKeyJwk = publicJwk;
    notify('New device: a fresh encryption key was created. Ask a room member to re-invite you to restore old chats.', 'error');
  }

  // ------------------------------------------------------------ room keys --
  async function myPublicJwk() {
    return PolarCrypto.storedPublicJwk() || state.user.publicKeyJwk;
  }

  // Resolve the AES room key for a room object (from the API).
  async function resolveRoomKey(room) {
    const me = room.members.find((m) => m.id === state.user.id);
    if (!me) throw new Error('You are not a member of this room.');
    if (room.wrappedRoomKey) {
      const wrapper = room.members.find((m) => m.id === (room.wrappedBy || state.user.id));
      const wrapperKey = wrapper?.publicKeyJwk;
      if (!wrapperKey) throw new Error('Cannot find the key that wrapped this room key.');
      return PolarCrypto.unwrapRoomKey(room.wrappedRoomKey, state.privateKey, wrapperKey);
    }
    // Invite-code joiner: unwrap with the code, then store a self-wrapped key.
    if (room.inviteWrappedRoomKey && state.lastInviteCode) {
      const key = await PolarCrypto.unwrapRoomKeyFromInvite(room.inviteWrappedRoomKey, state.lastInviteCode, room.id);
      const selfWrapped = await PolarCrypto.wrapRoomKeyForSelf(key, state.privateKey, await myPublicJwk());
      await api.call(`/rooms/${room.id}/wrapped-key`, { method: 'POST', body: { wrappedRoomKey: selfWrapped } });
      room.wrappedRoomKey = selfWrapped;
      room.wrappedBy = state.user.id;
      return key;
    }
    throw new Error('No room key available. Ask a member to add you to this room.');
  }

  async function createRoom(name) {
    const roomKey = await PolarCrypto.generateRoomKey();
    const selfWrapped = await PolarCrypto.wrapRoomKeyForSelf(roomKey, state.privateKey, await myPublicJwk());
    // The invite code is only known after creation, so create first with a
    // placeholder invite wrap, then fix it once the code is known.
    const { room } = await api.call('/rooms', {
      method: 'POST',
      body: { name, wrappedRoomKey: selfWrapped, inviteWrappedRoomKey: selfWrapped },
    });
    const inviteWrapped = await PolarCrypto.wrapRoomKeyForInvite(roomKey, room.inviteCode, room.id);
    // The invite code is only known after creation, so the correct
    // invite-wrapped key is posted right after (creator-only route).
    await api.call(`/rooms/${room.id}/invite-key`, { method: 'POST', body: { inviteWrappedRoomKey: inviteWrapped } });
    return room;
  }

  async function joinRoomByCode(code) {
    const { room } = await api.call('/rooms/join', { method: 'POST', body: { inviteCode: code } });
    state.lastInviteCode = code.trim().toUpperCase();
    return room;
  }

  async function inviteMember(username) {
    const room = state.activeRoom;
    const { user } = await api.call(`/users/${encodeURIComponent(username)}`);
    if (!user.publicKeyJwk) throw new Error(`${username} has no encryption key yet (they need to sign in again).`);
    const wrapped = await PolarCrypto.wrapRoomKey(state.roomKey, state.privateKey, user.publicKeyJwk);
    const { room: updated } = await api.call(`/rooms/${room.id}/members`, {
      method: 'POST', body: { username, wrappedRoomKey: wrapped },
    });
    return updated;
  }

  // -------------------------------------------------------------- socket ---
  function connectSocket() {
    if (state.socket) state.socket.disconnect();
    const socket = io({ auth: { token: state.token } });
    state.socket = socket;
    PolarVoice.attach(socket, state.user.id);

    socket.on('connect_error', (err) => {
      console.warn('socket error:', err.message);
    });
    socket.on('message:new', async (msg) => {
      if (!state.activeRoom || msg.room !== state.activeRoom.id) return;
      await renderIncomingMessage(msg);
    });
    socket.on('presence', ({ roomId, users }) => {
      if (state.activeRoom && roomId === state.activeRoom.id) {
        state.onlineUsers = users;
        renderPresence();
      }
    });
    socket.on('typing:start', ({ roomId, username }) => {
      if (!state.activeRoom || roomId !== state.activeRoom.id || username === state.user.username) return;
      state.typingUsers.set(username, setTimeout(() => {
        state.typingUsers.delete(username);
        renderTyping();
      }, 3000));
      renderTyping();
    });
    socket.on('typing:stop', ({ username }) => {
      if (state.typingUsers.has(username)) {
        clearTimeout(state.typingUsers.get(username));
        state.typingUsers.delete(username);
        renderTyping();
      }
    });
  }

  // --------------------------------------------------------------- rooms ---
  async function loadRooms() {
    const { rooms } = await api.call('/rooms');
    state.rooms = rooms;
    renderRoomList();
    if (!state.activeRoom && rooms.length > 0) await openRoom(rooms[0].id);
    else if (rooms.length === 0) renderEmptyState();
  }

  async function openRoom(roomId) {
    const room = state.rooms.find((r) => r.id === roomId);
    if (!room) return;
    if (state.activeRoom) {
      state.socket?.emit('room:leave', state.activeRoom.id);
      if (state.inCall) PolarVoice.leaveCall();
    }
    state.activeRoom = room;
    state.typingUsers.clear();
    try {
      state.roomKey = await resolveRoomKey(room);
    } catch (err) {
      state.roomKey = null;
      renderRoom(room);
      $('messages').innerHTML = `<div class="text-center text-gray-500 my-4">${escapeHtml(err.message)}</div>`;
      return;
    }
    renderRoom(room);
    await loadHistory(room);
    state.socket?.emit('room:join', room.id, (res) => {
      if (res?.ok) { state.onlineUsers = res.users || []; renderPresence(); }
    });
  }

  async function loadHistory(room) {
    const { messages } = await api.call(`/rooms/${room.id}/messages?limit=100`);
    $('messages').innerHTML = '';
    if (!messages.length) {
      $('messages').innerHTML = '<div class="text-center text-gray-500 my-4">No messages yet.</div>';
      return;
    }
    for (const msg of messages) await renderIncomingMessage(msg, true);
    scrollToBottom();
  }

  async function renderIncomingMessage(msg, skipScroll) {
    const box = $('messages');
    const empty = box.querySelector('.text-center');
    if (empty) box.innerHTML = '';
    let text;
    try {
      text = state.roomKey
        ? await PolarCrypto.decryptMessage(state.roomKey, msg.ciphertext, msg.iv)
        : 'Encrypted message — no room key on this device.';
    } catch {
      text = 'Could not decrypt this message (wrong room key).';
    }
    const isSent = msg.sender.username === state.user.username;
    const el = document.createElement('div');
    el.className = `message bubble ${isSent ? 'sent' : ''} animate__animated ${isSent ? 'animate__fadeInRight' : 'animate__fadeInLeft'}`;
    el.innerHTML = `<strong>${escapeHtml(msg.sender.displayName)}:</strong> ${escapeHtml(text)}<div class="message-time">${fmtTime(msg.createdAt)}</div>`;
    box.appendChild(el);
    if (!skipScroll) scrollToBottom();
  }

  async function sendMessage() {
    const input = $('message-input');
    const text = input.value.trim();
    if (!text || !state.activeRoom || !state.roomKey) return;
    const { ciphertext, iv } = await PolarCrypto.encryptMessage(state.roomKey, text);
    input.value = '';
    state.socket?.emit('typing:stop', { roomId: state.activeRoom.id });
    state.socket?.emit('message:send', { roomId: state.activeRoom.id, ciphertext, iv }, (res) => {
      if (res && !res.ok) notify(res.error || 'Message failed to send', 'error');
    });
  }

  // -------------------------------------------------------------- render ---
  function renderRoomList() {
    const list = $('room-list');
    list.innerHTML = '';
    if (!state.rooms.length) {
      list.innerHTML = '<div class="constellation-empty">No rooms yet.</div>';
      return;
    }
    state.rooms.forEach((room) => {
      const el = document.createElement('div');
      el.className = 'user-item animate__animated animate__fadeIn';
      el.innerHTML = `<div class="mr-3"><img src="${avatarFor({ displayName: room.name }, 40)}" class="w-10 h-10 rounded-full avatar" alt=""></div>
        <div><div class="font-semibold">${escapeHtml(room.name)}</div>
        <div class="text-xs text-gray-500">${room.members.length} member${room.members.length === 1 ? '' : 's'}</div></div>`;
      el.addEventListener('click', () => openRoom(room.id));
      list.appendChild(el);
    });
  }

  function renderRoom(room) {
    $('chat-title').textContent = room.name;
    $('chat-member-count').textContent = `${room.members.length} member${room.members.length === 1 ? '' : 's'}`;
    $('invite-code').textContent = `Invite code: ${room.inviteCode}`;
    const members = $('member-list');
    members.innerHTML = '';
    room.members.forEach((m) => {
      const el = document.createElement('div');
      el.className = 'user-item';
      el.innerHTML = `<div class="relative mr-3"><img src="${avatarFor(m, 40)}" class="w-10 h-10 rounded-full avatar" alt="${escapeHtml(m.displayName)}">
        <span class="status-indicator ${state.onlineUsers.some((u) => u.id === m.id) ? 'status-online' : 'status-offline'} absolute bottom-0 right-0"></span></div>
        <div><div class="font-semibold">${escapeHtml(m.displayName)}</div>
        <div class="text-xs text-gray-500">@${escapeHtml(m.username)}</div></div>`;
      members.appendChild(el);
    });
    document.querySelectorAll('#room-list .user-item').forEach((el, i) => {
      el.classList.toggle('active-room', state.rooms[i]?.id === room.id);
    });
  }

  function renderPresence() {
    if (state.activeRoom) renderRoom(state.activeRoom);
    $('chat-status').textContent = state.onlineUsers.length
      ? `${state.onlineUsers.length} online in this room`
      : '';
  }

  function renderTyping() {
    const names = [...state.typingUsers.keys()];
    $('typing-indicator').style.display = names.length ? 'inline-block' : 'none';
    $('typing-text').textContent = names.length ? `${names.join(', ')} ${names.length === 1 ? 'is' : 'are'} typing…` : '';
  }

  function renderEmptyState() {
    $('chat-title').textContent = 'No room selected';
    $('chat-member-count').textContent = '';
    $('invite-code').textContent = '';
    $('member-list').innerHTML = '';
    $('messages').innerHTML = '<div class="text-center text-gray-500 my-4">No room selected.</div>';
  }

  function scrollToBottom() {
    const box = $('messages');
    box.scrollTop = box.scrollHeight;
  }

  function updateProfile() {
    const u = state.user;
    $('user-name').textContent = u.displayName;
    $('user-pfp').src = avatarFor(u, 80);
    $('user-pfp').alt = u.displayName;
  }

  // ------------------------------------------------------------ admin -----
  // Owner admin panel: a drawer opened from the meridian rail, visible
  // only when the logged-in user is the owner. Non-owners never see the
  // rail button or the drawer, and no admin requests are made for them.
  function refreshAdminPanel() {
    const panel = $('admin-panel');
    const railBtn = $('rail-admin-button');
    if (state.user && state.user.isOwner) {
      railBtn.classList.remove('hide');
      loadAdmin().catch((err) => notify(err.message, 'error'));
    } else {
      railBtn.classList.add('hide');
      panel.classList.add('hide');
      panel.classList.remove('open');
      $('admin-user-list').innerHTML = '';
      $('admin-room-list').innerHTML = '';
    }
  }

  function toggleAdminDrawer(open) {
    const panel = $('admin-panel');
    const shouldOpen = open !== undefined ? open : !panel.classList.contains('open');
    if (shouldOpen) {
      panel.classList.remove('hide');
      requestAnimationFrame(() => panel.classList.add('open'));
      // Lists are only loaded at login — refresh on open so a room or
      // user created since then shows up instead of stale data.
      if (state.user && state.user.isOwner) loadAdmin().catch((err) => notify(err.message, 'error'));
    } else {
      panel.classList.remove('open');
      setTimeout(() => panel.classList.add('hide'), 350);
    }
  }

  async function loadAdmin() {
    const { users } = await api.call('/admin/users');
    const { rooms } = await api.call('/admin/rooms');
    renderAdminUsers(users);
    renderAdminRooms(rooms);
  }

  function renderAdminUsers(users) {
    const list = $('admin-user-list');
    list.innerHTML = '';
    if (!users.length) {
      list.innerHTML = '<div class="text-center p-4 text-gray-500">No users.</div>';
      return;
    }
    users.forEach((u) => {
      const el = document.createElement('div');
      el.className = 'user-item admin-row';
      const isSelf = state.user && u.id === state.user.id;
      el.innerHTML = `<div class="mr-3"><img src="${avatarFor(u, 40)}" class="w-10 h-10 rounded-full avatar" alt=""></div>
        <div class="flex-grow"><div class="font-semibold">${escapeHtml(u.displayName)}${u.isOwner ? ` <span class="owner-mark">${STAR_SVG}OWNER</span>` : ''}</div>
        <div class="text-xs text-gray-500">@${escapeHtml(u.username)} · joined ${fmtDate(u.createdAt)}</div></div>`;
      if (!isSelf) {
        const btn = document.createElement('button');
        btn.className = 'btn btn-danger admin-delete';
        btn.textContent = 'Delete';
        btn.addEventListener('click', () => deleteAdminUser(u.id, u.username));
        el.appendChild(btn);
      }
      list.appendChild(el);
    });
  }

  function renderAdminRooms(rooms) {
    const list = $('admin-room-list');
    list.innerHTML = '';
    if (!rooms.length) {
      list.innerHTML = '<div class="text-center p-4 text-gray-500">No rooms.</div>';
      return;
    }
    rooms.forEach((r) => {
      const el = document.createElement('div');
      el.className = 'user-item admin-row';
      el.innerHTML = `<div class="flex-grow"><div class="font-semibold">${escapeHtml(r.name)}</div>
        <div class="text-xs text-gray-500">Code ${escapeHtml(r.inviteCode)} · ${r.memberCount} member${r.memberCount === 1 ? '' : 's'} · ${fmtDate(r.createdAt)}</div></div>`;
      const btn = document.createElement('button');
      btn.className = 'btn btn-danger admin-delete';
      btn.textContent = 'Delete';
      btn.addEventListener('click', () => deleteAdminRoom(r.id, r.name));
      el.appendChild(btn);
      list.appendChild(el);
    });
  }

  async function deleteAdminUser(id, username) {
    if (!confirm(`Delete @${username}? Their room memberships and the messages they sent will be removed. This cannot be undone.`)) return;
    try {
      await api.call(`/admin/users/${id}`, { method: 'DELETE' });
      notify(`Deleted @${username}.`);
      await loadAdmin();
      await loadRooms();
      await refreshActiveRoom();
    } catch (err) { notify(err.message, 'error'); }
  }

  async function deleteAdminRoom(id, name) {
    if (!confirm(`Delete room "${name}" and all of its messages? This cannot be undone.`)) return;
    try {
      await api.call(`/admin/rooms/${id}`, { method: 'DELETE' });
      notify(`Deleted room "${name}".`);
      const wasActive = state.activeRoom && state.activeRoom.id === id;
      state.rooms = state.rooms.filter((r) => r.id !== id);
      if (wasActive) {
        state.activeRoom = null;
        state.roomKey = null;
        renderEmptyState();
      }
      renderRoomList();
      await loadAdmin();
      if (wasActive) await loadRooms();
    } catch (err) { notify(err.message, 'error'); }
  }

  // Re-fetch the active room so the sidebar member list reflects an admin
  // change (e.g. a deleted user) without reopening the room.
  async function refreshActiveRoom() {
    if (!state.activeRoom) return;
    try {
      const { room } = await api.call(`/rooms/${state.activeRoom.id}`);
      state.activeRoom = room;
      state.rooms = state.rooms.map((r) => (r.id === room.id ? room : r));
      renderRoom(room);
    } catch { /* room may have been deleted; the caller handles that */ }
  }

  function showAuth() {
    $('auth-container').classList.remove('hide');
    $('main-container').classList.add('hide');
  }

  function showMain() {
    $('auth-container').classList.add('hide');
    $('main-container').classList.remove('hide');
    updateProfile();
    refreshAdminPanel();
  }

  // ---------------------------------------------------------------- auth ---
  async function doLogin(username, password) {
    const { token, user } = await api.call('/auth/login', {
      method: 'POST', auth: false, body: { username, password },
    });
    state.token = token;
    state.user = user;
    localStorage.setItem('polar:token', token);
    await ensureIdentity(password);
    afterAuth();
  }

  async function doSignup(displayName, username, password, bio, avatarUrl, signupCode) {
    // Generate the encryption identity first — the public key is uploaded
    // with the signup request. The private key never leaves this browser.
    const { publicJwk } = await PolarCrypto.generateIdentity(password);
    const body = { username, displayName, password, bio, avatarUrl, publicKeyJwk: publicJwk };
    // Friends-only gate: only sent when the instance requires it.
    if (signupCode) body.signupCode = signupCode;
    const { token, user } = await api.call('/auth/signup', {
      method: 'POST', auth: false, body,
    });
    state.token = token;
    state.user = user;
    state.privateKey = await PolarCrypto.loadPrivateKey(password);
    localStorage.setItem('polar:token', token);
    afterAuth();
  }

  function afterAuth() {
    showMain();
    connectSocket();
    loadRooms().catch((err) => notify(err.message, 'error'));
  }

  function logout() {
    if (state.inCall) PolarVoice.leaveCall();
    state.socket?.disconnect();
    state.socket = null;
    state.token = null;
    state.user = null;
    state.privateKey = null;
    state.rooms = [];
    state.activeRoom = null;
    state.roomKey = null;
    $('admin-panel').classList.add('hide');
    $('admin-panel').classList.remove('open');
    $('rail-admin-button').classList.add('hide');
    $('admin-user-list').innerHTML = '';
    $('admin-room-list').innerHTML = '';
    localStorage.removeItem('polar:token');
    showAuth();
  }

  // ---------------------------------------------------------------- voice --
  function wireVoice() {
    PolarVoice.on('state', (s) => {
      state.inCall = s.inCall;
      $('call-button').innerHTML = s.inCall ? `${PHONE_SVG}<span>Leave call</span>` : `${PHONE_SVG}<span>Call</span>`;
      $('call-bar').classList.toggle('hide', !s.inCall);
      $('call-participants').textContent = s.inCall
        ? `In call (${s.count}/${PolarVoice.MAX_PEERS} max): you${s.peers.length ? ', ' + s.peers.map((p) => p.username).join(', ') : ''}`
        : '';
      $('mute-button').innerHTML = s.muted ? `${MIC_OFF_SVG}<span>Unmute</span>` : `${MIC_SVG}<span>Mute</span>`;
    });
    $('call-button').addEventListener('click', async () => {
      if (!state.activeRoom) return notify('Open a room first.', 'error');
      if (state.inCall) { PolarVoice.leaveCall(); return; }
      const res = await PolarVoice.joinCall(state.activeRoom.id);
      if (!res.ok) notify(res.error || 'Could not join call', 'error');
    });
    $('mute-button').addEventListener('click', () => PolarVoice.toggleMute());
    $('leave-call-button').addEventListener('click', () => PolarVoice.leaveCall());
  }

  function bindEvents() {
    // Auth
    $('login-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      try {
        await doLogin($('login-username').value.trim(), $('login-password').value);
        notify('Login successful!');
      } catch (err) { notify(err.message, 'error'); }
    });
    $('signup-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      try {
        await doSignup(
          $('signup-fullname').value.trim(),
          $('signup-username').value.trim(),
          $('signup-password').value,
          $('signup-bio').value.trim(),
          $('signup-avatar').value.trim(),
          $('signup-code').value.trim(),
        );
        notify('Account created.');
      } catch (err) { notify(err.message, 'error'); }
    });
    $('switch-to-signup').addEventListener('click', (e) => {
      e.preventDefault();
      $('login-form').classList.add('hide');
      $('signup-form').classList.remove('hide');
    });
    $('switch-to-login').addEventListener('click', (e) => {
      e.preventDefault();
      $('signup-form').classList.add('hide');
      $('login-form').classList.remove('hide');
    });
    $('logout-button').addEventListener('click', () => { logout(); notify('Logged out'); });

    // Theme — dark is the default, matching the portfolio.
    let darkMode = localStorage.getItem('theme') !== 'light';
    const applyTheme = () => {
      document.body.classList.toggle('dark', darkMode);
      $('toggle-theme').innerHTML = darkMode ? SUN_SVG : MOON_SVG;
      $('polar-logo').src = darkMode ? 'polar2.png' : 'polar1.png';
      $('auth-logo').src = darkMode ? 'polar2.png' : 'polar1.png';
      localStorage.setItem('theme', darkMode ? 'dark' : 'light');
    };
    applyTheme();
    $('toggle-theme').addEventListener('click', () => { darkMode = !darkMode; applyTheme(); });

    // Rooms
    $('create-room-button').addEventListener('click', async () => {
      const name = $('new-room-name').value.trim();
      if (!name) return notify('Enter a room name first.', 'error');
      try {
        const room = await createRoom(name);
        $('new-room-name').value = '';
        state.rooms.push(room);
        renderRoomList();
        notify(`Room "${room.name}" created — invite code ${room.inviteCode}`);
        await openRoom(room.id);
      } catch (err) { notify(err.message, 'error'); }
    });
    $('join-room-button').addEventListener('click', async () => {
      const code = $('join-code').value.trim();
      if (!code) return notify('Enter an invite code.', 'error');
      try {
        const room = await joinRoomByCode(code);
        $('join-code').value = '';
        if (!state.rooms.some((r) => r.id === room.id)) state.rooms.push(room);
        renderRoomList();
        notify(`Joined "${room.name}"`);
        await openRoom(room.id);
      } catch (err) { notify(err.message, 'error'); }
    });
    $('copy-invite-button').addEventListener('click', async () => {
      if (!state.activeRoom) return;
      try {
        await navigator.clipboard.writeText(state.activeRoom.inviteCode);
        notify(`Invite code ${state.activeRoom.inviteCode} copied — share it with your friends.`);
      } catch { notify(`Invite code: ${state.activeRoom.inviteCode}`); }
    });
    $('invite-member-button').addEventListener('click', async () => {
      const username = $('invite-username').value.trim().toLowerCase();
      if (!username) return notify('Enter a username to invite.', 'error');
      if (!state.activeRoom || !state.roomKey) return notify('Open a room first.', 'error');
      try {
        const updated = await inviteMember(username);
        $('invite-username').value = '';
        Object.assign(state.activeRoom, updated);
        state.rooms = state.rooms.map((r) => (r.id === updated.id ? updated : r));
        renderRoom(updated);
        notify(`${username} added to the room.`);
      } catch (err) { notify(err.message, 'error'); }
    });

    // Messaging
    $('send-message').addEventListener('click', () => sendMessage());
    $('message-input').addEventListener('keypress', (e) => {
      if (e.key === 'Enter') sendMessage();
    });
    let typingTimer = null;
    $('message-input').addEventListener('input', () => {
      if (!state.activeRoom || !state.socket) return;
      state.socket.emit('typing:start', { roomId: state.activeRoom.id });
      clearTimeout(typingTimer);
      typingTimer = setTimeout(() => {
        state.socket?.emit('typing:stop', { roomId: state.activeRoom.id });
      }, 2000);
    });

    // Admin drawer (owner only — the rail button is hidden otherwise).
    $('rail-admin-button').addEventListener('click', () => toggleAdminDrawer());
    $('admin-close').addEventListener('click', () => toggleAdminDrawer(false));

    window.addEventListener('beforeunload', () => {
      if (state.socket) state.socket.disconnect();
    });
  }

  // Friends-only signup gate: show the invite-code field (and require it)
  // only when the server says this instance requires one. Defaults to
  // hidden/open if the config fetch fails.
  async function applySignupGate() {
    try {
      const cfg = await api.call('/config', { auth: false });
      const required = !!cfg.signupCodeRequired;
      $('signup-code-group').classList.toggle('hide', !required);
      $('signup-code').required = required;
    } catch {
      $('signup-code-group').classList.add('hide');
      $('signup-code').required = false;
    }
  }

  async function boot() {
    bindEvents();
    wireVoice();
    await applySignupGate();
    if (state.token) {
      try {
        const { user } = await api.call('/auth/me');
        state.user = user;
        showMain();
        // Private key unlock needs the password: ask for it once per device.
        const password = prompt('Enter your password:');
        if (!password) { logout(); notify('Password is needed to unlock your encrypted chats.', 'error'); return; }
        try {
          await ensureIdentity(password);
        } catch (err) {
          logout();
          notify(err.message, 'error');
          return;
        }
        connectSocket();
        await loadRooms();
      } catch {
        logout();
        showAuth();
      }
    } else {
      showAuth();
    }
  }

  document.addEventListener('DOMContentLoaded', boot);
})();
