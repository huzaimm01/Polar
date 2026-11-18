'use strict';
/* Polar v2 voice calls — WebRTC mesh, audio-only (Opus), no video yet.
 *
 * Signalling goes through Socket.io (call:join/offer/answer/ice). Media is
 * peer-to-peer and never touches the server. ICE defaults to Google's public
 * STUN servers; a TURN server can be configured via TURN_URL in .env and is
 * served to the client through /api/config — never hardcoded.
 *
 * Limits: mesh calls cap at 5 people in v1 (each peer sends one stream to
 * every other peer). Bigger groups need an SFU (e.g. LiveKit) — a v2 item.
 * Voice needs HTTPS in production (getUserMedia is blocked on plain HTTP,
 * except localhost). TURN is needed for strict/symmetric NATs.
 */
const PolarVoice = (() => {
  const MAX_PEERS = 5;
  let socket = null;
  let iceServers = [{ urls: 'stun:stun.l.google.com:19302' }, { urls: 'stun:stun1.l.google.com:19302' }];
  let localStream = null;
  let roomId = null;
  let myId = null;
  let inCall = false;
  let muted = false;
  const peers = new Map(); // peerId -> { pc, username, audioEl }
  const listeners = { state: [], peers: [] };

  function on(event, fn) { listeners[event].push(fn); }
  function emitState() {
    const state = {
      inCall, muted, roomId,
      peers: [...peers.values()].map((p) => ({ id: p.id, username: p.username })),
      count: peers.size + (inCall ? 1 : 0),
    };
    listeners.state.forEach((fn) => fn(state));
    listeners.peers.forEach((fn) => fn(state.peers));
  }

  async function loadConfig() {
    try {
      const res = await fetch('/api/config');
      const cfg = await res.json();
      if (Array.isArray(cfg.iceServers) && cfg.iceServers.length) iceServers = cfg.iceServers;
    } catch { /* keep STUN defaults */ }
  }

  function attach(ioSocket, userId) {
    socket = ioSocket;
    myId = userId;

    socket.on('call:peer-joined', async ({ roomId: r, peer }) => {
      if (r !== roomId || !inCall || peer.id === myId) return;
      await connectToPeer(peer.id, peer.username, true);
    });
    socket.on('call:peer-left', ({ roomId: r, peer }) => {
      if (r !== roomId) return;
      closePeer(peer.id);
    });
    socket.on('call:offer', async ({ roomId: r, from, data }) => {
      if (r !== roomId || !inCall) return;
      const peer = await connectToPeer(from.id, from.username, false);
      await peer.pc.setRemoteDescription(new RTCSessionDescription(data));
      const answer = await peer.pc.createAnswer();
      await peer.pc.setLocalDescription(answer);
      socket.emit('call:answer', { roomId, to: from.id, data: answer });
    });
    socket.on('call:answer', async ({ roomId: r, from, data }) => {
      if (r !== roomId || !inCall) return;
      const peer = peers.get(from.id);
      if (peer) await peer.pc.setRemoteDescription(new RTCSessionDescription(data));
    });
    socket.on('call:ice', async ({ roomId: r, from, data }) => {
      if (r !== roomId || !inCall || !data) return;
      const peer = peers.get(from.id);
      if (peer) { try { await peer.pc.addIceCandidate(new RTCIceCandidate(data)); } catch { /* late candidate */ } }
    });
  }

  async function connectToPeer(peerId, username, initiator) {
    if (peers.has(peerId)) return peers.get(peerId);
    const pc = new RTCPeerConnection({ iceServers });
    if (localStream) localStream.getTracks().forEach((t) => pc.addTrack(t, localStream));
    const audioEl = new Audio();
    audioEl.autoplay = true;
    pc.ontrack = (event) => { audioEl.srcObject = event.streams[0]; };
    pc.onicecandidate = (event) => {
      if (event.candidate) socket.emit('call:ice', { roomId, to: peerId, data: event.candidate });
    };
    const peer = { id: peerId, username: username || peerId, pc, audioEl };
    peers.set(peerId, peer);
    emitState();
    if (initiator) {
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      socket.emit('call:offer', { roomId, to: peerId, data: offer });
    }
    return peer;
  }

  function closePeer(peerId) {
    const peer = peers.get(peerId);
    if (!peer) return;
    try { peer.pc.close(); } catch { /* already closed */ }
    if (peer.audioEl.srcObject) peer.audioEl.srcObject.getTracks().forEach((t) => t.stop());
    peers.delete(peerId);
    emitState();
  }

  async function joinCall(activeRoomId) {
    if (inCall) return { ok: false, error: 'Already in a call' };
    if (!socket) return { ok: false, error: 'Not connected' };
    if (!navigator.mediaDevices?.getUserMedia) {
      return { ok: false, error: 'Microphone access is not available (voice needs HTTPS, or localhost).' };
    }
    await loadConfig();
    try {
      localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
    } catch {
      return { ok: false, error: 'Microphone permission was denied.' };
    }
    roomId = activeRoomId;
    const res = await new Promise((resolve) => {
      socket.emit('call:join', { roomId }, (r) => resolve(r || { ok: false }));
    });
    if (!res.ok) {
      localStream.getTracks().forEach((t) => t.stop());
      localStream = null; roomId = null;
      return { ok: false, error: res.error || 'Could not join the call' };
    }
    inCall = true;
    muted = false;
    // Connect to everyone already in the call.
    for (const peer of res.peers || []) {
      if (peer.id !== myId) await connectToPeer(peer.id, peer.username, true);
    }
    emitState();
    return { ok: true };
  }

  function leaveCall() {
    if (!inCall) return;
    if (socket && roomId) socket.emit('call:leave', { roomId });
    [...peers.keys()].forEach(closePeer);
    if (localStream) { localStream.getTracks().forEach((t) => t.stop()); localStream = null; }
    inCall = false;
    roomId = null;
    emitState();
  }

  function toggleMute() {
    if (!localStream) return muted;
    muted = !muted;
    localStream.getAudioTracks().forEach((t) => { t.enabled = !muted; });
    emitState();
    return muted;
  }

  return { on, attach, joinCall, leaveCall, toggleMute, MAX_PEERS, get inCall() { return inCall; } };
})();
