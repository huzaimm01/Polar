# Polar v2 — Connect Your Circle

Real chat rooms for you and your friends, end-to-end encrypted. Polar v1 was a
single static page with fake users (`password123` for everyone), messages in
`localStorage`, and a typing indicator that lied. V2 is a real backend: one
MongoDB connection string is all it takes to deploy.

## Deploy in 3 steps

1. **Get a free database.** Create a free MongoDB Atlas cluster (M0 tier) at
   <https://cloud.mongodb.com> → *Connect* → *Drivers* → copy the connection string.
2. **Paste the one key.**
   ```bash
   cp .env.example .env
   # open .env and paste your connection string as MONGODB_URI
   ```
3. **Run it.**
   ```bash
   npm install && npm start
   # open http://localhost:3000
   ```

That's it. `MONGODB_URI` is the **only required setting**. `PORT` defaults to
3000. `JWT_SECRET` is optional — without one, Polar generates a random secret
at boot and logs a warning; sessions are invalidated on restart, so set one
for any real deployment.

If `MONGODB_URI` is missing, Polar refuses to start and tells you exactly what
to do. It never silently falls back to `localStorage` or an insecure store.

### One-click options

- **Render:** `render.yaml` is included (New → Blueprint in the Render
  dashboard, then set `MONGODB_URI`). A `JWT_SECRET` is generated for you.
- **Docker:** `docker build -t polar . && docker run -e MONGODB_URI=... -p 3000:3000 polar`

### Local testing without Atlas

```bash
npm run dev:memory   # ephemeral in-memory MongoDB, data lost on exit
npm test             # full test suite, also in-memory
```

## Friends-only signup (optional)

By default signup is open — anyone who can reach your instance can create an
account. If you host an instance for just yourself and your friends, set
`SIGNUP_CODE` to a private code (as an env var in your host dashboard, e.g.
Render — never commit it) and share it with your friends only. Signup then
requires the code, and the signup form only shows the invite-code field when
the server requires it. Self-hosting from a clone? Leave `SIGNUP_CODE` unset
and signup stays open, or set your own code for your own friends.

## Owner account (optional)

By default nobody has special powers. If you host an instance, set
`OWNER_USERNAME` to your own username (as an env var in your host dashboard —
never commit it) and your account becomes the owner: an Admin panel appears
in the sidebar where you can see every user and room, and delete rooms (with
their messages) or users (with their memberships and messages). You still log
in with your normal password — the env var only marks which account is the
owner. The owner cannot delete their own account. Leave `OWNER_USERNAME`
unset and nobody is owner.

## How it works

| Piece | Tech |
| --- | --- |
| Server | Node 24, Express, Socket.io, Mongoose |
| Auth | bcrypt (12 rounds), JWT (7 days) |
| Realtime | Socket.io — messages, typing, presence, call signalling |
| Encryption | Browser WebCrypto only — no crypto dependencies |
| Voice | WebRTC mesh, audio-only (Opus), signalling via Socket.io |

**Rooms.** Create a room, share its 6-character invite code, or add a friend by
username. Each room has its own encryption key.

**Messages.** Encrypted in your browser with the room's AES-GCM key (fresh
random IV per message). The server stores ciphertext + IV only, and relays it
to room members over Socket.io. Plaintext never reaches the server.

**Typing & presence.** Real this time — `typing:start/stop` and online users
are per-room, from actual sockets. Non-members are rejected from room channels.

## Encryption — the honest version

- **Identity:** on signup, your browser generates an ECDH P-256 keypair. The
  public key is uploaded; the **private key never leaves your browser** — it is
  encrypted with a key derived from your password (PBKDF2, 100k iterations,
  AES-GCM) and stored in `localStorage`. Your password unlocks it on login.
- **Room keys:** each room has a random 256-bit AES-GCM key, generated in the
  creator's browser. It is wrapped for each member with ECDH + HKDF + AES-KW,
  so only that member can unwrap it. The server stores wrapped keys only.
- **Joining by invite code:** the creator also wraps the room key with a key
  derived from the invite code itself (PBKDF2). Anyone who knows the code can
  unwrap the room key — that is the tradeoff that lets code-joining work
  without an online member. **Treat an invite code like a password** and only
  share it with people you trust. After joining, your browser re-wraps the key
  for you, so you no longer need the code.
- **Joining by username:** an existing member wraps the room key for the new
  member's public key in their browser. No shared code involved.

### Security notes — what Polar v2 does *not* do

- **The server operator could serve malicious JavaScript** or add themselves
  to a room. This is true of every web-based E2EE chat; Polar does not claim
  otherwise. If you don't trust the person running the server, don't use their
  instance — run your own (that's the point of the one-key deploy).
- **Losing your password loses your private key**, and with it your old
  messages on a new device. There is no password reset for encryption keys.
  A room member can re-invite you so you can read new messages, but old
  history stays locked. (Key backup/export is a planned v2 item.)
- **No forward secrecy in v1.** Room keys don't rotate yet; if a room key
  ever leaks, past messages in that room could be decrypted. Key rotation is
  a planned v2 item.
- **No independent security audit.** This is a small project built on standard
  WebCrypto primitives (ECDH P-256, HKDF-SHA-256, AES-GCM, AES-KW, PBKDF2).
  It is not the Signal protocol, and nothing here is "military-grade" or
  "unbreakable".

## Voice calls

Yes — voice calls work. Audio-only in v1 (Opus), peer-to-peer WebRTC mesh:

- Click **📞 Call** in a room header. Media flows directly between browsers;
  the server only relays signalling (offers/answers/ICE).
- Mute/unmute and leave from the in-call bar. Calls cap at **5 people** in v1
  (mesh = every peer sends a stream to every other peer). Bigger groups need
  an SFU (e.g. LiveKit free tier) — a v2 item.
- ICE defaults to Google's public STUN servers. For strict/symmetric NATs you
  need a TURN server: set `TURN_URL` (+ `TURN_USERNAME` / `TURN_PASSWORD`) in
  `.env`. TURN credentials are never hardcoded; the client fetches them from
  `/api/config`.
- **Voice needs HTTPS in production** (microphone access is blocked on plain
  HTTP). `localhost` is fine for testing.

## Project layout

```
server.js            entry point — env checks, fail-fast, static + API + sockets
server/
  models.js          User / Room / Message schemas (ciphertext only)
  auth.js            JWT helpers + Express auth middleware
  routes.js          REST API: auth, users, rooms, messages
  socket.js          Socket.io: rooms, messages, typing, presence, call signalling
public/
  index.html         app shell (Polar look: Josefin Sans, #f5f3f5 / #13293D, #1E88E5)
  style.css          styles extracted from v1 + v2 additions
  crypto.js          WebCrypto E2EE (identity, room keys, message encrypt/decrypt)
  voice.js           WebRTC mesh voice calls
  app.js             UI + API + socket wiring
test/test.js         `npm test` — full flow incl. real decrypt checks
old/                 untouched v1 files + old/index-v1-legacy.html (backup of v1)
```

## API sketch

```
POST /api/auth/signup {username, displayName, password, bio?, avatarUrl?, publicKeyJwk, signupCode?}  (signupCode required only when SIGNUP_CODE is set)
POST /api/auth/login  {username, password}            -> {token, user}
GET  /api/auth/me                                     -> {user}
POST /api/auth/public-key {publicKeyJwk}              -> rotate keys on a new device
GET  /api/users/:username                             -> {user} (public key for inviting)
POST /api/rooms {name, wrappedRoomKey, inviteWrappedRoomKey}
POST /api/rooms/join {inviteCode}
GET  /api/rooms                                       -> my rooms (with my wrapped key)
GET  /api/rooms/:id/members
POST /api/rooms/:id/members {username, wrappedRoomKey}
POST /api/rooms/:id/wrapped-key {wrappedRoomKey}      -> store my own wrapped key
POST /api/rooms/:id/invite-key {inviteWrappedRoomKey} -> creator only
GET  /api/rooms/:id/messages?limit=100                -> ciphertexts, oldest first
POST /api/rooms/:id/messages {ciphertext, iv}
GET  /api/admin/users                                  -> owner only: all users
GET  /api/admin/rooms                                  -> owner only: all rooms
DELETE /api/admin/rooms/:id                           -> owner only: room + its messages
DELETE /api/admin/users/:id                           -> owner only: user + memberships + their messages (not self)
GET  /health                                          -> {ok, db}
GET  /api/config                                      -> {iceServers, maxCallPeers, signupCodeRequired}
```

Socket.io (JWT in handshake `auth.token`): `room:join/leave`,
`message:send` → `message:new`, `typing:start/stop`, `presence`,
`call:join/leave/offer/answer/ice`, `call:peer-joined/left`.

## Notes / known gaps

- v1's default users (`huzaim`, `mussab`, … / `password123`) are gone, along
  with all `localStorage` user/message stores. Everyone signs up fresh.
- `old/` is untouched. The v1 single-file app is backed up at
  `old/index-v1-legacy.html`.
- New-device login asks for your password again to unlock the encryption keys
  (the JWT alone is not enough). If the device has no saved key, a fresh
  identity is created and uploaded — old rooms need a re-invite.
- The root `index.html` is just a pointer page now; the app lives in `public/`.
