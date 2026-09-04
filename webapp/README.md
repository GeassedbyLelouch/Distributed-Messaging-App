# BraidLink web frontend

A browser UI for the existing `ml_kem_braid` messaging stack. This adds a
**presentation and orchestration layer only** — it does not touch key
generation, KDF/HKDF derivation, the PQXDH handshake, the Braid SCKA state
machine, the Double Ratchet, or AEAD encryption/decryption. Every
cryptographic step still happens exactly where it already lived, inside
`ml_kem_braid.client.client.BraidChatClient` and the modules it calls.

## Why there's a second small server (`agent.py`)

The crypto in this project is implemented in Python
(`BraidChatClient`), not JavaScript. A browser tab can't call Python
directly, and re-implementing ML-KEM / X25519 / the Double Ratchet in
JavaScript would mean a second, independent crypto implementation — exactly
what you asked me not to do.

So the shape is:

```
 Browser (this frontend)  <-- HTTP + WebSocket -->  agent.py (local bridge)  <-- HTTPS -->  core ml_kem_braid FastAPI server
   HTML/CSS/JS only                                  owns one unmodified                     unmodified "dumb relay"
   no key material ever                              BraidChatClient in memory               (unchanged from the repo)
   touches this page                                 for this device
```

`agent.py` runs once per logged-in device (think: the desktop-app process
behind a chat client). It:

1. Calls `BraidChatClient.register()`, `.start_session()`, `.poll()`,
   `.pump_session()`, and `.send_chat()` — all **unmodified**, imported
   straight from `ml_kem_braid.client.client`.
2. Proxies the core server's plain metadata routes (`/contacts`,
   `/contact-requests`, `/users/by-username/...`) with a pass-through
   `Authorization: Bearer <token>` header. These routes never carry key
   material — only usernames, device ids, and timestamps, exactly as the
   core server already defines them.
3. Reshapes the results into small JSON responses for the browser, and
   pushes new decrypted messages / handshake-status changes to the browser
   over a local WebSocket.

The private key material `BraidChatClient` generates lives only inside this
process's memory, exactly as it already did in `tests/` and in the existing
`ml_kem_braid.testnet` demo. This frontend does not add any new place keys
are stored, and does not send plaintext anywhere the protocol wasn't already
designed to send it — the browser only ever receives text that
`DoubleRatchet.decrypt(...)` already produced inside the untouched client.

## What was and wasn't touched

**Not modified, not reimplemented, not "cleaned up":**
`ml_kem_braid/core/*`, `ml_kem_braid/pqxdh/*`, `ml_kem_braid/protocol/*`,
`ml_kem_braid/client/client.py`, `ml_kem_braid/client/transport.py`,
`ml_kem_braid/server/app.py`, `ml_kem_braid/sesame/*`, and (on the
`vrf-ed25519` branch) `ml_kem_braid/crypto/*` and `ml_kem_braid/attestation/*`.
The existing demo UI at `ml_kem_braid/server/static/` is also left alone.

**New, added by this frontend work:**
`agent.py` (orchestration + proxy only) and everything in `static/`
(HTML/CSS/JS).

## Running it

1. Start the existing core server, unmodified, from the repo root:
   ```bash
   pip install -r requirements.txt
   python -m ml_kem_braid.server.app
   # or: uvicorn ml_kem_braid.server.app:create_app --factory --port 8000
   ```
2. Copy this `webapp/` folder to the repo root (next to `ml_kem_braid/`) so
   `agent.py` can `import ml_kem_braid`.
3. Start one bridge process **per device/user** you want to log in as a
   separate browser tab (they're isolated by port):
   ```bash
   uvicorn agent:app --port 8899   # e.g. Alice's device
   uvicorn agent:app --port 8900   # e.g. Bob's device, in another terminal
   ```
4. Open `http://localhost:8899/` (and `:8900/` in another tab/browser),
   enter the core server's address (`http://localhost:8000`) and a
   username, and click **Connect**. Add each other as a contact, accept the
   request, then open the chat.

The `vrf-ed25519` branch exposes the same REST/WebSocket surface (plus
server-side rate limiting), so this same frontend works against it
unchanged — just point `server_url` at that server instead.

## Known limitations (by design, not oversights)

- **No persistent identity vault is wired in.** Each `agent.py` process
  holds keys in memory only; restarting it means registering a new device.
  The repo already has `ml_kem_braid.client.vault_client` /
  `ml_kem_braid.decentralized.InMemoryClientVault` for persistent
  client-side vaults — wiring one in was left out rather than guessed at,
  since it touches how identity secrets are stored and that's exactly the
  kind of decision you asked me not to make unilaterally.
- **One active peer device per contact** is assumed by the UI (the
  underlying client supports multiple devices per contact; the browser UI
  just doesn't expose a device picker yet).
- **HTTP polling transport**, not `WebSocketTransport`, is used between the
  agent and the core server, matching the simpler of the two supported
  transports. Swapping in `WebSocketTransport` (also unmodified, already in
  `ml_kem_braid.client.transport`) is a drop-in change in `agent.py`'s
  `connect()`.
