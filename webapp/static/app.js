/**
 * BraidLink frontend.
 *
 * This file only ever talks to the local bridge (`agent.py`) over
 * `/api/...` and a WebSocket at `/api/events`. It never generates keys,
 * derives secrets, or performs any cryptographic operation itself — every
 * message shown here was already decrypted by the existing Python client
 * before the bridge handed it to this page as plain JSON.
 */

const state = {
  sessionId: sessionStorage.getItem("braidlink_session_id") || null,
  username: null,
  deviceId: null,
  contacts: [],
  sessionStatus: new Map(), // "user:device" -> {ready, epoch}
  activePeer: null, // {username, device_id}
  ws: null,
};

const el = (id) => document.getElementById(id);

function peerKey(username, deviceId) {
  return `${username}:${deviceId}`;
}

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail || detail;
    } catch (_) {
      /* ignore */
    }
    throw new Error(detail);
  }
  if (res.status === 204) return null;
  return res.json();
}

function withSession(qs = "") {
  return `session_id=${encodeURIComponent(state.sessionId)}${qs ? "&" + qs : ""}`;
}

// ---------------------------------------------------------------------------
// Connect flow
// ---------------------------------------------------------------------------

el("connect-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const serverUrl = el("server-url").value.trim();
  const username = el("username").value.trim();
  const button = el("connect-button");
  const status = el("connect-status");

  button.disabled = true;
  status.dataset.tone = "";
  status.textContent = "Registering device and establishing key material…";

  try {
    const resp = await api("/api/connect", {
      method: "POST",
      body: JSON.stringify({ server_url: serverUrl, username }),
    });
    state.sessionId = resp.session_id;
    state.username = resp.username;
    state.deviceId = resp.device_id;
    sessionStorage.setItem("braidlink_session_id", state.sessionId);
    enterApp();
  } catch (err) {
    status.dataset.tone = "error";
    status.textContent = `Could not connect: ${err.message}`;
    button.disabled = false;
  }
});

el("disconnect-button").addEventListener("click", async () => {
  if (state.ws) state.ws.close();
  if (state.sessionId) {
    try {
      await api("/api/disconnect", {
        method: "POST",
        body: JSON.stringify({ session_id: state.sessionId }),
      });
    } catch (_) {
      /* best effort */
    }
  }
  sessionStorage.removeItem("braidlink_session_id");
  window.location.reload();
});

async function enterApp() {
  el("connect-screen").classList.add("hidden");
  el("app-shell").classList.remove("hidden");
  el("rail-username").textContent = state.username;
  el("rail-device").textContent = `device ${state.deviceId}`;
  connectEvents();
  await refreshContacts();
  await refreshRequests();
}

// If a session id survived a page refresh, try to resume it rather than
// forcing a fresh /api/connect (which would create a *second* device).
async function tryResume() {
  if (!state.sessionId) return;
  try {
    const status = await api(`/api/status?${withSession()}`);
    state.username = status.username;
    state.deviceId = status.device_id;
    await enterApp();
  } catch (_) {
    sessionStorage.removeItem("braidlink_session_id");
    state.sessionId = null;
  }
}

// ---------------------------------------------------------------------------
// Live events
// ---------------------------------------------------------------------------

function connectEvents() {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${window.location.host}/api/events?${withSession()}`);
  state.ws = ws;

  ws.addEventListener("open", () => setConnDot("up"));
  ws.addEventListener("close", () => setConnDot("down"));
  ws.addEventListener("error", () => setConnDot("down"));

  ws.addEventListener("message", (evt) => {
    const data = JSON.parse(evt.data);
    if (data.type === "message") {
      handleIncomingMessage(data);
    } else if (data.type === "session_status") {
      handleSessionStatus(data);
    } else if (data.type === "dropped") {
      console.warn("dropped envelope", data);
    } else if (data.type === "error") {
      console.error("agent error", data.detail);
    }
  });
}

function setConnDot(state_) {
  const dot = el("conn-dot");
  dot.dataset.state = state_ === "up" ? "ok" : state_;
}

function handleSessionStatus(data) {
  const key = peerKey(data.peer_username, data.peer_device_id);
  state.sessionStatus.set(key, { ready: data.ready, epoch: data.epoch });
  renderContactRows();
  if (state.activePeer && peerKey(state.activePeer.username, state.activePeer.device_id) === key) {
    renderThreadStatus();
  }
}

function handleIncomingMessage(data) {
  const key = peerKey(data.peer_username, data.peer_device_id);
  if (state.activePeer && peerKey(state.activePeer.username, state.activePeer.device_id) === key) {
    appendBubble(data);
  }
}

// ---------------------------------------------------------------------------
// Contacts
// ---------------------------------------------------------------------------

async function refreshContacts() {
  state.contacts = await api(`/api/contacts?${withSession()}`);
  renderContactRows();
  renderContactList();
}

function renderContactRows() {
  const list = el("chat-contact-list");
  list.innerHTML = "";
  if (state.contacts.length === 0) {
    list.innerHTML = `<p class="empty-row">No contacts yet. Add one from Contacts.</p>`;
    return;
  }
  for (const c of state.contacts) {
    const row = document.createElement("div");
    row.className = "contact-row";
    const key = peerKey(c.contact_username, c.contact_device_id);
    const status = state.sessionStatus.get(key);
    const dotState = !status ? "" : status.ready ? "ready" : "pending";
    row.innerHTML = `
      <span class="status-dot" data-state="${dotState}"></span>
      <span class="contact-row-name">${escapeHtml(c.alias || c.contact_username)}</span>
      <span class="contact-row-device">#${c.contact_device_id}</span>
    `;
    row.addEventListener("click", () => openThread(c.contact_username, c.contact_device_id));
    if (
      state.activePeer &&
      state.activePeer.username === c.contact_username &&
      state.activePeer.device_id === c.contact_device_id
    ) {
      row.classList.add("is-active");
    }
    list.appendChild(row);
  }
}

function renderContactList() {
  const list = el("contact-list");
  list.innerHTML = "";
  if (state.contacts.length === 0) {
    list.innerHTML = `<p class="empty-row">No contacts yet.</p>`;
    return;
  }
  for (const c of state.contacts) {
    const row = document.createElement("div");
    row.className = "list-row";
    row.innerHTML = `
      <div class="list-row-main">
        <div class="list-row-name">${escapeHtml(c.alias || c.contact_username)}</div>
        <div class="list-row-meta">${escapeHtml(c.contact_username)} · device #${c.contact_device_id}</div>
      </div>
      <button class="danger" data-action="remove">Remove</button>
    `;
    row.querySelector('[data-action="remove"]').addEventListener("click", async () => {
      await api(`/api/contacts/${c.contact_id}?${withSession()}`, { method: "DELETE" });
      await refreshContacts();
    });
    list.appendChild(row);
  }
}

el("refresh-contacts").addEventListener("click", refreshContacts);

el("lookup-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = el("lookup-username").value.trim();
  const box = el("lookup-result");
  box.textContent = "Searching…";
  try {
    const found = await api(`/api/users/${encodeURIComponent(username)}?${withSession()}`);
    box.innerHTML = `
      <div class="found-row">
        <div class="list-row-main">
          <div class="list-row-name">${escapeHtml(found.username_display)}</div>
          <div class="list-row-meta">device #${found.device_id}</div>
        </div>
        <button class="primary" id="lookup-add">Add</button>
      </div>
    `;
    el("lookup-add").addEventListener("click", async () => {
      await api("/api/contacts", {
        method: "POST",
        body: JSON.stringify({
          session_id: state.sessionId,
          username: found.username_display,
          device_id: found.device_id,
        }),
      });
      box.textContent = "Request sent.";
      await refreshRequests();
    });
  } catch (err) {
    box.textContent = `No user found: ${err.message}`;
  }
});

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

async function refreshRequests() {
  const data = await api(`/api/contact-requests?${withSession()}`);
  renderRequestList(el("inbound-requests"), data.inbound, true);
  renderRequestList(el("outbound-requests"), data.outbound, false);

  const pendingInbound = data.inbound.filter((r) => r.status === "pending").length;
  const badge = el("requests-badge");
  if (pendingInbound > 0) {
    badge.hidden = false;
    badge.textContent = String(pendingInbound);
  } else {
    badge.hidden = true;
  }
}

function renderRequestList(container, requests, actionable) {
  container.innerHTML = "";
  if (requests.length === 0) {
    container.innerHTML = `<p class="empty-row">Nothing here.</p>`;
    return;
  }
  for (const r of requests) {
    const row = document.createElement("div");
    row.className = "list-row";
    const actions =
      actionable && r.status === "pending"
        ? `<button class="primary" data-action="accept">Accept</button>
           <button class="danger" data-action="deny">Decline</button>`
        : `<span class="list-row-meta">${escapeHtml(r.status)}</span>`;
    row.innerHTML = `
      <div class="list-row-main">
        <div class="list-row-name">${escapeHtml(r.peer_username_display)}</div>
        <div class="list-row-meta">device #${r.peer_device_id}</div>
      </div>
      ${actions}
    `;
    if (actionable && r.status === "pending") {
      row.querySelector('[data-action="accept"]').addEventListener("click", async () => {
        await api(`/api/contact-requests/${r.request_id}/accept`, {
          method: "POST",
          body: JSON.stringify({ session_id: state.sessionId }),
        });
        await Promise.all([refreshRequests(), refreshContacts()]);
      });
      row.querySelector('[data-action="deny"]').addEventListener("click", async () => {
        await api(`/api/contact-requests/${r.request_id}/deny`, {
          method: "POST",
          body: JSON.stringify({ session_id: state.sessionId }),
        });
        await refreshRequests();
      });
    }
    container.appendChild(row);
  }
}

el("refresh-requests").addEventListener("click", refreshRequests);

// ---------------------------------------------------------------------------
// Chat thread
// ---------------------------------------------------------------------------

async function openThread(username, deviceId) {
  state.activePeer = { username, device_id: deviceId };
  el("thread-peer-name").textContent = username;
  renderContactRows();
  renderThreadStatus();

  el("composer-input").disabled = false;
  el("composer-send").disabled = false;
  el("composer-input").placeholder = `Message ${username}`;

  const body = el("thread-body");
  body.innerHTML = `<p class="empty-hint">Loading conversation…</p>`;

  try {
    await api("/api/chat/start", {
      method: "POST",
      body: JSON.stringify({ session_id: state.sessionId, peer_username: username, peer_device_id: deviceId }),
    });
  } catch (err) {
    body.innerHTML = `<p class="empty-hint">Could not start session: ${escapeHtml(err.message)}</p>`;
    return;
  }

  const history = await api(`/api/chat/history?${withSession(`peer_username=${encodeURIComponent(username)}&peer_device_id=${deviceId}`)}`);
  body.innerHTML = "";
  if (history.length === 0) {
    body.innerHTML = `<p class="empty-hint">No messages yet. Say hello once the channel is secured.</p>`;
  } else {
    for (const entry of history) appendBubble(entry, false);
  }
  scrollThreadToBottom();
}

function renderThreadStatus() {
  if (!state.activePeer) return;
  const key = peerKey(state.activePeer.username, state.activePeer.device_id);
  const status = state.sessionStatus.get(key);
  const line = el("thread-status");
  if (!status) {
    line.textContent = "Establishing secure channel…";
    line.dataset.tone = "pending";
  } else if (status.ready) {
    line.textContent = `Secured · epoch ${status.epoch}`;
    line.dataset.tone = "ready";
  } else {
    line.textContent = "Establishing secure channel…";
    line.dataset.tone = "pending";
  }
}

function appendBubble(entry, autoScroll = true) {
  const body = el("thread-body");
  const hint = body.querySelector(".empty-hint");
  if (hint) hint.remove();

  const bubble = document.createElement("div");
  bubble.className = `bubble bubble-${entry.direction}`;
  const time = new Date(entry.ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  bubble.innerHTML = `${escapeHtml(entry.text)}<span class="bubble-meta">epoch ${entry.epoch} · ${time}</span>`;
  body.appendChild(bubble);
  if (autoScroll) scrollThreadToBottom();
}

function scrollThreadToBottom() {
  const body = el("thread-body");
  body.scrollTop = body.scrollHeight;
}

el("composer").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!state.activePeer) return;
  const input = el("composer-input");
  const text = input.value;
  if (!text.trim()) return;

  input.disabled = true;
  el("composer-send").disabled = true;
  try {
    const resp = await api("/api/chat/send", {
      method: "POST",
      body: JSON.stringify({
        session_id: state.sessionId,
        peer_username: state.activePeer.username,
        peer_device_id: state.activePeer.device_id,
        text,
      }),
    });
    appendBubble({ direction: "out", text, epoch: resp.epoch, ts: Date.now() / 1000 });
    input.value = "";
  } catch (err) {
    const body = el("thread-body");
    const notice = document.createElement("p");
    notice.className = "empty-hint";
    notice.textContent = `Not sent: ${err.message}`;
    body.appendChild(notice);
    scrollThreadToBottom();
  } finally {
    input.disabled = false;
    el("composer-send").disabled = false;
    input.focus();
  }
});

// ---------------------------------------------------------------------------
// Nav
// ---------------------------------------------------------------------------

document.querySelectorAll(".rail-item[data-view]").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".rail-item[data-view]").forEach((b) => b.classList.remove("is-active"));
    btn.classList.add("is-active");
    const target = btn.dataset.view;
    document.querySelectorAll(".view").forEach((v) => {
      v.classList.toggle("hidden", v.dataset.viewPanel !== target);
    });
    if (target === "contacts") refreshContacts();
    if (target === "requests") refreshRequests();
  });
});

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

// Poll contact/request lists periodically as a fallback to the push events
// (e.g. picks up a new inbound contact request without a page reload).
setInterval(() => {
  if (!state.sessionId) return;
  refreshRequests().catch(() => {});
}, 8000);

tryResume();
