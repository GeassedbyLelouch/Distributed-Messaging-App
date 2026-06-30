"use strict";

const SESSION_KEY = "braidlink.session";

let latestLookupRequest = 0;

const state = {
  username: "",
  deviceId: "",
  token: "",
  contacts: [],
  requests: { inbound: [], outbound: [] },
  lookupResult: null,
  selectedContactId: "",
  chatContactId: "",
  view: "device",
};

const els = {
  registerForm: document.querySelector("#register-form"),
  registerUsername: document.querySelector("#register-username"),
  registerStatus: document.querySelector("#register-status"),
  clearSessionButton: document.querySelector("#clear-session-button"),
  registrationPanel: document.querySelector("#registration-panel"),
  contactsPanel: document.querySelector("#contacts-panel"),
  chatPanel: document.querySelector("#chat-panel"),
  refreshContactsButton: document.querySelector("#refresh-contacts-button"),
  searchForm: document.querySelector("#search-form"),
  searchUsername: document.querySelector("#search-username"),
  lookupResult: document.querySelector("#lookup-result"),
  requestList: document.querySelector("#request-list"),
  requestCount: document.querySelector("#request-count"),
  contactList: document.querySelector("#contact-list"),
  contactCount: document.querySelector("#contact-count"),
  inspectorBody: document.querySelector("#inspector-body"),
  startChatButton: document.querySelector("#start-chat-button"),
  deleteContactButton: document.querySelector("#delete-contact-button"),
  railUsername: document.querySelector("#rail-username"),
  railDeviceId: document.querySelector("#rail-device-id"),
  mobileDeviceSummary: document.querySelector("#mobile-device-summary"),
  navContacts: document.querySelector("#nav-contacts"),
  navChat: document.querySelector("#nav-chat"),
  navDevice: document.querySelector("#nav-device"),
  mobileNavContacts: document.querySelector("#mobile-nav-contacts"),
  mobileNavChat: document.querySelector("#mobile-nav-chat"),
  mobileNavDevice: document.querySelector("#mobile-nav-device"),
  workspaceTitle: document.querySelector("#workspace-title"),
  sessionStrip: document.querySelector("#session-strip"),
  sessionUsername: document.querySelector("#session-username"),
  sessionDevice: document.querySelector("#session-device"),
  chatContactList: document.querySelector("#chat-contact-list"),
  chatContactCount: document.querySelector("#chat-contact-count"),
  chatThreadTitle: document.querySelector("#chat-thread-title"),
  chatThread: document.querySelector("#chat-thread"),
  chatComposer: document.querySelector("#chat-composer"),
  chatMessageInput: document.querySelector("#chat-message-input"),
  chatSendButton: document.querySelector("#chat-send-button"),
};

function restoreSession() {
  try {
    const saved = JSON.parse(localStorage.getItem(SESSION_KEY) || "{}");
    state.username = typeof saved.username === "string" ? saved.username : "";
    state.deviceId = Number.isInteger(saved.deviceId) ? saved.deviceId : "";
    state.token = typeof saved.token === "string" ? saved.token : "";
    state.view = hasSession() ? "contacts" : "device";
  } catch {
    localStorage.removeItem(SESSION_KEY);
  }
}

function persistSession() {
  if (!state.token) {
    localStorage.removeItem(SESSION_KEY);
    return;
  }

  localStorage.setItem(
    SESSION_KEY,
    JSON.stringify({
      username: state.username,
      deviceId: state.deviceId,
      token: state.token,
    }),
  );
}

function hasSession() {
  return Boolean(state.username && state.deviceId && state.token);
}

function setStatus(element, message = "", tone = "") {
  element.textContent = message;
  element.classList.remove("is-error", "is-success", "is-warning");
  if (tone) {
    element.classList.add(`is-${tone}`);
  }
}

function setBusy(form, busy) {
  form.querySelectorAll("button, input").forEach((control) => {
    control.disabled = busy;
  });
}

async function readError(response, fallback) {
  try {
    const body = await response.json();
    if (typeof body.detail === "string") {
      return body.detail;
    }
    if (body.detail && typeof body.detail.message === "string") {
      return body.detail.message;
    }
  } catch {
    return fallback;
  }
  return fallback;
}

function authHeaders() {
  return {
    Authorization: `Bearer ${state.token}`,
  };
}

function isCurrentLookup(requestId) {
  return requestId === latestLookupRequest;
}

function showView(view) {
  if (view !== "device" && !hasSession()) {
    state.view = "device";
  } else {
    state.view = view;
  }

  render();
}

async function registerDevice(event) {
  event.preventDefault();
  const username = els.registerUsername.value.trim();
  if (!username) {
    setStatus(els.registerStatus, "Enter a username.", "error");
    return;
  }

  setBusy(els.registerForm, true);
  setStatus(els.registerStatus, "Registering...");

  try {
    const response = await fetch("/ui/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username }),
    });

    if (response.status === 404) {
      setStatus(
        els.registerStatus,
        "Registration is unavailable. Local demo mode must enable BRAID_ENABLE_DEMO_UI=1.",
        "error",
      );
      return;
    }

    if (!response.ok) {
      setStatus(
        els.registerStatus,
        await readError(response, "Registration failed."),
        "error",
      );
      return;
    }

    const body = await response.json();
    state.username = body.username;
    state.deviceId = body.device_id;
    state.token = body.auth_token;
    state.contacts = [];
    state.requests = { inbound: [], outbound: [] };
    state.selectedContactId = "";
    state.chatContactId = "";
    state.lookupResult = null;
    state.view = "contacts";
    persistSession();
    render();
    setStatus(els.registerStatus, "Registered.", "success");
    await loadWorkspaceData();
  } catch {
    setStatus(els.registerStatus, "Registration failed. Check the server.", "error");
  } finally {
    setBusy(els.registerForm, false);
  }
}

async function searchUser(event) {
  event.preventDefault();
  const username = els.searchUsername.value.trim();
  if (!username) {
    renderLookupMessage("Enter a full username.", "warning");
    return;
  }

  const requestId = ++latestLookupRequest;
  setBusy(els.searchForm, true);
  renderLookupMessage("Searching...");

  try {
    const response = await fetch(`/users/by-username/${encodeURIComponent(username)}`);
    if (!isCurrentLookup(requestId)) {
      return;
    }

    if (response.status === 404) {
      state.lookupResult = null;
      renderLookupMessage("No exact match.");
      return;
    }

    if (!response.ok) {
      const message = await readError(response, "Lookup failed.");
      if (!isCurrentLookup(requestId)) {
        return;
      }
      state.lookupResult = null;
      renderLookupMessage(message, "error");
      return;
    }

    const result = await response.json();
    if (!isCurrentLookup(requestId)) {
      return;
    }
    state.lookupResult = result;
    renderLookupResult();
  } catch {
    if (!isCurrentLookup(requestId)) {
      return;
    }
    state.lookupResult = null;
    renderLookupMessage("Lookup failed. Check the server.", "error");
  } finally {
    if (isCurrentLookup(requestId)) {
      setBusy(els.searchForm, false);
    }
  }
}

async function addLookupContact() {
  if (!state.lookupResult || !hasSession()) {
    return;
  }

  const contact = state.lookupResult;
  renderLookupMessage("Sending request...");

  try {
    const response = await fetch("/contacts", {
      method: "POST",
      headers: {
        ...authHeaders(),
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: contact.username_display,
        device_id: contact.device_id,
      }),
    });

    if (response.status === 401) {
      clearSession("Session expired.");
      return;
    }

    if (!response.ok) {
      renderLookupMessage(await readError(response, "Could not send request."), "error");
      return;
    }

    await loadContactRequests();
    renderLookupMessage("Request sent.", "success");
  } catch {
    renderLookupMessage("Could not send request. Check the server.", "error");
  }
}

async function loadWorkspaceData() {
  if (!hasSession()) {
    return;
  }
  await loadContacts();
  await loadContactRequests();
}

async function loadContacts() {
  if (!hasSession()) {
    return;
  }

  try {
    const response = await fetch("/contacts", { headers: authHeaders() });
    if (response.status === 401) {
      clearSession("Session expired.");
      return;
    }
    if (!response.ok) {
      renderLookupMessage(await readError(response, "Could not load contacts."), "error");
      return;
    }

    state.contacts = await response.json();
    if (
      state.selectedContactId &&
      !state.contacts.some((contact) => contact.contact_id === state.selectedContactId)
    ) {
      state.selectedContactId = "";
    }
    if (
      state.chatContactId &&
      !state.contacts.some((contact) => contact.contact_id === state.chatContactId)
    ) {
      state.chatContactId = "";
    }
    renderContacts();
    renderInspector();
    renderChat();
    if (state.lookupResult) {
      renderLookupResult();
    }
  } catch {
    renderLookupMessage("Could not load contacts. Check the server.", "error");
  }
}

async function loadContactRequests() {
  if (!hasSession()) {
    return;
  }

  try {
    const response = await fetch("/contact-requests", { headers: authHeaders() });
    if (response.status === 401) {
      clearSession("Session expired.");
      return;
    }
    if (!response.ok) {
      renderLookupMessage(await readError(response, "Could not load requests."), "error");
      return;
    }

    state.requests = await response.json();
    renderContactRequests();
    if (state.lookupResult) {
      renderLookupResult();
    }
  } catch {
    renderLookupMessage("Could not load requests. Check the server.", "error");
  }
}

async function acceptContactRequest(requestId) {
  try {
    const response = await fetch(`/contact-requests/${encodeURIComponent(requestId)}/accept`, {
      method: "POST",
      headers: authHeaders(),
    });
    if (response.status === 401) {
      clearSession("Session expired.");
      return;
    }
    if (!response.ok) {
      renderLookupMessage(await readError(response, "Could not accept request."), "error");
      return;
    }
    await loadWorkspaceData();
    renderLookupMessage("Request accepted.", "success");
  } catch {
    renderLookupMessage("Could not accept request. Check the server.", "error");
  }
}

async function denyContactRequest(requestId) {
  try {
    const response = await fetch(`/contact-requests/${encodeURIComponent(requestId)}/deny`, {
      method: "POST",
      headers: authHeaders(),
    });
    if (response.status === 401) {
      clearSession("Session expired.");
      return;
    }
    if (!response.ok) {
      renderLookupMessage(await readError(response, "Could not deny request."), "error");
      return;
    }
    await loadContactRequests();
    renderLookupMessage("Request denied.", "success");
  } catch {
    renderLookupMessage("Could not deny request. Check the server.", "error");
  }
}

async function deleteSelectedContact() {
  const selected = selectedContact();
  if (!selected) {
    return;
  }

  try {
    const response = await fetch(`/contacts/${encodeURIComponent(selected.contact_id)}`, {
      method: "DELETE",
      headers: authHeaders(),
    });
    if (response.status === 401) {
      clearSession("Session expired.");
      return;
    }
    if (!response.ok) {
      renderLookupMessage(await readError(response, "Could not remove contact."), "error");
      return;
    }
    state.selectedContactId = "";
    await loadContacts();
    renderLookupMessage("Contact removed.", "success");
  } catch {
    renderLookupMessage("Could not remove contact. Check the server.", "error");
  }
}

function clearSession(message = "") {
  state.username = "";
  state.deviceId = "";
  state.token = "";
  state.contacts = [];
  state.requests = { inbound: [], outbound: [] };
  state.lookupResult = null;
  state.selectedContactId = "";
  state.chatContactId = "";
  state.view = "device";
  persistSession();
  render();
  setStatus(els.registerStatus, message);
}

function render() {
  const registered = hasSession();
  const activeView = registered ? state.view : "device";

  els.registrationPanel.classList.toggle("is-hidden", registered && activeView !== "device");
  els.contactsPanel.classList.toggle("is-hidden", !registered || activeView !== "contacts");
  els.chatPanel.classList.toggle("is-hidden", !registered || activeView !== "chat");
  els.refreshContactsButton.disabled = !registered;
  els.clearSessionButton.disabled = !registered;
  els.sessionStrip.hidden = !registered;

  els.railUsername.textContent = registered ? state.username : "Not registered";
  els.railUsername.title = els.railUsername.textContent;
  els.railDeviceId.textContent = registered ? `Device ${state.deviceId}` : "No device token";
  els.mobileDeviceSummary.textContent = registered
    ? `${state.username} · ${state.deviceId}`
    : "Not registered";
  els.mobileDeviceSummary.title = els.mobileDeviceSummary.textContent;
  els.sessionUsername.textContent = registered ? state.username : "Unknown";
  els.sessionUsername.title = els.sessionUsername.textContent;
  els.sessionDevice.textContent = registered ? `Device ${state.deviceId}` : "Device -";
  els.workspaceTitle.textContent =
    activeView === "chat" ? "Chat" : activeView === "device" ? "Device" : "Contacts";

  setNavState(activeView, registered);
  renderContacts();
  renderContactRequests();
  renderInspector();
  renderChat();
  if (!registered) {
    renderLookupMessage("");
  }
}

function setNavState(activeView, registered) {
  const pairs = [
    [els.navContacts, "contacts"],
    [els.navChat, "chat"],
    [els.navDevice, "device"],
    [els.mobileNavContacts, "contacts"],
    [els.mobileNavChat, "chat"],
    [els.mobileNavDevice, "device"],
  ];

  pairs.forEach(([element, view]) => {
    element.classList.toggle("is-active", activeView === view);
    if (view !== "device") {
      element.toggleAttribute("disabled", !registered);
    }
  });
}

function renderLookupMessage(message, tone = "") {
  els.lookupResult.replaceChildren();
  if (!message) {
    return;
  }

  const line = document.createElement("p");
  line.className = "status-line";
  if (tone) {
    line.classList.add(`is-${tone}`);
  }
  line.textContent = message;
  els.lookupResult.append(line);
}

function renderLookupResult() {
  const result = state.lookupResult;
  els.lookupResult.replaceChildren();
  if (!result) {
    return;
  }

  const contactId = `${result.username_display}:${result.device_id}`;
  const existing = state.contacts.some((contact) => contact.contact_id === contactId);
  const pendingOutbound = state.requests.outbound.some((request) =>
    requestMatchesLookup(request, result),
  );
  const pendingInbound = state.requests.inbound.some((request) =>
    requestMatchesLookup(request, result),
  );
  const ownDevice = state.username === result.username_display && state.deviceId === result.device_id;

  const container = document.createElement("div");
  container.className = "lookup-card";

  const copy = document.createElement("div");
  const name = document.createElement("strong");
  name.textContent = result.username_display;
  name.title = result.username_display;
  const meta = document.createElement("p");
  meta.textContent = `Device ${result.device_id}`;
  copy.append(name, meta);

  const button = document.createElement("button");
  button.className = "primary-button";
  button.type = "button";
  if (existing) {
    button.textContent = "Added";
    button.disabled = true;
  } else if (ownDevice) {
    button.textContent = "You";
    button.disabled = true;
  } else if (pendingOutbound) {
    button.textContent = "Sent";
    button.disabled = true;
  } else if (pendingInbound) {
    button.textContent = "Respond";
    button.addEventListener("click", () => showView("contacts"));
  } else {
    button.textContent = "Request";
    button.addEventListener("click", addLookupContact);
  }

  container.append(copy, button);
  els.lookupResult.append(container);
}

function requestMatchesLookup(request, result) {
  return (
    request.peer_username_display === result.username_display &&
    request.peer_device_id === result.device_id
  );
}

function renderContactRequests() {
  els.requestList.replaceChildren();
  const inbound = Array.isArray(state.requests.inbound) ? state.requests.inbound : [];
  const outbound = Array.isArray(state.requests.outbound) ? state.requests.outbound : [];
  const total = inbound.length + outbound.length;
  els.requestCount.textContent = String(total);

  if (!hasSession()) {
    return;
  }

  if (total === 0) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No pending requests";
    els.requestList.append(empty);
    return;
  }

  inbound.forEach((request) => {
    els.requestList.append(requestRow(request));
  });
  outbound.forEach((request) => {
    els.requestList.append(requestRow(request));
  });
}

function requestRow(request) {
  const row = document.createElement("div");
  row.className = "request-row";
  row.setAttribute("role", "listitem");

  const copy = document.createElement("div");
  copy.className = "request-copy";
  const name = document.createElement("strong");
  name.textContent = request.peer_username_display;
  name.title = request.peer_username_display;
  const meta = document.createElement("span");
  meta.textContent =
    request.direction === "inbound"
      ? `Incoming · Device ${request.peer_device_id}`
      : `Sent · Device ${request.peer_device_id}`;
  copy.append(name, meta);

  const actions = document.createElement("div");
  actions.className = "request-actions";
  if (request.direction === "inbound") {
    const accept = document.createElement("button");
    accept.className = "primary-button";
    accept.type = "button";
    accept.textContent = "Accept";
    accept.setAttribute("aria-label", `Accept ${request.peer_username_display}`);
    accept.addEventListener("click", () => acceptContactRequest(request.request_id));

    const deny = document.createElement("button");
    deny.className = "danger-button";
    deny.type = "button";
    deny.textContent = "Deny";
    deny.setAttribute("aria-label", `Deny ${request.peer_username_display}`);
    deny.addEventListener("click", () => denyContactRequest(request.request_id));
    actions.append(accept, deny);
  } else {
    const status = document.createElement("span");
    status.className = "pending-chip";
    status.textContent = "Pending";
    actions.append(status);
  }

  row.append(copy, actions);
  return row;
}

function renderContacts() {
  els.contactList.replaceChildren();
  els.contactCount.textContent = String(state.contacts.length);

  if (!hasSession()) {
    return;
  }

  if (state.contacts.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No contacts";
    els.contactList.append(empty);
    return;
  }

  state.contacts.forEach((contact) => {
    const isSelected = contact.contact_id === state.selectedContactId;
    const displayName = contact.alias || contact.username_display;
    const accessibleName = `${displayName} (${contact.username_display})`;
    const row = document.createElement("div");
    row.className = "contact-row";
    row.classList.toggle("is-selected", isSelected);
    row.setAttribute("role", "listitem");

    const select = document.createElement("button");
    select.className = "contact-select";
    select.type = "button";
    select.setAttribute("aria-pressed", String(isSelected));
    select.setAttribute("aria-label", `Select ${accessibleName}`);
    select.addEventListener("click", () => {
      state.selectedContactId = contact.contact_id;
      renderContacts();
      renderInspector();
    });

    const main = document.createElement("span");
    main.className = "contact-main";
    const name = document.createElement("span");
    name.className = "contact-name";
    name.textContent = displayName;
    name.title = name.textContent;
    const meta = document.createElement("span");
    meta.className = "contact-meta";
    meta.textContent = `${contact.username_display} · Device ${contact.contact_device_id}`;
    meta.title = meta.textContent;
    main.append(name, meta);
    select.append(main);

    const remove = document.createElement("button");
    remove.className = "danger-button contact-remove";
    remove.type = "button";
    remove.textContent = "Remove";
    remove.setAttribute("aria-label", `Remove ${accessibleName}`);
    remove.addEventListener("click", async () => {
      state.selectedContactId = contact.contact_id;
      await deleteSelectedContact();
    });

    row.append(select, remove);
    els.contactList.append(row);
  });
}

function selectedContact() {
  return state.contacts.find((contact) => contact.contact_id === state.selectedContactId) || null;
}

function selectedChatContact() {
  return state.contacts.find((contact) => contact.contact_id === state.chatContactId) || null;
}

function renderInspector() {
  const contact = selectedContact();
  els.inspectorBody.replaceChildren();
  els.deleteContactButton.disabled = !contact;
  els.startChatButton.disabled = !contact;

  if (!contact) {
    els.deleteContactButton.setAttribute("aria-label", "Remove selected contact");
    els.startChatButton.setAttribute("aria-label", "Start chat with selected contact");
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No contact selected";
    els.inspectorBody.append(empty);
    return;
  }

  const displayName = contact.alias || contact.username_display;
  els.deleteContactButton.setAttribute(
    "aria-label",
    `Remove ${displayName} (${contact.username_display})`,
  );
  els.startChatButton.setAttribute(
    "aria-label",
    `Start chat with ${displayName} (${contact.username_display})`,
  );

  const stack = document.createElement("div");
  stack.className = "detail-stack";
  stack.append(
    detailRow("Name", displayName),
    detailRow("Username", contact.username_display),
    detailRow("Device", String(contact.contact_device_id)),
    detailRow("Contact ID", contact.contact_id, true),
    verifiedRow(contact.verified),
  );
  els.inspectorBody.append(stack);
}

function renderChat() {
  els.chatContactList.replaceChildren();
  els.chatContactCount.textContent = String(state.contacts.length);

  if (!hasSession()) {
    resetChatThread();
    return;
  }

  if (state.contacts.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No contacts";
    els.chatContactList.append(empty);
    resetChatThread();
    return;
  }

  state.contacts.forEach((contact) => {
    const button = document.createElement("button");
    button.className = "chat-contact-button";
    button.classList.toggle("is-selected", contact.contact_id === state.chatContactId);
    button.type = "button";
    button.textContent = contact.alias || contact.username_display;
    button.title = `${contact.username_display} · Device ${contact.contact_device_id}`;
    button.setAttribute("aria-pressed", String(contact.contact_id === state.chatContactId));
    button.addEventListener("click", () => openChatWithContact(contact.contact_id));
    els.chatContactList.append(button);
  });

  const contact = selectedChatContact();
  if (!contact) {
    resetChatThread();
    return;
  }

  const displayName = contact.alias || contact.username_display;
  els.chatThreadTitle.textContent = displayName;
  els.chatThreadTitle.title = `${contact.username_display} · Device ${contact.contact_device_id}`;
  els.chatThread.replaceChildren();
  const empty = document.createElement("p");
  empty.className = "empty-state";
  empty.textContent = "No messages";
  els.chatThread.append(empty);
  els.chatMessageInput.disabled = true;
  els.chatMessageInput.placeholder = "Encrypted session not active in browser";
  els.chatSendButton.disabled = true;
}

function resetChatThread() {
  els.chatThreadTitle.textContent = "No contact selected";
  els.chatThread.replaceChildren();
  const empty = document.createElement("p");
  empty.className = "empty-state";
  empty.textContent = "Select a contact";
  els.chatThread.append(empty);
  els.chatMessageInput.disabled = true;
  els.chatMessageInput.placeholder = "Select a contact";
  els.chatSendButton.disabled = true;
}

function openChatWithContact(contactId) {
  state.chatContactId = contactId;
  showView("chat");
  renderChat();
}

function detailRow(label, value, wrap = false) {
  const row = document.createElement("div");
  row.className = "detail-row";
  const labelEl = document.createElement("span");
  labelEl.className = "detail-label";
  labelEl.textContent = label;
  const valueEl = document.createElement("span");
  valueEl.className = wrap ? "detail-value wrap" : "detail-value";
  valueEl.textContent = value || "-";
  valueEl.title = valueEl.textContent;
  row.append(labelEl, valueEl);
  return row;
}

function verifiedRow(verified) {
  const row = document.createElement("div");
  row.className = "detail-row";
  const labelEl = document.createElement("span");
  labelEl.className = "detail-label";
  labelEl.textContent = "Status";
  const valueEl = document.createElement("span");
  valueEl.className = verified ? "verified-dot is-verified" : "verified-dot";
  valueEl.textContent = verified ? "Verified" : "Unverified";
  row.append(labelEl, valueEl);
  return row;
}

function bindNav(element, view) {
  element.addEventListener("click", (event) => {
    event.preventDefault();
    showView(view);
  });
}

els.registerForm.addEventListener("submit", registerDevice);
els.searchForm.addEventListener("submit", searchUser);
els.refreshContactsButton.addEventListener("click", loadWorkspaceData);
els.clearSessionButton.addEventListener("click", () => clearSession("Session cleared."));
els.deleteContactButton.addEventListener("click", deleteSelectedContact);
els.startChatButton.addEventListener("click", () => {
  const contact = selectedContact();
  if (contact) {
    openChatWithContact(contact.contact_id);
  }
});
els.chatComposer.addEventListener("submit", (event) => event.preventDefault());
bindNav(els.navContacts, "contacts");
bindNav(els.navChat, "chat");
bindNav(els.navDevice, "device");
bindNav(els.mobileNavContacts, "contacts");
bindNav(els.mobileNavChat, "chat");
bindNav(els.mobileNavDevice, "device");

restoreSession();
render();
if (hasSession()) {
  loadWorkspaceData();
}
