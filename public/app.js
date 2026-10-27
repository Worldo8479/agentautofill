const paths = {
  vault: '<rect x="4" y="3" width="16" height="18" rx="3"/><circle cx="12" cy="12" r="4"/><path d="M12 8v8m-4-4h8M7 6h.01"/>',
  key: '<circle cx="8" cy="15" r="5"/><path d="m11.5 11.5 9-9M16 7l3 3m-6-1 3 3"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21v-2a8 8 0 0 1 16 0v2"/>',
  pin: '<path d="M20 10c0 6-8 12-8 12S4 16 4 10a8 8 0 1 1 16 0Z"/><circle cx="12" cy="10" r="3"/>',
  shield: '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z"/><path d="m8 12 3 3 5-6"/>',
  lock: '<rect x="5" y="10" width="14" height="11" rx="3"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/>',
  unlock: '<rect x="5" y="10" width="14" height="11" rx="3"/><path d="M8 10V7a4 4 0 0 1 7-2m-3 10v2"/>',
  pass: '<path d="M3 7V4h18v3a4 4 0 0 0 0 8v5H3v-5a4 4 0 0 0 0-8Z"/><path d="M14 4v3m0 3v3m0 3v4"/>',
  activity: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  settings: '<path d="m9 3-1 3-3 1-2 4 2 2v4l4 3 3-1 3 1 4-3v-4l2-2-2-4-3-1-1-3H9Z"/><circle cx="12" cy="12" r="3"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  arrow: '<path d="M5 12h14m-5-5 5 5-5 5"/>',
  chevron: '<path d="m9 5 7 7-7 7"/>',
  down: '<path d="m6 9 6 6 6-6"/>',
  search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
  computer: '<rect x="3" y="3" width="18" height="13" rx="2"/><path d="M8 21h8m-4-5v5"/>',
  help: '<circle cx="12" cy="12" r="9"/><path d="M9 9a3 3 0 1 1 4 3v2m0 3h.01"/>',
  edit: '<path d="m15 4 5 5M4 20l5-1L21 7a2 2 0 0 0-5-5L4 14v6Z"/>',
  trash: '<path d="M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7m4-7v7"/>',
  close: '<path d="m6 6 12 12M6 18 18 6"/>',
  check: '<path d="m5 12 4 4L19 6"/>',
  copy: '<rect x="8" y="8" width="13" height="13" rx="2"/><path d="M16 8V3H3v13h5"/>',
  bot: '<rect x="3" y="7" width="18" height="14" rx="4"/><path d="M12 7V3m-2 0h4M7 12h.01M17 12h.01M8 17h8"/>',
  refresh: '<path d="M20 7a9 9 0 1 0 1 9M20 3v5h-5"/>',
  leaf: '<path d="M20 3C7 2 2 7 5 15c7 6 15 2 15-12ZM4 21 15 10"/>',
};
const icon = name => `<svg viewBox="0 0 24 24" aria-hidden="true">${paths[name] || paths.vault}</svg>`;
const brand = '<span class="brandmark"><svg viewBox="0 0 32 32" aria-hidden="true"><path d="M15 7a9 9 0 1 0 6 16v2h4V7h-4v2a9 9 0 0 0-6-2Zm1 5a4 4 0 1 1 0 8 4 4 0 0 1 0-8Z"/></svg></span>agentautofill';
const escape = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
const names = { login: 'Login', identity: 'Identity', address: 'Address' };
const typeIcon = { login: 'key', identity: 'user', address: 'pin' };
const fieldNames = { username: 'Username / email', password: 'Password', firstName: 'First name', lastName: 'Last name', email: 'Email address', phone: 'Phone number', fullName: 'Full name', address1: 'Street address', address2: 'Apartment / suite', city: 'City', region: 'State / region', postalCode: 'Postal code', country: 'Country' };
const typeFields = { login: ['username', 'password'], identity: ['firstName', 'lastName', 'email', 'phone'], address: ['fullName', 'address1', 'address2', 'city', 'region', 'postalCode', 'country'] };
const defaults = { username: 'input[name="username"]', password: 'input[type="password"]', firstName: '#firstName', lastName: '#lastName', email: '#email', phone: '#phone', fullName: '#fullName', address1: '#address1', address2: '#address2', city: '#city', region: '#region', postalCode: '#postalCode', country: '#country' };
let token = null;
let initialized = false;
let view = 'vault';
let filter = 'all';
let query = '';
let sort = 'recent';
let data = { entries: [], passes: [], activity: [] };
let latestPass = null;
const root = document.querySelector('#app');
const dialog = document.querySelector('#dialog');
let returnFocus;
function toast(message) { const el = document.querySelector('#toast'); el.textContent = message; el.classList.add('show'); clearTimeout(toast.timer); toast.timer = setTimeout(() => el.classList.remove('show'), 3500); }
async function api(path, body, method = body === undefined ? 'GET' : 'POST') {
  const response = await fetch(path, { method, headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(token ? { Authorization: `Bearer ${token}` } : {}) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  const result = await response.json();
  if (!response.ok) {
    if (response.status === 401 && token) { token = null; data = { entries: [], passes: [], activity: [] }; latestPass = null; render(); }
    throw new Error(result.error || 'Something went wrong.');
  }
  return result;
}
async function refresh() { if (token) data = await api('/api/vault'); render(); }
function showModal(html) { returnFocus = document.activeElement; dialog.innerHTML = html; if (!dialog.open) dialog.showModal(); }
function closeModal() { dialog.close(); dialog.innerHTML = ''; returnFocus?.focus(); }
function modalHead(title, subtitle) { return `<div class="dialog-head"><div><h2>${title}</h2><p>${subtitle}</p></div><button class="icon-btn" data-action="close" aria-label="Close dialog">${icon('close')}</button></div>`; }
function formError(message) { const el = dialog.querySelector('.form-error'); if (el) el.textContent = message; else toast(message); }
function requireUnlock() { if (token) return true; authModal(); return false; }
function count(type) { return type === 'all' ? data.entries.length : data.entries.filter(entry => entry.type === type).length; }
function timeLabel(date) { return new Date(date).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }); }
function expiryLabel(date) { return new Date(date).toLocaleString(undefined, { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }); }
function stateOf(pass) { return pass.status === 'ready' && pass.expiresAt <= Date.now() ? 'expired' : pass.status; }
function render() {
  const titles = { vault: 'Your vault', passes: 'Agent passes', activity: 'Activity', security: 'Security & privacy' };
  root.innerHTML = `<aside class="sidebar"><a href="/" class="brand" aria-label="agentautofill home">${brand}</a><div class="workspace"><span>PW</span><div><strong>Personal workspace</strong><small>Just you. By design.</small></div>${icon('down')}</div><p class="nav-label">Workspace</p><nav aria-label="Main navigation">${[['vault','vault','My vault'],['passes','pass','Agent passes'],['activity','activity','Activity'],['security','shield','Security']].map(([id, glyph, label]) => `<button data-view="${id}" class="nav-item ${view === id ? 'active' : ''}" ${view === id ? 'aria-current="page"' : ''}>${icon(glyph)}${label}${id === 'vault' ? `<span class="count">${data.entries.length}</span>` : ''}</button>`).join('')}</nav><div class="sidebar-bottom"><button class="nav-item" data-action="how">${icon('help')}How agentautofill works</button><div class="local-card"><p><span class="dot"></span>Running on this device</p><small>Local storage. Private by default.</small></div><div class="owner"><span class="avatar">ME</span><div>Personal vault<small>${token ? 'Unlocked for this session' : 'Your private workspace'}</small></div><button data-action="${token ? 'lock' : 'unlock'}" aria-label="${token ? 'Lock' : 'Unlock'} vault">${icon(token ? 'unlock' : 'lock')}</button></div></div></aside>
  <div class="shell"><header class="topbar"><div class="breadcrumb">Personal workspace <span>/</span> <strong>${view === 'vault' ? 'My vault' : titles[view]}</strong></div><a href="/" class="brand mobile-brand">${brand}</a><div class="topright"><span class="environment">${icon('computer')}Local workspace</span><span class="status-pill ${token ? '' : 'locked'}"><span class="dot"></span>${token ? 'Vault unlocked' : initialized ? 'Vault locked' : 'Ready to set up'}</span><button class="icon-btn" data-action="how" aria-label="Help">${icon('help')}</button></div></header>
  <main class="main"><div class="page-heading"><div><h1>${titles[view]}</h1><p class="subtitle">${{ vault: 'Your information, ready to use. Always in your control.', passes: 'Give your agent access to an action. Keep the details private.', activity: 'A clear record of what happened in your workspace.', security: 'Know exactly where your information goes.' }[view]}</p></div><div class="actions">${view === 'vault' ? `<button class="btn secondary" data-action="add">${icon('plus')}Add item</button>` : ''}${['vault','passes'].includes(view) ? `<button class="btn primary" data-action="pass">${icon('pass')}Create agent pass</button>` : `<button class="btn secondary" data-action="refresh">${icon('refresh')}Refresh</button>`}</div></div>
  ${!token ? `<div class="intro-banner">${icon('lock')}<div><h3>${initialized ? 'Your vault is locked' : 'A little privacy goes a long way.'}</h3><p>${initialized ? 'Unlock to manage your details and create agent passes.' : 'Create your encrypted vault to start saving and sharing safely.'}</p></div><button class="btn" data-action="unlock">${initialized ? 'Unlock vault' : 'Set up your vault'}${icon('arrow')}</button></div>` : ''}
  ${view === 'vault' ? vaultView() : view === 'passes' ? passesView() : view === 'activity' ? activityView() : securityView()}
  <div class="bottom-note">${icon('shield')}Stored on your device. Used only through the keys you share.</div></main></div>`;
}
function vaultView() {
  return `<div class="stats">${[['all','vault','All items'],['login','key','Logins'],['identity','user','Identities'],['address','pin','Addresses']].map(([type,glyph,title]) => `<button class="stat ${filter === type ? 'selected' : ''}" data-filter="${type}"><div class="stat-top">${title}<span class="stat-icon">${icon(glyph)}</span></div><div class="stat-value">${count(type)}<small>${count(type) === 1 ? 'item' : 'items'}</small></div></button>`).join('')}</div><div class="content-grid"><section class="panel"><div class="panel-head"><h2>Saved items</h2><div class="actions"><small>Only you hold the key</small><button class="icon-btn" data-action="add" aria-label="Add vault item" title="Add item">${icon('plus')}</button></div></div><div class="tabs" role="tablist" aria-label="Item type">${[['all','All items'],['login','Logins'],['identity','Identities'],['address','Addresses']].map(([id,label]) => `<button class="tab ${filter === id ? 'active' : ''}" role="tab" aria-selected="${filter === id}" data-filter="${id}">${label}</button>`).join('')}</div><div class="search-row"><label class="search">${icon('search')}<input id="search" aria-label="Search vault" placeholder="Search your vault…" value="${escape(query)}"><span class="shortcut">/</span></label><select id="sort" aria-label="Sort items"><option value="recent" ${sort === 'recent' ? 'selected' : ''}>Recently added</option><option value="name" ${sort === 'name' ? 'selected' : ''}>Name A–Z</option></select></div><div class="table-head"><span>Item name</span><span>Type</span><span></span></div><div id="entry-list">${entriesView()}</div><div class="panel-foot"><span>${count('all')} encrypted ${count('all') === 1 ? 'item' : 'items'}</span><span>${icon('lock')}AES-256-GCM encryption</span></div></section><aside class="right-column"><section class="handoff-card"><p class="eyebrow">Made for the agent era</p><h2>A helpful agent.<br>A private you.</h2><p>Let AI fill in the blanks.<br>Without handing over your details.</p><div class="connection" aria-hidden="true"><span class="node">${icon('vault')}</span><span class="line"></span><span class="node central">${icon('lock')}</span><span class="line"></span><span class="node">${icon('bot')}</span></div><button class="btn primary" data-action="pass">Create an agent pass ${icon('arrow')}</button><p class="card-note">One task. One PIN. Your permission.</p></section><section class="how-card"><h3>A safer way to autofill</h3>${[['Save your details','Keep logins, identities, and addresses in one encrypted vault.'],['Set the boundaries','Choose the fields and expiry. Your agent supplies the page when using the pass.'],['Let your agent help','Share the prompt. Your private browser handles the rest.']].map(([title,desc],i) => `<div class="step"><span>${i+1}</span><div><h4>${title}</h4><p>${desc}</p></div></div>`).join('')}</section></aside></div>`;
}
function entriesView() {
  const entries = data.entries.filter(entry => (filter === 'all' || entry.type === filter) && `${entry.label} ${entry.site} ${names[entry.type]}`.toLowerCase().includes(query.toLowerCase())).sort((a,b) => sort === 'name' ? a.label.localeCompare(b.label) : b.updatedAt.localeCompare(a.updatedAt));
  if (!entries.length) return `<div class="empty"><span class="empty-symbol">${icon(query ? 'search' : token ? 'vault' : 'lock')}</span><h3>${query ? 'No matching items' : !token && initialized ? 'A private space for your details' : 'Your vault, a fresh start'}</h3><p>${query ? 'Try another name or choose a different category.' : 'Save the details you use every day. Choose exactly when and where they’re used.'}</p>${query ? '' : `<button class="btn secondary" data-action="add">${icon('plus')}Add your first item</button>${token && !data.entries.length ? '<button class="text-btn" data-action="sample">Or try a sample identity →</button>' : ''}`}</div>`;
  return entries.map(entry => `<div class="entry-row"><div class="entry-main"><span class="entry-icon ${entry.type}">${icon(typeIcon[entry.type])}</span><div class="entry-text"><strong>${escape(entry.label)}</strong><small>${entry.site ? escape(new URL(entry.site).hostname) : `${entry.fields.length} protected fields`} · ${timeLabel(entry.updatedAt)}</small></div></div><span class="type-badge">${names[entry.type]}</span><div class="row-buttons"><button class="icon-btn" data-action="edit" data-id="${entry.id}" aria-label="Edit ${escape(entry.label)}" title="Edit item">${icon('edit')}</button><button class="icon-btn" data-action="item-pass" data-id="${entry.id}" aria-label="Create pass for ${escape(entry.label)}" title="Create pass">${icon('arrow')}</button></div></div>`).join('');
}
function passesView() {
  return `<section class="panel"><div class="panel-head"><h2>Your agent passes</h2><button class="text-btn" data-action="refresh">${icon('refresh')}Refresh status</button></div>${data.passes.length ? data.passes.map(pass => `<div class="pass-card"><span class="entry-icon">${icon('pass')}</span><div><strong>${escape(pass.label)}</strong><p>No preset destination</p><small>${pass.fields.length} fields · Expires ${expiryLabel(pass.expiresAt)}</small></div><span class="status-pill">${stateOf(pass)}</span>${stateOf(pass) === 'ready' ? `<button class="btn secondary" data-action="revoke" data-id="${pass.id}">Revoke</button>` : ''}</div>`).join('') : `<div class="empty"><span class="empty-symbol">${icon('pass')}</span><h3>A little access. A lot of control.</h3><p>Create a single-use pass to let an agent trigger a private autofill.</p><button class="btn primary" data-action="pass">${icon('plus')}Create your first pass</button></div>`}<div class="panel-foot">PINs are shown once. All pending passes are revoked when you lock your vault.</div></section>`;
}
function activityView() { return `<section class="panel"><div class="panel-head"><h2>Recent activity</h2><small>Last 100 events · No secret values</small></div>${data.activity.length ? `<div class="activity-list">${data.activity.map(event => `<div class="activity-row"><span class="entry-icon">${icon(event.action.includes('Pass') ? 'pass' : 'shield')}</span><div><strong>${escape(event.action)}</strong><p>${escape(event.detail)}</p></div><time>${timeLabel(event.at)} · ${new Date(event.at).toLocaleTimeString([], { hour:'2-digit',minute:'2-digit' })}</time></div>`).join('')}</div>` : `<div class="empty"><span class="empty-symbol">${icon('activity')}</span><h3>Nothing to report. Yet.</h3><p>Saved items, passes, and autofills will appear here.</p></div>`}</section>`; }
function securityView() {
  return `<div class="security-grid"><section class="info-card">${icon('vault')}<h3>Your vault stays here.</h3><p>Your details are encrypted with AES-256-GCM. A key derived from your master password using scrypt unlocks them. The key stays in server memory while unlocked.</p><p>There is no password recovery. Keep your master password safe and back up <code>.data/vault.enc</code>.</p><button class="btn secondary" data-action="${token ? 'lock' : 'unlock'}">${icon('lock')}${token ? 'Lock vault now' : 'Unlock vault'}</button></section><section class="info-card">${icon('pass')}<h3>Permission with an expiration.</h3><p>Every pass has a random 32-digit PIN, a unique agent URL and specific fields. No destination URL is required to create a key; the agent supplies it at use time. PINs are stored as hashes and consumed before a fill starts, even if it fails.</p><p>Five incorrect attempts revoke a pass. Locking the vault revokes pending passes and closes private browser windows. The vault auto-locks after 30 minutes without owner API activity.</p></section><section class="info-card">${icon('bot')}<h3>Actions without a read API.</h3><p>The agent endpoint returns only a result and a field count. It never returns values, screenshots, page contents, or browser cookies. The private browser is separate from the agent’s browsing session.</p><p>This does not protect against an agent with access to your desktop, process memory, files, or private browser. Keep those permissions separate.</p></section><section class="info-card">${icon('computer')}<h3>Built to work on localhost.</h3><p>Copy the generated prompt into an agent running on this computer. Its URL is based on the local address you’re using, so no deployment is required.</p><p>A cloud agent cannot reach your localhost automatically. Use an authorized local request tool. This app intentionally binds to loopback and rejects other hosts; do not expose it as a public service.</p></section><section class="info-card wide">${icon('shield')}<h3>Your agent chooses the page.</h3><p>Keys have no preset destination. An agent with the PIN chooses the page when using the key; that website receives the selected values. Login items remain limited to their saved website origin. The browser allows same-origin resources and blocks cross-origin requests, popups, WebSockets, service workers, and navigation away from the exact URL supplied for that fill. Some sites, third-party login flows, CAPTCHAs, and embedded forms may not work. agentautofill fills top-level form fields; it never automatically clicks submit. Review the private browser before submitting. This is a local prototype, not an independently audited password manager.</p></section></div>`;
}
function authModal() {
  showModal(`${modalHead(initialized ? 'Welcome back.' : 'Your vault. Your key.', initialized ? 'Enter your master password to unlock this session.' : 'One master password protects all of your saved details.')}<form id="auth-form"><div class="dialog-body"><div class="notice">${initialized ? 'Your key will stay in memory only while the vault is unlocked.' : '<strong>Make it memorable. Keep it private.</strong><br>Use at least 12 characters. There’s no password reset or recovery.'}</div><div class="form-error" role="alert"></div><div class="field"><label for="master">Master password</label><input id="master" name="password" type="password" minlength="12" maxlength="1024" required autocomplete="${initialized ? 'current-password' : 'new-password'}" autofocus placeholder="At least 12 characters"></div>${!initialized ? '<div class="field"><label for="confirm">Confirm password</label><input id="confirm" name="confirm" type="password" minlength="12" required autocomplete="new-password" placeholder="One more time"></div>' : ''}</div><div class="dialog-actions"><button type="button" class="btn secondary" data-action="close">Cancel</button><button type="submit" class="btn primary">${icon('lock')}${initialized ? 'Unlock vault' : 'Create vault'}</button></div></form>`);
}
function itemFields(type, editing) {
  return `${type === 'login' ? `<div class="field full"><label for="item-site">Website</label><input id="item-site" name="site" type="url" required placeholder="https://example.com" value="${escape(editing?.site || '')}"><small>Login passes are restricted to this exact website origin.</small></div>` : ''}${typeFields[type].map(field => `<div class="field ${['password','address1'].includes(field) ? 'full' : ''}"><label for="value-${field}">${fieldNames[field]}</label><input id="value-${field}" name="${field}" type="${field === 'password' ? 'password' : field === 'email' ? 'email' : field === 'phone' ? 'tel' : 'text'}" autocomplete="off" maxlength="2048" placeholder="${editing?.fields.includes(field) ? 'Saved · leave blank to keep' : field === 'country' ? 'e.g. United Kingdom' : fieldNames[field]}"></div>`).join('')}`;
}
function itemModal(id) {
  if (!requireUnlock()) return;
  const entry = data.entries.find(e => e.id === id);
  const type = entry?.type || (filter === 'all' ? 'login' : filter);
  showModal(`${modalHead(entry ? 'Edit vault item' : 'Make yourself at home.', entry ? 'Existing values stay hidden. Enter a new value to replace one.' : 'Save a few details. Keep them close.')}<form id="item-form" data-id="${entry?.id || ''}"><div class="dialog-body"><div class="form-error" role="alert"></div><div class="form-grid"><div class="field"><label for="item-type">Item type</label><select id="item-type" name="type" ${entry ? 'disabled' : ''}>${Object.entries(names).map(([key,name]) => `<option value="${key}" ${type === key ? 'selected' : ''}>${name}</option>`).join('')}</select></div><div class="field"><label for="item-label">Item name</label><input id="item-label" name="label" value="${escape(entry?.label || '')}" required maxlength="80" placeholder="e.g. Personal login" autofocus></div></div><hr class="divider"><div class="form-grid" id="item-fields">${itemFields(type, entry)}</div><p class="form-description">${entry ? 'Updating this item revokes its unused agent passes. To remove a saved field, delete the item and create it again.' : 'Values are encrypted on disk and are never included in an agent prompt.'}</p></div><div class="dialog-actions">${entry ? `<button type="button" class="btn danger" data-action="delete" data-id="${entry.id}">${icon('trash')}Delete</button>` : ''}<button type="button" class="btn secondary" data-action="close">Cancel</button><button class="btn primary" type="submit">${icon('lock')}${entry ? 'Save changes' : 'Save to vault'}</button></div></form>`);
}
function mappingRows(entry) { return entry ? entry.fields.map(field => `<div class="mapping"><input type="checkbox" id="map-${field}" name="map-${field}" checked aria-label="Allow ${fieldNames[field]}"><label for="map-${field}">${fieldNames[field]}</label><input type="text" name="selector-${field}" aria-label="CSS selector for ${fieldNames[field]}" value="${escape(defaults[field])}"></div>`).join('') : ''; }
function passModal(id) {
  if (!requireUnlock()) return;
  if (!data.entries.length) { itemModal(); toast('Save an item first, then create a pass.'); return; }
  const entry = data.entries.find(item => item.id === id) || data.entries[0];
  showModal(`${modalHead('A pass, with boundaries.', 'Choose the details and expiry. Your agent picks the page when using the key.')}<form id="pass-form"><div class="dialog-body"><div class="form-error" role="alert"></div><div class="field"><label for="pass-entry">Vault item</label><select id="pass-entry" name="entryId">${data.entries.map(item => `<option value="${item.id}" ${item.id === entry.id ? 'selected' : ''}>${escape(item.label)} · ${names[item.type]}</option>`).join('')}</select></div><div class="form-grid"><div class="field"><label for="pass-label">Pass name</label><input id="pass-label" name="label" placeholder="e.g. Fill my shipping details" maxlength="80" value="${escape(entry.label)}"></div><div class="field"><label for="pass-minutes">Expires in</label><select name="minutes" id="pass-minutes"><option value="5">5 minutes</option><option value="15" selected>15 minutes</option><option value="30">30 minutes</option><option value="60">1 hour</option><option value="360">6 hours</option><option value="720">12 hours</option><option value="1440">1 day</option><option value="4320">3 days</option><option value="10080">7 days</option><option value="20160">14 days</option><option value="43200">30 days</option></select><small>Up to 30 days. Locking or restarting the vault still revokes unused keys.</small></div></div><p class="mapping-title">Allowed fields & form selectors</p><div id="mappings">${mappingRows(entry)}</div><p class="form-description">Match each field to the website’s CSS selector (for example, #email). Uncheck any field you don’t want to share.</p><div class="notice"><strong>One use. No automatic submission.</strong><br>Your agent chooses the page at use time and triggers the fill in a separate private browser. You review and submit. Cross-origin and embedded forms are not supported.</div></div><div class="dialog-actions"><button type="button" class="btn secondary" data-action="close">Cancel</button><button class="btn primary" type="submit">${icon('pass')}Generate agent pass</button></div></form>`);
}
function generatedModal(pass) {
  latestPass = pass;
  showModal(`${modalHead('Your handoff is ready.', 'Share this prompt only with the agent you want to authorize.')}<div class="dialog-body generated"><div class="success-heading"><span class="success-icon">${icon('check')}</span><h3>One task. Permission granted.</h3><p>This pass expires on ${expiryLabel(pass.expiresAt)} and can be used once.</p></div><span class="eyebrow">Your one-time PIN</span><div class="pin">${escape(pass.pin)}</div><span class="eyebrow">Dedicated agent branch</span><div class="url">${escape(pass.agentUrl)}</div><div class="field"><label for="generated-prompt">Ready-to-use agent prompt</label><textarea id="generated-prompt" readonly>${escape(pass.prompt)}</textarea></div><div class="notice warning">Copy it now. The PIN cannot be retrieved later. An agent on this computer can use the localhost URL; a remote agent needs an authorized local tool.</div></div><div class="dialog-actions"><button class="btn secondary" data-action="copy-link">${icon('copy')}Copy link</button><button class="btn primary" data-action="copy-prompt">${icon('copy')}Copy agent prompt</button></div>`);
}
async function copy(value) { try { await navigator.clipboard.writeText(value); toast('Copied to clipboard'); } catch { const el = dialog.querySelector('textarea'); el?.select(); toast('Select and copy the prompt with your keyboard.'); } }
document.addEventListener('click', async event => {
  const button = event.target.closest('button');
  if (!button) return;
  if (button.dataset.view) { view = button.dataset.view; if (token) await refresh().catch(error => toast(error.message)); else render(); return; }
  if (button.dataset.filter) { filter = button.dataset.filter; render(); return; }
  const action = button.dataset.action;
  const id = button.dataset.id;
  try {
    if (action === 'close') { closeModal(); latestPass = null; }
    if (action === 'unlock') authModal();
    if (action === 'add') itemModal();
    if (action === 'edit') itemModal(id);
    if (action === 'pass') passModal();
    if (action === 'item-pass') passModal(id);
    if (action === 'lock') { await api('/api/lock', {}); token = null; latestPass = null; data = { entries: [], passes: [], activity: [] }; closeModal(); render(); toast('Vault locked. Pending passes revoked.'); }
    if (action === 'refresh') { if (requireUnlock()) { await refresh(); toast('You’re up to date'); } }
    if (action === 'how') { view = 'security'; render(); }
    if (action === 'sample') {
      button.disabled = true;
      await api('/api/entries', { type: 'identity', label: 'Sample identity', values: { firstName: 'Alex', lastName: 'Morgan', email: 'alex@example.com', phone: '+44 7700 900123' } });
      filter = 'all'; await refresh(); toast('Sample identity added. Try it with the local demo.');
    }
    if (action === 'copy-prompt' && latestPass) await copy(latestPass.prompt);
    if (action === 'copy-link' && latestPass) await copy(latestPass.agentUrl);
    if (action === 'delete') {
      const entry = data.entries.find(item => item.id === id);
      showModal(`${modalHead('Remove this item?', 'This also revokes all unused passes for this item.')}<div class="dialog-body"><p class="form-description">${escape(entry.label)} and its saved values will be removed from your vault. This cannot be undone.</p><div class="form-error" role="alert"></div></div><div class="dialog-actions"><button class="btn secondary" data-action="close">Keep item</button><button class="btn danger" data-action="confirm-delete" data-id="${id}">Delete item</button></div>`);
    }
    if (action === 'confirm-delete') { button.disabled = true; await api(`/api/entries/${id}`, {}, 'DELETE'); closeModal(); await refresh(); toast('Item removed'); }
    if (action === 'revoke') { button.disabled = true; await api(`/api/passes/${id}/revoke`, {}); await refresh(); toast('Pass revoked'); }
  } catch (error) { button.disabled = false; if (dialog.open) formError(error.message); else toast(error.message); }
});
document.addEventListener('input', event => { if (event.target.id === 'search') { query = event.target.value; document.querySelector('#entry-list').innerHTML = entriesView(); } });
document.addEventListener('change', event => {
  if (event.target.id === 'sort') { sort = event.target.value; document.querySelector('#entry-list').innerHTML = entriesView(); }
  if (event.target.id === 'item-type') dialog.querySelector('#item-fields').innerHTML = itemFields(event.target.value);
  if (event.target.id === 'pass-entry') {
    const entry = data.entries.find(item => item.id === event.target.value);
    dialog.querySelector('#mappings').innerHTML = mappingRows(entry);
    dialog.querySelector('#pass-label').value = entry.label;
  }
});
document.addEventListener('submit', async event => {
  const form = event.target;
  if (!form.id.endsWith('-form')) return;
  event.preventDefault();
  const submit = form.querySelector('[type="submit"]');
  submit.disabled = true;
  const values = new FormData(form);
  try {
    if (form.id === 'auth-form') {
      if (!initialized && values.get('password') !== values.get('confirm')) throw new Error('The passwords don’t match. Try again.');
      const result = await api(initialized ? '/api/unlock' : '/api/setup', { password: values.get('password') });
      token = result.token; initialized = true; closeModal(); await refresh(); toast('Your vault is unlocked');
    }
    if (form.id === 'item-form') {
      const type = dialog.querySelector('#item-type').value;
      const fields = Object.fromEntries(typeFields[type].map(field => [field, values.get(field) || '']));
      await api('/api/entries', { id: form.dataset.id || undefined, type, label: values.get('label'), site: values.get('site'), values: fields });
      closeModal(); await refresh(); toast('Saved securely to your vault');
    }
    if (form.id === 'pass-form') {
      const entry = data.entries.find(item => item.id === values.get('entryId'));
      const mappings = entry.fields.filter(field => values.get(`map-${field}`)).map(field => ({ field, selector: values.get(`selector-${field}`) }));
      const pass = await api('/api/passes', { entryId: entry.id, label: values.get('label'), minutes: Number(values.get('minutes')), mappings });
      await refresh(); generatedModal(pass);
    }
  } catch (error) { formError(error.message); } finally { submit.disabled = false; }
});
dialog.addEventListener('cancel', () => { latestPass = null; dialog.innerHTML = ''; });
dialog.addEventListener('click', event => { if (event.target === dialog) { const rect = dialog.getBoundingClientRect(); if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) { latestPass = null; closeModal(); } } });
document.addEventListener('keydown', event => { if (event.key === '/' && !dialog.open && !['INPUT','TEXTAREA'].includes(document.activeElement.tagName)) { event.preventDefault(); document.querySelector('#search')?.focus(); } });
try { initialized = (await api('/api/status')).initialized; } catch (error) { toast(error.message); }
render();
