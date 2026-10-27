const paths = {
  vault: '<rect x="4" y="3" width="16" height="18" rx="3"/><circle cx="12" cy="12" r="4"/><path d="M12 8v8m-4-4h8M7 6h.01"/>',
  key: '<circle cx="8" cy="15" r="5"/><path d="m11.5 11.5 9-9M16 7l3 3m-6-1 3 3"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21v-2a8 8 0 0 1 16 0v2"/>',
  pin: '<path d="M20 10c0 6-8 12-8 12S4 16 4 10a8 8 0 1 1 16 0Z"/><circle cx="12" cy="10" r="3"/>',
  shield: '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z"/><path d="m8 12 3 3 5-6"/>',
  lock: '<rect x="5" y="10" width="14" height="11" rx="3"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/>',
  logout: '<path d="M9 4H4v16h5m5-13 5 5-5 5M8 12h11"/>',
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
let account = null;
let csrf = null;
let legacyAvailable = false;
let authMode = 'login';
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
  const response = await fetch(path, { method, credentials: 'same-origin', headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(csrf && body !== undefined ? { 'X-CSRF-Token': csrf } : {}) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  const result = await response.json();
  if (!response.ok) {
    if (response.status === 401 && account) { clearAccount(); closeModal(); render(); }
    throw new Error(result.error || 'Something went wrong.');
  }
  return result;
}
async function refresh() { if (account) { data = await api('/api/vault'); account = data.user; legacyAvailable = data.legacyAvailable; } render(); }
function clearAccount() { account = null; csrf = null; latestPass = null; data = { entries: [], passes: [], activity: [] }; query = ''; filter = 'all'; view = 'vault'; }
function showModal(html) { returnFocus = document.activeElement; dialog.innerHTML = html; if (!dialog.open) dialog.showModal(); }
function closeModal() { dialog.close(); dialog.innerHTML = ''; returnFocus?.focus(); }
function modalHead(title, subtitle) { return `<div class="dialog-head"><div><h2>${title}</h2><p>${subtitle}</p></div><button class="icon-btn" data-action="close" aria-label="Close dialog">${icon('close')}</button></div>`; }
function formError(message) { const el = (dialog.open ? dialog : root).querySelector('.form-error'); if (el) el.textContent = message; else toast(message); }
function requireLogin() { if (account) return true; render(); return false; }
function count(type) { return type === 'all' ? data.entries.length : data.entries.filter(entry => entry.type === type).length; }
function timeLabel(date) { return new Date(date).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }); }
function expiryLabel(date) { return new Date(date).toLocaleString(undefined, { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }); }
function stateOf(pass) { return pass.status === 'ready' && pass.expiresAt <= Date.now() ? 'expired' : pass.status; }
function render() {
  if (!account) { root.innerHTML = authView(); return; }
  const titles = { vault: 'Your vault', passes: 'Agent passes', activity: 'Activity', security: 'Account & security' };
  root.innerHTML = `<aside class="sidebar"><a href="/" class="brand" aria-label="agentautofill home">${brand}</a><div class="workspace"><span>PW</span><div><strong>Personal workspace</strong><small>Just you. By design.</small></div>${icon('down')}</div><p class="nav-label">Workspace</p><nav aria-label="Main navigation">${[['vault','vault','My vault'],['passes','pass','Agent passes'],['activity','activity','Activity'],['security','user','Account']].map(([id, glyph, label]) => `<button data-view="${id}" class="nav-item ${view === id ? 'active' : ''}" ${view === id ? 'aria-current="page"' : ''}>${icon(glyph)}${label}${id === 'vault' ? `<span class="count">${data.entries.length}</span>` : ''}</button>`).join('')}</nav><div class="sidebar-bottom"><button class="nav-item" data-action="how">${icon('help')}How agentautofill works</button><div class="local-card"><p><span class="dot"></span>Running on this device</p><small>Local storage. Private by default.</small></div><div class="owner"><span class="avatar">${escape(account.name.slice(0,2).toUpperCase())}</span><div class="account-owner"><strong>${escape(account.name)}</strong><small>${escape(account.email)}</small></div><button data-action="logout" aria-label="Log out" title="Log out">${icon('logout')}</button></div></div></aside>
  <div class="shell"><header class="topbar"><div class="breadcrumb">Personal workspace <span>/</span> <strong>${view === 'vault' ? 'My vault' : titles[view]}</strong></div><a href="/" class="brand mobile-brand">${brand}</a><div class="topright"><span class="environment">${icon('computer')}Local workspace</span><span class="status-pill"><span class="dot"></span>Logged in</span><button class="icon-btn" data-action="how" aria-label="Help">${icon('help')}</button></div></header>
  <main class="main"><div class="page-heading"><div><h1>${titles[view]}</h1><p class="subtitle">${{ vault: 'Your information, ready to use. Always in your control.', passes: 'Give your agent access to an action. Keep the details private.', activity: 'A clear record of what happened in your workspace.', security: 'Know exactly where your information goes.' }[view]}</p></div><div class="actions">${view === 'vault' ? `<button class="btn secondary" data-action="add">${icon('plus')}Add item</button>` : ''}${['vault','passes'].includes(view) ? `<button class="btn primary" data-action="pass">${icon('pass')}Create agent pass</button>` : `<button class="btn secondary" data-action="refresh">${icon('refresh')}Refresh</button>`}</div></div>
  ${legacyAvailable ? `<div class="intro-banner">${icon('vault')}<div><h3>Bring your existing details with you.</h3><p>Import your previous local vault using its password. The original stays untouched.</p></div><button class="btn" data-action="import">Import vault ${icon('arrow')}</button></div>` : ''}
  ${view === 'vault' ? vaultView() : view === 'passes' ? passesView() : view === 'activity' ? activityView() : securityView()}
  <div class="bottom-note">${icon('shield')}Stored on your device. Used only through the keys you share.</div></main></div>`;
}
function vaultView() {
  return `<div class="stats">${[['all','vault','All items'],['login','key','Logins'],['identity','user','Identities'],['address','pin','Addresses']].map(([type,glyph,title]) => `<button class="stat ${filter === type ? 'selected' : ''}" data-filter="${type}"><div class="stat-top">${title}<span class="stat-icon">${icon(glyph)}</span></div><div class="stat-value">${count(type)}<small>${count(type) === 1 ? 'item' : 'items'}</small></div></button>`).join('')}</div><div class="content-grid"><section class="panel"><div class="panel-head"><h2>Saved items</h2><div class="actions"><small>Private to your account</small><button class="icon-btn" data-action="add" aria-label="Add vault item" title="Add item">${icon('plus')}</button></div></div><div class="tabs" role="tablist" aria-label="Item type">${[['all','All items'],['login','Logins'],['identity','Identities'],['address','Addresses']].map(([id,label]) => `<button class="tab ${filter === id ? 'active' : ''}" role="tab" aria-selected="${filter === id}" data-filter="${id}">${label}</button>`).join('')}</div><div class="search-row"><label class="search">${icon('search')}<input id="search" aria-label="Search vault" placeholder="Search your vault…" value="${escape(query)}"><span class="shortcut">/</span></label><select id="sort" aria-label="Sort items"><option value="recent" ${sort === 'recent' ? 'selected' : ''}>Recently added</option><option value="name" ${sort === 'name' ? 'selected' : ''}>Name A–Z</option></select></div><div class="table-head"><span>Item name</span><span>Type</span><span></span></div><div id="entry-list">${entriesView()}</div><div class="panel-foot"><span>${count('all')} encrypted ${count('all') === 1 ? 'item' : 'items'}</span><span>${icon('lock')}AES-256-GCM encryption</span></div></section><aside class="right-column"><section class="handoff-card"><p class="eyebrow">Made for the agent era</p><h2>A helpful agent.<br>A private you.</h2><p>Let AI fill in the blanks.<br>Without handing over your details.</p><div class="connection" aria-hidden="true"><span class="node">${icon('vault')}</span><span class="line"></span><span class="node central">${icon('lock')}</span><span class="line"></span><span class="node">${icon('bot')}</span></div><button class="btn primary" data-action="pass">Create an agent pass ${icon('arrow')}</button><p class="card-note">One task. One PIN. Your permission.</p></section><section class="how-card"><h3>A safer way to autofill</h3>${[['Save your details','Keep logins, identities, and addresses in one encrypted vault.'],['Set the boundaries','Choose the fields and expiry. Your agent supplies the page when using the pass.'],['Let your agent help','Share the prompt. Your private browser handles the rest.']].map(([title,desc],i) => `<div class="step"><span>${i+1}</span><div><h4>${title}</h4><p>${desc}</p></div></div>`).join('')}</section></aside></div>`;
}
function entriesView() {
  const entries = data.entries.filter(entry => (filter === 'all' || entry.type === filter) && `${entry.label} ${entry.site} ${names[entry.type]}`.toLowerCase().includes(query.toLowerCase())).sort((a,b) => sort === 'name' ? a.label.localeCompare(b.label) : b.updatedAt.localeCompare(a.updatedAt));
  if (!entries.length) return `<div class="empty"><span class="empty-symbol">${icon(query ? 'search' : 'vault')}</span><h3>${query ? 'No matching items' : 'Your vault, a fresh start'}</h3><p>${query ? 'Try another name or choose a different category.' : 'Save the details you use every day. Choose exactly when and where they’re used.'}</p>${query ? '' : `<button class="btn secondary" data-action="add">${icon('plus')}Add your first item</button>${account && !data.entries.length ? '<button class="text-btn" data-action="sample">Or try a sample identity →</button>' : ''}`}</div>`;
  return entries.map(entry => `<div class="entry-row"><div class="entry-main"><span class="entry-icon ${entry.type}">${icon(typeIcon[entry.type])}</span><div class="entry-text"><strong>${escape(entry.label)}</strong><small>${entry.site ? escape(new URL(entry.site).hostname) : `${entry.fields.length} protected fields`} · ${timeLabel(entry.updatedAt)}</small></div></div><span class="type-badge">${names[entry.type]}</span><div class="row-buttons"><button class="icon-btn" data-action="edit" data-id="${entry.id}" aria-label="Edit ${escape(entry.label)}" title="Edit item">${icon('edit')}</button><button class="icon-btn" data-action="item-pass" data-id="${entry.id}" aria-label="Create pass for ${escape(entry.label)}" title="Create pass">${icon('arrow')}</button></div></div>`).join('');
}
function passesView() {
  return `<section class="panel"><div class="panel-head"><h2>Your agent passes</h2><button class="text-btn" data-action="refresh">${icon('refresh')}Refresh status</button></div>${data.passes.length ? data.passes.map(pass => `<div class="pass-card"><span class="entry-icon">${icon('pass')}</span><div><strong>${escape(pass.label)}</strong><p>No preset destination</p><small>${pass.fields.length} fields · Expires ${expiryLabel(pass.expiresAt)}</small></div><span class="status-pill">${stateOf(pass)}</span>${stateOf(pass) === 'ready' ? `<button class="btn secondary" data-action="revoke" data-id="${pass.id}">Revoke</button>` : ''}</div>`).join('') : `<div class="empty"><span class="empty-symbol">${icon('pass')}</span><h3>A little access. A lot of control.</h3><p>Create a single-use pass to let an agent trigger a private autofill.</p><button class="btn primary" data-action="pass">${icon('plus')}Create your first pass</button></div>`}<div class="panel-foot">PINs are shown once. Keys remain active after logout, until used, revoked, or expired.</div></section>`;
}
function activityView() { return `<section class="panel"><div class="panel-head"><h2>Recent activity</h2><small>Last 100 events · No secret values</small></div>${data.activity.length ? `<div class="activity-list">${data.activity.map(event => `<div class="activity-row"><span class="entry-icon">${icon(event.action.includes('Pass') ? 'pass' : 'shield')}</span><div><strong>${escape(event.action)}</strong><p>${escape(event.detail)}</p></div><time>${timeLabel(event.at)} · ${new Date(event.at).toLocaleTimeString([], { hour:'2-digit',minute:'2-digit' })}</time></div>`).join('')}</div>` : `<div class="empty"><span class="empty-symbol">${icon('activity')}</span><h3>Nothing to report. Yet.</h3><p>Saved items, passes, and autofills will appear here.</p></div>`}</section>`; }
function securityView() {
  return `<div class="security-grid"><section class="info-card">${icon('user')}<h3>Your account</h3><p><strong>${escape(account.name)}</strong><br>${escape(account.email)}</p><p>Your saved items, keys, and activity belong to this account. You stay logged in when you refresh the page.</p><button class="btn secondary" data-action="logout">${icon('logout')}Log out</button></section><section class="info-card">${icon('shield')}<h3>Encrypted on this device.</h3><p>Account passwords are stored as salted scrypt hashes. Your details are encrypted with AES-256-GCM using a local server-managed key. There is no separate vault password or unlock step.</p><p>Back up both <code>.data/accounts.enc</code> and <code>.data/account-key</code>. Email is a login identifier; email verification and password recovery are not configured.</p></section><section class="info-card">${icon('pass')}<h3>Keys follow their own expiry.</h3><p>Keys can last from 5 minutes to 30 days and survive logout and restarts. Each key is one-use, field-scoped, and protected by a random 32-digit PIN. Five wrong PINs revoke it.</p><p>Use Agent passes to revoke a key. Updating or deleting a saved item revokes that item’s unused keys.</p></section><section class="info-card">${icon('computer')}<h3>A local account.</h3><p>Accounts and data live on this computer. Your session uses an HttpOnly, SameSite cookie with a seven-day expiry. Logging out ends the current session; a server restart requires login again.</p><p>Remote agents need an authorized local tool to use localhost. Keep this app on loopback; it is not configured for public hosting.</p></section><section class="info-card wide">${icon('bot')}<h3>Actions without a read API.</h3><p>Agents receive only status and field counts, never secret values, screenshots, page contents, or cookies. An agent chooses the destination at use time. Login items remain restricted to their saved website. The destination receives the values, so share keys only with an agent you trust.</p><p>This does not protect against an agent with unrestricted desktop, filesystem, process-memory, or private-browser access. A local server key allows the app to perform an authorized fill while you are logged out. Protect that key and the device. This remains a local prototype, not an independently audited password manager.</p>${legacyAvailable ? '<button class="btn secondary" data-action="import">Import previous vault</button>' : ''}</section></div>`;
}
function authView() {
  const signup = authMode === 'signup';
  return `<main class="auth-page"><section class="auth-story"><a href="/" class="brand">${brand}</a><div class="auth-story-content"><p class="eyebrow">Your details. Your account.</p><h1>A helpful agent.<br>A private you.</h1><p>Keep your everyday details in one place.<br>Give your agent just the access it needs.</p><div class="auth-feature">${icon('shield')}An encrypted workspace for every account</div><div class="auth-feature">${icon('pass')}One-use agent keys with up to 30 days’ expiry</div><div class="auth-feature">${icon('computer')}Stored right here on your device</div></div><span class="auth-local"><span class="dot"></span>Local workspace · No cloud sync</span></section><section class="auth-form-area"><div class="auth-card"><div class="auth-tabs" aria-label="Account access"><button data-action="auth-mode" data-mode="login" class="${signup ? '' : 'active'}" aria-pressed="${!signup}">Log in</button><button data-action="auth-mode" data-mode="signup" class="${signup ? 'active' : ''}" aria-pressed="${signup}">Sign up</button></div><h2>${signup ? 'Make it yours.' : 'Welcome back.'}</h2><p class="auth-description">${signup ? 'Create your account and start your private workspace.' : 'Log in to your agentautofill account.'}</p><form id="auth-form" data-mode="${authMode}"><div class="form-error" role="alert"></div>${signup ? '<div class="field"><label for="account-name">Your name</label><input id="account-name" name="name" autocomplete="name" required maxlength="80" placeholder="Your name"></div>' : ''}<div class="field"><label for="account-email">Email address</label><input id="account-email" name="email" type="email" autocomplete="username" required maxlength="254" placeholder="you@example.com"></div><div class="field"><label for="account-password">Password</label><div class="password-input"><input id="account-password" name="password" type="password" autocomplete="${signup ? 'new-password' : 'current-password'}" required ${signup ? 'minlength="12"' : ''} maxlength="1024" placeholder="${signup ? 'At least 12 characters' : 'Your password'}"><button type="button" data-action="password-toggle" aria-label="Show password">Show</button></div>${signup ? '<small>Use 12 or more characters. Password recovery is not available yet.</small>' : ''}</div>${signup ? '<div class="field"><label for="account-confirm">Confirm password</label><input id="account-confirm" name="confirm" type="password" autocomplete="new-password" required minlength="12" maxlength="1024" placeholder="Enter your password again"></div>' : ''}<button class="btn primary auth-submit" type="submit">${signup ? 'Create account' : 'Log in'} ${icon('arrow')}</button></form><p class="auth-switch">${signup ? 'Already have an account?' : 'New here?'} <button class="text-btn" data-action="auth-mode" data-mode="${signup ? 'login' : 'signup'}">${signup ? 'Log in' : 'Create an account'}</button></p>${legacyAvailable ? '<div class="notice auth-migration"><strong>Have an existing vault?</strong><br>Create an account, then import your saved details with your previous vault password.</div>' : ''}<p class="auth-note">${icon('lock')}Your account is local to this installation.</p></div></section></main>`;
}
function importModal() {
  if (!requireLogin()) return;
  showModal(`${modalHead('Bring your details along.', 'Import your previous local vault into this account.')}<form id="import-form"><div class="dialog-body"><div class="notice">Your original encrypted vault stays untouched. Its entries will be copied into <strong>${escape(account.email)}</strong>. Only one account can claim this import.</div><div class="form-error" role="alert"></div><div class="field"><label for="legacy-password">Previous vault password</label><input id="legacy-password" name="password" type="password" autocomplete="off" required maxlength="1024" autofocus></div></div><div class="dialog-actions"><button type="button" class="btn secondary" data-action="close">Cancel</button><button type="submit" class="btn primary">Import saved details</button></div></form>`);
}
function itemFields(type, editing) {
  return `${type === 'login' ? `<div class="field full"><label for="item-site">Website</label><input id="item-site" name="site" type="url" required placeholder="https://example.com" value="${escape(editing?.site || '')}"><small>Login passes are restricted to this exact website origin.</small></div>` : ''}${typeFields[type].map(field => `<div class="field ${['password','address1'].includes(field) ? 'full' : ''}"><label for="value-${field}">${fieldNames[field]}</label><input id="value-${field}" name="${field}" type="${field === 'password' ? 'password' : field === 'email' ? 'email' : field === 'phone' ? 'tel' : 'text'}" autocomplete="off" maxlength="2048" placeholder="${editing?.fields.includes(field) ? 'Saved · leave blank to keep' : field === 'country' ? 'e.g. United Kingdom' : fieldNames[field]}"></div>`).join('')}`;
}
function itemModal(id) {
  if (!requireLogin()) return;
  const entry = data.entries.find(e => e.id === id);
  const type = entry?.type || (filter === 'all' ? 'login' : filter);
  showModal(`${modalHead(entry ? 'Edit vault item' : 'Make yourself at home.', entry ? 'Existing values stay hidden. Enter a new value to replace one.' : 'Save a few details. Keep them close.')}<form id="item-form" data-id="${entry?.id || ''}"><div class="dialog-body"><div class="form-error" role="alert"></div><div class="form-grid"><div class="field"><label for="item-type">Item type</label><select id="item-type" name="type" ${entry ? 'disabled' : ''}>${Object.entries(names).map(([key,name]) => `<option value="${key}" ${type === key ? 'selected' : ''}>${name}</option>`).join('')}</select></div><div class="field"><label for="item-label">Item name</label><input id="item-label" name="label" value="${escape(entry?.label || '')}" required maxlength="80" placeholder="e.g. Personal login" autofocus></div></div><hr class="divider"><div class="form-grid" id="item-fields">${itemFields(type, entry)}</div><p class="form-description">${entry ? 'Updating this item revokes its unused agent passes. To remove a saved field, delete the item and create it again.' : 'Values are encrypted on disk and are never included in an agent prompt.'}</p></div><div class="dialog-actions">${entry ? `<button type="button" class="btn danger" data-action="delete" data-id="${entry.id}">${icon('trash')}Delete</button>` : ''}<button type="button" class="btn secondary" data-action="close">Cancel</button><button class="btn primary" type="submit">${icon('lock')}${entry ? 'Save changes' : 'Save to vault'}</button></div></form>`);
}
function mappingRows(entry) { return entry ? entry.fields.map(field => `<div class="mapping"><input type="checkbox" id="map-${field}" name="map-${field}" checked aria-label="Allow ${fieldNames[field]}"><label for="map-${field}">${fieldNames[field]}</label><input type="text" name="selector-${field}" aria-label="CSS selector for ${fieldNames[field]}" value="${escape(defaults[field])}"></div>`).join('') : ''; }
function passModal(id) {
  if (!requireLogin()) return;
  if (!data.entries.length) { itemModal(); toast('Save an item first, then create a pass.'); return; }
  const entry = data.entries.find(item => item.id === id) || data.entries[0];
  showModal(`${modalHead('A pass, with boundaries.', 'Choose the details and expiry. Your agent picks the page when using the key.')}<form id="pass-form"><div class="dialog-body"><div class="form-error" role="alert"></div><div class="field"><label for="pass-entry">Vault item</label><select id="pass-entry" name="entryId">${data.entries.map(item => `<option value="${item.id}" ${item.id === entry.id ? 'selected' : ''}>${escape(item.label)} · ${names[item.type]}</option>`).join('')}</select></div><div class="form-grid"><div class="field"><label for="pass-label">Pass name</label><input id="pass-label" name="label" placeholder="e.g. Fill my shipping details" maxlength="80" value="${escape(entry.label)}"></div><div class="field"><label for="pass-minutes">Expires in</label><select name="minutes" id="pass-minutes"><option value="5">5 minutes</option><option value="15" selected>15 minutes</option><option value="30">30 minutes</option><option value="60">1 hour</option><option value="360">6 hours</option><option value="720">12 hours</option><option value="1440">1 day</option><option value="4320">3 days</option><option value="10080">7 days</option><option value="20160">14 days</option><option value="43200">30 days</option></select><small>Up to 30 days. Keys remain active after logout and server restarts.</small></div></div><p class="mapping-title">Allowed fields & form selectors</p><div id="mappings">${mappingRows(entry)}</div><p class="form-description">Match each field to the website’s CSS selector (for example, #email). Uncheck any field you don’t want to share.</p><div class="notice"><strong>One use. No automatic submission.</strong><br>Your agent chooses the page at use time and triggers the fill in a separate private browser. You review and submit. Cross-origin and embedded forms are not supported.</div></div><div class="dialog-actions"><button type="button" class="btn secondary" data-action="close">Cancel</button><button class="btn primary" type="submit">${icon('pass')}Generate agent pass</button></div></form>`);
}
function generatedModal(pass) {
  latestPass = pass;
  showModal(`${modalHead('Your handoff is ready.', 'Share this prompt only with the agent you want to authorize.')}<div class="dialog-body generated"><div class="success-heading"><span class="success-icon">${icon('check')}</span><h3>One task. Permission granted.</h3><p>This pass expires on ${expiryLabel(pass.expiresAt)} and can be used once.</p></div><span class="eyebrow">Your one-time PIN</span><div class="pin">${escape(pass.pin)}</div><span class="eyebrow">Dedicated agent branch</span><div class="url">${escape(pass.agentUrl)}</div><div class="field"><label for="generated-prompt">Ready-to-use agent prompt</label><textarea id="generated-prompt" readonly>${escape(pass.prompt)}</textarea></div><div class="notice warning">Copy it now. The PIN cannot be retrieved later. An agent on this computer can use the localhost URL; a remote agent needs an authorized local tool.</div></div><div class="dialog-actions"><button class="btn secondary" data-action="copy-link">${icon('copy')}Copy link</button><button class="btn primary" data-action="copy-prompt">${icon('copy')}Copy agent prompt</button></div>`);
}
async function copy(value) { try { await navigator.clipboard.writeText(value); toast('Copied to clipboard'); } catch { const el = dialog.querySelector('textarea'); el?.select(); toast('Select and copy the prompt with your keyboard.'); } }
document.addEventListener('click', async event => {
  const button = event.target.closest('button');
  if (!button) return;
  if (button.dataset.view) { view = button.dataset.view; if (account) await refresh().catch(error => toast(error.message)); else render(); return; }
  if (button.dataset.filter) { filter = button.dataset.filter; render(); return; }
  const action = button.dataset.action;
  const id = button.dataset.id;
  try {
    if (action === 'close') { closeModal(); latestPass = null; }
    if (action === 'auth-mode') { authMode = button.dataset.mode; render(); }
    if (action === 'password-toggle') { const input = root.querySelector('#account-password'); const hidden = input.type === 'password'; input.type = hidden ? 'text' : 'password'; button.textContent = hidden ? 'Hide' : 'Show'; button.setAttribute('aria-label', hidden ? 'Hide password' : 'Show password'); }
    if (action === 'import') importModal();
    if (action === 'add') itemModal();
    if (action === 'edit') itemModal(id);
    if (action === 'pass') passModal();
    if (action === 'item-pass') passModal(id);
    if (action === 'logout') { await api('/api/auth/logout', {}); clearAccount(); closeModal(); authMode = 'login'; render(); toast('You’re logged out'); }
    if (action === 'refresh') { if (requireLogin()) { await refresh(); toast('You’re up to date'); } }
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
      const signup = form.dataset.mode === 'signup';
      if (signup && values.get('password') !== values.get('confirm')) throw new Error('The passwords don’t match. Try again.');
      const result = await api(signup ? '/api/auth/signup' : '/api/auth/login', { name: values.get('name'), email: values.get('email'), password: values.get('password') });
      account = result.user; csrf = result.csrf; legacyAvailable = result.legacyAvailable;
      form.reset(); await refresh(); toast(signup ? 'Your account is ready' : 'Welcome back');
    }
    if (form.id === 'import-form') {
      const result = await api('/api/account/import-legacy', { password: values.get('password') });
      legacyAvailable = false; closeModal(); await refresh(); toast(`${result.imported} items imported`);
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
root.innerHTML = `<main class="auth-loading"><div class="brand">${brand}</div><p>Loading your account…</p></main>`;
try {
  const session = await api('/api/auth/session');
  account = session.user; csrf = session.csrf; legacyAvailable = session.legacyAvailable;
  await refresh();
} catch (error) { render(); toast(error.message); }
