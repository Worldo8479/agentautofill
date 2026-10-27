# agentautofill

A local web app with signup, login, account-specific autofill records, and single-use agent keys. An agent can trigger a private form fill without receiving saved values through the API.

## Run

Requires Node.js 22+ and a graphical desktop for private browser windows.

```sh
npm install
npm run browser:install
npm start
```

Open **http://127.0.0.1:4317**. Existing Google Chrome is used automatically on macOS, making the browser-install step optional there. Elsewhere, install Chromium or set `BROWSER_CHANNEL=chrome` to use installed Chrome.

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `4317` | Loopback HTTP port |
| `VAULT_PATH` | `.data/vault.enc` | Previous vault to import; its parent directory holds new account storage |
| `BROWSER_CHANNEL` | Chrome on macOS when available; bundled Chromium otherwise | Playwright browser channel |

No external API keys, model subscriptions, email provider, or build step are required. Prompts are generated locally; no AI service receives your saved details.

## Accounts

1. Choose **Sign up**, enter your name and email, and choose a password of at least 12 characters.
2. Use **Log in** with that email and password. Email matching is case-insensitive. Each account has separate saved items, keys, and activity.
3. Refreshing the page preserves login through an HttpOnly cookie. Sessions expire seven days after login. **Log out** invalidates the current browser session; other signed-in browsers remain signed in.
4. After a server restart, log in again. Account records, saved details, and unexpired keys persist.

These are accounts for this local installation, not cloud accounts. Email is a login identifier: email verification, password reset, and account recovery are not implemented. Keep your password safe.

### Import your previous vault

The previous `.data/vault.enc` file is preserved. After creating an account, use **Import vault** and enter its previous master password. Items are copied into the signed-in account, and the original encrypted file is left byte-for-byte unchanged. Only one account can claim that import; knowing a new account password alone does not grant access to the old vault. No old password or item values are returned to the browser during import.

Do not delete the original until you have verified your imported items and made a backup. Old in-memory passes from the pre-account app cannot be recovered; create new keys after importing.

## Create and use an agent key

1. Add a login, identity, or address. Existing values remain hidden; editing replaces only fields you enter. Delete and recreate an item to remove a field.
2. Create an agent pass. Choose the item, allowed fields, CSS selectors, and an expiry from **5 minutes to 30 days**. No destination URL is required or stored on a key.
3. Copy the generated prompt. It contains a unique `/agent/<random-id>` branch, a random 32-digit one-time PIN, scope, selectors, and expiry. The PIN is shown once.
4. The agent opens that branch and enters the PIN and the page URL for its task, or sends the JSON request below. Only public HTTPS pages and the local demo are supported. Login items remain restricted to their saved website origin.
5. A fresh, separate browser window fills the selected fields. The agent receives only status and a field count. **You** review and submit manually. Windows close after 15 minutes or when the server stops.

Keys remain usable after logout and server restarts, until used, revoked, or expired. Logging out is not a substitute for revoking a key. Updating or deleting an item revokes its unused keys. A failed browser fill still consumes the PIN; missing or disallowed page URLs may be corrected without consuming it.

For a first test, add the sample identity, create a key, open its agent page, and choose **Use the local demo form**. That form never sends entered values to a server.

```http
POST /api/agent/<branch-id>/execute
Content-Type: application/json

{"pin":"<one-time PIN>","target":"https://example.com/form"}
```

A successful response contains `status: "filled"`, `fieldsFilled`, and a fixed explanatory message. It never contains autofill values. Invalid PINs return `401`; missing or disallowed URLs return `400`; unavailable or consumed keys return `410`; browser failures return `422` and consume the key.

## Storage and security boundary

Account data is encrypted using AES-256-GCM, with a fresh IV for every atomic write. The encryption key is managed by the local server, not derived from each user's account password. This lets authorized agent keys work while the owner is logged out. Account passwords use independent random salts and scrypt verifiers (`N=32768`, `r=8`, `p=1`). Passwords are never stored in plaintext.

Back up **both** files while the server is stopped:

- `.data/accounts.enc` — encrypted account metadata, password verifiers, saved details, activity, key hashes, and key states.
- `.data/account-key` — the random installation encryption key, created with owner-only file permissions.

Losing `account-key` makes the account database unreadable. Anyone with access to both files can decrypt it, so protect the device and the backup. The server refuses to generate a replacement key over an existing database. `.data/` is git-ignored.

The app enforces:

- Account ownership on every owner API operation; no plaintext-value retrieval endpoint.
- Random session identifiers stored as hashes on the server. Cookies are HttpOnly and SameSite=Strict, with a seven-day server-enforced expiry. Sessions are not persisted across server restarts. Cookie names include the port to isolate separate local installations.
- Same-origin checks, JSON-only mutation requests, and session-bound CSRF tokens for authenticated writes. Signup/login rate limits and generic incorrect-credential responses.
- Random 128-bit agent branch IDs and 32-digit PINs (about 106 bits of entropy). Only PIN hashes are persisted. Five incorrect attempts revoke a key.
- A reservation during destination validation, and persisted consumption before any browser work. Interrupted in-flight keys fail closed on restart instead of becoming replayable.
- Public destination DNS validation and address pinning. Login origin checks and exact-page checks during filling.
- Private contexts without downloads or service workers. Cross-origin requests, popups, WebSockets, and navigation away from the supplied URL are blocked. Raw browser errors are never returned to agents.
- Loopback-only HTTP binding, Host validation, no CORS, strict CSP, and no-store responses. The owner UI uses no third-party scripts, analytics, fonts, or assets.

### Limits

The local HTTP cookie does not use the `Secure` flag because the app serves loopback HTTP. Public deployment would require HTTPS, secure cookies, operational hardening, and a separately secured browser service; do not tunnel this owner app to the internet.

The destination website receives the filled values and can read or transmit them. Share keys only with agents you trust to choose the intended destination. An identity or address key allows its holder to choose any supported public HTTPS page.

An agent with unrestricted shell, filesystem, debugger, desktop/screen, process-memory, owner-session, or private-browser access is outside the privacy boundary. Prompts cannot enforce secrecy against those tools. The service decrypts data in memory and cannot reliably erase JavaScript strings or browser memory.

The private browser is a fresh session, not the owner's or agent's existing authenticated browser. Third-party authentication, redirects, embedded frames, CAPTCHAs, payment flows, and websites requiring cross-origin resources may not work. A changing page may cause a partial fill; failure consumes the key and closes its window. Submitting to a different URL is also blocked.

A cloud agent cannot reach another computer's localhost. Use an authorized local request tool. The app remains a local prototype, not an independently audited password manager, and should not be your only credential backup.

Relevant references: [OWASP session management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), [Node crypto](https://nodejs.org/api/crypto.html), and [Playwright isolated contexts](https://playwright.dev/docs/browser-contexts).

## Development

```sh
npm run dev       # Watch the server; reload the browser for frontend changes
npm run check     # JavaScript syntax checks
npm test          # Authentication, isolation, migration, key lifecycle, and browser tests
```

Tests use temporary accounts and fictional records; they never use the real `.data` directory. The browser integration test requires Chrome or Chromium.

`node test/preview-fixture.js` creates a disposable workspace on port 4318. Log in with `alex@example.com` and `local-ui-test-only-password`. It contains fictional sample data and is removed on normal shutdown. Never save real data in that preview.
