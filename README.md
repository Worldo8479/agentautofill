# agentautofill

A local web app with signup, login, account-specific autofill records, and single-use agent keys. An agent can pass encrypted field values to this app’s receiving form without receiving a decryption key or plaintext response.

## Run

Requires Node.js 22+. Only legacy private-browser passes require a graphical desktop and Chrome or Chromium.

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

These are accounts for this local installation, not cloud accounts. Email is a login identifier and is not verified. Password resets use a saved recovery code; no email service is configured.

### Forgot password

- Signup shows a random 256-bit recovery code once. Store it outside this app; do not share it with an agent. Only its SHA-256 hash is persisted.
- Existing users should log in and select **Account → Set up recovery code**, confirming their current password. Replacing a code invalidates the old one.
- On the login screen, choose **Forgot password?**, enter your email, saved recovery code, and a new password of at least 12 characters. A successful reset consumes the code, ends all account sessions, revokes unused agent keys, and closes existing private browser windows. Saved items remain intact. Log in and generate a new recovery code afterward.
- Recovery works on localhost and survives server restarts. Invalid emails/codes receive the same error; reset attempts are rate limited. Without a saved code or the current password, there is no self-service reset.

### Import your previous vault

The previous `.data/vault.enc` file is preserved. After creating an account, use **Import vault** and enter its previous master password. Items are copied into the signed-in account, and the original encrypted file is left byte-for-byte unchanged. Only one account can claim that import; knowing a new account password alone does not grant access to the old vault. No old password or item values are returned to the browser during import.

Do not delete the original until you have verified your imported items and made a backup. Old in-memory passes from the pre-account app cannot be recovered; create new keys after importing.

## Create and submit an encrypted package

1. Add a login, identity, or address. Existing values remain hidden; editing replaces only fields you enter.
2. Choose **Create agent pass**, select the fields, and set an expiry from **5 minutes to 30 days**. No PIN, CSS selectors, or destination URL entry is needed. The recipient is explicitly the **agentautofill receiving form on this device**.
3. Copy the prompt shown once. It includes a dedicated `/submit/<random-id>` form, its submission endpoint, and a ciphertext package. It never includes plaintext values or a decryption key.
4. The agent pastes the package unchanged into the receiving form and submits it, or sends the JSON request below.
5. The server checks authorization, expiry, revocation, and package integrity, reserves the one-time package durably, then decrypts it. It stores the submitted fields in the owner's encrypted account database and returns only a receipt ID and field count. Activity records the receipt without field values. The last 100 submissions are retained; there is no read API for their contents.

```http
POST /api/forms/<package-id>/submit
Content-Type: application/json

{"payload":"<exact encrypted package>"}
```

A successful response contains `status: "accepted"`, `receiptId`, `fieldsReceived`, and a fixed message. Wrong ciphertext returns `400`; expired, revoked, or consumed packages return `410`. A processing failure consumes the package and returns a generic `422`. If a connection fails after submitting, check Activity before trying again: the server may already have accepted the submission.

This repository is both sender and receiver. This flow accepts and stores a form submission locally; it does not log in to external sites, fill their fields, or perform a purchase. Ordinary websites cannot decrypt these packages. Another website needs its own receiving integration and private key; the app currently targets only its own receiving form.

Packages survive logout and restarts. Editing/deleting their source item, explicit revocation, or a password reset invalidates unused packages. Anyone holding a package can perform its authorized submission once, so keep it private even though they cannot read its contents through the API. No plaintext values are placed into the agent's DOM, URLs, cookies, or local storage.

### Encryption and receiving boundary

Each package uses a fresh 256-bit AES-GCM key and 96-bit IV. The content key is wrapped with RSA-3072 OAEP using SHA-256 and the receiver's public key. The form ID is bound through GCM additional authenticated data and the OAEP label. A persisted SHA-256 digest pins the exact authorized ciphertext; possessing a public key alone does not authorize arbitrary submissions. Receiving requires the matching one-time record as well as valid ciphertext.

The private recipient key is generated on first package creation and stored inside `accounts.enc`, encrypted by the installation storage key. It is never served to a browser or agent. Back up both storage files described below. The private key and original vault values are accessible to the local server: this is protection for the agent-facing transport, not protection from the receiver or someone with filesystem/process access. JavaScript cannot guarantee erasure of plaintext strings from memory. HTTPS is still required before any public deployment.

### Existing PIN passes

Previously generated `/agent/<id>` PIN passes keep their private-browser behavior, including saved website restrictions for logins. Their legacy `/api/passes` creation and `/api/agent/<id>/execute` APIs remain for compatibility. New passes generated in the UI use encrypted submission. The `/demo` plaintext form remains only for legacy browser testing.

## Storage and security boundary

Account data is encrypted using AES-256-GCM, with a fresh IV for every atomic write. The encryption key is managed by the local server, not derived from each user's account password. This lets authorized agent keys work while the owner is logged out. Account passwords use independent random salts and scrypt verifiers (`N=32768`, `r=8`, `p=1`). Passwords are never stored in plaintext.

Back up **both** files while the server is stopped:

- `.data/accounts.enc` — encrypted account metadata, password verifiers, saved details, received submissions, recipient private key, activity, package/PIN hashes, and key states.
- `.data/account-key` — the random installation encryption key, created with owner-only file permissions.

Losing `account-key` makes the account database unreadable. Anyone with access to both files can decrypt it, so protect the device and the backup. The server refuses to generate a replacement key over an existing database. `.data/` is git-ignored.

The app enforces:

- Account ownership on every owner API operation; no plaintext-value retrieval endpoint.
- Random session identifiers stored as hashes on the server. Cookies are HttpOnly and SameSite=Strict, with a seven-day server-enforced expiry. Sessions are not persisted across server restarts. Cookie names include the port to isolate separate local installations.
- Same-origin checks, JSON-only mutation requests, and session-bound CSRF tokens for authenticated writes. Signup/login rate limits and generic incorrect-credential responses.
- Random 128-bit receiving form IDs and authenticated encrypted packages. Only the package digest is retained for redemption. Legacy PIN passes use 32-digit PINs and revoke after five incorrect attempts.
- A reservation during destination validation, and persisted consumption before any browser work. Interrupted in-flight keys fail closed on restart instead of becoming replayable.
- Public destination DNS validation and address pinning. Login origin checks and exact-page checks during filling.
- Private contexts without downloads or service workers. Cross-origin requests, popups, WebSockets, and navigation away from the supplied URL are blocked. Raw browser errors are never returned to agents.
- Loopback-only HTTP binding, Host validation, no CORS, strict CSP, and no-store responses. The owner UI uses no third-party scripts, analytics, fonts, or assets.

### Limits

The local HTTP cookie does not use the `Secure` flag because the app serves loopback HTTP. Public deployment would require HTTPS, secure cookies, operational hardening, and a separately secured browser service; do not tunnel this owner app to the internet.

For legacy browser passes, the destination website receives the filled values and can read or transmit them. Share keys only with agents you trust to choose the intended destination. An identity or address key allows its holder to choose any supported public HTTPS page.

An agent with unrestricted shell, filesystem, debugger, desktop/screen, process-memory, owner-session, or private-browser access is outside the privacy boundary. Prompts cannot enforce secrecy against those tools. The service decrypts data in memory and cannot reliably erase JavaScript strings or browser memory.

The legacy private browser is a fresh session, not the owner's or agent's existing authenticated browser. Third-party authentication, redirects, embedded frames, CAPTCHAs, payment flows, and websites requiring cross-origin resources may not work. A changing page may cause a partial fill; failure consumes the key and closes its window. Submitting to a different URL is also blocked.

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
