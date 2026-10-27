# agentautofill

A local web app for saving logins, identities, and addresses, then granting an AI agent a **single autofill action with approved fields** without returning the saved values through the agent API.

## Run

Requires Node.js 22 or newer and a graphical desktop for the private browser window.

```sh
npm install
npm run browser:install
npm start
```

Open **http://127.0.0.1:4317**. On macOS, an existing Google Chrome installation is used automatically, so the browser installation step is optional. On other platforms, install Chromium with the command above, or set `BROWSER_CHANNEL=chrome` to use installed Google Chrome.

Optional environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `4317` | Loopback HTTP port |
| `VAULT_PATH` | `.data/vault.enc` | Encrypted vault location |
| `BROWSER_CHANNEL` | Chrome on macOS when available; bundled Chromium otherwise | Playwright browser channel |

No external API keys, model subscriptions, remote databases, or build step are required. The prompt is generated locally from the approved grant; no AI service receives your vault data.

## Use it

1. Create a master password of at least 12 characters. There is no recovery mechanism.
2. Add a login, identity, or address. Existing values are never revealed in the UI; editing replaces only the fields you enter. To remove a field, delete and recreate the item.
3. Create an agent pass. Choose an item, expiration (5 minutes to 30 days), allowed fields, and form selectors. **No destination URL is required or stored on a key.** Login items remain restricted to their saved HTTPS origin when used.
4. Copy the generated prompt. It contains a unique `/agent/<random-id>` branch, a 32-digit one-time PIN, the field scope, selectors, and expiry. The PIN is only shown at creation.
5. The agent opens that branch and enters the PIN and the page URL for its task, or supplies `pin` and `target` to the JSON endpoint in the prompt. A separate browser window fills the fields. The agent response contains only success/failure and the number of filled fields.
6. **You** review the private window and submit manually. agentautofill does not automatically submit forms. Windows close after 15 minutes or when you lock the vault.

For a first test, create your vault, click **Try a sample identity**, create a pass for that item without a destination, then open its agent page and choose **Use the local demo form** when redeeming it. The demo never sends entered values anywhere. Its selectors are preconfigured.

The owner UI provides search, category filters, editing, deletion, pass revocation, and an encrypted activity history. Locking revokes all pending passes and closes private windows. Updating or deleting an item revokes its pending passes.

## How the privacy boundary works

```text
Owner UI ── master password ──> Local encrypted vault
    │                                  │
    └── approved fields + expiry ──> One-use grant
                                       │
Agent ── branch + PIN + page URL ──> Redeem ──> Private browser ──> Chosen website
    <── status + count only ──┘              │
                                       Owner reviews
```

The PIN is a capability to perform one action; it is **not** an encryption key or a promise that arbitrary agent tools cannot inspect your computer. Prompts alone cannot hide a value from an agent that can read the DOM of the browser receiving it. agentautofill therefore never offers the agent browser handles, DOM reads, screenshots, cookies, arbitrary navigation, or scripts.

### Included protections

- AES-256-GCM encrypted storage with a fresh IV on every write; scrypt key derivation with a random salt (`N=32768`, `r=8`, `p=1`). Atomic file replacement and restrictive file permissions.
- Master password and encryption key are not persisted. The owner’s bearer token stays only in page memory, not cookies or local storage. No plaintext-value retrieval endpoint exists.
- Cryptographically random 128-bit branch IDs and 32-digit PINs (approximately 106 bits). Only PIN hashes are held by the server.
- Keys are reserved while the agent-supplied URL is validated, then the PIN is atomically consumed before launching a browser. Missing, invalid, or disallowed URLs leave the key available for a corrected request. A failed or interrupted fill still consumes the PIN. Five wrong PIN attempts revoke a grant.
- Expiry, explicit revocation, a 30-minute owner-API inactivity lock, and a limit on private browser windows. Keys may expire up to 30 days after creation and are retained until their expiry, plus one day of history. Locking (including the inactivity lock) still revokes pending keys; all passes are ephemeral and invalid after a process restart. A long expiration does not keep the vault unlocked.
- No target URL is stored or required at key creation. The agent supplies it at redemption. Exact URL checks during each fill and login origin binding still apply. Public HTTPS destinations only, apart from the built-in loopback demo. Public target DNS is validated and its address is pinned in the private browser to reduce rebinding risk.
- Private contexts without service workers or downloads. Cross-origin requests, popups, WebSockets, and navigation away from the exact URL are blocked. Errors from browser internals are replaced with fixed messages, because raw browser errors can contain sensitive values.
- Loopback-only binding, Host and Origin validation, JSON-only mutation endpoints, no CORS, strict CSP, no-store responses, and no third-party scripts, analytics, fonts, or remote assets in the owner UI.

### Important limits

- **An agent with unrestricted shell, filesystem, debugger, desktop/screen, process-memory, or private-browser access is outside this boundary.** Do not give such an agent access to your unlocked owner session. JavaScript strings and browser memory cannot be reliably zeroed; the OS and browser may retain memory or crash dumps. Key buffers are cleared on lock, but this is not an OS-level secret-isolation product.
- The destination website necessarily receives the values. A trusted origin can still contain malicious or compromised scripts and can transmit the values. Share keys only with agents you trust to choose the right destination. A key for identity or address data lets its holder choose any supported public HTTPS page. These controls do not make a malicious destination safe.
- The browser is a fresh isolated session, not the user’s or agent’s existing authenticated browser. Third-party authentication, redirects, embedded frames, CAPTCHAs, payment workflows, and sites requiring external assets may not work. A page changing during filling can cause a partial fill; the pass is consumed and its window closes on failure. Manually submitting to a different URL is also blocked by the exact-page policy.
- **Localhost works for an agent operating on the same machine.** A cloud agent cannot reach another machine’s loopback interface. Use an authorized local request tool. Do not tunnel or publish the owner app: it has no production multi-user authentication, HTTPS termination, distributed storage, or remotely hosted browser isolation. A remote relay would need a separately secured, agent-only gateway.
- Labels, the agent-branch URL, field names, selectors, and the PIN appear in the generated prompt. No destination URL is preset. Keep secrets out of labels and out of any page URL supplied at redemption. The agent can see this scope metadata, and the recipient of the prompt can consume the capability.
- This is a working local prototype, **not an independently audited password manager**. Do not use it as the only backup of important credentials.

Back up `.data/vault.enc` while the app is stopped. Restore that file and use the original master password. Pending passes are intentionally not backed up. The vault file and dependencies are git-ignored; never commit vault files or pass prompts.

## Agent endpoint

The generated prompt supplies the full URL and PIN. A successful call returns no secret values:

```http
POST /api/agent/<branch-id>/execute
Content-Type: application/json

{"pin":"<one-time PIN>","target":"https://example.com/form"}
```

```json
{
  "status": "filled",
  "fieldsFilled": 4,
  "message": "Filled in the owner’s private browser. The owner must review and submit. No values are returned."
}
```

Agent calls require no owner token. Missing or disallowed page URLs return `400` without consuming the PIN. Invalid PINs return `401`; unavailable, expired, or consumed passes return `410`; browser failures return `422` and consume the pass. Unknown requests never return raw vault values or underlying browser diagnostics.

## Development and checks

```sh
npm run dev       # watch the Node server; reload the browser after frontend edits
npm run check     # JavaScript syntax checks
npm test          # API security tests + a real headless private-browser fill
```

Tests use temporary encrypted vaults and fictional values; they never use `.data/vault.enc`. Browser integration tests require Chrome/Chromium. On a machine without Chrome, run `npm run browser:install` first.

For disposable manual UI testing, `node test/preview-fixture.js` starts a fictional workspace on port 4318. Unlock it with `local-ui-test-only-password`. Its vault is held in the OS temporary directory and is removed on normal shutdown. Do not use it for real data.

The implementation uses Node’s built-in HTTP and crypto libraries with Playwright as its only runtime dependency. Frontend files are served directly, so deployment to static hosting alone cannot provide the private autofill service. Relevant platform references: [Node crypto](https://nodejs.org/api/crypto.html), [Playwright isolated contexts](https://playwright.dev/docs/browser-contexts), and [Playwright request interception](https://playwright.dev/docs/api/class-browsercontext#browser-context-route).
