# Gmail Header Analyzer

A Chrome extension that analyses the email you open in Gmail, automatically. Open an email and a side panel shows where it really came from, whether it passed SPF, DKIM and DMARC, which links lie about their destination, and which attachments are risky. No copying headers, no "Show original".

Built as a learning project inspired by the email header analysis module of TCM Security's SOC 101 course.

> **Status: early development.** Header and body analysis work today. IP/domain reputation lookups, a risk score and an AI summary are next (see [Roadmap](#roadmap)).

## What it does today

When you open an email in Gmail, the extension fetches the complete original message through the Gmail API and reports:

| Section | What you see |
|---|---|
| **Findings** | Plain-English red flags: DMARC/SPF failures, missing DKIM, Reply-To or bounce address on another domain, misleading links, risky attachments |
| **Authentication** | SPF, DKIM and DMARC results, taken only from the `Authentication-Results` header Google itself added |
| **Sender IP** | The IP that actually connected to Google (verified), kept separate from IPs the sender *claims* (earliest hop, `X-Originating-IP`, `X-Sender-IP`) |
| **Received path** | Every hop, oldest first, with delays between hops |
| **Links** | Every link, its real destination, and whether the visible text points somewhere else (e.g. text says `paypal.com`, link goes to `paypa1-secure.net`) |
| **Attachments** | File name, type, size, risky-extension flags and SHA-256 hash (for VirusTotal lookups) |
| **Raw headers** | All headers, unfolded and decoded |

### Why some IPs are "verified" and others aren't

Every mail server adds a `Received` header to the **top** of the message. Anything below Google's own entry was written before Google saw the email, so the sender could have forged it. The extension therefore trusts only the newest hop recorded by a `google.com` server, and labels everything else as a claim. The same rule applies to `Authentication-Results`: a spammer can paste in a fake `dmarc=pass` line, so only Google's is used. The test suite includes forged examples of both.

## How it works

```
Gmail tab ─► content.js ─► background.js ─────────────► side panel
           (finds the open    (signs in, fetches the raw   (renders the report;
            message's ID)      email via Gmail API,         email data is shown
                               parses, caches in memory)    as text only)
                                       │
                                       └─► Cloudflare Worker  (roadmap: lookups, score, AI;
                                                               holds the API keys)
```

- **Read-only access.** The only Google permission requested is `gmail.readonly`.
- **Nothing written to disk.** Reports live in `chrome.storage.session`, which is cleared when Chrome closes.
- **Email content never leaves your browser** in the current version. When lookups arrive, only indicators (IPs, domains, URLs, file hashes) will be sent to reputation services.
- **"Disconnect Gmail"** at the bottom of the panel revokes the token and clears all stored reports.

## Run it yourself

You need: Google Chrome (116+), [Node.js 22+](https://nodejs.org/), and a Google account. Setup takes about 10 minutes, once.

### 1. Clone and install

```bash
git clone https://github.com/<your-username>/gmail-header-analyzer.git
cd gmail-header-analyzer
npm install
```

(Or click **Fork** on GitHub first and clone your fork.)

### 2. Get your extension ID

```bash
npm run setup
```

This creates a private key in `.local/` (gitignored) that fixes your extension's ID, and prints it:

```
Your extension ID: abcdefghijklmnopabcdefghijklmnop
```

Keep `.local/extension-key.pem`. If you delete it, you get a new ID and must update your OAuth client.

### 3. Set up Google sign-in

Every person who runs the extension uses their **own** Google Cloud project, so nobody shares credentials.

1. Go to [Google Cloud Console](https://console.cloud.google.com/) and create a project (any name).
2. **Enable the Gmail API:** APIs & Services → Library → search "Gmail API" → Enable.
3. **Configure sign-in:** open **Google Auth Platform** (formerly "OAuth consent screen") → Get started. Enter an app name and your email, choose **External** as the audience.
4. **Add yourself as a test user:** Google Auth Platform → **Audience** → Test users → add your Gmail address. Leave the app in **Testing**; it doesn't need to be published.
5. **Add the scope:** Google Auth Platform → **Data access** → Add or remove scopes → add `https://www.googleapis.com/auth/gmail.readonly`.
6. **Create the client:** Google Auth Platform → **Clients** → Create client → Application type **Chrome Extension** → paste your extension ID from step 2 into **Item ID** → Create.
7. Copy the client ID (ends in `.apps.googleusercontent.com`) and run:

```bash
npm run setup -- --client-id=YOUR_CLIENT_ID.apps.googleusercontent.com
```

This writes `extension/manifest.json` (also gitignored).

### 4. Load it in Chrome

1. Open `chrome://extensions` and switch on **Developer mode** (top right).
2. Click **Load unpacked** and select the `extension` folder.
3. Confirm the ID shown matches the one from step 2.

### 5. Use it

1. Open Gmail and click the extension's toolbar icon to open the side panel (pin it from the puzzle-piece menu for easy access).
2. Click **Connect Gmail** and approve read-only access. Google will warn that the app is unverified; that's expected for your own testing app.
3. Open any email. The panel updates on its own each time you open a different email.

After changing code, click **Reload** on the extension card at `chrome://extensions`, then refresh the Gmail tab.

## Development

```bash
npm test          # parser, service worker and Worker tests (Node built-ins only)
npm run worker:dev  # run the Cloudflare Worker locally on http://localhost:8787
```

For the Worker, copy `worker/.dev.vars.example` to `worker/.dev.vars` and set `ALLOWED_ORIGINS=chrome-extension://<your extension ID>`.

```
extension/
  manifest.template.json   committed template; `npm run setup` fills in your key and client ID
  content.js               detects the open email in Gmail
  background.js            sign-in, Gmail API fetch, caching
  lib/                     parser (pure JS, runs in the browser and in Node tests)
  sidepanel/               report UI
worker/                    Cloudflare Worker (API keys, lookups — in progress)
scripts/setup-extension.mjs
test/                      node:test suites and sample .eml fixtures
```

## Troubleshooting

| Problem | Fix |
|---|---|
| `bad client id` or sign-in window errors | The ID at `chrome://extensions` must match the **Item ID** on your OAuth client. Re-run `npm run setup` and compare. |
| "Access denied" (403) | Gmail API not enabled, or your Gmail address isn't on the **Test users** list. |
| "couldn't find this message ID" (404) | Gmail may have changed its page markup. Please [open an issue](../../issues) with your Chrome version. |
| Asked to connect again after about a week | Normal for apps in Testing mode: Google expires their sign-in after 7 days. Click **Connect Gmail** again. |
| Panel says "Open Gmail in this tab" while Gmail is open | Refresh the Gmail tab (needed once after installing or reloading the extension). |

## Roadmap

- [x] Step 1 — Sign in, fetch the raw email via Gmail API, parse it
- [x] Step 2 — Extract indicators and show them in the side panel
- [ ] Step 3 — Worker lookups: AbuseIPDB, VirusTotal, RDAP (owner, ASN, **domain age**), with caching
- [ ] Step 4 — Explainable rule-based risk score (every point traceable to a finding)
- [ ] Step 5 — AI summary that explains the evidence but can never lower the score (email text is attacker-controlled, so prompt injection is assumed)

## Known limitations

- **Gmail and Workspace senders:** when the email was sent through Google's own servers, the original sender's IP is hidden by design. The panel says so.
- **Domain comparison is approximate:** "same organisation" checks use a built-in list of multi-part suffixes such as `co.uk` and `com.ng`. A full Public Suffix List is planned.
- **Gmail markup can change:** the extension reads one attribute from Gmail's page to find the message ID. Everything else comes from the API.

## Contributing

Forks and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). To report a security problem, see [SECURITY.md](SECURITY.md).

## Licence

[MIT](LICENSE)
