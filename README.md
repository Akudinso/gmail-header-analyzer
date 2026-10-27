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
git clone https://github.com/Akudinso/gmail-header-analyzer.git
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

Google only lets an extension read Gmail if it has an OAuth client, which lives inside a Google Cloud project. Every person who runs this extension creates their **own**, so nobody shares credentials.

This is free. You don't need billing, a credit card or the "$300 free trial" banner; ignore or dismiss it.

> **Use a new, dedicated project** even if you already have others. A project has one sign-in screen and one list of permissions. Adding Gmail access to a project you use for something else mixes the two apps' settings and permissions together.

#### 3a. Create the project

1. Open [console.cloud.google.com](https://console.cloud.google.com/) and sign in with the Gmail account you want to analyse.
2. At the top left, next to the **Google Cloud** logo, click the **project picker** (the button showing your current project's name, or "Select a project").
3. In the window that opens, click **New project** (top right).
4. Fill in:
   - **Project name:** `gmail-header-analyzer`
   - **Organization / Location:** leave as **No organization**
5. Click **Create** and wait a few seconds for the notification.
6. Click the project picker again and select **gmail-header-analyzer**.

**Check before every step below:** the project picker must show `gmail-header-analyzer`. Doing a step in the wrong project is the most common reason sign-in fails later.

#### 3b. Enable the Gmail API

1. Open [APIs & Services → Library](https://console.cloud.google.com/apis/library) (or ☰ menu → **APIs & Services** → **Library**).
2. Search for **Gmail API** and click it.
3. Click **Enable**.

#### 3c. Set up the sign-in screen

1. Open [Google Auth Platform](https://console.cloud.google.com/auth/overview), or type `Google Auth Platform` into the console search bar. (Older guides call this the "OAuth consent screen".)
2. Click **Get started** and complete the four sections:

   | Section | What to enter |
   |---|---|
   | **App information** | App name: `Gmail Header Analyzer`. User support email: your Gmail address. |
   | **Audience** | Choose **External**. (*Internal* is only available to Google Workspace organisations.) |
   | **Contact information** | Your Gmail address. |
   | **Finish** | Tick the box to agree to the Google API Services User Data Policy. |

3. Click **Create**.

#### 3d. Add yourself as a test user

The app stays in **Testing** mode, which means only accounts you list here can sign in. You don't need to publish it.

1. In Google Auth Platform's left menu, click **Audience**.
2. Under **Test users**, click **Add users**.
3. Enter the Gmail address you'll analyse and click **Save**.

#### 3e. Allow read-only Gmail access

1. In the left menu, click **Data access**.
2. Click **Add or remove scopes**.
3. Find `https://www.googleapis.com/auth/gmail.readonly` using the filter box. If it's not listed, paste it into **Manually add scopes** and click **Add to table**.
4. Tick it and click **Update**.
5. Click **Save** at the bottom of the page.

Google lists this as a "restricted" scope. That only matters if you publish the app to the public; for your own testing use it works as-is.

#### 3f. Create the OAuth client

1. In the left menu, click **Clients**, then **Create client**.
2. Fill in:
   - **Application type:** **Chrome Extension**
   - **Name:** `Gmail Header Analyzer extension` (only you see this)
   - **Item ID:** your extension ID from step 2 (32 letters, a–p only)
3. Click **Create**.
4. Copy the **Client ID**. It looks like `123456789012-abc123….apps.googleusercontent.com`. You can find it again later under **Clients**.

#### 3g. Add the client ID to the extension

From the project folder, run:

```bash
npm run setup -- --client-id=PASTE_YOUR_CLIENT_ID_HERE
```

This writes `extension/manifest.json` (gitignored) with your client ID and key.

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
