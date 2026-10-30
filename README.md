# Gmail Header Analyzer

A Chrome extension that analyses the email you open in Gmail, automatically. Open an email and a side panel shows where it really came from, whether it passed SPF, DKIM and DMARC, which links lie about their destination, and which attachments are risky. No copying headers, no "Show original".

Built as a learning project inspired by the email header analysis module of TCM Security's SOC 101 course.

> **Status: early development.** Header analysis, reputation lookups and an explainable risk score work today. An AI summary is next (see [Roadmap](#roadmap)).

## What it does today

When you open an email in Gmail, the extension fetches the complete original message through the Gmail API and reports:

| Section | What you see |
|---|---|
| **Risk** | A 0–100 score (Low, Suspicious, High) with every finding listed in plain English, strongest first, showing exactly how many points it added. See [How the risk score works](#how-the-risk-score-works). |
| **Authentication** | SPF, DKIM and DMARC results, taken only from the `Authentication-Results` header Google itself added |
| **Sender IP** | The IP that actually connected to Google (verified), kept separate from IPs the sender *claims* (earliest hop, `X-Originating-IP`, `X-Sender-IP`) |
| **Received path** | Every hop, oldest first, with delays between hops |
| **Links** | Every link, its real destination, and whether the visible text points somewhere else (e.g. text says `paypal.com`, link goes to `paypa1-secure.net`) |
| **Attachments** | File name, type, size, risky-extension flags and SHA-256 hash (for VirusTotal lookups) |
| **Raw headers** | All headers, unfolded and decoded |
| **Reputation lookups** *(optional, [needs the Worker](#6-turn-on-lookups-optional))* | Sender IP: AbuseIPDB score and reports, owner, ASN, network, reverse DNS, VirusTotal detections. Every domain involved: whether it **exists at all** (catches made-up TLDs like `.ikz`), **registration date and age**, registrar, VirusTotal detections. Reverse DNS is checked in both directions, so a PTR name the IP's owner simply made up is labelled unconfirmed. Suspicious links and attachment hashes checked against VirusTotal. |

### How the risk score works

Every point traces back to a finding you can read, and the same email always gets the same score. The rules are in [`extension/lib/findings.js`](extension/lib/findings.js).

1. **Each finding has a fixed number of points**, set by how often it shows up in *legitimate* mail:

   | Finding | Points | Why |
   |---|---|---|
   | Forged Google hop | 30 | Never happens in real mail |
   | DMARC fail | 30 | The From domain didn't authorise the email |
   | Link text points to a different domain | 25 | Classic phishing trick |
   | Domain registered under 30 days ago (From/Reply-To) | 25 | Phishing domains are usually brand new |
   | Server's own name doesn't match Google's lookup | 20 | Impersonation, e.g. "docs.google.com" from a rented server |
   | Reply-To on another domain | 15 | Replies are diverted |
   | Domain registered 30–90 days ago (From/Reply-To/bounce/DKIM) | 10 | Still young, but legitimate new businesses land here too |
   | Bounce address on another domain | 5 | Normal for every newsletter service, so it counts for little |
   | Sender header on another domain | 5 | Normal for mailing lists and booking services |

2. **Related findings share a cap.** Findings fall into five groups (authentication, sender identity, sending infrastructure, links, attachments), each with a maximum. A DMARC failure usually brings SPF and DKIM problems with it; the cap stops one root cause being counted three times. A finding over the cap shows "+10 of 20".
3. **Passes never lower the score.** SPF, DKIM and DMARC passing proves a domain sent the email, not that the domain is honest. Attackers pass all three on domains they registered last week.
4. **Decisive findings set a minimum of 60.** A From domain that can't exist, a forged Google hop, or a file or link that several antivirus engines call malicious essentially never appear in legitimate mail. Any one of them makes the email High risk on its own.
5. **Levels:** 0–24 Low, 25–59 Suspicious, 60–100 High. If lookups are off or still running, the panel says the score may be incomplete.

### Why some IPs are "verified" and others aren't

Every mail server adds a `Received` header to the **top** of the message. Anything below Google's own entry was written before Google saw the email, so the sender could have forged it. The extension therefore trusts only the newest hop recorded by a `google.com` server, and labels everything else as a claim. The same rule applies to `Authentication-Results`: a spammer can paste in a fake `dmarc=pass` line, so only Google's is used. The test suite includes forged examples of both.

## How it works

```
Gmail tab ─► content.js ─► background.js ─────────────► side panel
           (finds the open    (signs in, fetches the raw   (renders the report;
            message's ID)      email via Gmail API,         email data is shown
                               parses, caches in memory)    as text only)
                                       │
                                       └─► Cloudflare Worker ─► AbuseIPDB, VirusTotal,
                                           (holds API keys,       RDAP, reverse DNS
                                            caches results)
```

- **Read-only access.** The only Google permission requested is `gmail.readonly`.
- **Nothing written to disk.** Reports live in `chrome.storage.session`, which is cleared when Chrome closes.
- **Email content never leaves your browser.** Only indicators go to the Worker: IP addresses, domain names, attachment hashes, and full URLs **only for links that already look suspicious** (link text that lies, or links to bare IPs). Ordinary links often contain personal tokens, such as password resets or unsubscribe IDs, so for those only the domain is checked.
- **Your Gmail token stays with Google.** The Worker authenticates the extension with its own random key, so it never receives anything that can read your mail.
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

The app stays in **Testing** mode, which means Google only lets the accounts you list here sign in to it. You don't need to publish it.

The address to add is **your own Gmail address**: the inbox you'll be opening emails in while the extension runs (for example `yourname@gmail.com`). It is *not* the address of anyone who sends you email; the extension can analyse mail from any sender.

1. In Google Auth Platform's left menu, click **Audience**.
2. Under **Test users**, click **Add users**.
3. Type your own Gmail address and click **Save**.

If you use more than one Gmail account and want to analyse each of them, add each address here.

> **One account must match three places:** the test user you add here, the Gmail inbox you have open, and the Google account Chrome itself is signed into (click your profile picture at the top right of Chrome to check). The extension signs in with Chrome's account, so if that differs from the Gmail tab, it will be looking in the wrong mailbox.

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

### 6. Turn on lookups (optional)

Steps 1–5 give you the full header analysis. Lookups add IP reputation, domain age and VirusTotal results. They run through a small Cloudflare Worker that keeps your API keys off the extension. Anyone could unzip an extension and read keys stored inside it.

`npm run setup` has already created `worker/.dev.vars` with a random `WORKER_KEY` and your extension ID. You only add the API keys.

#### 6a. Get two free API keys

| Service | Sign up | Where the key is | Free limit |
|---|---|---|---|
| VirusTotal | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) | Your profile picture (top right) → **API key** | 4 lookups a minute, 500 a day |
| AbuseIPDB | [abuseipdb.com/register](https://www.abuseipdb.com/register) | **Account** → **API** → **Create Key** | 1,000 checks a day |

Open `worker/.dev.vars` in a text editor and paste them in:

```
VT_API_KEY=paste-virustotal-key
ABUSEIPDB_API_KEY=paste-abuseipdb-key
```

You can skip either one. Domain age (RDAP) and reverse DNS need no key and work regardless.

#### 6b. Run the Worker on your computer

The Worker is a small server program. The extension sends it each email's IPs, domains and hashes, and the Worker asks VirusTotal and AbuseIPDB about them. The extension can only get lookups while the Worker is running.

1. Open a terminal (Terminal on Mac, PowerShell on Windows) and go to the project folder:
   ```bash
   cd path/to/gmail-header-analyzer
   ```
2. Start the Worker:
   ```bash
   npm run worker:dev
   ```
3. Wait until it prints a line like `Ready on http://localhost:8787`.
   - `localhost` means "this computer".
   - `8787` is the port the Worker listens on.
   - `npm run setup` already saved this address in the extension, so there's nothing to type into Chrome.
4. **Leave this terminal window open.** You can minimise it. The Worker runs only while that command runs; closing the window or pressing `Ctrl+C` stops it.
5. Optional check: open [http://localhost:8787/health](http://localhost:8787/health) in Chrome. You should see `"virustotal":true` and `"abuseipdb":true` for each key you added.
6. In Gmail, open an email. The **Reputation lookups** section in the side panel fills in after a few seconds.

If the Worker isn't running, the header analysis still works and the lookups section says *"Couldn't reach the Worker"*. Start it again with step 2 and press **Re-analyse**.

You'll need to run `npm run worker:dev` again each time you restart your computer. To avoid that, deploy it instead (6c).

#### 6c. Or deploy it, so it's always on (free)

Running locally means the terminal must stay open. Deploying puts the Worker on Cloudflare's free tier instead.

1. Create a free account at [dash.cloudflare.com/sign-up](https://dash.cloudflare.com/sign-up).
2. Sign in from the terminal (a browser window opens to approve):
   ```bash
   npx wrangler login
   ```
3. Deploy. The first time, Wrangler may ask you to pick a `workers.dev` subdomain.
   ```bash
   npm run worker:deploy
   ```
   Note the URL it prints, e.g. `https://gmail-header-analyzer.yourname.workers.dev`.
4. Copy each setting from `worker/.dev.vars` to Cloudflare. Run each command, then paste the **value** from `.dev.vars` when asked:
   ```bash
   npx wrangler secret put WORKER_KEY --config worker/wrangler.toml
   npx wrangler secret put ALLOWED_ORIGINS --config worker/wrangler.toml
   npx wrangler secret put VT_API_KEY --config worker/wrangler.toml
   npx wrangler secret put ABUSEIPDB_API_KEY --config worker/wrangler.toml
   ```
5. Point the extension at it, then click **Reload** at `chrome://extensions`:
   ```bash
   npm run setup -- --worker-url=https://gmail-header-analyzer.yourname.workers.dev
   ```

To check it, open `https://<your worker URL>/health` in a browser. Every setting you added should show `true`.

#### How the free VirusTotal limit is handled

One email can contain more indicators than VirusTotal's 4-per-minute allowance. Each email therefore gets up to 4 fresh VirusTotal lookups, spent in this order:
1. Sender IP
2. From domain
3. Attachments
4. Suspicious links
5. Other domains

Anything left over shows as *skipped*. Results are cached for 6 hours, and cached answers don't count against the 4, so pressing **Re-analyse** a minute later fills in the rest. Change the allowance with `VT_MAX_LOOKUPS` in `worker/wrangler.toml` if you have a paid key.

## Development

```bash
npm test            # parser, service worker and Worker tests (Node built-ins only; upstream APIs are faked)
npm run worker:dev  # run the Cloudflare Worker locally on http://localhost:8787
```

```
extension/
  manifest.template.json   committed template; `npm run setup` fills in your key and client ID
  content.js               detects the open email in Gmail
  background.js            sign-in, Gmail API fetch, caching, calls the Worker
  lib/                     parser, lookup-request builder, findings and risk score (pure JS, runs in the browser and in Node tests)
  sidepanel/               report UI
worker/
  src/index.js             auth, input validation, VirusTotal budget
  src/lookups.js           AbuseIPDB, VirusTotal, RDAP (via IANA bootstrap), DNS checks, reverse DNS
  src/cache.js             KV cache if bound, in-memory otherwise
scripts/setup-extension.mjs
test/                      node:test suites and sample .eml fixtures
```

## Troubleshooting

| Problem | Fix |
|---|---|
| `bad client id` or sign-in window errors | The ID at `chrome://extensions` must match the **Item ID** on your OAuth client. Re-run `npm run setup` and compare. |
| "Access denied" (403) | Gmail API not enabled, or your Gmail address isn't on the **Test users** list. |
| "couldn't find this message ID" on every email | The Gmail tab is a different account from the one Chrome is signed into. See the note in step 3d. |
| "couldn't find this message ID" (404) | Gmail may have changed its page markup. Please [open an issue](../../issues) with your Chrome version. |
| Asked to connect again after about a week | Normal for apps in Testing mode: Google expires their sign-in after 7 days. Click **Connect Gmail** again. |
| Panel says "Open Gmail in this tab" while Gmail is open | Refresh the Gmail tab (needed once after installing or reloading the extension). |
| Lookups: "Couldn't reach the Worker" | Start it with `npm run worker:dev`, or check the deployed URL with `/health`. |
| Lookups: "rejected the extension's key" or "doesn't allow this extension's ID" | The Worker's `WORKER_KEY` / `ALLOWED_ORIGINS` don't match the extension. Re-run `npm run setup`, restart `npm run worker:dev`, or re-copy the secrets for a deployed Worker (6c step 4). |
| Lookups: "No API key on the Worker" | Add the key to `worker/.dev.vars` and restart the Worker (or `wrangler secret put` it if deployed). |
| Domain shows "Registry doesn't publish RDAP data" | Some country-code registries (for example `.id`) don't offer RDAP, so the registration date isn't available. That's a gap in public data, not a problem with the email. |

## Roadmap

- [x] Step 1 — Sign in, fetch the raw email via Gmail API, parse it
- [x] Step 2 — Extract indicators and show them in the side panel
- [x] Step 3 — Worker lookups: AbuseIPDB, VirusTotal, RDAP (owner, **domain age**), reverse DNS, with caching
- [x] Step 4 — Explainable rule-based risk score (every point traceable to a finding)
- [ ] Step 5 — AI summary that explains the evidence but can never lower the score (email text is attacker-controlled, so prompt injection is assumed)

## Known limitations

- **Gmail and Workspace senders:** when the email was sent through Google's own servers, the original sender's IP is hidden by design. The panel says so.
- **Domain comparison uses the Public Suffix List**, bundled in `extension/lib/psl-data.js`. Refresh it occasionally with `npm run update-psl`.
- **VirusTotal "not found" isn't "safe":** an attachment VirusTotal has never seen is simply unknown. Files are never uploaded, by design.
- **Gmail markup can change:** the extension reads one attribute from Gmail's page to find the message ID. Everything else comes from the API.

## Contributing

Forks and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). To report a security problem, see [SECURITY.md](SECURITY.md).

## Licence

[MIT](LICENSE)

`extension/lib/psl-data.js` is generated from the [Public Suffix List](https://publicsuffix.org/), which is licensed under [MPL-2.0](https://mozilla.org/MPL/2.0/).
