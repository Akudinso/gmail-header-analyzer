# Security policy

This extension reads email, so security reports are taken seriously.

## Reporting a vulnerability

Please **don't** open a public issue for security problems. Use GitHub's private reporting instead: the **Security** tab of this repository → **Report a vulnerability**.

Include what you found, steps to reproduce, and, if possible, a sample `.eml` that triggers it. With real emails, please strip personal data first.

## In scope

- An email that makes the side panel run script, load remote content or show misleading results (for example, a forged header being shown as verified)
- Ways for a web page or another extension to read reports or trigger Gmail API calls
- Ways to call the Worker without its key, or to make it fetch arbitrary URLs
- Email content that makes the AI summary contradict the score, leak data, or escape its fence
- Secrets or personal data ending up in the repository, logs or storage that persists to disk

## Design commitments

- Read-only Gmail access (`gmail.readonly`); no send, modify or delete permissions
- Reports are kept in `chrome.storage.session` (memory only)
- Email content is never sent to the Worker or lookup services; only indicators are (IPs, domains, attachment hashes, and full URLs only for links that already look suspicious)
- The optional AI summary is the only feature that sends email text (to Google Gemini, via the Worker). It is off until the user turns it on, and URL query strings and email addresses are removed first
- The AI cannot change the risk score; its output is schema-checked and discarded if it contradicts the score
- The Gmail OAuth token is only ever sent to Google; the Worker is authenticated with a separate random key
- The Worker validates every indicator and contacts only fixed hosts, so it can't be used as an open proxy
