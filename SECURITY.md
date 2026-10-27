# Security policy

This extension reads email, so security reports are taken seriously.

## Reporting a vulnerability

Please **don't** open a public issue for security problems. Use GitHub's private reporting instead: the **Security** tab of this repository → **Report a vulnerability**.

Include what you found, steps to reproduce, and, if possible, a sample `.eml` that triggers it. With real emails, please strip personal data first.

## In scope

- An email that makes the side panel run script, load remote content or show misleading results (for example, a forged header being shown as verified)
- Ways for a web page or another extension to read reports or trigger Gmail API calls
- Secrets or personal data ending up in the repository, logs or storage that persists to disk

## Design commitments

- Read-only Gmail access (`gmail.readonly`); no send, modify or delete permissions
- Reports are kept in `chrome.storage.session` (memory only)
- Email content is never sent to third-party lookup services; only indicators (IPs, domains, URLs, file hashes) will be
