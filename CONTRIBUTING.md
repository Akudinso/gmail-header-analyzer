# Contributing

Thanks for helping. This is a learning project, so questions and small fixes are just as welcome as features.

## Getting started

Follow "Run it yourself" in the [README](README.md), then:

```bash
npm test
```

Tests use only Node's built-in test runner, so they run without a browser or any API keys.

## Ground rules

1. **Treat every email as hostile.** Headers, bodies and filenames are written by attackers.
   - In the side panel, build elements with the `el()` helper, which sets `textContent`. Never use `innerHTML` with email data.
   - Never make links from emails clickable.
   - Keep parsing bounded (depth, counts, sizes).
2. **Trust only what Google recorded.** Anything below Google's newest `Received` hop or not from `authserv-id mx.google.com` is a claim, not a fact. Label it that way.
3. **No secrets in the extension.** API keys belong in the Worker (`worker/.dev.vars` locally, `wrangler secret put` in production). Your extension key and OAuth client ID stay in gitignored files.
4. **Add a test with every parser change.** If you fix a real-world email that broke the parser, add a trimmed, anonymised `.eml` to `test/fixtures/`. Remove real names, addresses and IPs that belong to people.

## Pull requests

- Keep each PR to one change and describe what it fixes or adds.
- Run `npm test` before opening it; CI runs the same command.
- If you change the side panel, include a screenshot.
