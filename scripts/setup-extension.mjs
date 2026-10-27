#!/usr/bin/env node
// One command that configures your copy of the project. Safe to re-run.
//
// It writes three gitignored files, so nothing personal ever reaches GitHub:
//   extension/manifest.json  your extension key (fixes the extension ID) + OAuth client ID
//   extension/config.json    where the Worker is, and the key to call it with
//   worker/.dev.vars         the same Worker key + your extension ID, for `npm run worker:dev`
//
// Why the key: Google's "Chrome Extension" OAuth client is tied to ONE extension
// ID. An unpacked extension's ID normally depends on the folder path, so every
// clone would break sign-in. Pinning a public key in the manifest makes the ID
// stable. Each person who clones the repo gets their own key pair.
//
// Usage:
//   npm run setup                                   # create key, print extension ID
//   npm run setup -- --client-id=XXXX               # add your Google OAuth client ID
//   npm run setup -- --worker-url=https://...       # point at a deployed Worker (default: local)

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const localDir = join(root, ".local");
const keyPath = join(localDir, "extension-key.pem");
const configPath = join(localDir, "config.json");
const templatePath = join(root, "extension", "manifest.template.json");
const manifestPath = join(root, "extension", "manifest.json");
const extConfigPath = join(root, "extension", "config.json");
const devVarsPath = join(root, "worker", ".dev.vars");
const devVarsExamplePath = join(root, "worker", ".dev.vars.example");

const CLIENT_ID_PATTERN = /^[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com$/;
const DEFAULT_WORKER_URL = "http://localhost:8787";

function loadOrCreatePrivateKey() {
  mkdirSync(localDir, { recursive: true });
  if (existsSync(keyPath)) return createPrivateKey(readFileSync(keyPath, "utf8"));
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  writeFileSync(keyPath, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  console.log(`Created a new extension key at .local/extension-key.pem (keep it; it fixes your extension ID).`);
  return privateKey;
}

// Chrome's extension ID: SHA-256 of the DER public key, first 16 bytes,
// each hex digit 0-f mapped to the letters a-p.
export function extensionIdFromPublicKeyDer(der) {
  const hex = createHash("sha256").update(der).digest("hex").slice(0, 32);
  return [...hex].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
}

function parseArgs(argv) {
  const out = {};
  for (const arg of argv) {
    const m = /^--([a-z-]+)=(.*)$/.exec(arg);
    if (m) out[m[1]] = m[2].trim();
  }
  return out;
}

/** Set KEY=value lines in a .env-style file, keeping every other line (e.g. your API keys). */
export function upsertEnv(text, values) {
  const lines = text.split(/\r?\n/);
  for (const [k, v] of Object.entries(values)) {
    const i = lines.findIndex((l) => new RegExp(`^\\s*${k}\\s*=`).test(l));
    if (i >= 0) lines[i] = `${k}=${v}`;
    else lines.push(`${k}=${v}`);
  }
  return lines.join("\n").replace(/\n*$/, "\n");
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const privateKey = loadOrCreatePrivateKey();
  const publicDer = createPublicKey(privateKey).export({ type: "spki", format: "der" });
  const extensionId = extensionIdFromPublicKeyDer(publicDer);

  const config = existsSync(configPath) ? JSON.parse(readFileSync(configPath, "utf8")) : {};
  if (args["client-id"]) {
    if (!CLIENT_ID_PATTERN.test(args["client-id"])) {
      console.error(`That doesn't look like a Google OAuth client ID (expected ...apps.googleusercontent.com).`);
      process.exit(1);
    }
    config.clientId = args["client-id"];
  }
  if (args["worker-url"] !== undefined) {
    try {
      const u = new URL(args["worker-url"]);
      if (!/^https?:$/.test(u.protocol)) throw new Error();
      config.workerUrl = u.origin;
    } catch {
      console.error(`--worker-url must be an http(s) URL, e.g. https://gmail-header-analyzer.you.workers.dev`);
      process.exit(1);
    }
  }
  config.workerUrl ??= DEFAULT_WORKER_URL;
  config.workerKey ??= randomBytes(32).toString("base64url");
  writeFileSync(configPath, JSON.stringify(config, null, 2), { mode: 0o600 });

  // Worker side: always kept in sync, even before the OAuth client exists.
  const devVars = existsSync(devVarsPath)
    ? readFileSync(devVarsPath, "utf8")
    : existsSync(devVarsExamplePath)
      ? readFileSync(devVarsExamplePath, "utf8")
      : "";
  writeFileSync(
    devVarsPath,
    upsertEnv(devVars, { ALLOWED_ORIGINS: `chrome-extension://${extensionId}`, WORKER_KEY: config.workerKey }),
    { mode: 0o600 }
  );

  console.log(`\nYour extension ID: ${extensionId}\n`);

  if (!config.clientId) {
    console.log(`Next: create an OAuth client in Google Cloud Console`);
    console.log(`  Application type: Chrome Extension`);
    console.log(`  Item ID:          ${extensionId}`);
    console.log(`Then run:  npm run setup -- --client-id=YOUR_CLIENT_ID\n`);
    console.log(`(Full walkthrough in README.md, "Set up Google sign-in".)`);
    return;
  }

  const manifest = readFileSync(templatePath, "utf8")
    .replace("__EXTENSION_PUBLIC_KEY__", publicDer.toString("base64"))
    .replace("__OAUTH_CLIENT_ID__", config.clientId);
  JSON.parse(manifest); // fail loudly if the template is broken
  writeFileSync(manifestPath, manifest);
  writeFileSync(extConfigPath, JSON.stringify({ workerUrl: config.workerUrl, workerKey: config.workerKey }, null, 2));

  console.log(`Wrote extension/manifest.json (client ID ${config.clientId})`);
  console.log(`Wrote extension/config.json  (Worker at ${config.workerUrl})`);
  console.log(`Updated worker/.dev.vars      (add your VirusTotal and AbuseIPDB keys there)\n`);
  console.log(`Reload the extension at chrome://extensions to pick up changes.`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main();
}
