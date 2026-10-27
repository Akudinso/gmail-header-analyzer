#!/usr/bin/env node
// Generates extension/manifest.json from the template.
//
// Why this exists: Google's "Chrome Extension" OAuth client is tied to ONE
// extension ID. An unpacked extension's ID normally changes with the folder
// path, so every clone would break sign-in. Pinning a public key in the
// manifest ("key") makes the ID stable. Each person who clones the repo gets
// their own key pair (kept in .local/, never committed) and their own OAuth
// client ID, so no secrets are shared through GitHub.
//
// Usage:
//   npm run setup                         # step 1: create key, print extension ID
//   npm run setup -- --client-id=XXXX     # step 2: write manifest with your client ID

import { createHash, generateKeyPairSync, createPrivateKey, createPublicKey } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const localDir = join(root, ".local");
const keyPath = join(localDir, "extension-key.pem");
const configPath = join(localDir, "config.json");
const templatePath = join(root, "extension", "manifest.template.json");
const manifestPath = join(root, "extension", "manifest.json");

const CLIENT_ID_PATTERN = /^[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com$/;

function loadOrCreatePrivateKey() {
  mkdirSync(localDir, { recursive: true });
  if (existsSync(keyPath)) {
    return createPrivateKey(readFileSync(keyPath, "utf8"));
  }
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

function main() {
  const args = parseArgs(process.argv.slice(2));
  const privateKey = loadOrCreatePrivateKey();
  const publicDer = createPublicKey(privateKey).export({ type: "spki", format: "der" });
  const publicKeyB64 = publicDer.toString("base64");
  const extensionId = extensionIdFromPublicKeyDer(publicDer);

  let config = existsSync(configPath) ? JSON.parse(readFileSync(configPath, "utf8")) : {};
  if (args["client-id"]) {
    if (!CLIENT_ID_PATTERN.test(args["client-id"])) {
      console.error(`That doesn't look like a Google OAuth client ID (expected ...apps.googleusercontent.com).`);
      process.exit(1);
    }
    config.clientId = args["client-id"];
    writeFileSync(configPath, JSON.stringify(config, null, 2));
  }

  console.log(`\nYour extension ID: ${extensionId}\n`);

  if (!config.clientId) {
    console.log(`Next: create an OAuth client in Google Cloud Console`);
    console.log(`  Application type: Chrome Extension`);
    console.log(`  Item ID:          ${extensionId}`);
    console.log(`Then run:  npm run setup -- --client-id=YOUR_CLIENT_ID\n`);
    console.log(`(Full walkthrough in README.md, "Set up Google sign-in".)`);
    return;
  }

  const template = readFileSync(templatePath, "utf8");
  const manifest = template
    .replace("__EXTENSION_PUBLIC_KEY__", publicKeyB64)
    .replace("__OAUTH_CLIENT_ID__", config.clientId);
  JSON.parse(manifest); // fail loudly if the template is broken
  writeFileSync(manifestPath, manifest);
  console.log(`Wrote extension/manifest.json with client ID ${config.clientId}.`);
  console.log(`Load the "extension" folder at chrome://extensions (Developer mode → Load unpacked).`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main();
}
