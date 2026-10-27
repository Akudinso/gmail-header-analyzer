// Exercises the service worker with a fake `chrome` API and a fake Gmail API,
// so the whole open-email -> fetch -> analyse -> store flow is tested without a browser.
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const raw = readFileSync(new URL("./fixtures/phish.eml", import.meta.url));
const store = new Map();
let onMessage;
let signedIn = false;
const fetchCalls = [];

globalThis.chrome = {
  runtime: {
    id: "ext-id",
    onInstalled: { addListener() {} },
    onMessage: { addListener: (fn) => (onMessage = fn) },
  },
  tabs: { onRemoved: { addListener() {} }, sendMessage: async () => {} },
  sidePanel: { setPanelBehavior: async () => {} },
  identity: {
    getAuthToken: async ({ interactive }) => {
      if (!signedIn && !interactive) throw new Error("OAuth2 not granted or revoked.");
      signedIn = true;
      return { token: "fake-token" };
    },
    removeCachedAuthToken: async () => {},
    clearAllCachedAuthTokens: async () => {},
  },
  storage: {
    session: {
      async get(keys) {
        const list = keys == null ? [...store.keys()] : Array.isArray(keys) ? keys : [keys];
        return Object.fromEntries(list.filter((k) => store.has(k)).map((k) => [k, structuredClone(store.get(k))]));
      },
      async set(obj) {
        for (const [k, v] of Object.entries(obj)) store.set(k, structuredClone(v));
      },
      async remove(keys) {
        for (const k of [].concat(keys)) store.delete(k);
      },
      async clear() {
        store.clear();
      },
    },
  },
};

globalThis.fetch = async (url, opts) => {
  fetchCalls.push({ url: String(url), auth: opts?.headers?.Authorization });
  return new Response(JSON.stringify({ id: "18c5f2a9e4b1d3c7", raw: raw.toString("base64url") }), { status: 200 });
};

function send(msg, sender = { id: "ext-id", tab: { id: 7 } }) {
  return new Promise((resolve) => {
    const async = onMessage(msg, sender, resolve);
    if (!async) resolve(undefined);
  });
}

before(async () => {
  await import("../extension/background.js");
});

test("opening an email before sign-in asks for Gmail access", async () => {
  await send({ type: "gmail:open", messageIds: ["18c5f2a9e4b1d3c7"] });
  assert.equal(store.get("tab:7").status, "needs-auth");
  assert.equal(fetchCalls.length, 0);
});

test("after connecting, the raw email is fetched and analysed", async () => {
  await send({ type: "panel:connect", tabId: 7 }, { id: "ext-id" });
  const state = store.get("tab:7");
  assert.equal(state.status, "ready", state.error);
  assert.equal(state.report.senderIp.verified.ip, "45.33.32.156");
  assert.equal(fetchCalls[0].url, "https://gmail.googleapis.com/gmail/v1/users/me/messages/18c5f2a9e4b1d3c7?format=raw");
  assert.equal(fetchCalls[0].auth, "Bearer fake-token");
});

test("reopening the same email uses the cache", async () => {
  await send({ type: "gmail:closed" });
  assert.equal(store.get("tab:7").status, "idle");
  await send({ type: "gmail:open", messageIds: ["18c5f2a9e4b1d3c7"] });
  assert.equal(store.get("tab:7").status, "ready");
  assert.equal(fetchCalls.length, 1);
});

test("Re-analyse bypasses the cache", async () => {
  await send({ type: "panel:refresh", tabId: 7 }, { id: "ext-id" });
  assert.equal(fetchCalls.length, 2);
});

test("messages from other extensions are ignored", async () => {
  const handled = onMessage({ type: "panel:disconnect" }, { id: "someone-else" }, () => {});
  assert.equal(handled, false);
  assert.ok(store.has("tab:7"));
});

test("Gmail API errors become a readable message", async () => {
  globalThis.fetch = async () => new Response(JSON.stringify({ error: { message: "nope" } }), { status: 404 });
  await send({ type: "gmail:open", messageIds: ["aaaaaaaaaaaaaaaa"] });
  const state = store.get("tab:7");
  assert.equal(state.status, "error");
  assert.match(state.error, /couldn't find this message ID/);
});
