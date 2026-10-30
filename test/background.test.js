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
    getURL: (path) => `chrome-extension://ext-id/${path}`,
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
    local: {
      data: {},
      async get(key) {
        return key in this.data ? { [key]: this.data[key] } : {};
      },
      async set(obj) {
        Object.assign(this.data, obj);
      },
    },
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

const workerCalls = [];
const summaryCalls = [];
const gmailFetch = async (url, opts) => {
  fetchCalls.push({ url: String(url), auth: opts?.headers?.Authorization });
  return new Response(JSON.stringify({ id: "18c5f2a9e4b1d3c7", raw: raw.toString("base64url") }), { status: 200 });
};
// Routes: extension config file, the Worker, and the Gmail API.
globalThis.fetch = async (url, opts) => {
  const u = String(url);
  if (u === "chrome-extension://ext-id/config.json") {
    return new Response(JSON.stringify({ workerUrl: "http://localhost:8787", workerKey: "k3y" }));
  }
  if (u === "http://localhost:8787/v1/summarise") {
    summaryCalls.push(JSON.parse(opts.body));
    return new Response(JSON.stringify({ status: "ok", data: { summary: "A fake PayPal warning.", keyPoints: [], aiAssessment: "consistent", aiConcern: "", injectionSuspected: false, model: "m" } }));
  }
  if (u === "http://localhost:8787/v1/enrich") {
    workerCalls.push({ auth: opts.headers.authorization, body: JSON.parse(opts.body) });
    return new Response(JSON.stringify({ ip: { value: "45.33.32.156", abuseipdb: { status: "ok", data: { abuseScore: 90 } } }, claimedIps: [], domains: [], urls: [], hashes: [], limits: {} }));
  }
  return gmailFetch(url, opts);
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

test("indicators (not email content) are sent to the Worker with the Worker key", async () => {
  const state = store.get("tab:7");
  assert.equal(state.report.enrichment.status, "ok");
  assert.equal(state.report.enrichment.results.ip.abuseipdb.data.abuseScore, 90);
  assert.equal(workerCalls.length, 1);
  assert.equal(workerCalls[0].auth, "Bearer k3y", "Worker key, never the Gmail token");
  const sent = JSON.stringify(workerCalls[0].body);
  assert.ok(!sent.includes("fake-token"));
  assert.ok(!sent.includes("Dear customer"), "no body text");
  assert.equal(workerCalls[0].body.ip, "45.33.32.156");
});

test("reopening the same email uses the cache", async () => {
  await send({ type: "gmail:closed" });
  assert.equal(store.get("tab:7").status, "idle");
  await send({ type: "gmail:open", messageIds: ["18c5f2a9e4b1d3c7"] });
  assert.equal(store.get("tab:7").status, "ready");
  assert.equal(fetchCalls.length, 1);
  assert.equal(workerCalls.length, 1, "cached report keeps its lookups");
});

test("Re-analyse bypasses the cache", async () => {
  await send({ type: "panel:refresh", tabId: 7 }, { id: "ext-id" });
  assert.equal(fetchCalls.length, 2);
});

test("AI summary is off by default, and runs after lookups once turned on", async () => {
  assert.equal(summaryCalls.length, 0, "never called before opt-in");
  assert.equal(store.get("tab:7").report.aiSummary, undefined);
  await send({ type: "panel:set-ai", tabId: 7, enabled: true }, { id: "ext-id" });
  const r = store.get("tab:7").report;
  assert.equal(r.aiSummary.status, "ok");
  assert.equal(r.aiSummary.data.summary, "A fake PayPal warning.");
  assert.equal(typeof r.aiSummary.forScore, "number");
  const sent = summaryCalls[0];
  assert.equal(sent.assessment.level, "high");
  assert.ok(sent.assessment.findings.length > 0);
  assert.ok(sent.email.body.includes("Dear customer"), "the summary is the one feature that sends body text");
  assert.ok(!JSON.stringify(sent).includes("fake-token"));
  // Reopening uses the cached summary.
  await send({ type: "gmail:closed" });
  await send({ type: "gmail:open", messageIds: ["18c5f2a9e4b1d3c7"] });
  assert.equal(summaryCalls.length, 1);
  await send({ type: "panel:set-ai", tabId: 7, enabled: false }, { id: "ext-id" });
});

test("messages from other extensions are ignored", async () => {
  const handled = onMessage({ type: "panel:disconnect" }, { id: "someone-else" }, () => {});
  assert.equal(handled, false);
  assert.ok(store.has("tab:7"));
});

test("an unreachable Worker doesn't break the header analysis", async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    if (String(url).startsWith("http://localhost:8787")) throw new TypeError("Failed to fetch");
    return realFetch(url, opts);
  };
  await send({ type: "panel:refresh", tabId: 7 }, { id: "ext-id" });
  const state = store.get("tab:7");
  assert.equal(state.status, "ready");
  assert.equal(state.report.enrichment.status, "unreachable");
  assert.match(state.report.enrichment.error, /Is it running/);
  globalThis.fetch = realFetch;
});

test("Gmail API errors become a readable message", async () => {
  globalThis.fetch = async () => new Response(JSON.stringify({ error: { message: "nope" } }), { status: 404 });
  await send({ type: "gmail:open", messageIds: ["aaaaaaaaaaaaaaaa"] });
  const state = store.get("tab:7");
  assert.equal(state.status, "error");
  assert.match(state.error, /couldn't find this message ID/);
});
