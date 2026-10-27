// Service worker: signs in, fetches the raw email from the Gmail API,
// analyses it and stores the report for the side panel.
//
// Storage: chrome.storage.session only (kept in memory, cleared when the
// browser closes). Email reports are never written to disk.

import { base64ToBytes } from "./lib/encoding.js";
import { analyseRawMessage } from "./lib/analyse.js";
import { buildEnrichRequest, isEmptyRequest } from "./lib/enrich-request.js";

const GMAIL_API = "https://gmail.googleapis.com/gmail/v1/users/me/messages";
const CACHE_LIMIT = 25;
const ENRICH_TIMEOUT_MS = 30000;
const requestSeq = new Map(); // tabId -> latest request number (drops stale results)

// ---------- Worker config (written by `npm run setup` into config.json) ----------

let configPromise = null;
function loadConfig() {
  configPromise ??= fetch(chrome.runtime.getURL("config.json"))
    .then((r) => (r.ok ? r.json() : {}))
    .catch(() => ({}));
  return configPromise;
}

/** Ask the Worker about the report's indicators. Never throws. */
async function enrichReport(report) {
  const { workerUrl, workerKey } = await loadConfig();
  if (!workerUrl || !workerKey) return { status: "off" };
  const request = buildEnrichRequest(report);
  if (isEmptyRequest(request)) return { status: "ok", request, results: null };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ENRICH_TIMEOUT_MS);
  try {
    const res = await fetch(new URL("/v1/enrich", workerUrl), {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${workerKey}` },
      body: JSON.stringify(request),
      signal: controller.signal,
    });
    if (!res.ok) {
      const detail = await res.json().catch(() => ({}));
      const hints = {
        401: "The Worker rejected the extension's key. Re-run `npm run setup` and restart the Worker.",
        403: "The Worker doesn't allow this extension's ID. Re-run `npm run setup` and restart the Worker.",
        503: "The Worker has no WORKER_KEY set.",
      };
      return { status: "error", request, error: hints[res.status] ?? `Worker error ${res.status}${detail.error ? `: ${detail.error}` : ""}` };
    }
    return { status: "ok", request, results: await res.json() };
  } catch (err) {
    return {
      status: "unreachable",
      request,
      error: err?.name === "AbortError" ? "The Worker took too long to answer." : `Couldn't reach the Worker at ${workerUrl}. Is it running?`,
    };
  } finally {
    clearTimeout(timer);
  }
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(console.error);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove(tabKey(tabId));
  requestSeq.delete(tabId);
});

const tabKey = (tabId) => `tab:${tabId}`;
const msgKey = (id) => `msg:${id}`;

async function setTabState(tabId, patch) {
  const key = tabKey(tabId);
  const { [key]: current = {} } = await chrome.storage.session.get(key);
  await chrome.storage.session.set({ [key]: { ...current, ...patch, updatedAt: Date.now() } });
}

async function getTabState(tabId) {
  const key = tabKey(tabId);
  return (await chrome.storage.session.get(key))[key] ?? null;
}

// ---------- Auth ----------

class AuthNeededError extends Error {}

async function getToken(interactive) {
  try {
    const result = await chrome.identity.getAuthToken({ interactive });
    const token = typeof result === "string" ? result : result?.token;
    if (!token) throw new AuthNeededError("No token returned");
    return token;
  } catch (err) {
    if (err instanceof AuthNeededError) throw err;
    // Non-interactive call fails with "The user is not signed in" / "OAuth2 not granted".
    throw new AuthNeededError(err?.message || String(err));
  }
}

async function disconnect() {
  try {
    const token = await getToken(false);
    await chrome.identity.removeCachedAuthToken({ token });
    await fetch(`https://oauth2.googleapis.com/revoke?token=${encodeURIComponent(token)}`, { method: "POST" });
  } catch {
    /* already signed out */
  }
  await chrome.identity.clearAllCachedAuthTokens();
  await chrome.storage.session.clear();
}

// ---------- Gmail API ----------

class GmailApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function fetchRawMessage(messageId, retry = true) {
  const token = await getToken(false);
  const res = await fetch(`${GMAIL_API}/${encodeURIComponent(messageId)}?format=raw`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (res.status === 401 && retry) {
    await chrome.identity.removeCachedAuthToken({ token });
    return fetchRawMessage(messageId, false);
  }
  if (!res.ok) {
    let detail = "";
    try {
      detail = (await res.json())?.error?.message ?? "";
    } catch {
      /* not JSON */
    }
    const hints = {
      401: "Google rejected the sign-in. Click Connect Gmail again.",
      403: "Access denied. Check the Gmail API is enabled in your Google Cloud project and your account is a test user.",
      404: "Gmail API couldn't find this message ID. Gmail may have changed its page markup — please open an issue.",
      429: "Gmail API rate limit hit. Wait a moment and press Re-analyse.",
    };
    throw new GmailApiError(res.status, hints[res.status] ?? `Gmail API error ${res.status}${detail ? `: ${detail}` : ""}`);
  }
  const data = await res.json();
  if (!data.raw) throw new GmailApiError(500, "Gmail API returned no raw message.");
  return base64ToBytes(data.raw);
}

// ---------- Cache ----------

async function cacheGet(id) {
  return (await chrome.storage.session.get(msgKey(id)))[msgKey(id)] ?? null;
}

async function cachePut(id, report) {
  const { cacheIndex = [] } = await chrome.storage.session.get("cacheIndex");
  const next = [id, ...cacheIndex.filter((x) => x !== id)];
  const evicted = next.slice(CACHE_LIMIT);
  await chrome.storage.session.set({ [msgKey(id)]: report, cacheIndex: next.slice(0, CACHE_LIMIT) });
  if (evicted.length) await chrome.storage.session.remove(evicted.map(msgKey));
}

// ---------- Pipeline ----------

async function analyse(tabId, messageId, { force = false } = {}) {
  const seq = (requestSeq.get(tabId) ?? 0) + 1;
  requestSeq.set(tabId, seq);
  const stale = () => requestSeq.get(tabId) !== seq;

  await setTabState(tabId, { status: "loading", selectedId: messageId, error: null });
  try {
    let report = force ? null : await cacheGet(messageId);
    if (!report) {
      const bytes = await fetchRawMessage(messageId);
      report = await analyseRawMessage(bytes, { messageId });
    }
    if (stale()) return;
    // Show the header analysis straight away; lookups fill in when they arrive.
    const needsLookups = report.enrichment?.status !== "ok";
    if (needsLookups) report.enrichment = { status: "loading" };
    await setTabState(tabId, { status: "ready", report });
    if (needsLookups) {
      report.enrichment = await enrichReport(report);
      if (stale()) return;
      await setTabState(tabId, { status: "ready", report });
    }
    await cachePut(messageId, report);
  } catch (err) {
    if (stale()) return;
    if (err instanceof AuthNeededError) {
      await setTabState(tabId, { status: "needs-auth", report: null });
    } else {
      console.error("[gmail-header-analyzer]", err);
      await setTabState(tabId, { status: "error", error: err.message || String(err), report: null });
    }
  }
}

async function handleOpen(tabId, messageIds) {
  const prev = await getTabState(tabId);
  // Default to the newest message in the conversation (last in page order),
  // but keep the user's choice if they picked another one in this thread.
  const keep = prev?.selectedId && messageIds.includes(prev.selectedId) && prev.status !== "idle";
  const selected = keep ? prev.selectedId : messageIds[messageIds.length - 1];
  await setTabState(tabId, { messageIds });
  if (keep && prev.status === "ready") return;
  await analyse(tabId, selected);
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const fromTab = sender.tab?.id;
  const run = async () => {
    switch (msg?.type) {
      case "gmail:open":
        if (fromTab != null && Array.isArray(msg.messageIds)) await handleOpen(fromTab, msg.messageIds.slice(0, 50));
        return { ok: true };
      case "gmail:closed":
        if (fromTab != null) {
          requestSeq.set(fromTab, (requestSeq.get(fromTab) ?? 0) + 1);
          await setTabState(fromTab, { status: "idle", messageIds: [], selectedId: null, report: null, error: null });
        }
        return { ok: true };

      // ---- from the side panel (no sender.tab; tabId passed explicitly) ----
      case "panel:connect": {
        await getToken(true);
        const state = await getTabState(msg.tabId);
        if (state?.selectedId) await analyse(msg.tabId, state.selectedId);
        else await chrome.tabs.sendMessage(msg.tabId, { type: "gmail:rescan" }).catch(() => {});
        return { ok: true };
      }
      case "panel:select":
        await analyse(msg.tabId, msg.messageId);
        return { ok: true };
      case "panel:refresh": {
        const state = await getTabState(msg.tabId);
        if (state?.selectedId) await analyse(msg.tabId, state.selectedId, { force: true });
        return { ok: true };
      }
      case "panel:rescan":
        await chrome.tabs.sendMessage(msg.tabId, { type: "gmail:rescan" }).catch(() => {});
        return { ok: true };
      case "panel:disconnect":
        await disconnect();
        return { ok: true };
      default:
        return { ok: false };
    }
  };
  // Only accept messages from this extension (content script or side panel).
  if (sender.id !== chrome.runtime.id) return false;
  run()
    .then(sendResponse)
    .catch((err) => sendResponse({ ok: false, error: err?.message || String(err) }));
  return true; // async response
});
