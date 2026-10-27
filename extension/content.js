// Runs on mail.google.com. Its only job: notice which email is open and tell
// the service worker its Gmail API message ID. It never reads email content
// from the page — the full message is fetched through the Gmail API instead.

(() => {
  const HEX_ID = /^[0-9a-f]{12,20}$/i;
  let lastKey = null;
  let timer = null;

  function isVisible(el) {
    return el.getClientRects().length > 0;
  }

  // Gmail tags each message in an open conversation with:
  //   data-legacy-message-id="18c5f2a9e4b1d3c7"   (hex — same ID the Gmail API uses)
  //   data-message-id="#msg-f:1785123456789012345" (decimal form of the same ID)
  // Gmail can change its markup at any time, so both are checked.
  function openMessageIds() {
    const ids = [];
    for (const el of document.querySelectorAll("[data-legacy-message-id]")) {
      const id = el.getAttribute("data-legacy-message-id");
      if (HEX_ID.test(id) && isVisible(el)) ids.push(id.toLowerCase());
    }
    if (!ids.length) {
      for (const el of document.querySelectorAll("[data-message-id]")) {
        const m = /msg-f:(\d{10,25})/.exec(el.getAttribute("data-message-id") || "");
        if (m && isVisible(el)) {
          try {
            ids.push(BigInt(m[1]).toString(16));
          } catch {
            /* ignore malformed */
          }
        }
      }
    }
    return [...new Set(ids)];
  }

  function report() {
    const ids = openMessageIds();
    const key = ids.join(",");
    if (key === lastKey) return;
    lastKey = key;
    const msg = ids.length ? { type: "gmail:open", messageIds: ids } : { type: "gmail:closed" };
    chrome.runtime.sendMessage(msg).catch(() => {
      // Service worker restarting or extension reloaded; next change will retry.
      lastKey = null;
    });
  }

  function schedule() {
    clearTimeout(timer);
    timer = setTimeout(report, 400); // Gmail mutates the DOM constantly; debounce.
  }

  new MutationObserver(schedule).observe(document.documentElement, { childList: true, subtree: true });
  window.addEventListener("hashchange", schedule);

  // Side panel asks "what's open right now?" when it first loads.
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg?.type === "gmail:rescan") {
      lastKey = null;
      report();
    }
  });

  schedule();
})();
