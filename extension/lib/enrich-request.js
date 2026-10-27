// Decides which indicators from a report get sent to the Worker for lookups.
//
// Privacy rule: only indicators leave the browser, never email text. And
// full URLs are sent only for links that already look suspicious, because
// ordinary links (password resets, unsubscribe links, shared docs) often
// contain personal tokens. Every link's *domain* is still checked.
//
// "Suspicious" = the link text points elsewhere, the link is a bare IP, or it
// is on shared hosting where anyone can publish (storage.googleapis.com,
// *.github.io, *.web.app ...), where the parent domain's good reputation says
// nothing about the page. Shared document services (docs.google.com,
// SharePoint) are deliberately not included: their links are often private.

import { lookupDomain } from "./netutil.js";

const MAX = { domains: 10, urls: 5, hashes: 5, claimedIps: 3 };

export function buildEnrichRequest(report) {
  const roles = new Map();
  const addRole = (domain, role) => {
    const d = lookupDomain(domain);
    if (!d) return;
    if (!roles.has(d)) roles.set(d, new Set());
    roles.get(d).add(role);
  };
  const s = report.summary;
  addRole(s.from?.domain, "from");
  addRole(s.replyTo?.domain, "reply-to");
  addRole(s.returnPath?.domain, "return-path");
  addRole(s.sender?.domain, "sender");
  addRole(report.auth.dkim?.domain, "dkim");
  // Suspicious links' domains first so they survive the cap.
  const suspicious = (u) => u.textMismatch || u.isIp || u.sharedHosting;
  const urls = [...report.urls].sort((a, b) => Number(suspicious(b)) - Number(suspicious(a)));
  for (const u of urls) if (!u.isIp) addRole(u.host, "link");

  const rank = (r) => (r.has("from") ? 0 : [...r].some((x) => x !== "link") ? 1 : 2);
  const domains = [...roles.entries()]
    .sort((a, b) => rank(a[1]) - rank(b[1]))
    .slice(0, MAX.domains)
    .map(([domain, r]) => ({ domain, roles: [...r] }));

  const attachments = [...report.attachments].sort((a, b) => Number(a.inline) - Number(b.inline));

  return {
    ip: report.senderIp.verified?.ip ?? null,
    claimedIps: report.senderIp.claimed.map((c) => c.ip).filter((ip) => ip !== report.senderIp.verified?.ip).slice(0, MAX.claimedIps),
    domains,
    urls: urls.filter(suspicious).map((u) => u.url).slice(0, MAX.urls),
    hashes: attachments.map((a) => a.sha256).filter(Boolean).slice(0, MAX.hashes),
  };
}

export function isEmptyRequest(req) {
  return !req.ip && !req.claimedIps.length && !req.domains.length && !req.urls.length && !req.hashes.length;
}
