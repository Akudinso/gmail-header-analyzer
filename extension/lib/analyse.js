// Turns a raw RFC 5322 message into a structured, JSON-safe report.
// Steps 3-5 (lookups, scoring, AI) consume `report.indicators`.

import { decodeEncodedWords, decodeHtmlEntities, sha256Hex } from "./encoding.js";
import { getHeader, getHeaders, parseMessage } from "./mime.js";
import {
  messageIdDomain,
  parseAddress,
  parseAuthResults,
  parseReceived,
  parseReceivedSpf,
} from "./headers.js";
import { isNonPublicIp, lookupDomain, normaliseHost, registrableDomain, sameOrg } from "./netutil.js";

// The receiving server we trust. Gmail adds these headers itself; anything
// the sender wrote further down the message could be forged.
const TRUSTED_AUTHSERV = "mx.google.com";
const GOOGLE_HOST = /(^|\.)google\.com$/;

const MAX_URLS = 150;
const PREVIEW_CHARS = 4000;
const RISKY_EXTENSIONS =
  /\.(exe|scr|pif|com|bat|cmd|js|jse|vbs|vbe|wsf|wsh|hta|ps1|msi|msix|jar|lnk|iso|img|vhd|html?|svg|docm|xlsm|pptm|one|reg|cpl)$/i;

export function selectAuthResults(headers) {
  // Topmost Authentication-Results from Google = what Gmail actually verified.
  for (const v of getHeaders(headers, "authentication-results")) {
    const parsed = parseAuthResults(v);
    if (parsed.authservId === TRUSTED_AUTHSERV) return parsed;
  }
  return null;
}

function summariseAuth(auth) {
  const pick = (method) => auth?.results.find((r) => r.method === method) ?? null;
  const dkimAll = auth?.results.filter((r) => r.method === "dkim") ?? [];
  const dkimPass = dkimAll.find((r) => r.result === "pass");
  const dkim = dkimPass ?? dkimAll[0] ?? null;
  const spf = pick("spf");
  const dmarc = pick("dmarc");
  return {
    trustedSource: auth ? TRUSTED_AUTHSERV : null,
    spf: spf ? { result: spf.result, domain: spf.props["smtp.mailfrom"]?.split("@").pop() ?? null } : null,
    dkim: dkim
      ? {
          result: dkim.result,
          domain: normaliseHost(dkim.props["header.d"] ?? dkim.props["header.i"]?.split("@").pop() ?? "") || null,
          selector: dkim.props["header.s"] ?? null,
        }
      : null,
    dkimSignatures: dkimAll.length,
    dmarc: dmarc
      ? { result: dmarc.result, policy: (dmarc.props.p ?? "").toLowerCase() || null, domain: dmarc.props["header.from"] ?? null }
      : null,
  };
}

/**
 * Work out the sending IP, keeping verified and unverified sources apart.
 *  1. Received-SPF client-ip written by Google  -> verified
 *  2. Topmost hop received BY a google.com host -> verified (the IP that connected to Gmail)
 *  3. Bottom-most public IP / X-Originating-IP / X-Sender-IP -> claimed by sender, unverified
 */
export function determineSenderIp(headers, hops) {
  // The NEWEST hop recorded by a google.com server with a public "from" IP is
  // where the message entered Google. Servers prepend Received headers, so a
  // forged hop can only sit below Google's real one, never above it.
  let verified = null;
  let entryIndex = -1;
  for (let i = hops.length - 1; i >= 0; i--) {
    const h = hops[i];
    if (h.by && GOOGLE_HOST.test(h.by) && h.publicIps.length) {
      entryIndex = i;
      verified = { ip: h.publicIps[0], hop: i, source: `Received hop ${i + 1} (connection into ${h.by})` };
      break;
    }
  }
  // Received-SPF is only used to confirm that IP; on its own it could be forged.
  const spfHeader = getHeader(headers, "received-spf");
  if (verified && spfHeader) {
    const spf = parseReceivedSpf(spfHeader);
    if (spf.clientIp === verified.ip && spf.reporter && GOOGLE_HOST.test(spf.reporter)) {
      verified.source += " — confirmed by Google's Received-SPF";
    }
  }

  const claimed = [];
  const firstPublicHop = hops.findIndex((h) => h.publicIps.length);
  if (firstPublicHop >= 0) {
    claimed.push({ ip: hops[firstPublicHop].publicIps[0], source: `Earliest public Received hop (${firstPublicHop + 1})` });
  }
  for (const name of ["x-originating-ip", "x-sender-ip", "x-orig-ip"]) {
    const v = getHeader(headers, name);
    const ip = v?.replace(/[\[\]\s]/g, "");
    if (ip && !isNonPublicIp(ip)) claimed.push({ ip, source: name.replace(/(^|-)([a-z])/g, (m) => m.toUpperCase()) });
  }
  // If the server that handed the message to Gmail is itself Google's
  // (Gmail / Workspace sender), the real originating IP is hidden by design.
  const entry = entryIndex >= 0 ? hops[entryIndex] : null;
  const sentViaGoogle = Boolean(entry && GOOGLE_HOST.test(entry.reverseDns || entry.fromHost || ""));

  return {
    verified,
    claimed: claimed.filter((c, i, arr) => arr.findIndex((x) => x.ip === c.ip) === i),
    sentViaGoogle,
  };
}

function stripHtml(html) {
  return decodeHtmlEntities(
    html
      .replace(/<(script|style|head)[\s\S]*?<\/\1>/gi, " ")
      .replace(/<br\s*\/?>|<\/(p|div|tr|li|h\d)>/gi, "\n")
      .replace(/<[^>]+>/g, " ")
  )
    .replace(/[ \t ]+/g, " ")
    .replace(/\n\s*\n+/g, "\n\n")
    .trim();
}

function safeUrl(href) {
  try {
    const u = new URL(href.trim());
    return u.protocol === "http:" || u.protocol === "https:" ? u : null;
  } catch {
    return null;
  }
}

/** Host the visible link text *claims* to go to, if the text looks like a URL/domain. */
function claimedHost(text) {
  const t = text.trim();
  const m = /^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[\/:?#]\S*)?$/i.exec(t);
  return m ? normaliseHost(m[1]) : null;
}

export function extractUrls(html, text) {
  const urls = new Map();
  const add = (href, linkText, source) => {
    if (urls.size >= MAX_URLS) return;
    const u = safeUrl(href);
    if (!u) return;
    const key = u.href;
    const host = normaliseHost(u.hostname);
    const claimed = linkText ? claimedHost(linkText) : null;
    const entry = urls.get(key) ?? {
      url: u.href,
      host,
      domain: registrableDomain(host),
      isIp: /^[\d.]+$/.test(host) || host.includes(":"),
      texts: [],
      textMismatch: false,
      sources: [],
    };
    if (linkText && entry.texts.length < 3 && !entry.texts.includes(linkText)) entry.texts.push(linkText);
    if (claimed && !sameOrg(claimed, host)) entry.textMismatch = true;
    if (!entry.sources.includes(source)) entry.sources.push(source);
    urls.set(key, entry);
  };

  if (html) {
    const anchor = /<a\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a\s*>/gi;
    for (const m of html.matchAll(anchor)) {
      const href = decodeHtmlEntities(m[1] ?? m[2] ?? m[3] ?? "");
      const linkText = stripHtml(m[4]).slice(0, 200);
      add(href, linkText, "html");
    }
  }
  const plain = [text, html ? stripHtml(html) : ""].join("\n");
  for (const m of plain.matchAll(/\bhttps?:\/\/[^\s<>"'`)\]]+/gi)) {
    add(m[0].replace(/[.,;:!?]+$/, ""), null, "text");
  }
  return [...urls.values()];
}

async function describeAttachments(attachments) {
  const out = [];
  for (const a of attachments) {
    const name = decodeEncodedWords(a.filename);
    const flags = [];
    if (RISKY_EXTENSIONS.test(name)) flags.push("risky-extension");
    if (/\.[a-z0-9]{2,4}\.[a-z0-9]{2,4}$/i.test(name) && RISKY_EXTENSIONS.test(name)) flags.push("double-extension");
    out.push({
      filename: name,
      contentType: a.contentType,
      inline: a.inline,
      size: a.bytes?.length ?? 0,
      sha256: a.bytes ? await sha256Hex(a.bytes) : null,
      flags,
    });
  }
  return out;
}

export async function analyseRawMessage(bytes, meta = {}) {
  const msg = parseMessage(bytes);
  const h = msg.headers;

  // Received headers are prepended by each server, so reverse to get oldest-first.
  const hops = getHeaders(h, "received").map(parseReceived).reverse();
  hops.forEach((hop, i) => {
    const prev = hops[i - 1];
    hop.delaySeconds =
      prev && hop.timestamp && prev.timestamp ? Math.round((hop.timestamp - prev.timestamp) / 1000) : null;
  });

  const from = parseAddress(getHeader(h, "from"));
  const replyTo = parseAddress(getHeader(h, "reply-to"));
  const sender = parseAddress(getHeader(h, "sender"));
  const returnPath = parseAddress(getHeader(h, "return-path"));
  const auth = summariseAuth(selectAuthResults(h));
  const senderIp = determineSenderIp(h, hops);
  const urls = extractUrls(msg.html, msg.text);
  const attachments = await describeAttachments(msg.attachments);

  const checks = {
    replyToDiffers: Boolean(replyTo?.domain && from?.domain && !sameOrg(replyTo.domain, from.domain)),
    returnPathDiffers: Boolean(returnPath?.domain && from?.domain && !sameOrg(returnPath.domain, from.domain)),
    dkimNotAligned: Boolean(auth.dkim?.domain && from?.domain && !sameOrg(auth.dkim.domain, from.domain)),
    displayNameHasEmail: Boolean(from?.name && /@/.test(from.name) && !from.name.toLowerCase().includes(from.email?.toLowerCase())),
    linkTextMismatches: urls.filter((u) => u.textMismatch).length,
    ipLinks: urls.filter((u) => u.isIp).length,
    riskyAttachments: attachments.filter((a) => a.flags.length).length,
  };

  const domains = new Set(
    [from?.domain, replyTo?.domain, sender?.domain, returnPath?.domain, auth.dkim?.domain, ...urls.map((u) => u.domain)]
      .filter(Boolean)
      .map((d) => lookupDomain(d))
      .filter(Boolean)
  );
  const ips = new Set([senderIp.verified?.ip, ...senderIp.claimed.map((c) => c.ip)].filter(Boolean));

  const bodyText = msg.text?.trim() || (msg.html ? stripHtml(msg.html) : "");

  return {
    version: 1,
    messageId: meta.messageId ?? null,
    analysedAt: new Date().toISOString(),
    summary: {
      subject: decodeEncodedWords(getHeader(h, "subject") ?? "") || "(no subject)",
      date: getHeader(h, "date"),
      from,
      to: decodeEncodedWords(getHeader(h, "to") ?? "") || null,
      replyTo,
      sender,
      returnPath,
      messageIdDomain: messageIdDomain(getHeader(h, "message-id")),
    },
    auth,
    senderIp,
    hops,
    urls,
    attachments,
    checks,
    indicators: {
      ips: [...ips],
      domains: [...domains],
      urls: urls.map((u) => u.url),
      hashes: attachments.map((a) => a.sha256).filter(Boolean),
    },
    body: {
      hasHtml: Boolean(msg.html),
      hasText: Boolean(msg.text),
      preview: bodyText.slice(0, PREVIEW_CHARS),
      truncated: bodyText.length > PREVIEW_CHARS,
    },
    headers: h,
  };
}
