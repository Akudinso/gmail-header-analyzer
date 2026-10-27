// Parsers for the security-relevant headers.

import { decodeEncodedWords } from "./encoding.js";
import { extractIps, isNonPublicIp, normaliseHost } from "./netutil.js";

/** "Name" <user@example.com>  ->  { name, email, domain } */
export function parseAddress(value) {
  if (!value) return null;
  const decoded = decodeEncodedWords(value).trim();
  const angle = [...decoded.matchAll(/<([^<>]*)>/g)].pop();
  let email = angle ? angle[1].trim() : null;
  if (!email) {
    const bare = /[^\s<>"',;]+@[^\s<>"',;]+/.exec(decoded);
    email = bare ? bare[0] : null;
  }
  if (email) email = email.replace(/^mailto:/i, "");
  const name = angle
    ? decoded.slice(0, angle.index).trim().replace(/^"|"$/g, "").trim() || null
    : null;
  const at = email ? email.lastIndexOf("@") : -1;
  const domain = at > 0 ? normaliseHost(email.slice(at + 1)) : null;
  return { name, email: email || null, domain, raw: decoded };
}

/**
 * One Received header -> structured hop.
 * Typical: "from mail.example.com (mail.example.com. [45.33.32.156]) by mx.google.com
 *           with ESMTPS id abc for <you@gmail.com>; Tue, 27 Oct 2026 09:14:02 -0700 (PDT)"
 */
export function parseReceived(value) {
  const semi = value.lastIndexOf(";");
  const main = semi >= 0 ? value.slice(0, semi) : value;
  const dateStr = semi >= 0 ? value.slice(semi + 1).trim() : null;
  const ts = dateStr ? Date.parse(dateStr.replace(/\s*\([^)]*\)\s*$/, "")) : NaN;

  const fromIdx = main.search(/\bfrom\s/i);
  const byIdx = main.search(/\bby\s/i);
  const fromSection =
    fromIdx >= 0 ? main.slice(fromIdx, byIdx > fromIdx ? byIdx : undefined) : "";

  const fromHost = /\bfrom\s+(\S+)/i.exec(fromSection)?.[1] ?? null;
  const rdns = /\(([^\s()\[\]]+?)\.?\s*\[/.exec(fromSection)?.[1] ?? null;
  const by = /\bby\s+(\S+)/i.exec(main)?.[1] ?? null;
  const withProto = /\bwith\s+(\S+)/i.exec(main)?.[1] ?? null;
  const ips = extractIps(fromSection);

  return {
    fromHost: fromHost ? normaliseHost(fromHost) : null,
    reverseDns: rdns ? normaliseHost(rdns) : null,
    by: by ? normaliseHost(by) : null,
    with: withProto,
    ips,
    publicIps: ips.filter((ip) => !isNonPublicIp(ip)),
    timestamp: Number.isFinite(ts) ? ts : null,
    raw: value,
  };
}

/**
 * Authentication-Results (RFC 8601).
 * "mx.google.com; dkim=pass header.i=@x.com header.s=s1; spf=pass (...) smtp.mailfrom=a@x.com; dmarc=pass (p=REJECT) header.from=x.com"
 */
export function parseAuthResults(value) {
  const firstSemi = value.indexOf(";");
  const authservId = normaliseHost((firstSemi >= 0 ? value.slice(0, firstSemi) : value).trim().split(/\s+/)[0]);
  const body = firstSemi >= 0 ? value.slice(firstSemi + 1) : "";
  const results = [];
  for (const clause of body.split(";")) {
    const m = /^\s*([a-z0-9-]+)\s*=\s*([a-z]+)\b([\s\S]*)$/i.exec(clause);
    if (!m) continue;
    const props = {};
    const rest = m[3];
    for (const p of rest.matchAll(/\b([a-z]+\.[a-z0-9-]+|p|sp|dis)\s*=\s*("[^"]*"|[^\s;()]+)/gi)) {
      props[p[1].toLowerCase()] = p[2].replace(/^"|"$/g, "");
    }
    const comment = /\(([^)]*)\)/.exec(rest)?.[1] ?? null;
    results.push({ method: m[1].toLowerCase(), result: m[2].toLowerCase(), props, comment });
  }
  return { authservId, results, raw: value };
}

/** Received-SPF: pass (google.com: domain of ... designates 1.2.3.4 as permitted sender) client-ip=1.2.3.4; */
export function parseReceivedSpf(value) {
  const result = /^\s*([a-z]+)/i.exec(value)?.[1]?.toLowerCase() ?? null;
  const clientIp = /client-ip=([0-9a-f:.]+)/i.exec(value)?.[1] ?? null;
  const envelopeFrom = /envelope-from=<?([^\s;>]+)>?/i.exec(value)?.[1] ?? null;
  const reporter = /\(([a-z0-9.-]+):/i.exec(value)?.[1]?.toLowerCase() ?? null;
  return { result, clientIp, envelopeFrom, reporter, raw: value };
}

/** Domain from a Message-ID like <abc@mail.example.com> */
export function messageIdDomain(value) {
  const m = /@([^>\s]+)>?\s*$/.exec(value || "");
  return m ? normaliseHost(m[1]) : null;
}
