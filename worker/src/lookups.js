// Threat-intel lookups. Every function returns a small, normalised object:
//   { status: "ok" | "not_found" | "not_configured" | "skipped" | "rate_limited" | "error", data?, error?, cached? }
// Only fixed hosts are ever contacted, and every value has been validated by
// index.js before it gets here, so the Worker can't be used as an open proxy.

const TIMEOUT_MS = 8000;
const TTL = { ok: 6 * 3600, rdap: 7 * 24 * 3600, notFound: 3600 };

async function fetchJson(url, init = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, { ...init, signal: controller.signal, headers: { accept: "application/json", ...init.headers } });
    let json = null;
    try {
      json = await res.json();
    } catch {
      /* empty or non-JSON body */
    }
    return { status: res.status, json };
  } finally {
    clearTimeout(timer);
  }
}

/** Shared wrapper: cache lookups, turn HTTP outcomes into a status. */
async function cachedLookup(cache, key, ttlOk, fn) {
  const hit = await cache.get(key);
  if (hit) return { ...hit, cached: true };
  let result;
  try {
    result = await fn();
  } catch (err) {
    return { status: "error", error: err?.name === "AbortError" ? "timed out" : String(err?.message || err) };
  }
  if (result.status === "ok") await cache.put(key, result, ttlOk);
  else if (result.status === "not_found") await cache.put(key, result, TTL.notFound);
  return { ...result, cached: false };
}

function httpOutcome(status, json, parse, { keyed = true } = {}) {
  if (status === 200) return { status: "ok", data: parse(json) };
  if (status === 404) return { status: "not_found" };
  if (status === 429) return { status: "rate_limited" };
  if (keyed && (status === 401 || status === 403)) return { status: "error", error: "API key rejected" };
  if (keyed && status === 400) return { status: "invalid" };
  return { status: "error", error: `HTTP ${status}` };
}

const USER_AGENT = "gmail-header-analyzer (+https://github.com/Akudinso/gmail-header-analyzer)";

// ---------- VirusTotal ----------

const VT = "https://www.virustotal.com/api/v3";

function vtStats(attr) {
  const s = attr?.last_analysis_stats ?? {};
  return {
    malicious: s.malicious ?? 0,
    suspicious: s.suspicious ?? 0,
    harmless: s.harmless ?? 0,
    undetected: s.undetected ?? 0,
  };
}

/** VirusTotal URL identifier: unpadded base64url of the URL. */
export function vtUrlId(url) {
  const bytes = new TextEncoder().encode(url);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const VT_PATHS = {
  ip: (v) => `ip_addresses/${encodeURIComponent(v)}`,
  domain: (v) => `domains/${encodeURIComponent(v)}`,
  url: (v) => `urls/${vtUrlId(v)}`,
  file: (v) => `files/${v}`,
};

const VT_PARSERS = {
  ip: (a) => ({ ...vtStats(a), reputation: a.reputation ?? null, asn: a.asn ?? null, asOwner: a.as_owner ?? null, country: a.country ?? null, network: a.network ?? null }),
  domain: (a) => ({
    ...vtStats(a),
    reputation: a.reputation ?? null,
    registrar: a.registrar ?? null,
    createdAt: a.creation_date ? new Date(a.creation_date * 1000).toISOString() : null,
    categories: [...new Set(Object.values(a.categories ?? {}))].slice(0, 4),
  }),
  url: (a) => ({ ...vtStats(a), finalUrl: a.last_final_url ?? null, title: a.title ?? null }),
  file: (a) => ({
    ...vtStats(a),
    name: a.meaningful_name ?? null,
    type: a.type_description ?? null,
    threatLabel: a.popular_threat_classification?.suggested_threat_label ?? null,
  }),
};

export function virustotal(kind, value, env, cache) {
  if (!env.VT_API_KEY) return { status: "not_configured" };
  return cachedLookup(cache, `vt:${kind}:${value}`, TTL.ok, async () => {
    const { status, json } = await fetchJson(`${VT}/${VT_PATHS[kind](value)}`, { headers: { "x-apikey": env.VT_API_KEY } });
    return httpOutcome(status, json, (j) => VT_PARSERS[kind](j?.data?.attributes ?? {}));
  });
}

// ---------- AbuseIPDB ----------

export function abuseipdb(ip, env, cache) {
  if (!env.ABUSEIPDB_API_KEY) return { status: "not_configured" };
  return cachedLookup(cache, `abuseipdb:${ip}`, TTL.ok, async () => {
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`;
    const { status, json } = await fetchJson(url, { headers: { Key: env.ABUSEIPDB_API_KEY } });
    return httpOutcome(status, json, (j) => {
      const d = j?.data ?? {};
      return {
        abuseScore: d.abuseConfidenceScore ?? null,
        totalReports: d.totalReports ?? 0,
        distinctReporters: d.numDistinctUsers ?? 0,
        lastReportedAt: d.lastReportedAt ?? null,
        country: d.countryCode ?? null,
        isp: d.isp ?? null,
        usageType: d.usageType ?? null,
        domain: d.domain ?? null,
        isTor: Boolean(d.isTor),
        isWhitelisted: d.isWhitelisted ?? null,
      };
    });
  });
}

// ---------- RDAP (no key needed) ----------
//
// IANA publishes which registry runs RDAP for each TLD and IP block
// ("bootstrap" files). Asking the registry directly is faster and more
// reliable than going through a redirector, and tells us when a TLD has
// no RDAP service at all (many country-code TLDs don't).

const BOOTSTRAP_TTL = 24 * 3600;
const bootstrapMemory = new Map();

async function bootstrap(kind, cache) {
  const mem = bootstrapMemory.get(kind);
  if (mem && mem.expires > Date.now()) return mem.services;
  const key = `rdap-bootstrap:${kind}`;
  let services = (await cache.get(key))?.services ?? null;
  if (!services) {
    const { status, json } = await fetchJson(`https://data.iana.org/rdap/${kind}.json`, { headers: { "user-agent": USER_AGENT } });
    if (status !== 200 || !Array.isArray(json?.services)) throw new Error(`IANA bootstrap HTTP ${status}`);
    services = json.services;
    await cache.put(key, { services }, BOOTSTRAP_TTL);
  }
  bootstrapMemory.set(kind, { services, expires: Date.now() + BOOTSTRAP_TTL * 1000 });
  return services;
}

export function rdapServerForDomain(services, domain) {
  const tld = domain.split(".").pop();
  const entry = services.find(([tlds]) => tlds.includes(tld));
  return entry ? entry[1].find((u) => u.startsWith("https://")) ?? entry[1][0] : null;
}

function ipToBits(ip) {
  if (ip.includes(":")) {
    return [...expandIPv6(ip)].map((h) => parseInt(h, 16).toString(2).padStart(4, "0")).join("");
  }
  return ip.split(".").map((o) => Number(o).toString(2).padStart(8, "0")).join("");
}

export function rdapServerForIp(services, ip) {
  const bits = ipToBits(ip);
  let best = null;
  for (const [prefixes, urls] of services) {
    for (const p of prefixes) {
      const [base, len] = p.split("/");
      if (base.includes(":") !== ip.includes(":")) continue;
      const n = Number(len);
      if (ipToBits(base).slice(0, n) === bits.slice(0, n) && (!best || n > best.n)) {
        best = { n, url: urls.find((u) => u.startsWith("https://")) ?? urls[0] };
      }
    }
  }
  return best?.url ?? null;
}

const join = (server, path) => server.replace(/\/?$/, "/") + path;

async function rdapFetch(url) {
  return fetchJson(url, { headers: { accept: "application/rdap+json, application/json", "user-agent": USER_AGENT } });
}

function vcardName(entity) {
  const fn = entity?.vcardArray?.[1]?.find?.((f) => f[0] === "fn");
  return fn ? String(fn[3]) : null;
}

function entityWithRole(entities, role) {
  for (const e of entities ?? []) {
    if (e.roles?.includes(role)) return e;
    const nested = entityWithRole(e.entities, role);
    if (nested) return nested;
  }
  return null;
}

export function rdapDomain(domain, cache, now = Date.now()) {
  return cachedLookup(cache, `rdap:domain:${domain}`, TTL.rdap, async () => {
    let server;
    try {
      server = rdapServerForDomain(await bootstrap("dns", cache), domain);
      if (!server) return { status: "unsupported" };
    } catch {
      server = "https://rdap.org/"; // IANA unreachable: fall back to the public redirector
    }
    const { status, json } = await rdapFetch(join(server, `domain/${encodeURIComponent(domain)}`));
    return httpOutcome(
      status,
      json,
      (j) => {
        const event = (name) => j?.events?.find((e) => e.eventAction === name)?.eventDate ?? null;
        const created = event("registration");
        return {
          createdAt: created,
          ageDays: created ? Math.floor((now - Date.parse(created)) / 86400000) : null,
          expiresAt: event("expiration"),
          registrar: vcardName(entityWithRole(j?.entities, "registrar")),
          status: (j?.status ?? []).slice(0, 6),
        };
      },
      { keyed: false }
    );
  });
}

export function rdapIp(ip, cache) {
  return cachedLookup(cache, `rdap:ip:${ip}`, TTL.rdap, async () => {
    let server;
    try {
      server = rdapServerForIp(await bootstrap(ip.includes(":") ? "ipv6" : "ipv4", cache), ip);
      if (!server) return { status: "unsupported" };
    } catch {
      server = "https://rdap.org/";
    }
    const { status, json } = await rdapFetch(join(server, `ip/${encodeURIComponent(ip)}`));
    return httpOutcome(
      status,
      json,
      (j) => {
        const cidr = j?.cidr0_cidrs?.[0];
        return {
          name: j?.name ?? null,
          handle: j?.handle ?? null,
          country: j?.country ?? null,
          range: cidr ? `${cidr.v4prefix ?? cidr.v6prefix}/${cidr.length}` : j?.startAddress ? `${j.startAddress} – ${j.endAddress}` : null,
          organisation: vcardName(entityWithRole(j?.entities, "registrant")),
        };
      },
      { keyed: false }
    );
  });
}

// ---------- DNS over HTTPS (Cloudflare 1.1.1.1) ----------

const DNS_TYPES = { A: 1, NS: 2, PTR: 12, MX: 15, AAAA: 28 };
const NXDOMAIN = 3;

async function dnsQuery(name, type) {
  const { status, json } = await fetchJson(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
    { headers: { accept: "application/dns-json" } }
  );
  if (status !== 200 || typeof json?.Status !== "number") throw new Error(`DNS HTTP ${status}`);
  return {
    nxdomain: json.Status === NXDOMAIN,
    answers: (json.Answer ?? []).filter((a) => a.type === DNS_TYPES[type]).map((a) => String(a.data).replace(/\.$/, "")),
  };
}

function expandIPv6(ip) {
  const [head, tail = ""] = ip.toLowerCase().split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const missing = ip.includes("::") ? 8 - h.length - t.length : 0;
  return [...h, ...Array(missing).fill("0"), ...t].map((g) => g.padStart(4, "0")).join("");
}

export function reverseName(ip) {
  if (ip.includes(":")) return [...expandIPv6(ip)].reverse().join(".") + ".ip6.arpa";
  return ip.split(".").reverse().join(".") + ".in-addr.arpa";
}

/**
 * Reverse DNS plus forward confirmation. Whoever controls an IP block can
 * set its PTR record to any name (even someone else's university domain),
 * so a PTR name only means something if that name also resolves back to
 * the same IP ("forward-confirmed reverse DNS").
 */
export function reverseDns(ip, cache) {
  return cachedLookup(cache, `ptr:${ip}`, TTL.ok, async () => {
    const ptr = await dnsQuery(reverseName(ip), "PTR");
    if (!ptr.answers.length) return { status: "not_found" };
    const name = ptr.answers[0];
    let forwardConfirmed = false;
    try {
      const fwd = await dnsQuery(name, ip.includes(":") ? "AAAA" : "A");
      const norm = (x) => (x.includes(":") ? expandIPv6(x) : x);
      forwardConfirmed = fwd.answers.some((a) => norm(a) === norm(ip));
    } catch {
      /* leave unconfirmed */
    }
    return { status: "ok", data: { names: ptr.answers, forwardConfirmed } };
  });
}

/**
 * Does the domain exist at all? A From address on a made-up TLD (".ikz") or
 * a domain that was never registered can't be a real organisation's mail.
 */
export function domainDns(domain, cache) {
  return cachedLookup(cache, `dns:${domain}`, TTL.ok, async () => {
    const tld = domain.split(".").pop();
    const tldCheck = await dnsQuery(`${tld}.`, "NS");
    if (tldCheck.nxdomain) return { status: "ok", data: { tldExists: false, domainExists: false, hasMx: false, hasAddress: false } };
    const [mx, a] = await Promise.all([dnsQuery(domain, "MX"), dnsQuery(domain, "A")]);
    return {
      status: "ok",
      data: {
        tldExists: true,
        domainExists: !(mx.nxdomain && a.nxdomain),
        hasMx: mx.answers.length > 0,
        hasAddress: a.answers.length > 0,
      },
    };
  });
}
