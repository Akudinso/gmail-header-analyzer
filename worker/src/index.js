// Cloudflare Worker backend. It holds the API keys (VirusTotal, AbuseIPDB,
// Gemini) so they never ship inside the extension.
//
// Endpoints:
//   GET  /health      -> which keys are configured (booleans only)
//   POST /v1/enrich   -> reputation, ownership and age for an email's indicators
//   POST /v1/summarise -> AI explanation of the (fixed) risk assessment, via Gemini
//
// Access control (both required):
//   1. Origin must be in ALLOWED_ORIGINS (your extension: chrome-extension://<id>)
//   2. Authorization: Bearer <WORKER_KEY> — a random key `npm run setup` creates
//      and shares between the extension and this Worker.
// The extension never sends its Gmail token here: this Worker only needs to know
// the caller is you, not to read your mail.

import { createCache } from "./cache.js";
import { summarise, validateSummaryRequest } from "./summary.js";
import { abuseipdb, domainDns, rdapDomain, rdapIp, reverseDns, virustotal } from "./lookups.js";
import { isIPv4, isIPv6, isNonPublicIp } from "../../extension/lib/netutil.js";

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };
const MAX_BODY_BYTES = 32 * 1024;
const LIMITS = { claimedIps: 3, domains: 10, urls: 5, hashes: 5 };
const DEFAULT_VT_BUDGET = 4; // VirusTotal's free tier allows 4 requests a minute

function allowedOrigins(env) {
  return String(env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function corsHeaders(request, env) {
  const origin = request.headers.get("origin");
  if (!origin || !allowedOrigins(env).includes(origin)) return {};
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "content-type, authorization",
    "access-control-max-age": "86400",
    vary: "origin",
  };
}

function json(body, status, request, env) {
  return new Response(JSON.stringify(body), { status, headers: { ...JSON_HEADERS, ...corsHeaders(request, env) } });
}

async function digest(s) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
}

/** Constant-time comparison (compares hashes so length differences don't leak). */
async function keysMatch(given, expected) {
  const [a, b] = await Promise.all([digest(given), digest(expected)]);
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ---------- input validation ----------

const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;
const SHA256 = /^[a-f0-9]{64}$/;
const ROLES = new Set(["from", "reply-to", "return-path", "sender", "dkim", "link"]);

const publicIp = (v) => typeof v === "string" && (isIPv4(v) || isIPv6(v)) && !isNonPublicIp(v);

function cleanUrl(v) {
  if (typeof v !== "string" || v.length > 2048) return null;
  try {
    const u = new URL(v);
    return u.protocol === "http:" || u.protocol === "https:" ? u.href : null;
  } catch {
    return null;
  }
}

export function validateRequest(body) {
  if (!body || typeof body !== "object") return null;
  const uniq = (arr) => [...new Set(arr)];
  const domains = [];
  for (const d of Array.isArray(body.domains) ? body.domains : []) {
    const name = String(d?.domain ?? "").toLowerCase();
    if (!DOMAIN.test(name) || domains.some((x) => x.domain === name)) continue;
    const roles = (Array.isArray(d.roles) ? d.roles : []).filter((r) => ROLES.has(r));
    domains.push({ domain: name, roles: roles.length ? uniq(roles) : ["link"] });
  }
  return {
    ip: publicIp(body.ip) ? body.ip.toLowerCase() : null,
    claimedIps: uniq((Array.isArray(body.claimedIps) ? body.claimedIps : []).filter(publicIp)).filter((ip) => ip !== body.ip).slice(0, LIMITS.claimedIps),
    domains: domains.slice(0, LIMITS.domains),
    urls: uniq((Array.isArray(body.urls) ? body.urls : []).map(cleanUrl).filter(Boolean)).slice(0, LIMITS.urls),
    hashes: uniq((Array.isArray(body.hashes) ? body.hashes : []).map((h) => String(h).toLowerCase()).filter((h) => SHA256.test(h))).slice(0, LIMITS.hashes),
  };
}

// ---------- enrichment ----------

/**
 * VirusTotal's free tier is the bottleneck, so it gets a per-request budget
 * spent in order of investigative value. Everything else is still looked up
 * by the free/keyless sources and marked "skipped" for VirusTotal.
 */
export function planVirusTotal(req, budget) {
  const queue = [];
  if (req.ip) queue.push({ kind: "ip", value: req.ip });
  for (const d of req.domains.filter((d) => d.roles.includes("from"))) queue.push({ kind: "domain", value: d.domain });
  for (const h of req.hashes) queue.push({ kind: "file", value: h });
  for (const u of req.urls) queue.push({ kind: "url", value: u });
  for (const d of req.domains.filter((d) => !d.roles.includes("from") && d.roles.some((r) => r !== "link"))) queue.push({ kind: "domain", value: d.domain });
  for (const d of req.domains.filter((d) => d.roles.every((r) => r === "link"))) queue.push({ kind: "domain", value: d.domain });
  return { run: queue.slice(0, budget), skipped: queue.slice(budget) };
}

export async function enrich(req, env) {
  const cache = createCache(env);
  const budget = Math.max(0, Number(env.VT_MAX_LOOKUPS ?? DEFAULT_VT_BUDGET) || 0);
  const vtResults = new Map();
  const vtKey = (kind, value) => `${kind}:${value}`;
  // Cached VirusTotal answers are free, so serve those first and spend the
  // budget only on indicators VirusTotal hasn't been asked about recently.
  // DNS first (free and fast): a domain on a TLD that doesn't exist is fake,
  // so it isn't worth a VirusTotal lookup or an RDAP query.
  const dns = new Map(await Promise.all(req.domains.map(async (d) => [d.domain, await domainDns(d.domain, cache)])));
  const fakeTld = (domain) => dns.get(domain)?.data?.tldExists === false;
  const all = env.VT_API_KEY ? planVirusTotal(req, Infinity).run.filter((t) => !(t.kind === "domain" && fakeTld(t.value))) : [];
  const uncached = [];
  for (const t of all) {
    const hit = env.VT_API_KEY ? await cache.get(`vt:${t.kind}:${t.value}`) : null;
    if (hit) vtResults.set(vtKey(t.kind, t.value), { ...hit, cached: true });
    else uncached.push(t);
  }
  const plan = { run: uncached.slice(0, budget), skipped: uncached.slice(budget) };
  await Promise.all(plan.run.map(async (t) => vtResults.set(vtKey(t.kind, t.value), await virustotal(t.kind, t.value, env, cache))));
  const vt = (kind, value) => vtResults.get(vtKey(kind, value)) ?? (env.VT_API_KEY ? { status: "skipped" } : { status: "not_configured" });

  const [ip, claimedIps, domains] = await Promise.all([
    req.ip
      ? Promise.all([abuseipdb(req.ip, env, cache), rdapIp(req.ip, cache), reverseDns(req.ip, cache)]).then(([a, r, p]) => ({
          value: req.ip,
          abuseipdb: a,
          virustotal: vt("ip", req.ip),
          rdap: r,
          reverseDns: p,
        }))
      : null,
    Promise.all(req.claimedIps.map(async (value) => ({ value, abuseipdb: await abuseipdb(value, env, cache) }))),
    Promise.all(
      req.domains.map(async (d) =>
        fakeTld(d.domain)
          ? { ...d, dns: dns.get(d.domain), rdap: { status: "not_applicable" }, virustotal: { status: "not_applicable" } }
          : { ...d, dns: dns.get(d.domain), rdap: await rdapDomain(d.domain, cache), virustotal: vt("domain", d.domain) }
      )
    ),
  ]);

  return {
    ip,
    claimedIps,
    domains,
    urls: req.urls.map((url) => ({ url, virustotal: vt("url", url) })),
    hashes: req.hashes.map((sha256) => ({ sha256, virustotal: vt("file", sha256) })),
    limits: { virustotalBudget: budget, virustotalUsed: plan.run.length, virustotalSkipped: env.VT_API_KEY ? plan.skipped.length : 0 },
  };
}

// ---------- routing ----------

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      const cors = corsHeaders(request, env);
      return new Response(null, { status: Object.keys(cors).length ? 204 : 403, headers: cors });
    }

    // Browsers send Origin on cross-origin requests; reject unknown extensions/sites.
    const origin = request.headers.get("origin");
    if (origin && !allowedOrigins(env).includes(origin)) {
      return json({ error: "origin not allowed" }, 403, request, env);
    }

    if (url.pathname === "/health" && request.method === "GET") {
      return json(
        {
          ok: true,
          configured: {
            workerKey: Boolean(env.WORKER_KEY),
            virustotal: Boolean(env.VT_API_KEY),
            abuseipdb: Boolean(env.ABUSEIPDB_API_KEY),
            gemini: Boolean(env.GEMINI_API_KEY),
            sharedCache: Boolean(env.LOOKUP_CACHE),
          },
        },
        200,
        request,
        env
      );
    }

    const routes = {
      "/v1/enrich": { validate: validateRequest, run: enrich },
      "/v1/summarise": { validate: validateSummaryRequest, run: summarise },
    };
    const route = request.method === "POST" ? routes[url.pathname] : null;
    if (route) {
      if (!env.WORKER_KEY) return json({ error: "WORKER_KEY is not set on the Worker" }, 503, request, env);
      const auth = request.headers.get("authorization") ?? "";
      const given = auth.startsWith("Bearer ") ? auth.slice(7) : "";
      if (!given || !(await keysMatch(given, env.WORKER_KEY))) return json({ error: "unauthorised" }, 401, request, env);

      const text = await request.text();
      if (text.length > MAX_BODY_BYTES) return json({ error: "request too large" }, 413, request, env);
      let body;
      try {
        body = JSON.parse(text);
      } catch {
        return json({ error: "invalid JSON" }, 400, request, env);
      }
      const req = route.validate(body);
      if (!req) return json({ error: "invalid request" }, 400, request, env);
      return json(await route.run(req, env), 200, request, env);
    }

    return json({ error: "not found" }, 404, request, env);
  },
};
