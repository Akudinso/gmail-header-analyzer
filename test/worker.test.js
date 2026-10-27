import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import worker, { planVirusTotal, validateRequest } from "../worker/src/index.js";
import { _clearMemoryCache } from "../worker/src/cache.js";
import { reverseName, vtUrlId } from "../worker/src/lookups.js";

const origin = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";
const KEY = "test-worker-key-123";
const baseEnv = { ALLOWED_ORIGINS: origin, WORKER_KEY: KEY, VT_API_KEY: "vt", ABUSEIPDB_API_KEY: "ab" };

// ---------- fake upstream APIs ----------
let calls = [];
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

function fakeUpstream(url, init) {
  const u = new URL(url);
  calls.push({ host: u.host, path: u.pathname + u.search, headers: init?.headers ?? {} });
  if (u.host === "api.abuseipdb.com") {
    return json({ data: { abuseConfidenceScore: 87, totalReports: 41, numDistinctUsers: 12, countryCode: "US", isp: "Linode", usageType: "Data Center/Web Hosting/Transit", isTor: false } });
  }
  if (u.host === "www.virustotal.com") {
    if (u.pathname.startsWith("/api/v3/files/")) return json({ error: { code: "NotFoundError" } }, 404);
    if (u.pathname.startsWith("/api/v3/ip_addresses/")) return json({ data: { attributes: { last_analysis_stats: { malicious: 3, suspicious: 1, harmless: 60, undetected: 20 }, asn: 63949, as_owner: "Akamai Connected Cloud", country: "US" } } });
    return json({ data: { attributes: { last_analysis_stats: { malicious: 5, suspicious: 0, harmless: 50, undetected: 30 }, creation_date: 1792800000 } } });
  }
  if (u.host === "rdap.org") {
    if (u.pathname.startsWith("/ip/")) return json({ name: "LINODE-US", handle: "NET-45-33-0-0-1", country: "US", cidr0_cidrs: [{ v4prefix: "45.33.0.0", length: 17 }], entities: [{ roles: ["registrant"], vcardArray: ["vcard", [["fn", {}, "text", "Akamai Technologies, Inc."]]] }] });
    return json({
      events: [{ eventAction: "registration", eventDate: "2026-10-20T00:00:00Z" }, { eventAction: "expiration", eventDate: "2027-10-20T00:00:00Z" }],
      entities: [{ roles: ["registrar"], vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "NameCheap, Inc."]]] }],
      status: ["client transfer prohibited"],
    });
  }
  if (u.host === "cloudflare-dns.com") return json({ Status: 0, Answer: [{ name: "x", type: 12, data: "li982-156.members.linode.com." }] });
  throw new Error(`unexpected upstream ${u.host}`);
}

beforeEach(() => {
  calls = [];
  _clearMemoryCache();
  globalThis.fetch = async (url, init) => fakeUpstream(url, init);
});

const enrichRequest = (body, { key = KEY, from = origin } = {}) =>
  new Request("http://w/v1/enrich", {
    method: "POST",
    headers: { origin: from, authorization: `Bearer ${key}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });

const sample = {
  ip: "45.33.32.156",
  claimedIps: ["185.199.108.153", "192.168.1.10"],
  domains: [
    { domain: "paypal.com", roles: ["from"] },
    { domain: "paypa1-help.net", roles: ["reply-to"] },
    { domain: "paypa1-secure.net", roles: ["link"] },
  ],
  urls: ["http://paypa1-secure.net/login?id=42"],
  hashes: ["a".repeat(64)],
};

// ---------- access control ----------

test("health reports which keys are configured, without revealing them", async () => {
  const res = await worker.fetch(new Request("http://w/health", { headers: { origin } }), { ...baseEnv, ABUSEIPDB_API_KEY: "" });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.deepEqual(body.configured, { workerKey: true, virustotal: true, abuseipdb: false, ai: false, sharedCache: false });
  assert.ok(!JSON.stringify(body).includes(KEY));
  assert.equal(res.headers.get("access-control-allow-origin"), origin);
});

test("unknown origins are rejected", async () => {
  const res = await worker.fetch(enrichRequest(sample, { from: "https://evil.example" }), baseEnv);
  assert.equal(res.status, 403);
  assert.equal(calls.length, 0);
});

test("CORS preflight only succeeds for the configured extension", async () => {
  const ok = await worker.fetch(new Request("http://w/v1/enrich", { method: "OPTIONS", headers: { origin } }), baseEnv);
  assert.equal(ok.status, 204);
  const bad = await worker.fetch(new Request("http://w/v1/enrich", { method: "OPTIONS", headers: { origin: "chrome-extension://other" } }), baseEnv);
  assert.equal(bad.status, 403);
});

test("wrong or missing key is refused before any lookup", async () => {
  assert.equal((await worker.fetch(enrichRequest(sample, { key: "wrong" }), baseEnv)).status, 401);
  assert.equal((await worker.fetch(enrichRequest(sample, { key: "" }), baseEnv)).status, 401);
  assert.equal((await worker.fetch(enrichRequest(sample), { ...baseEnv, WORKER_KEY: "" })).status, 503, "fails closed when unconfigured");
  assert.equal(calls.length, 0);
});

test("oversized and malformed bodies are rejected", async () => {
  const big = { domains: Array.from({ length: 2000 }, (_, i) => ({ domain: `d${i}.example.com` })) };
  assert.equal((await worker.fetch(enrichRequest(big), baseEnv)).status, 413);
  const bad = new Request("http://w/v1/enrich", { method: "POST", headers: { origin, authorization: `Bearer ${KEY}` }, body: "{not json" });
  assert.equal((await worker.fetch(bad, baseEnv)).status, 400);
});

// ---------- validation ----------

test("validation drops anything that isn't a clean indicator", () => {
  const v = validateRequest({
    ip: "10.0.0.1",
    claimedIps: ["8.8.8.8", "8.8.8.8", "not-an-ip", "127.0.0.1"],
    domains: [{ domain: "Example.COM", roles: ["from", "admin"] }, { domain: "../etc/passwd" }, { domain: "x" }, { domain: "example.com" }],
    urls: ["javascript:alert(1)", "https://ok.example/a", "file:///etc/passwd"],
    hashes: ["A".repeat(64), "zz", "a".repeat(64)],
  });
  assert.equal(v.ip, null, "private IPs are never looked up");
  assert.deepEqual(v.claimedIps, ["8.8.8.8"]);
  assert.deepEqual(v.domains, [{ domain: "example.com", roles: ["from"] }]);
  assert.deepEqual(v.urls, ["https://ok.example/a"]);
  assert.deepEqual(v.hashes, ["a".repeat(64)]);
});

test("VirusTotal budget goes to the highest-value indicators first", () => {
  const req = validateRequest(sample);
  const plan = planVirusTotal(req, 4);
  assert.deepEqual(plan.run.map((t) => `${t.kind}:${t.value}`), [
    "ip:45.33.32.156",
    "domain:paypal.com",
    `file:${"a".repeat(64)}`,
    "url:http://paypa1-secure.net/login?id=42",
  ]);
  assert.deepEqual(plan.skipped.map((t) => t.value), ["paypa1-help.net", "paypa1-secure.net"]);
});

// ---------- enrichment ----------

test("enrich combines all sources", async () => {
  const res = await worker.fetch(enrichRequest(sample), baseEnv);
  assert.equal(res.status, 200);
  const r = await res.json();

  assert.equal(r.ip.value, "45.33.32.156");
  assert.equal(r.ip.abuseipdb.data.abuseScore, 87);
  assert.equal(r.ip.virustotal.data.malicious, 3);
  assert.equal(r.ip.virustotal.data.asn, 63949);
  assert.equal(r.ip.rdap.data.range, "45.33.0.0/17");
  assert.equal(r.ip.rdap.data.organisation, "Akamai Technologies, Inc.");
  assert.deepEqual(r.ip.reverseDns.data.names, ["li982-156.members.linode.com"]);

  assert.deepEqual(r.claimedIps.map((c) => c.value), ["185.199.108.153"], "private claimed IP dropped");

  const reply = r.domains.find((d) => d.domain === "paypa1-help.net");
  assert.equal(reply.rdap.data.registrar, "NameCheap, Inc.");
  assert.equal(reply.rdap.data.createdAt, "2026-10-20T00:00:00Z");
  assert.equal(typeof reply.rdap.data.ageDays, "number");
  assert.equal(reply.virustotal.status, "skipped", "over the VirusTotal budget");

  assert.equal(r.urls[0].virustotal.data.malicious, 5);
  assert.equal(r.hashes[0].virustotal.status, "not_found");
  assert.deepEqual(r.limits, { virustotalBudget: 4, virustotalUsed: 4, virustotalSkipped: 2 });

  const vtCalls = calls.filter((c) => c.host === "www.virustotal.com");
  assert.equal(vtCalls.length, 4);
  assert.ok(vtCalls.every((c) => c.headers["x-apikey"] === "vt"));
  assert.ok(calls.find((c) => c.host === "api.abuseipdb.com").headers.Key === "ab");
});

test("repeat lookups come from the cache, and cached hits don't use the VirusTotal budget", async () => {
  await worker.fetch(enrichRequest(sample), baseEnv);
  const first = calls.length;
  const r = await (await worker.fetch(enrichRequest(sample), baseEnv)).json();
  const newCalls = calls.slice(first);
  assert.equal(r.ip.abuseipdb.cached, true);
  assert.equal(r.ip.virustotal.cached, true);
  // The 4 cached VirusTotal answers were free, so the 2 domains skipped last time get looked up now.
  assert.deepEqual(newCalls.map((c) => c.host), ["www.virustotal.com", "www.virustotal.com"]);
  assert.equal(r.domains.find((d) => d.domain === "paypa1-help.net").virustotal.status, "ok");
  assert.equal(r.limits.virustotalSkipped, 0);

  const third = calls.length;
  await worker.fetch(enrichRequest(sample), baseEnv);
  assert.equal(calls.length, third, "fully cached: no upstream calls at all");
});

test("missing API keys degrade gracefully", async () => {
  const r = await (await worker.fetch(enrichRequest(sample), { ...baseEnv, VT_API_KEY: "", ABUSEIPDB_API_KEY: "" })).json();
  assert.equal(r.ip.abuseipdb.status, "not_configured");
  assert.equal(r.ip.virustotal.status, "not_configured");
  assert.equal(r.domains[0].virustotal.status, "not_configured");
  assert.equal(r.ip.rdap.status, "ok", "keyless sources still work");
  assert.deepEqual(r.limits, { virustotalBudget: 4, virustotalUsed: 0, virustotalSkipped: 0 });
});

test("upstream rate limits and outages are reported, not thrown", async () => {
  globalThis.fetch = async (url) => {
    const u = new URL(url);
    if (u.host === "www.virustotal.com") return json({}, 429);
    if (u.host === "api.abuseipdb.com") throw new Error("network down");
    return fakeUpstream(url);
  };
  const r = await (await worker.fetch(enrichRequest(sample), baseEnv)).json();
  assert.equal(r.ip.virustotal.status, "rate_limited");
  assert.equal(r.ip.abuseipdb.status, "error");
});

// ---------- helpers ----------

test("VirusTotal URL ids and reverse DNS names", () => {
  assert.equal(vtUrlId("http://example.com/"), "aHR0cDovL2V4YW1wbGUuY29tLw");
  assert.equal(reverseName("45.33.32.156"), "156.32.33.45.in-addr.arpa");
  assert.equal(reverseName("2001:4860::8888"), "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.1.0.0.2.ip6.arpa");
});
