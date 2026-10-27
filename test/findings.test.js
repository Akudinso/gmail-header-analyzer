import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { analyseRawMessage } from "../extension/lib/analyse.js";
import { assessReport, buildFindings, GROUPS, scoreFindings } from "../extension/lib/findings.js";

const load = async (name, enrichment) => {
  const r = await analyseRawMessage(new Uint8Array(readFileSync(new URL(`./fixtures/${name}`, import.meta.url))));
  if (enrichment) r.enrichment = enrichment;
  return r;
};
const ids = (a) => a.findings.map((f) => f.id.split(":")[0]);
const ok = (data) => ({ status: "ok", data });

// Lookup results shaped like what the Worker returned for Kay's real phishing email.
const kayLookups = {
  status: "ok",
  results: {
    ip: {
      value: "45.33.32.156",
      abuseipdb: ok({ abuseScore: 0, totalReports: 0, isTor: false }),
      virustotal: ok({ malicious: 0, suspicious: 0, harmless: 62, undetected: 30 }),
      reverseDns: ok({ names: ["host.unrelated-university.edu"], forwardConfirmed: false }),
    },
    domains: [
      { domain: "adewo.ikz", roles: ["from"], dns: ok({ tldExists: false, domainExists: false }) },
      { domain: "example-invest.my.id", roles: ["return-path", "dkim"], dns: ok({ tldExists: true, domainExists: true }), rdap: ok({ ageDays: 61 }), virustotal: ok({ malicious: 0, suspicious: 0, harmless: 60, undetected: 32 }) },
    ],
    urls: [{ url: "https://storage.googleapis.com/x", virustotal: { status: "not_found" } }],
    hashes: [],
  },
};

test("Kay's real phishing email scores High risk, with every point traceable", async () => {
  const a = assessReport(await load("forged-helo.eml", kayLookups));
  assert.equal(a.level, "high");
  assert.equal(a.score, 100);
  assert.equal(a.provisional, false);
  assert.deepEqual(ids(a).slice(0, 3), ["fake_tld", "forged_hops", "helo_mismatch"]);
  // Points only come from findings; the sum of awarded points (capped) is the score.
  assert.equal(Math.min(100, a.findings.reduce((s, f) => s + f.awarded, 0)), a.score);
  // Infrastructure has 30 + 20 + 5 = 55 points but is capped at 40.
  const infra = a.groups.find((g) => g.id === "infrastructure");
  assert.equal(infra.points, 40);
  assert.equal(a.findings.find((f) => f.id === "ptr_unconfirmed").awarded, 0);
});

test("even without lookups, the same email is already High risk from headers alone", async () => {
  const a = assessReport(await load("forged-helo.eml"));
  assert.equal(a.provisional, true);
  assert.equal(a.level, "high");
  assert.ok(!ids(a).includes("fake_tld"), "the fake TLD needs the DNS lookup");
});

test("the classic PayPal phish scores High risk", async () => {
  const a = assessReport(await load("phish.eml"));
  assert.equal(a.level, "high");
  for (const id of ["dmarc_fail", "spf_fail", "no_dkim", "reply_to_differs", "link_text_mismatch", "ip_links", "double_ext"]) {
    assert.ok(ids(a).includes(id), id);
  }
  // DMARC fail (30) + SPF (10) + no DKIM (10) = 50, capped at 35: one root cause isn't counted three times.
  assert.equal(a.groups.find((g) => g.id === "authentication").points, 35);
});

test("a legitimate university email scores 0", async () => {
  const a = assessReport(await load("legit.eml", {
    status: "ok",
    results: { ip: { value: "147.188.192.20", abuseipdb: ok({ abuseScore: 0, totalReports: 0 }), reverseDns: ok({ names: ["mail-out.bcu.ac.uk"], forwardConfirmed: true }) }, domains: [{ domain: "bcu.ac.uk", roles: ["from"], dns: ok({ tldExists: true, domainExists: true }), rdap: ok({ ageDays: 9000 }) }], urls: [], hashes: [] },
  }));
  assert.equal(a.score, 0);
  assert.equal(a.level, "low");
  assert.deepEqual(a.findings, []);
});

test("a typical newsletter (bounce domain differs) stays Low risk", async () => {
  const raw = readFileSync(new URL("./fixtures/legit.eml", import.meta.url), "utf8")
    .replace("Return-Path: <noreply@news.bcu.ac.uk>", "Return-Path: <bounce-123@mail.sendgrid.net>");
  const a = assessReport(await analyseRawMessage(new TextEncoder().encode(raw)));
  assert.deepEqual(ids(a), ["return_path_differs"]);
  assert.equal(a.score, 5);
  assert.equal(a.level, "low");
});

test("decisive findings reach High risk alone, and say so", () => {
  const a = scoreFindings([{ id: "fake_tld", group: "identity", points: 45, text: "fake", decisive: true }]);
  assert.equal(a.score, 60);
  assert.equal(a.level, "high");
  assert.deepEqual(a.floor, { sum: 45, minimum: 60, because: "fake" });
  const b = scoreFindings([{ id: "reply_to_differs", group: "identity", points: 45, text: "x" }]);
  assert.equal(b.level, "suspicious", "the same points without a decisive finding stay Suspicious");
  assert.equal(b.floor, null);
});

test("a fake From domain alone is High risk", async () => {
  const r = await load("legit.eml", { status: "ok", results: { domains: [{ domain: "bcu.ac.uk", roles: ["from"], dns: ok({ tldExists: false }) }], urls: [], hashes: [] } });
  assert.equal(assessReport(r).level, "high");
});

test("findings are deterministic and every group has a cap", async () => {
  const r = await load("forged-helo.eml", kayLookups);
  assert.deepEqual(buildFindings(r), buildFindings(r));
  for (const f of buildFindings(r)) assert.ok(GROUPS[f.group], f.id);
});

test("level boundaries", () => {
  const one = (points) => scoreFindings([{ id: "x", group: "attachments", points, text: "" }]).level;
  assert.equal(one(24), "low");
  assert.equal(one(25), "suspicious");
  assert.equal(one(59), "suspicious");
  assert.equal(one(60), "high");
});
