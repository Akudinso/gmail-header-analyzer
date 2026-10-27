import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { analyseRawMessage } from "../extension/lib/analyse.js";
import { buildEnrichRequest, isEmptyRequest } from "../extension/lib/enrich-request.js";
import { validateRequest } from "../worker/src/index.js";

const load = async (name) => analyseRawMessage(new Uint8Array(readFileSync(new URL(`./fixtures/${name}`, import.meta.url))));

test("phishing email: verified IP, roles per domain, only suspicious full URLs", async () => {
  const req = buildEnrichRequest(await load("phish.eml"));
  assert.equal(req.ip, "45.33.32.156");
  assert.deepEqual(req.claimedIps, ["185.199.108.153"]);
  assert.deepEqual(req.domains[0], { domain: "paypal.com", roles: ["from", "link"] });
  assert.deepEqual(req.domains.find((d) => d.domain === "paypa1-help.net").roles, ["reply-to"]);
  assert.deepEqual(req.domains.find((d) => d.domain === "example.org").roles, ["return-path"]);
  assert.deepEqual(req.domains.find((d) => d.domain === "paypa1-secure.net").roles, ["link"]);
  // Mismatched link and IP link are sent in full; the ordinary paypal.com help link is not.
  assert.deepEqual(req.urls.sort(), ["http://198.51.100.7/track", "http://paypa1-secure.net/login?id=42&r=1"]);
  assert.equal(req.hashes.length, 1);
});

test("legit email: no full URLs leave the browser", async () => {
  const req = buildEnrichRequest(await load("legit.eml"));
  assert.deepEqual(req.urls, []);
  assert.deepEqual(req.domains, [{ domain: "bcu.ac.uk", roles: ["from", "return-path", "dkim", "link"] }]);
});

test("what the extension builds passes the Worker's validation", async () => {
  const req = buildEnrichRequest(await load("phish.eml"));
  const v = validateRequest(JSON.parse(JSON.stringify(req)));
  assert.equal(v.ip, req.ip);
  assert.equal(v.domains.length, req.domains.length);
  // The documentation-range IP link is sent, but the Worker never resolves non-public hosts as IPs.
  assert.equal(v.urls.length, req.urls.length);
  assert.equal(v.hashes.length, 1);
});

test("empty request detection", () => {
  assert.equal(isEmptyRequest({ ip: null, claimedIps: [], domains: [], urls: [], hashes: [] }), true);
});
