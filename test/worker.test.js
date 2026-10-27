import { test } from "node:test";
import assert from "node:assert/strict";
import worker from "../worker/src/index.js";

const env = { ALLOWED_ORIGINS: "chrome-extension://abcdefghijklmnopabcdefghijklmnop", VT_API_KEY: "x" };
const origin = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";

test("health reports which keys are configured, without revealing them", async () => {
  const res = await worker.fetch(new Request("http://w/health", { headers: { origin } }), env);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true, configured: { virustotal: true, abuseipdb: false, ai: false } });
  assert.equal(res.headers.get("access-control-allow-origin"), origin);
});

test("unknown origins are rejected", async () => {
  const res = await worker.fetch(new Request("http://w/health", { headers: { origin: "https://evil.example" } }), env);
  assert.equal(res.status, 403);
  assert.equal(res.headers.get("access-control-allow-origin"), null);
});

test("CORS preflight only succeeds for the configured extension", async () => {
  const ok = await worker.fetch(new Request("http://w/v1/enrich", { method: "OPTIONS", headers: { origin } }), env);
  assert.equal(ok.status, 204);
  const bad = await worker.fetch(new Request("http://w/v1/enrich", { method: "OPTIONS", headers: { origin: "chrome-extension://other" } }), env);
  assert.equal(bad.status, 403);
});

test("enrich is a placeholder until step 3", async () => {
  const res = await worker.fetch(new Request("http://w/v1/enrich", { method: "POST", headers: { origin } }), env);
  assert.equal(res.status, 501);
});
