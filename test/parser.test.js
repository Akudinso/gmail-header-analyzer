import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { analyseRawMessage } from "../extension/lib/analyse.js";
import { base64ToBytes, decodeEncodedWords } from "../extension/lib/encoding.js";
import { parseHeaderBlock } from "../extension/lib/mime.js";
import { parseAddress, parseAuthResults, parseReceived } from "../extension/lib/headers.js";
import { isNonPublicIp, registrableDomain } from "../extension/lib/netutil.js";

const fixture = (name) => new Uint8Array(readFileSync(new URL(`./fixtures/${name}`, import.meta.url)));
const toBytes = (s) => new TextEncoder().encode(s);

test("base64url decoding matches what the Gmail API returns", () => {
  const text = "Subject: hi?>\r\n";
  const b64url = Buffer.from(text).toString("base64url");
  assert.equal(new TextDecoder().decode(base64ToBytes(b64url)), text);
});

test("RFC 2047 encoded words, including adjacent words", () => {
  assert.equal(decodeEncodedWords("=?UTF-8?B?V2Vla2x5IG5ld3Mg4pyT?="), "Weekly news ✓");
  assert.equal(decodeEncodedWords("=?UTF-8?Q?Caf=C3=A9_Team?= <a@b.c>"), "Café Team <a@b.c>");
  assert.equal(decodeEncodedWords("=?UTF-8?B?QQ==?= =?UTF-8?B?Qg==?="), "AB");
});

test("header unfolding keeps order and joins continuation lines", () => {
  const h = parseHeaderBlock("Received: from a\r\n\tby b; date\r\nReceived: from c\r\n by d");
  assert.deepEqual(h.map((x) => x.value), ["from a by b; date", "from c by d"]);
});

test("non-public IP ranges are recognised", () => {
  for (const ip of ["10.1.2.3", "192.168.1.10", "172.20.0.1", "127.0.0.1", "100.64.1.1", "203.0.113.9", "::1", "fe80::1", "fd00::5"]) {
    assert.equal(isNonPublicIp(ip), true, ip);
  }
  for (const ip of ["45.33.32.156", "8.8.8.8", "172.32.0.1", "2a00:1450:4009::1"]) {
    assert.equal(isNonPublicIp(ip), false, ip);
  }
});

test("registrable domain handles multi-label suffixes", () => {
  assert.equal(registrableDomain("mail.news.bcu.ac.uk"), "bcu.ac.uk");
  assert.equal(registrableDomain("www.paypal.com"), "paypal.com");
  assert.equal(registrableDomain("shop.example.com.ng"), "example.com.ng");
});

test("Received header parsing", () => {
  const hop = parseReceived(
    "from mail.x.com (mail.x.com. [45.33.32.156]) by mx.google.com with ESMTPS id abc for <a@b.com>; Tue, 27 Oct 2026 02:15:08 -0700 (PDT)"
  );
  assert.equal(hop.fromHost, "mail.x.com");
  assert.equal(hop.reverseDns, "mail.x.com");
  assert.equal(hop.by, "mx.google.com");
  assert.equal(hop.with, "ESMTPS");
  assert.deepEqual(hop.publicIps, ["45.33.32.156"]);
  assert.equal(hop.timestamp, Date.parse("Tue, 27 Oct 2026 02:15:08 -0700"));
});

test("Received header with IPv6", () => {
  const hop = parseReceived("from host (host [IPv6:2a00:1450:4864:20::62f]) by mx.google.com with SMTP; Mon, 1 Jan 2026 00:00:00 +0000");
  assert.deepEqual(hop.publicIps, ["2a00:1450:4864:20::62f"]);
});

test("Authentication-Results parsing", () => {
  const ar = parseAuthResults(
    "mx.google.com; dkim=pass header.i=@x.com header.s=s1; spf=fail smtp.mailfrom=a@y.com; dmarc=fail (p=REJECT sp=NONE dis=QUARANTINE) header.from=x.com"
  );
  assert.equal(ar.authservId, "mx.google.com");
  assert.deepEqual(ar.results.map((r) => `${r.method}=${r.result}`), ["dkim=pass", "spf=fail", "dmarc=fail"]);
  assert.equal(ar.results[2].props.p, "REJECT");
  assert.equal(ar.results[0].props["header.i"], "@x.com");
});

test("address parsing with display names", () => {
  assert.deepEqual(
    { ...parseAddress('"PayPal Service" <service@paypal.com>'), raw: undefined },
    { name: "PayPal Service", email: "service@paypal.com", domain: "paypal.com", raw: undefined }
  );
  assert.equal(parseAddress("bare@Example.COM").domain, "example.com");
});

test("phishing fixture: full analysis", async () => {
  const r = await analyseRawMessage(fixture("phish.eml"), { messageId: "abc" });

  assert.equal(r.summary.subject, "Action required: your account is on höld");
  assert.equal(r.summary.from.email, "service@paypal.com");

  // Trust only Google's Authentication-Results, not the forged one further down.
  assert.equal(r.auth.trustedSource, "mx.google.com");
  assert.equal(r.auth.spf.result, "softfail");
  assert.equal(r.auth.dmarc.result, "fail");
  assert.equal(r.auth.dmarc.policy, "reject");
  assert.equal(r.auth.dkim, null);

  // Sender IP: the IP that connected to Google is verified; others are claims.
  assert.equal(r.senderIp.verified.ip, "45.33.32.156");
  assert.match(r.senderIp.verified.source, /confirmed by Google's Received-SPF/);
  assert.ok(r.senderIp.claimed.some((c) => c.ip === "185.199.108.153"));
  assert.equal(r.senderIp.sentViaGoogle, false);

  // Hops are oldest-first and the private submission IP is not treated as public.
  assert.equal(r.hops[0].by, "mail.paypa1-secure.net");
  assert.deepEqual(r.hops[0].publicIps, []);

  assert.equal(r.checks.replyToDiffers, true);
  assert.equal(r.checks.returnPathDiffers, true);
  assert.equal(r.checks.linkTextMismatches, 1, "link text says paypal.com but goes to paypa1-secure.net");
  assert.equal(r.checks.ipLinks, 1);

  const mismatched = r.urls.find((u) => u.textMismatch);
  assert.equal(mismatched.host, "paypa1-secure.net");
  assert.equal(mismatched.url, "http://paypa1-secure.net/login?id=42&r=1");

  // "www.paypal.com" text pointing to paypal.com is NOT a mismatch.
  assert.equal(r.urls.find((u) => u.host === "www.paypal.com").textMismatch, false);

  assert.equal(r.attachments.length, 1);
  const att = r.attachments[0];
  assert.equal(att.filename, "invoice.pdf.exe");
  assert.deepEqual(att.flags, ["risky-extension", "double-extension"]);
  const expected = createHash("sha256").update(Buffer.from("SGVsbG8sIHRoaXMgaXMgbm90IHJlYWxseSBtYWx3YXJlLg==", "base64")).digest("hex");
  assert.equal(att.sha256, expected);

  assert.ok(r.indicators.ips.includes("45.33.32.156"));
  assert.ok(r.indicators.domains.includes("paypa1-secure.net"));
  assert.ok(r.indicators.domains.includes("paypa1-help.net"));
  assert.ok(r.indicators.hashes.includes(expected));

  // Report must be JSON-safe so it can live in chrome.storage.
  assert.doesNotThrow(() => JSON.parse(JSON.stringify(r)));
});

test("legit fixture: clean signals, UTF-8 names, CRLF-insensitive", async () => {
  const lf = readFileSync(new URL("./fixtures/legit.eml", import.meta.url), "utf8");
  for (const raw of [lf, lf.replace(/\n/g, "\r\n")]) {
    const r = await analyseRawMessage(toBytes(raw));
    assert.equal(r.summary.subject, "Weekly news ✓");
    assert.equal(r.summary.from.name, "Café Team");
    assert.equal(r.auth.dkim.result, "pass");
    assert.equal(r.auth.dkim.domain, "bcu.ac.uk");
    assert.equal(r.auth.spf.result, "pass");
    assert.equal(r.auth.dmarc.result, "pass");
    assert.equal(r.senderIp.verified.ip, "147.188.192.20");
    assert.equal(r.checks.replyToDiffers, false);
    assert.equal(r.checks.returnPathDiffers, false, "news.bcu.ac.uk aligns with bcu.ac.uk");
    assert.equal(r.checks.dkimNotAligned, false);
    assert.equal(r.checks.linkTextMismatches, 0);
    assert.deepEqual(r.urls.map((u) => u.url), ["https://www.bcu.ac.uk/library"]);
    assert.equal(r.attachments.length, 0);
  }
});

test("a forged 'by mx.google.com' hop below the real one is ignored", async () => {
  const raw = readFileSync(new URL("./fixtures/legit.eml", import.meta.url), "utf8").replace(
    "From: ",
    "Received: from fake (fake [8.8.4.4]) by mx.google.com with SMTP; Mon, 26 Oct 2026 07:00:00 -0700\nFrom: "
  );
  const r = await analyseRawMessage(toBytes(raw));
  assert.equal(r.senderIp.verified.ip, "147.188.192.20");
  assert.ok(r.senderIp.claimed.some((c) => c.ip === "8.8.4.4"), "forged hop still visible as an unverified claim");
});

test("email with no Google hop reports no verified IP", async () => {
  const raw = "Received: from a (a [45.33.32.156]) by relay.example.org; Mon, 26 Oct 2026 07:00:00 +0000\nFrom: x@y.com\nSubject: t\n\nbody";
  const r = await analyseRawMessage(toBytes(raw));
  assert.equal(r.senderIp.verified, null);
  assert.equal(r.senderIp.claimed[0].ip, "45.33.32.156");
  assert.equal(r.auth.trustedSource, null);
});

test("hostile input stays bounded", async () => {
  let nested = "Content-Type: text/plain\n\ndeep";
  for (let i = 0; i < 50; i++) {
    nested = `Content-Type: multipart/mixed; boundary="b${i}"\n\n--b${i}\n${nested}\n--b${i}--`;
  }
  const r = await analyseRawMessage(toBytes(`From: a@b.c\n${nested}`));
  assert.ok(r); // no stack overflow / hang
});
