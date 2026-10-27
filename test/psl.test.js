import { test } from "node:test";
import assert from "node:assert/strict";
import { organisationalDomain, publicSuffix, registeredDomain } from "../extension/lib/psl.js";
import { lookupDomain, registrableDomain, sameOrg } from "../extension/lib/netutil.js";

test("Public Suffix List: official test vectors", () => {
  // From https://raw.githubusercontent.com/publicsuffix/list/main/tests/test_psl.txt
  const cases = [
    ["com", null], ["example.com", "example.com"], ["www.example.com", "example.com"],
    ["uk.com", null], ["example.uk.com", "example.uk.com"],
    ["ck", null], ["test.ck", null], ["b.test.ck", "b.test.ck"], ["www.ck", "www.ck"], ["www.www.ck", "www.ck"],
    ["jp", null], ["test.jp", "test.jp"], ["ac.jp", null], ["test.ac.jp", "test.ac.jp"],
    ["kyoto.jp", null], ["test.kyoto.jp", "test.kyoto.jp"], ["ide.kyoto.jp", null], ["b.ide.kyoto.jp", "b.ide.kyoto.jp"],
    ["c.kobe.jp", null], ["b.c.kobe.jp", "b.c.kobe.jp"], ["city.kobe.jp", "city.kobe.jp"], ["www.city.kobe.jp", "city.kobe.jp"],
  ];
  for (const [host, expected] of cases) assert.equal(organisationalDomain(host), expected, host);
});

test("the domains from Kay's real phishing email", () => {
  const dkim = "530.61195.kkvy.sb037.istimewainvestasisolutif.my.id";
  assert.equal(publicSuffix(dkim), "my.id");
  assert.equal(registeredDomain(dkim), "istimewainvestasisolutif.my.id");
  assert.equal(lookupDomain("sb037.istimewainvestasisolutif.my.id"), "istimewainvestasisolutif.my.id");
  assert.equal(sameOrg(dkim, "sb037.istimewainvestasisolutif.my.id"), true);
  assert.equal(sameOrg(dkim, "adewo.ikz"), false);
});

test("private suffixes separate owners but lookups use the registered domain", () => {
  assert.equal(registrableDomain("evil.github.io"), "evil.github.io");
  assert.equal(sameOrg("evil.github.io", "good.github.io"), false);
  assert.equal(lookupDomain("evil.github.io"), "github.io", "RDAP/VirusTotal know github.io, not the subdomain");
  assert.equal(lookupDomain("45.33.32.156"), null);
  assert.equal(lookupDomain("co.uk"), null);
});
