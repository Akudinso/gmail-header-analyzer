// Public Suffix List lookups (https://publicsuffix.org/list/ algorithm).
//
// registeredDomain("a.b.example.co.uk")     -> "example.co.uk"   (ICANN only)
// organisationalDomain("evil.github.io")    -> "evil.github.io"  (ICANN + private)

import { ICANN_RULES, PRIVATE_RULES } from "./psl-data.js";

let icann = null;
let all = null;

function build(ruleString, into = new Map()) {
  for (const rule of ruleString.split(" ")) {
    if (!rule) continue;
    if (rule.startsWith("!")) into.set(rule.slice(1), "exception");
    else into.set(rule, "normal");
  }
  return into;
}

function rules(includePrivate) {
  icann ??= build(ICANN_RULES);
  if (!includePrivate) return icann;
  all ??= build(PRIVATE_RULES, new Map(icann));
  return all;
}

/** The public suffix of a lowercase ASCII hostname, per the PSL algorithm. */
export function publicSuffix(host, { includePrivate = true } = {}) {
  const labels = host.split(".");
  const table = rules(includePrivate);
  let longest = 1; // implicit "*" rule: the last label is always a suffix
  for (let i = labels.length - 1; i >= 0; i--) {
    const candidate = labels.slice(i).join(".");
    const wildcard = ["*", ...labels.slice(i + 1)].join(".");
    const len = labels.length - i;
    if (table.get(candidate) === "exception") {
      // An exception rule wins outright; the suffix is the rule minus its first label.
      return labels.slice(i + 1).join(".");
    }
    if (table.get(candidate) === "normal" || (i + 1 <= labels.length - 1 && table.get(wildcard) === "normal")) {
      longest = Math.max(longest, len);
    }
  }
  return labels.slice(labels.length - longest).join(".");
}

function domainWithSuffix(host, includePrivate) {
  const h = String(host || "").trim().toLowerCase().replace(/\.$/, "");
  if (!h || !h.includes(".")) return null; // a single label is itself a suffix
  const suffix = publicSuffix(h, { includePrivate });
  if (h === suffix) return null; // the host *is* a public suffix, e.g. "co.uk"
  const labels = h.split(".");
  return labels.slice(labels.length - suffix.split(".").length - 1).join(".");
}

/** The domain registered at a registry (what RDAP and WHOIS describe). */
export function registeredDomain(host) {
  return domainWithSuffix(host, false);
}

/** The domain one owner controls, treating github.io, blogspot.com etc. as suffixes. */
export function organisationalDomain(host) {
  return domainWithSuffix(host, true);
}
