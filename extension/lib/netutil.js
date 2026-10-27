import { organisationalDomain, registeredDomain } from "./psl.js";

// IP and domain helpers.

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

export function isIPv4(s) {
  return IPV4.test(s);
}

export function isIPv6(s) {
  return /^[0-9a-f:.]+$/i.test(s) && s.includes(":") && s.split("::").length <= 2;
}

function v4ToInt(ip) {
  return ip.split(".").reduce((acc, o) => (acc << 8) + Number(o), 0) >>> 0;
}

const V4_NON_PUBLIC = [
  ["0.0.0.0", 8], // "this" network
  ["10.0.0.0", 8], // private
  ["100.64.0.0", 10], // carrier-grade NAT
  ["127.0.0.0", 8], // loopback
  ["169.254.0.0", 16], // link-local
  ["172.16.0.0", 12], // private
  ["192.0.0.0", 24], // IETF protocol assignments
  ["192.0.2.0", 24], // documentation (TEST-NET-1)
  ["192.168.0.0", 16], // private
  ["198.18.0.0", 15], // benchmarking
  ["198.51.100.0", 24], // documentation (TEST-NET-2)
  ["203.0.113.0", 24], // documentation (TEST-NET-3)
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved + broadcast
].map(([base, bits]) => [v4ToInt(base), bits]);

/** True for addresses that can't identify a sender on the public internet. */
export function isNonPublicIp(ip) {
  if (isIPv4(ip)) {
    const n = v4ToInt(ip);
    return V4_NON_PUBLIC.some(([base, bits]) => (n >>> (32 - bits)) === (base >>> (32 - bits)));
  }
  const s = ip.toLowerCase();
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (mapped) return isNonPublicIp(mapped[1]);
  return (
    s === "::" ||
    s === "::1" ||
    /^f[cd]/.test(s) || // fc00::/7 unique local
    /^fe[89ab]/.test(s) || // fe80::/10 link-local
    s.startsWith("2001:db8") || // documentation
    s.startsWith("ff") // multicast
  );
}

/** Pull IP literals out of free text such as a Received "from" clause. */
export function extractIps(text) {
  const found = [];
  const v4 = /(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])/g;
  for (const m of text.matchAll(v4)) found.push(m[1]);
  // IPv6 usually appears in brackets, sometimes prefixed "IPv6:"
  for (const m of text.matchAll(/\[(?:IPv6:)?([0-9a-f:.]{3,})\]/gi)) {
    if (isIPv6(m[1]) && !found.includes(m[1])) found.push(m[1].toLowerCase());
  }
  return [...new Set(found)];
}

export function normaliseHost(host) {
  return String(host || "").trim().toLowerCase().replace(/\.$/, "");
}

/**
 * Who controls a host, using the full Public Suffix List (private suffixes
 * like github.io count, so evil.github.io and good.github.io differ).
 * IP literals are returned as-is.
 */
export function registrableDomain(host) {
  const h = normaliseHost(host);
  if (!h || isIPv4(h) || h.includes(":")) return h || null;
  return organisationalDomain(h) ?? h;
}

/** The domain registered at a registry — what RDAP, WHOIS and VirusTotal describe. */
export function lookupDomain(host) {
  const h = normaliseHost(host);
  if (!h || isIPv4(h) || h.includes(":")) return null;
  return registeredDomain(h);
}

export function sameOrg(a, b) {
  if (!a || !b) return true; // nothing to compare
  return registrableDomain(a) === registrableDomain(b);
}
