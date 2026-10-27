// Byte/string helpers. Pure functions, no browser APIs beyond atob/TextDecoder,
// so they run in the extension service worker AND in Node for tests.

/** Decode base64 or base64url (Gmail API uses base64url) into bytes. */
export function base64ToBytes(input) {
  let s = String(input).replace(/[\s=]/g, "").replace(/-/g, "+").replace(/_/g, "/");
  s = s.replace(/[^A-Za-z0-9+/]/g, "");
  while (s.length % 4) s += "=";
  if (s.length % 4 === 1) s = s.slice(0, -1); // malformed tail; drop rather than throw
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Bytes -> "binary string" (one char per byte, 0-255). Lets us regex over raw MIME safely. */
export function bytesToBinary(bytes) {
  let out = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    out += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return out;
}

export function binaryToBytes(bin) {
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i) & 0xff;
  return out;
}

/** Decode bytes using a MIME charset name, falling back to UTF-8 then Latin-1. */
export function decodeBytes(bytes, charset = "utf-8") {
  const label = String(charset || "utf-8").trim().toLowerCase().replace(/^"|"$/g, "");
  try {
    return new TextDecoder(label === "us-ascii" ? "utf-8" : label, { fatal: false }).decode(bytes);
  } catch {
    try {
      return new TextDecoder("utf-8").decode(bytes);
    } catch {
      return bytesToBinary(bytes);
    }
  }
}

/** Quoted-printable (RFC 2045) -> bytes. */
export function quotedPrintableToBytes(bin) {
  const s = bin.replace(/=\r?\n/g, ""); // soft line breaks
  const out = [];
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "=" && /^[0-9A-Fa-f]{2}$/.test(s.substr(i + 1, 2))) {
      out.push(parseInt(s.substr(i + 1, 2), 16));
      i += 2;
    } else {
      out.push(c.charCodeAt(0) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

/** RFC 2047 encoded words, e.g. =?UTF-8?B?Q2Fmw6k=?= -> "Café". */
export function decodeEncodedWords(value) {
  if (!value || !value.includes("=?")) return value;
  // Whitespace between two adjacent encoded words is not part of the text.
  const joined = value.replace(/(\?=)\s+(?==\?)/g, "$1");
  return joined.replace(/=\?([^?\s]+)\?([BbQq])\?([^?\s]*)\?=/g, (whole, charset, enc, text) => {
    try {
      const cs = charset.split("*")[0]; // strip RFC 2231 language tag
      const bytes =
        enc.toUpperCase() === "B"
          ? base64ToBytes(text)
          : quotedPrintableToBytes(text.replace(/_/g, " "));
      return decodeBytes(bytes, cs);
    } catch {
      return whole;
    }
  });
}

const NAMED_ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };

/** Minimal HTML entity decoding — enough for hrefs and link text. */
export function decodeHtmlEntities(s) {
  return String(s).replace(/&(#x[0-9a-f]+|#[0-9]+|[a-z]+);/gi, (m, code) => {
    if (code[0] === "#") {
      const n = code[1].toLowerCase() === "x" ? parseInt(code.slice(2), 16) : parseInt(code.slice(1), 10);
      return Number.isFinite(n) && n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : m;
    }
    return NAMED_ENTITIES[code.toLowerCase()] ?? m;
  });
}

export async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
