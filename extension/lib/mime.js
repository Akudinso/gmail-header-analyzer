// Minimal, defensive MIME parser for a full RFC 5322 message.
// Input is attacker-controlled, so everything is bounded (depth, part count)
// and nothing here ever executes or renders content.

import {
  base64ToBytes,
  binaryToBytes,
  bytesToBinary,
  decodeBytes,
  decodeEncodedWords,
  quotedPrintableToBytes,
} from "./encoding.js";

const MAX_DEPTH = 10;
const MAX_PARTS = 300;

/** Split a binary string at the first blank line. */
export function splitHeadBody(bin) {
  const m = /\r?\n\r?\n/.exec(bin);
  if (!m) return { head: bin, body: "" };
  return { head: bin.slice(0, m.index), body: bin.slice(m.index + m[0].length) };
}

/**
 * Parse a header block into an ordered list, top header first.
 * Each entry: { name, value } where value is unfolded and UTF-8 decoded
 * but NOT RFC 2047 decoded (use decodeEncodedWords for display fields).
 */
export function parseHeaderBlock(headBin) {
  const headers = [];
  const lines = headBin.split(/\r?\n/);
  let current = null;
  for (const line of lines) {
    if (/^[ \t]/.test(line) && current) {
      current.raw += " " + line.trim(); // unfold (RFC 5322 §2.2.3)
      continue;
    }
    const idx = line.indexOf(":");
    if (idx <= 0) continue; // not a header line; ignore junk
    current = { name: line.slice(0, idx).trim(), raw: line.slice(idx + 1).trim() };
    headers.push(current);
  }
  return headers.map(({ name, raw }) => ({
    name,
    value: decodeBytes(binaryToBytes(raw), "utf-8"),
  }));
}

export function getHeader(headers, name) {
  const lower = name.toLowerCase();
  return headers.find((h) => h.name.toLowerCase() === lower)?.value ?? null;
}

export function getHeaders(headers, name) {
  const lower = name.toLowerCase();
  return headers.filter((h) => h.name.toLowerCase() === lower).map((h) => h.value);
}

/** Parse "type/subtype; a=b; c="d"" (supports RFC 2231 name*=charset''value). */
export function parseStructuredHeader(value) {
  if (!value) return { value: "", params: {} };
  const parts = [];
  let buf = "";
  let inQuotes = false;
  for (const ch of value) {
    if (ch === '"') inQuotes = !inQuotes;
    if (ch === ";" && !inQuotes) {
      parts.push(buf);
      buf = "";
    } else buf += ch;
  }
  parts.push(buf);
  const params = {};
  for (const p of parts.slice(1)) {
    const eq = p.indexOf("=");
    if (eq < 0) continue;
    let key = p.slice(0, eq).trim().toLowerCase();
    let val = p.slice(eq + 1).trim();
    if (val.startsWith('"') && val.endsWith('"')) val = val.slice(1, -1).replace(/\\(.)/g, "$1");
    // RFC 2231: filename*=utf-8''na%C3%AFve.pdf  (continuations like *0* are joined loosely)
    const ext = /^([^*]+)\*(?:\d+\*?)?$/.exec(key);
    if (ext) {
      key = ext[1];
      const m = /^([^']*)'[^']*'(.*)$/.exec(val);
      try {
        const bytes = binaryToBytes(
          (m ? m[2] : val).replace(/%([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
        );
        val = decodeBytes(bytes, m?.[1] || "utf-8");
      } catch {
        /* keep raw */
      }
      params[key] = (params[key] && !m ? params[key] : "") + val;
    } else {
      params[key] = decodeEncodedWords(val);
    }
  }
  return { value: parts[0].trim().toLowerCase(), params };
}

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function splitMultipart(body, boundary) {
  const re = new RegExp(`(?:^|\\r?\\n)--${escapeRegExp(boundary)}(--)?[ \\t]*(?=\\r?\\n|$)`, "g");
  const parts = [];
  let lastEnd = -1;
  let m;
  while ((m = re.exec(body))) {
    if (lastEnd >= 0) parts.push(body.slice(lastEnd, m.index));
    if (m[1]) break; // closing delimiter
    lastEnd = m.index + m[0].length;
    const nl = /^\r?\n/.exec(body.slice(lastEnd));
    if (nl) lastEnd += nl[0].length;
    if (parts.length >= MAX_PARTS) break;
  }
  return parts;
}

function decodeTransfer(bin, cte) {
  switch ((cte || "").toLowerCase()) {
    case "base64":
      return base64ToBytes(bin);
    case "quoted-printable":
      return quotedPrintableToBytes(bin);
    default:
      return binaryToBytes(bin);
  }
}

/**
 * Parse an entity (whole message or a part) into a tree.
 * Returns { headers, contentType, params, disposition, filename, children, bytes }
 */
export function parseEntity(bin, depth = 0, counter = { n: 0 }) {
  counter.n++;
  const { head, body } = splitHeadBody(bin);
  const headers = parseHeaderBlock(head);
  const ct = parseStructuredHeader(getHeader(headers, "content-type") || "text/plain; charset=us-ascii");
  const cd = parseStructuredHeader(getHeader(headers, "content-disposition") || "");
  const cte = (getHeader(headers, "content-transfer-encoding") || "7bit").trim();
  const node = {
    headers,
    contentType: ct.value || "text/plain",
    params: ct.params,
    disposition: cd.value || null,
    filename: cd.params.filename || ct.params.name || null,
    children: [],
    bytes: null,
  };

  if (node.contentType.startsWith("multipart/") && ct.params.boundary && depth < MAX_DEPTH) {
    for (const partBin of splitMultipart(body, ct.params.boundary)) {
      if (counter.n >= MAX_PARTS) break;
      node.children.push(parseEntity(partBin, depth + 1, counter));
    }
  } else {
    node.bytes = decodeTransfer(body, cte);
  }
  return node;
}

/** Flatten the tree into the parts an analyst cares about. */
export function collectParts(root) {
  const result = { text: null, html: null, attachments: [] };
  const walk = (node) => {
    if (node.children.length) return node.children.forEach(walk);
    const isAttachment =
      node.disposition === "attachment" ||
      (node.filename && node.disposition !== "inline") ||
      (!node.contentType.startsWith("text/") && node.contentType !== "message/delivery-status");
    if (!isAttachment && node.contentType === "text/plain" && result.text === null) {
      result.text = decodeBytes(node.bytes, node.params.charset);
    } else if (!isAttachment && node.contentType === "text/html" && result.html === null) {
      result.html = decodeBytes(node.bytes, node.params.charset);
    } else if (isAttachment || node.filename) {
      result.attachments.push({
        filename: node.filename || "(unnamed)",
        contentType: node.contentType,
        inline: node.disposition === "inline",
        bytes: node.bytes,
      });
    }
  };
  walk(root);
  return result;
}

export function parseMessage(bytes) {
  const bin = bytesToBinary(bytes);
  const root = parseEntity(bin);
  return { headers: root.headers, ...collectParts(root) };
}
