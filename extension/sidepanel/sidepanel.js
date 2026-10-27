import { assessReport } from "../lib/findings.js";

// Side panel UI. SECURITY: every value shown here comes from an email the
// attacker wrote. Never use innerHTML with report data — the el() helper
// only ever sets textContent. Links are shown as text, never clickable.

const app = document.getElementById("app");
const refreshBtn = document.getElementById("refresh");
const copyBtn = document.getElementById("copy");
const disconnectBtn = document.getElementById("disconnect");

let tabId = null;
let currentState = null;

// ---------- tiny DOM helper ----------
function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = String(v);
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

const card = (title, ...body) => el("section", { class: "card" }, title ? el("h2", { text: title }) : null, ...body);

function send(type, extra = {}) {
  return chrome.runtime.sendMessage({ type, tabId, ...extra });
}

// ---------- state screens ----------
function stateScreen(title, text, action) {
  return el("div", { class: "card state" }, el("p", { class: "title", text: title }), text ? el("p", { class: "muted", text }) : null, action);
}

function renderState(state) {
  currentState = state;
  refreshBtn.hidden = !(state?.status === "ready" || state?.status === "error");
  copyBtn.hidden = state?.status !== "ready";
  app.replaceChildren();

  if (!state) {
    app.append(
      stateScreen(
        "Open Gmail in this tab",
        "Go to mail.google.com and open an email. The analysis appears here automatically.",
        el("button", { class: "ghost", text: "Check again", onclick: () => send("panel:rescan") })
      )
    );
    return;
  }
  switch (state.status) {
    case "idle":
      app.append(stateScreen("Open an email", "Click any email in Gmail and it will be analysed automatically."));
      return;
    case "needs-auth":
      app.append(
        stateScreen(
          "Connect your Gmail",
          "One-time step. The extension asks for read-only access so it can fetch the full original email, including headers Gmail hides.",
          el("button", { class: "primary", text: "Connect Gmail", onclick: connect })
        )
      );
      return;
    case "loading":
      app.append(el("div", { class: "card state" }, el("div", { class: "spinner" }), el("p", { class: "muted", text: "Fetching and analysing…" })));
      return;
    case "error":
      app.append(stateScreen("Couldn't analyse this email", state.error, null));
      return;
    case "ready":
      renderReport(state.report, state);
      return;
  }
}

async function connect(e) {
  e.target.disabled = true;
  e.target.textContent = "Waiting for Google…";
  const res = await send("panel:connect");
  if (!res?.ok) {
    app.replaceChildren(stateScreen("Sign-in didn't complete", res?.error || "Try again.", el("button", { class: "primary", text: "Connect Gmail", onclick: connect })));
  }
}

// ---------- report ----------
function authChip(label, r) {
  const result = r?.result ?? "none";
  const cls = result === "pass" ? "pass" : ["fail", "softfail", "permerror"].includes(result) ? "fail" : "warn";
  return el("span", { class: `chip ${cls}`, title: r?.domain ? `${label} domain: ${r.domain}` : null }, `${label} ${result}`);
}

function fmtAddress(a) {
  if (!a) return "—";
  return a.name ? `${a.name} <${a.email ?? "?"}>` : a.email ?? a.raw;
}

function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function fmtDelay(s) {
  if (s == null) return null;
  if (Math.abs(s) < 60) return `+${s}s`;
  if (Math.abs(s) < 3600) return `+${Math.round(s / 60)}m`;
  return `+${(s / 3600).toFixed(1)}h`;
}

// ---------- risk score ----------

const PROVISIONAL_TEXT = {
  off: "Lookups aren't set up, so this score uses the headers, links and attachments only.",
  loading: "Lookups are still running; the score may go up.",
  error: "Lookups failed, so this score uses the headers, links and attachments only.",
  unreachable: "The Worker isn't running, so this score uses the headers, links and attachments only.",
};

function renderAssessment(assessment, enrichment) {
  const { score, level, label, findings, groups, provisional } = assessment;
  const header = el("div", { class: `score score-${level}` },
    el("div", { class: "score-num" }, el("span", { class: "big", text: score }), el("span", { class: "of", text: "/100" })),
    el("div", {},
      el("div", { class: "score-label", text: label }),
      el("div", { class: "muted", text: findings.length ? `${findings.length} finding${findings.length === 1 ? "" : "s"}, strongest first` : "No red flags in headers, links or attachments." })
    )
  );
  const meter = el("div", { class: "meter", role: "img", "aria-label": `Risk score ${score} out of 100` }, el("div", { class: "meter-fill", style: `width:${score}%` }));
  const breakdown = groups.length
    ? el("div", { class: "chips", style: "margin-top:10px" }, groups.map((g) => el("span", { class: "chip", title: `Capped at ${g.cap}` }, `${g.label} ${g.points}`)))
    : null;
  const floorNote = assessment.floor
    ? el("p", { class: "muted", style: "margin:8px 0 0", text: `The findings add up to ${assessment.floor.sum}, but one of them is decisive on its own, so the score is at least ${assessment.floor.minimum}.` })
    : null;
  const note = provisional ? el("p", { class: "muted", style: "margin:8px 0 0", text: PROVISIONAL_TEXT[enrichment?.status] ?? PROVISIONAL_TEXT.off }) : null;
  const list = findings.length
    ? el("ul", { class: "flags", style: "margin-top:12px" },
        findings.map((f) =>
          el("li", { class: f.awarded >= 25 || f.decisive ? "hi" : "" },
            el("span", { class: "pts", title: f.awarded < f.points ? `${f.points} points, but the ${f.group} group is capped` : `${f.points} points` }, f.awarded < f.points ? `+${f.awarded} of ${f.points}` : `+${f.awarded}`),
            el("span", {}, f.text, f.decisive ? el("strong", { text: " Decisive on its own." }) : null)
          )
        )
      )
    : null;
  return card("Risk", header, meter, breakdown, floorNote, note, list);
}

// ---------- lookups ----------

const NEW_DOMAIN_DAYS = 30;
const ok = (res) => res?.status === "ok" && res.data;

const STATUS_TEXT = {
  not_found: "Not in VirusTotal's database",
  skipped: "VirusTotal skipped (free-tier budget)",
  rate_limited: "Rate limited; try Re-analyse in a minute",
  not_configured: "No API key on the Worker",
  invalid: "VirusTotal says this isn't valid",
  unsupported: "Registry doesn't publish RDAP data",
  not_applicable: "Not looked up",
};

function statusLine(res) {
  if (!res || res.status === "ok") return null;
  return el("span", { class: "muted", text: res.status === "error" ? `Lookup failed: ${res.error}` : STATUS_TEXT[res.status] ?? res.status });
}

function vtChip(res) {
  if (!ok(res)) return null;
  const { malicious, suspicious, harmless, undetected } = res.data;
  const total = malicious + suspicious + harmless + undetected;
  const bad = malicious + suspicious;
  return el("span", { class: `chip ${bad ? "fail" : "pass"}`, title: `${malicious} malicious, ${suspicious} suspicious, ${harmless} harmless, ${undetected} undetected` }, `VirusTotal ${bad}/${total}`);
}

function row(label, ...value) {
  return [el("dt", { text: label }), el("dd", {}, ...value)];
}

function renderLookups(enrichment) {
  if (!enrichment || enrichment.status === "off") {
    return card("Reputation lookups", el("p", { class: "muted", style: "margin:0", text: "Not set up. See \"Turn on lookups\" in the README to add VirusTotal, AbuseIPDB and domain age." }));
  }
  if (enrichment.status === "loading") {
    return card("Reputation lookups", el("p", { class: "muted", style: "margin:0", text: "Checking IP, domains, links and attachments…" }));
  }
  if (enrichment.status !== "ok") {
    return card("Reputation lookups", el("p", { class: "muted", style: "margin:0", text: enrichment.error ?? "Lookups failed." }));
  }
  const x = enrichment.results;
  if (!x) return card("Reputation lookups", el("p", { class: "muted", style: "margin:0", text: "Nothing to look up in this email." }));

  const parts = [];

  if (x.ip) {
    const a = ok(x.ip.abuseipdb) ? x.ip.abuseipdb.data : null;
    const vt = ok(x.ip.virustotal) ? x.ip.virustotal.data : null;
    const rd = ok(x.ip.rdap) ? x.ip.rdap.data : null;
    const ptr = ok(x.ip.reverseDns) ? x.ip.reverseDns.data.names : null;
    parts.push(
      el("h3", { class: "sub", text: `Sender IP ${x.ip.value}` }),
      el("div", { class: "chips", style: "margin-bottom:6px" },
        a ? el("span", { class: `chip ${a.abuseScore >= 75 ? "fail" : a.abuseScore >= 25 ? "warn" : "pass"}` }, `AbuseIPDB ${a.abuseScore}%`) : null,
        vtChip(x.ip.virustotal),
        a?.isTor ? el("span", { class: "chip fail", text: "Tor exit" }) : null
      ),
      el("dl", { class: "kv" },
        row("Owner", rd?.organisation ?? vt?.asOwner ?? a?.isp ?? "—"),
        vt?.asn ? row("ASN", `AS${vt.asn}${vt.asOwner ? ` · ${vt.asOwner}` : ""}`) : null,
        row("Network", rd ? `${rd.name ?? ""} ${rd.range ? `(${rd.range})` : ""}`.trim() || "—" : statusLine(x.ip.rdap) ?? "—"),
        row("Country", a?.country ?? vt?.country ?? rd?.country ?? "—"),
        a?.usageType ? row("Usage", a.usageType) : null,
        row(
          "Reverse DNS",
          ptr ? ptr.join(", ") : x.ip.reverseDns?.status === "not_found" ? "None (no PTR record)" : "—",
          ptr && !x.ip.reverseDns.data.forwardConfirmed
            ? el("div", { class: "muted", text: "Unconfirmed: this name doesn't resolve back to the IP, so whoever runs the IP may have set it to anything." })
            : ptr
              ? el("div", { class: "muted", text: "Confirmed: the name resolves back to this IP." })
              : null
        ),
        a ? row("Reports", `${a.totalReports} from ${a.distinctReporters} source(s)${a.lastReportedAt ? `, last ${a.lastReportedAt.slice(0, 10)}` : ""}`) : row("AbuseIPDB", statusLine(x.ip.abuseipdb)),
        !vt ? row("VirusTotal", statusLine(x.ip.virustotal)) : null
      )
    );
  }

  if (x.claimedIps?.length) {
    parts.push(
      el("h3", { class: "sub", text: "Unverified IPs" }),
      el("ul", { class: "list" },
        x.claimedIps.map((c) => {
          const a = ok(c.abuseipdb) ? c.abuseipdb.data : null;
          return el("li", {}, el("span", { class: "mono", text: c.value }), " ",
            a ? el("span", { class: `chip ${a.abuseScore >= 25 ? "warn" : ""}`, text: `AbuseIPDB ${a.abuseScore}% · ${a.country ?? "?"} · ${a.isp ?? "?"}` }) : statusLine(c.abuseipdb));
        })
      )
    );
  }

  if (x.domains?.length) {
    parts.push(
      el("h3", { class: "sub", text: "Domains" }),
      el("ul", { class: "list" },
        x.domains.map((d) => {
          const rd = ok(d.rdap) ? d.rdap.data : null;
          const dns = ok(d.dns) ? d.dns.data : null;
          const isNew = rd?.ageDays != null && rd.ageDays < NEW_DOMAIN_DAYS;
          return el("li", {},
            el("div", { class: "chips", style: "margin-bottom:4px" },
              el("strong", { class: "mono", text: d.domain }),
              d.roles.map((role) => el("span", { class: "chip", text: role })),
              isNew ? el("span", { class: "chip fail", text: `${rd.ageDays}d old` }) : null,
              dns && !dns.tldExists ? el("span", { class: "chip fail", text: "fake TLD" }) : null,
              dns && dns.tldExists && !dns.domainExists ? el("span", { class: "chip fail", text: "doesn't exist" }) : null,
              vtChip(d.virustotal)
            ),
            el("div", { class: "muted" },
              dns && !dns.tldExists
                ? `.${d.domain.split(".").pop()} is not a real top-level domain`
                : rd
                  ? `Registered ${rd.createdAt ? rd.createdAt.slice(0, 10) : "date unknown"}${rd.registrar ? ` via ${rd.registrar}` : ""}`
                  : d.rdap?.status === "not_found"
                    ? "Registry has no record of this domain"
                    : ["Registration: ", statusLine(d.rdap)],
              !ok(d.virustotal) && !["not_configured", "not_applicable"].includes(d.virustotal?.status) ? [" · ", statusLine(d.virustotal)] : null
            )
          );
        })
      )
    );
  }

  if (x.urls?.length) {
    parts.push(
      el("h3", { class: "sub", text: "Suspicious links" }),
      el("ul", { class: "list" }, x.urls.map((u) => el("li", {}, el("div", { class: "mono", text: u.url }), el("div", { class: "chips", style: "margin-top:4px" },
                  vtChip(u.virustotal) ??
                    (u.virustotal?.status === "not_found"
                      ? el("span", { class: "muted", text: "VirusTotal has never scanned this exact URL. That means it's new or rarely seen, not that it's safe." })
                      : statusLine(u.virustotal))))))
    );
  }

  if (x.hashes?.length) {
    parts.push(
      el("h3", { class: "sub", text: "Attachment hashes" }),
      el("ul", { class: "list" },
        x.hashes.map((h) => {
          const vt = ok(h.virustotal) ? h.virustotal.data : null;
          return el("li", {},
            el("div", { class: "mono muted", text: h.sha256 }),
            el("div", { class: "chips", style: "margin-top:4px" },
              vtChip(h.virustotal) ?? (h.virustotal?.status === "not_found" ? el("span", { class: "muted", text: "Never seen by VirusTotal (unknown file, not proof it's safe)" }) : statusLine(h.virustotal)),
              vt?.threatLabel ? el("span", { class: "chip fail", text: vt.threatLabel }) : null
            )
          );
        })
      )
    );
  }

  if (x.limits?.virustotalSkipped) {
    parts.push(el("p", { class: "muted", style: "margin:8px 0 0", text: `${x.limits.virustotalSkipped} VirusTotal lookup(s) skipped to stay within the free tier. Press Re-analyse in a minute to fill them in.` }));
  }

  return card("Reputation lookups", ...parts);
}

function renderReport(r, state) {
  const s = r.summary;

  if (state.messageIds?.length > 1) {
    const select = el(
      "select",
      { "aria-label": "Message in this conversation", onchange: (e) => send("panel:select", { messageId: e.target.value }) },
      state.messageIds.map((id, i) => el("option", { value: id, selected: id === state.selectedId, text: `Message ${i + 1} of ${state.messageIds.length}${i === state.messageIds.length - 1 ? " (latest)" : ""}` }))
    );
    app.append(card("Conversation", select));
  }

  app.append(
    card(
      null,
      el("p", { class: "subject", text: s.subject }),
      el("dl", { class: "kv" },
        el("dt", { text: "From" }), el("dd", { text: fmtAddress(s.from) }),
        s.replyTo ? [el("dt", { text: "Reply-To" }), el("dd", { text: fmtAddress(s.replyTo) })] : null,
        el("dt", { text: "Return-Path" }), el("dd", { text: s.returnPath?.email ?? "—" }),
        el("dt", { text: "Date" }), el("dd", { text: s.date ?? "—" })
      )
    )
  );

  app.append(renderAssessment(assessReport(r), r.enrichment));

  app.append(renderLookups(r.enrichment));

  app.append(
    card(
      "Authentication",
      el("div", { class: "chips" }, authChip("SPF", r.auth.spf), authChip("DKIM", r.auth.dkim), authChip("DMARC", r.auth.dmarc)),
      el("p", { class: "muted", style: "margin:8px 0 0", text: r.auth.trustedSource ? `Verified by ${r.auth.trustedSource}.` : "Not verified by Google." })
    )
  );

  const ip = r.senderIp;
  app.append(
    card(
      "Sender IP",
      ip.verified
        ? el("div", {}, el("div", { class: "mono", text: ip.verified.ip }), el("div", { class: "muted", text: ip.verified.source }))
        : el("div", { class: "muted", text: "No Google-recorded connection found." }),
      ip.sentViaGoogle ? el("p", { class: "muted", style: "margin:6px 0 0", text: "Sent through Google's own servers, so the original sender's IP is hidden by design." }) : null,
      ip.heloMismatch
        ? el("p", { style: "margin:6px 0 0" },
            el("span", { class: "chip fail", text: "identity mismatch" }), " ",
            el("span", { class: "muted", text: `Claimed to be ${ip.heloMismatch.helo}; reverse DNS says ${ip.heloMismatch.reverseDns}.` }))
        : null,
      ip.claimed.length
        ? el("details", { style: "margin-top:8px" },
            el("summary", { text: `Unverified IPs claimed in the message (${ip.claimed.length})` }),
            el("ul", { class: "list", style: "margin-top:8px" }, ip.claimed.map((c) => el("li", {}, el("span", { class: "mono", text: c.ip }), " ", el("span", { class: "muted", text: c.source }))))
          )
        : null
    )
  );

  const trustedHop = ip.verified?.hop ?? -1;
  const forgedHops = new Set((ip.forgedGoogleHops ?? []).map((f) => f.hop));
  app.append(
    card(
      `Received path (${r.hops.length} hops, oldest first)`,
      el("ul", { class: "list" },
        r.hops.map((h, i) =>
          el("li", { class: `hop${i === trustedHop ? " trusted" : ""}${forgedHops.has(i) ? " forged" : ""}` },
            el("span", { class: "n", text: i + 1 }),
            el("div", {},
              forgedHops.has(i) ? el("span", { class: "chip fail", style: "margin-bottom:4px", text: "forged: Google didn't write this" }) : null,
              i === trustedHop ? el("span", { class: "chip pass", style: "margin-bottom:4px", text: "entered Google here" }) : null,
              el("div", {}, el("span", { class: "muted", text: "from " }), el("span", { class: "mono", text: h.fromHost ?? "—" }), h.ips.length ? el("span", { class: "mono", text: ` [${h.ips.join(", ")}]` }) : null),
              el("div", {}, el("span", { class: "muted", text: "by " }), el("span", { class: "mono", text: h.by ?? "—" }), h.with ? el("span", { class: "muted", text: ` · ${h.with}` }) : null, fmtDelay(h.delaySeconds) ? el("span", { class: "muted", text: ` · ${fmtDelay(h.delaySeconds)}` }) : null)
            )
          )
        )
      )
    )
  );

  app.append(
    card(
      `Links (${r.urls.length})`,
      r.urls.length
        ? el("ul", { class: "list" },
            r.urls.slice(0, 40).map((u) =>
              el("li", {},
                el("div", { class: "chips", style: "margin-bottom:4px" },
                  el("span", { class: "chip", text: u.domain ?? u.host }),
                  u.textMismatch ? el("span", { class: "chip fail", text: "text ≠ destination" }) : null,
                  u.isIp ? el("span", { class: "chip warn", text: "IP address" }) : null,
                  u.sharedHosting ? el("span", { class: "chip warn", text: "shared hosting" }) : null
                ),
                el("div", { class: "mono", text: u.url }),
                u.texts.length ? el("div", { class: "muted", text: `Shown as: ${u.texts.join(" | ")}` }) : null
              )
            )
          )
        : el("div", { class: "muted", text: "No links." }),
      r.urls.length > 40 ? el("p", { class: "muted", text: `+${r.urls.length - 40} more (Copy JSON for all).` }) : null
    )
  );

  app.append(
    card(
      `Attachments (${r.attachments.length})`,
      r.attachments.length
        ? el("ul", { class: "list" },
            r.attachments.map((a) =>
              el("li", {},
                el("div", {}, el("strong", { text: a.filename }), el("span", { class: "muted", text: ` · ${a.contentType} · ${fmtBytes(a.size)}${a.inline ? " · inline" : ""}` })),
                a.flags.length ? el("div", { class: "chips", style: "margin:4px 0" }, a.flags.map((fl) => el("span", { class: "chip fail", text: fl.replace("-", " ") }))) : null,
                el("div", { class: "mono muted", text: `SHA-256 ${a.sha256}` })
              )
            )
          )
        : el("div", { class: "muted", text: "No attachments." })
    )
  );

  app.append(
    card(
      "Raw headers",
      el("details", {}, el("summary", { text: `Show all ${r.headers.length} headers` }), el("pre", { text: r.headers.map((h) => `${h.name}: ${h.value}`).join("\n") }))
    )
  );
}

// ---------- wiring ----------
async function load() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  tabId = tab?.id ?? null;
  if (tabId == null) return renderState(null);
  const key = `tab:${tabId}`;
  const state = (await chrome.storage.session.get(key))[key] ?? null;
  renderState(state);
  if (!state) send("panel:rescan"); // panel opened before the content script reported
}

chrome.storage.session.onChanged.addListener((changes) => {
  const change = changes[`tab:${tabId}`];
  if (change) renderState(change.newValue ?? null);
});
chrome.tabs.onActivated.addListener(load);

refreshBtn.addEventListener("click", () => send("panel:refresh"));
copyBtn.addEventListener("click", async () => {
  const report = currentState?.report;
  await navigator.clipboard.writeText(JSON.stringify(report ? { ...report, assessment: assessReport(report) } : {}, null, 2));
  copyBtn.textContent = "Copied";
  setTimeout(() => (copyBtn.textContent = "Copy JSON"), 1200);
});
disconnectBtn.addEventListener("click", async () => {
  await send("panel:disconnect");
  load();
});

load();
