// Findings and the risk score.
//
// Every finding is a rule with an id, a group, a number of points and a
// sentence. The score is the sum of the points, so every point on screen
// can be traced to a finding and to the rule below that produced it.
//
// Design decisions (see README "How the risk score works"):
//
// 1. Points only go UP. A pass (SPF, DKIM, DMARC, clean reputation) proves a
//    domain sent the email, not that the domain is honest: attackers pass all
//    three on domains they registered last week. So passes earn no discount.
//
// 2. Related signals are grouped, and each group has a cap. A DMARC failure
//    usually comes with SPF and DKIM problems too; without caps, one root
//    cause would be counted three times.
//
// 3. Weights reflect how often a signal appears in LEGITIMATE mail, not just
//    phishing. A bounce address on another domain is normal for every
//    newsletter service (Mailchimp, SendGrid...), so it is worth 5. A forged
//    Google hop never happens in legitimate mail, so it is worth 30.
//
// 4. Some findings are decisive on their own: they essentially never occur
//    in legitimate mail (a From domain that can't exist, a forged Google hop,
//    a file or link several antivirus engines call malicious). Any one of
//    them sets a floor of 60, i.e. "High risk", whatever the other groups say.

export const GROUPS = {
  authentication: { label: "Authentication", cap: 35 },
  identity: { label: "Sender identity", cap: 50 },
  infrastructure: { label: "Sending infrastructure", cap: 40 },
  links: { label: "Links", cap: 45 },
  attachments: { label: "Attachments", cap: 60 },
};

export const LEVELS = [
  { min: 60, id: "high", label: "High risk" },
  { min: 25, id: "suspicious", label: "Suspicious" },
  { min: 0, id: "low", label: "Low risk" },
];

const NEW_DOMAIN_DAYS = 30;
export const DECISIVE_FLOOR = 60;
const ok = (res) => (res?.status === "ok" && res.data ? res.data : null);
const vtBad = (res) => {
  const d = ok(res);
  return d ? d.malicious + d.suspicious : 0;
};
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

/** All findings for a report, most points first. Pure function: same report, same result. */
export function buildFindings(r) {
  const out = [];
  const add = (id, group, points, text, decisive = false) => out.push({ id, group, points, text, decisive });
  const a = r.auth;
  const s = r.summary;
  const fromDomain = s.from?.domain ?? "the From domain";

  // ---- Authentication ----
  if (!a.trustedSource) {
    add("auth_unverified", "authentication", 15, "No Authentication-Results from Google found, so SPF, DKIM and DMARC can't be verified.");
  } else {
    if (a.dmarc?.result === "fail") {
      add("dmarc_fail", "authentication", 30, `DMARC failed for ${a.dmarc.domain ?? fromDomain}${a.dmarc.policy ? ` (the domain's policy is "${a.dmarc.policy}")` : ""}: the email isn't authorised by the domain in its From address.`);
    } else if (r.checks.noDmarc) {
      add("no_dmarc", "authentication", 10, `No DMARC result for ${fromDomain}, so nothing stops others sending as it.`);
    }
    if (a.spf && ["fail", "softfail"].includes(a.spf.result)) {
      add("spf_fail", "authentication", 10, `SPF ${a.spf.result}: ${a.spf.domain ?? "the envelope sender"} doesn't list the sending server as allowed.`);
    }
    if (!a.dkim) add("no_dkim", "authentication", 10, "The message has no DKIM signature.");
    else if (a.dkim.result !== "pass") add("dkim_fail", "authentication", 10, `DKIM ${a.dkim.result}: the signature doesn't match the message.`);
    if (r.checks.dkimNotAligned) add("dkim_not_aligned", "authentication", 5, `DKIM signed by ${a.dkim.domain}, which isn't the From domain.`);
  }

  // ---- Sender identity ----
  const lookups = r.enrichment?.status === "ok" ? r.enrichment.results : null;
  for (const d of lookups?.domains ?? []) {
    const dns = ok(d.dns);
    const roles = d.roles.join(", ");
    const isFrom = d.roles.includes("from");
    const isSenderSide = d.roles.some((role) => ["from", "reply-to", "sender"].includes(role));
    if (dns && !dns.tldExists) {
      add(`fake_tld:${d.domain}`, "identity", isFrom ? 45 : 25, `${d.domain} (${roles}) uses ".${d.domain.split(".").pop()}", which isn't a real top-level domain, so this address is fake.`, isFrom);
    } else if (dns && !dns.domainExists) {
      add(`no_such_domain:${d.domain}`, "identity", isFrom ? 40 : 20, `${d.domain} (${roles}) doesn't exist in DNS.`, isFrom);
    }
    const age = ok(d.rdap)?.ageDays;
    if (age != null && age < NEW_DOMAIN_DAYS) {
      add(`new_domain:${d.domain}`, "identity", isSenderSide ? 25 : 10, `${d.domain} (${roles}) was registered only ${plural(age, "day", "days")} ago.`);
    }
  }
  if (r.checks.replyToDiffers) add("reply_to_differs", "identity", 15, `Replies go to ${s.replyTo.domain}, not ${s.from.domain}.`);
  if (r.checks.displayNameHasEmail) add("display_name_email", "identity", 15, "The display name contains a different email address.");
  if (r.checks.returnPathDiffers) add("return_path_differs", "identity", 5, `Bounces go to ${s.returnPath.domain}, not ${s.from.domain}. (Common for newsletter services, so it counts for little on its own.)`);

  // ---- Sending infrastructure ----
  if (r.checks.forgedGoogleHops) {
    add("forged_hops", "infrastructure", 30, `${plural(r.checks.forgedGoogleHops, "Received header claims", "Received headers claim")} Google handled this email earlier, but Google didn't write ${r.checks.forgedGoogleHops === 1 ? "it" : "them"}. The sender forged ${r.checks.forgedGoogleHops === 1 ? "it" : "them"} to make the path look trustworthy.`, true);
  }
  if (r.checks.heloMismatch) {
    const m = r.senderIp.heloMismatch;
    add("helo_mismatch", "infrastructure", 20, `The sending server introduced itself as ${m.helo}, but Google recorded its address as ${m.reverseDns} [${m.ip}].`);
  }
  const ip = lookups?.ip;
  const abuse = ok(ip?.abuseipdb);
  if (abuse?.abuseScore >= 75) add("ip_abuse_high", "infrastructure", 25, `The sender IP has an AbuseIPDB score of ${abuse.abuseScore}% (${plural(abuse.totalReports, "report", "reports")}).`);
  else if (abuse?.abuseScore >= 25) add("ip_abuse_medium", "infrastructure", 10, `The sender IP has an AbuseIPDB score of ${abuse.abuseScore}% (${plural(abuse.totalReports, "report", "reports")}).`);
  if (abuse?.isTor) add("ip_tor", "infrastructure", 20, "The sender IP is a Tor exit node.");
  // One or two VirusTotal engines flagging a mail server's IP is common noise.
  const ipVt = vtBad(ip?.virustotal);
  if (ipVt >= 3) add("ip_vt", "infrastructure", 15, `${ipVt} VirusTotal engines flag the sender IP.`);
  else if (ipVt > 0) add("ip_vt_low", "infrastructure", 5, `${plural(ipVt, "VirusTotal engine flags", "VirusTotal engines flag")} the sender IP.`);
  const ptr = ok(ip?.reverseDns);
  if (ptr && !ptr.forwardConfirmed && !r.senderIp.sentViaGoogle) {
    add("ptr_unconfirmed", "infrastructure", 5, `The sender IP's reverse DNS name (${ptr.names[0]}) doesn't resolve back to it.`);
  }

  // ---- Links ----
  if (r.checks.linkTextMismatches) add("link_text_mismatch", "links", 25, `${plural(r.checks.linkTextMismatches, "link shows", "links show")} one domain but ${r.checks.linkTextMismatches === 1 ? "goes" : "go"} to another.`);
  if (r.checks.ipLinks) add("ip_links", "links", 15, `${plural(r.checks.ipLinks, "link points", "links point")} straight at an IP address.`);
  if (r.checks.sharedHostingLinks) add("shared_hosting", "links", 15, `${plural(r.checks.sharedHostingLinks, "link goes", "links go")} to shared hosting where anyone can publish a page, so the parent domain's reputation doesn't vouch for it.`);
  for (const u of lookups?.urls ?? []) {
    const n = vtBad(u.virustotal);
    if (n) add(`url_vt:${u.url}`, "links", n >= 2 ? 40 : 20, `${plural(n, "VirusTotal engine flags", "VirusTotal engines flag")} a link: ${u.url}`, n >= 2);
  }
  for (const d of lookups?.domains ?? []) {
    const n = vtBad(d.virustotal);
    if (n >= 2) add(`domain_vt:${d.domain}`, d.roles.includes("link") && d.roles.length === 1 ? "links" : "identity", 15, `${n} VirusTotal engines flag ${d.domain}.`);
  }

  // ---- Attachments ----
  for (const att of r.attachments) {
    if (att.flags.includes("double-extension")) add(`double_ext:${att.filename}`, "attachments", 35, `"${att.filename}" hides its real file type behind a second extension.`);
    else if (att.flags.includes("risky-extension")) add(`risky_ext:${att.filename}`, "attachments", 25, `"${att.filename}" is a file type that can run code when opened.`);
  }
  for (const h of lookups?.hashes ?? []) {
    const n = vtBad(h.virustotal);
    if (n) {
      const label = ok(h.virustotal).threatLabel;
      add(`file_vt:${h.sha256}`, "attachments", n >= 2 ? 60 : 30, `${plural(n, "VirusTotal engine flags", "VirusTotal engines flag")} an attachment${label ? ` as ${label}` : ""}.`, n >= 2);
    }
  }

  return out.sort((x, y) => y.points - x.points);
}

/**
 * Turn findings into a 0-100 score. Each group contributes at most its cap;
 * within a group the strongest findings count first, so a capped finding
 * shows "+0 (group capped)" rather than silently disappearing.
 */
export function scoreFindings(findings, { lookupsComplete = true } = {}) {
  const used = Object.fromEntries(Object.keys(GROUPS).map((g) => [g, 0]));
  const counted = findings.map((f) => {
    const room = GROUPS[f.group].cap - used[f.group];
    const awarded = Math.max(0, Math.min(f.points, room));
    used[f.group] += awarded;
    return { ...f, awarded };
  });
  const sum = Math.min(100, Object.values(used).reduce((x, y) => x + y, 0));
  const decisive = counted.filter((f) => f.decisive);
  const score = decisive.length ? Math.max(sum, DECISIVE_FLOOR) : sum;
  const level = LEVELS.find((l) => score >= l.min);
  return {
    score,
    level: level.id,
    label: level.label,
    findings: counted,
    groups: Object.entries(GROUPS)
      .map(([id, g]) => ({ id, label: g.label, points: used[id], cap: g.cap }))
      .filter((g) => g.points > 0),
    provisional: !lookupsComplete,
    // Set when a decisive finding lifted the score above the plain sum.
    floor: decisive.length && sum < DECISIVE_FLOOR ? { sum, minimum: DECISIVE_FLOOR, because: decisive[0].text } : null,
  };
}

/** Convenience: findings + score for a report, noting when lookups are missing. */
export function assessReport(r) {
  const status = r.enrichment?.status;
  return scoreFindings(buildFindings(r), { lookupsComplete: status === "ok" });
}
