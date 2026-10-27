// Cloudflare Worker backend. It holds the API keys (VirusTotal, AbuseIPDB,
// AI provider) so they never ship inside the extension, and it is where
// lookups, caching and scoring will live (roadmap steps 3-5).
//
// Status: skeleton. Endpoints:
//   GET  /health          -> { ok: true, configured: {...} }
//   POST /v1/enrich       -> 501 until step 3
//
// Planned access control (step 3): the extension sends its Google OAuth
// token; the Worker verifies it with Google and checks the account against
// ALLOWED_EMAILS, so a public Worker URL can't be used to burn your quotas.

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };

function allowedOrigins(env) {
  return String(env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function corsHeaders(request, env) {
  const origin = request.headers.get("origin");
  if (!origin || !allowedOrigins(env).includes(origin)) return {};
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "content-type, authorization",
    "access-control-max-age": "86400",
    vary: "origin",
  };
}

function json(body, status, request, env) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...JSON_HEADERS, ...corsHeaders(request, env) },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      const cors = corsHeaders(request, env);
      return new Response(null, { status: Object.keys(cors).length ? 204 : 403, headers: cors });
    }

    // Browsers send Origin on cross-origin requests; reject unknown extensions/sites.
    const origin = request.headers.get("origin");
    if (origin && !allowedOrigins(env).includes(origin)) {
      return json({ error: "origin not allowed" }, 403, request, env);
    }

    if (url.pathname === "/health" && request.method === "GET") {
      return json(
        {
          ok: true,
          configured: {
            virustotal: Boolean(env.VT_API_KEY),
            abuseipdb: Boolean(env.ABUSEIPDB_API_KEY),
            ai: Boolean(env.AI_API_KEY),
          },
        },
        200,
        request,
        env
      );
    }

    if (url.pathname === "/v1/enrich" && request.method === "POST") {
      return json({ error: "not implemented yet (roadmap step 3)" }, 501, request, env);
    }

    return json({ error: "not found" }, 404, request, env);
  },
};
