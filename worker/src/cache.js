// Lookup cache. Uses Workers KV when a LOOKUP_CACHE namespace is bound
// (shared across all Cloudflare locations, survives restarts); otherwise an
// in-memory map that lives as long as the Worker isolate (fine for local dev).

const memory = new Map();
const MAX_MEMORY_ENTRIES = 2000;

export function createCache(env) {
  const kv = env.LOOKUP_CACHE;
  return {
    async get(key) {
      if (kv) {
        const v = await kv.get(key, "json");
        return v ?? null;
      }
      const hit = memory.get(key);
      if (!hit) return null;
      if (hit.expires < Date.now()) {
        memory.delete(key);
        return null;
      }
      return hit.value;
    },
    async put(key, value, ttlSeconds) {
      if (kv) {
        // KV's minimum TTL is 60 seconds.
        await kv.put(key, JSON.stringify(value), { expirationTtl: Math.max(60, ttlSeconds) });
        return;
      }
      if (memory.size >= MAX_MEMORY_ENTRIES) memory.delete(memory.keys().next().value);
      memory.set(key, { value, expires: Date.now() + ttlSeconds * 1000 });
    },
  };
}

export function _clearMemoryCache() {
  memory.clear();
}
