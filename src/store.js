// Minimal in-memory store with per-entry TTL. Swap for a Redis-backed
// implementation of the same { get, set, delete } shape if this ever needs
// to run multi-process - nothing else in this package depends on Map
// internals.
export function createStore({ sweepIntervalMs = 60_000 } = {}) {
  const entries = new Map()

  function set(key, value, ttlMs) {
    entries.set(key, { value, expiresAt: Date.now() + ttlMs })
  }

  function get(key) {
    const entry = entries.get(key)
    if (!entry) return undefined
    if (entry.expiresAt < Date.now()) {
      entries.delete(key)
      return undefined
    }
    return entry.value
  }

  function del(key) {
    entries.delete(key)
  }

  const sweep = setInterval(() => {
    const now = Date.now()
    for (const [key, entry] of entries) {
      if (entry.expiresAt < now) entries.delete(key)
    }
  }, sweepIntervalMs)
  sweep.unref?.()

  return { get, set, delete: del }
}
