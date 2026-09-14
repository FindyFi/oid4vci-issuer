import { randomUUID } from 'node:crypto'

const NONCE_TTL_MS = 5 * 60 * 1000

export function nonceKey(value) {
  return `nonce:${value}`
}

// The Nonce Endpoint (OID4VCI 1.0 Section 7) is deliberately unauthenticated
// - it's not a protected resource, anyone can request a fresh c_nonce. The
// actual access control happens at the Credential Endpoint (a valid,
// single-use access token); the nonce only proves the proof JWT is fresh,
// independent of which token ends up presenting it.
export function createNonceHandler({ store }) {
  return function nonceHandler(req, res) {
    const value = randomUUID()
    store.set(nonceKey(value), { used: false }, NONCE_TTL_MS)
    res.set('Cache-Control', 'no-store')
    res.json({ c_nonce: value })
  }
}

// Single-use: a nonce is valid only the first time it's presented in a proof.
export function consumeNonce(store, value) {
  const key = nonceKey(value)
  const entry = store.get(key)
  if (!entry || entry.used) return false
  store.delete(key)
  return true
}
