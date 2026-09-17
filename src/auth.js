import { createHash, timingSafeEqual } from 'node:crypto'

// Constant-time comparison, so that a caller guessing the token cannot read
// the answer off the response time. Comparing SHA-256 digests rather than
// the raw strings keeps both sides the same fixed length whatever the token
// length is - timingSafeEqual throws on a length mismatch, and padding or
// truncating to a fixed window would either leak the length or compare only
// part of the token.
function tokenMatches(expected, provided) {
  if (typeof provided !== 'string') return false
  const digest = (value) => createHash('sha256').update(value, 'utf8').digest()
  return timingSafeEqual(digest(expected), digest(provided))
}

// Guards the coordinator-facing endpoints (offer creation) with a shared
// bearer token, the same way digitalcredentials/signing-service and its
// peers assume network isolation / a shared secret rather than public
// exposure - unlike the wallet-facing endpoints (token, credential,
// metadata, offer lookup), which are meant to be reachable by anyone.
export function requireCoordinatorToken(token) {
  return function coordinatorAuth(req, res, next) {
    if (!token) return next() // no token configured: auth disabled (local dev)
    const auth = req.get('authorization') || ''
    const [, provided] = auth.match(/^Bearer (.+)$/) || []
    if (!tokenMatches(token, provided)) {
      return res.status(401).json({ error: 'unauthorized' })
    }
    next()
  }
}
