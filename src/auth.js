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
    if (provided !== token) {
      return res.status(401).json({ error: 'unauthorized' })
    }
    next()
  }
}
