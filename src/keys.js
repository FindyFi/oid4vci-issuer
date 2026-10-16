import { generateKeyPair, exportJWK, calculateJwkThumbprint } from 'jose'

// Loads the issuer's own ES256 key for signing SD-JWTs. `value` is either a
// private EC P-256 JWK as a JSON string, or `generate` for local dev, which
// makes a fresh key on every start (wallets holding credentials signed by a
// previous key can no longer verify them against the published JWKS).
// The kid is always the RFC 7638 thumbprint of the public key, so the same
// key always gets the same kid, whatever the input JWK said.
export async function loadSigningKey(value) {
  let privateJwk
  if (value === 'generate') {
    const { privateKey } = await generateKeyPair('ES256', { extractable: true })
    privateJwk = await exportJWK(privateKey)
  } else {
    try {
      privateJwk = JSON.parse(value)
    } catch {
      throw new Error('SD_JWT_SIGNING_KEY must be a private EC P-256 JWK as JSON, or "generate".')
    }
  }

  const { kty, crv, x, y, d } = privateJwk || {}
  if (kty !== 'EC' || crv !== 'P-256' || !x || !y || !d) {
    throw new Error('SD_JWT_SIGNING_KEY must be a private EC P-256 JWK (kty "EC", crv "P-256", with x, y and d).')
  }

  const kid = await calculateJwkThumbprint({ kty, crv, x, y }, 'sha256')
  return {
    kid,
    privateJwk: { kty, crv, x, y, d },
    publicJwk: { kty, crv, x, y, kid, alg: 'ES256', use: 'sig' },
  }
}
