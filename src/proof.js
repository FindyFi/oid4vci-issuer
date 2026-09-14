import { importJWK, jwtVerify, decodeProtectedHeader } from 'jose'

// Verifies an OID4VCI proof-of-possession JWT: signature (against the
// public key it embeds in its own `jwk` header), audience, typ, and that it
// carries a nonce claim at all. Whether that nonce was actually issued by
// this service and hasn't been used yet is checked separately, against the
// nonce store (see src/nonce.js) - the Nonce Endpoint is unauthenticated and
// decoupled from any specific access token, so there's no single "expected"
// nonce to compare against here.
// The verified key is returned but - per this service's current
// bearer-credential design - never used for subject/holder binding; a
// future opt-in binding step would use `header.jwk` from here.
export async function verifyProof({ proofJwt, expectedAudience }) {
  if (!proofJwt) {
    throw new Error('Missing proof JWT.')
  }

  const header = decodeProtectedHeader(proofJwt)
  if (header.typ !== 'openid4vci-proof+jwt') {
    throw new Error(`Unexpected proof typ: ${header.typ}`)
  }
  if (!header.jwk) {
    throw new Error('Proof JWT must embed the holder public key in its jwk header.')
  }

  const key = await importJWK(header.jwk, header.alg)
  const { payload } = await jwtVerify(proofJwt, key, { audience: expectedAudience })

  if (!payload.nonce) {
    throw new Error('Proof JWT is missing the required nonce claim.')
  }

  return { header, payload }
}
