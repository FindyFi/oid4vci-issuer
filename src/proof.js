import { importJWK, jwtVerify, decodeProtectedHeader } from 'jose'

// Accepted when a credential configuration does not name any algorithm
// itself. Asymmetric only, deliberately: the key a proof is checked against
// is the one the presenter published in the JWT's own header, so a proof
// signed with a MAC algorithm proves nothing at all - anyone can mint a
// symmetric key, sign with it, and hand over both.
export const DEFAULT_PROOF_SIGNING_ALGORITHMS = ['ES256', 'ES384', 'ES512', 'EdDSA', 'PS256', 'PS384', 'PS512']

// Verifies an OID4VCI proof-of-possession JWT: algorithm, signature (against
// the public key it embeds in its own `jwk` header), audience, typ, and that
// it carries a nonce claim at all. Whether that nonce was actually issued by
// this service and hasn't been used yet is checked separately, against the
// nonce store (see src/nonce.js) - the Nonce Endpoint is unauthenticated and
// decoupled from any specific access token, so there's no single "expected"
// nonce to compare against here.
// `allowedAlgorithms` should come from the credential configuration's
// proof_types_supported.jwt.proof_signing_alg_values_supported, so that what
// the metadata advertises and what this accepts cannot drift apart.
// The verified key is returned but - per this service's current
// bearer-credential design - never used for subject/holder binding; a
// future opt-in binding step would use `header.jwk` from here.
export async function verifyProof({ proofJwt, expectedAudience, allowedAlgorithms }) {
  if (!proofJwt) {
    throw new Error('Missing proof JWT.')
  }

  const algorithms = allowedAlgorithms?.length ? allowedAlgorithms : DEFAULT_PROOF_SIGNING_ALGORITHMS

  const header = decodeProtectedHeader(proofJwt)
  if (header.typ !== 'openid4vci-proof+jwt') {
    throw new Error(`Unexpected proof typ: ${header.typ}`)
  }
  if (!algorithms.includes(header.alg)) {
    throw new Error(`Unsupported proof signing algorithm: ${header.alg}. Expected one of ${algorithms.join(', ')}.`)
  }
  if (!header.jwk) {
    throw new Error('Proof JWT must embed the holder public key in its jwk header.')
  }
  // Belt and braces alongside the allowlist above: an asymmetric `alg` can
  // never legitimately arrive with a symmetric key, and the allowlist is
  // caller-supplied.
  if (header.jwk.kty === 'oct') {
    throw new Error('Proof JWT must be signed with an asymmetric key.')
  }

  const key = await importJWK(header.jwk, header.alg)
  const { payload } = await jwtVerify(proofJwt, key, { audience: expectedAudience, algorithms })

  if (!payload.nonce) {
    throw new Error('Proof JWT is missing the required nonce claim.')
  }

  return { header, payload }
}
