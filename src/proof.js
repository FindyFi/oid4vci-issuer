import { importJWK, jwtVerify, decodeProtectedHeader } from 'jose'

// Accepted when a credential configuration does not name any algorithm
// itself. Asymmetric only, deliberately: the key a proof is checked against
// is the one the presenter published in the JWT's own header, so a proof
// signed with a MAC algorithm proves nothing at all - anyone can mint a
// symmetric key, sign with it, and hand over both.
export const DEFAULT_PROOF_SIGNING_ALGORITHMS = ['ES256', 'ES384', 'ES512', 'EdDSA', 'PS256', 'PS384', 'PS512']

// Verifies an OID4VCI proof-of-possession JWT: algorithm, signature (against
// the holder key in its header, see holderKeyOf), audience, typ, and that
// it carries a nonce claim at all. Whether that nonce was actually issued by
// this service and hasn't been used yet is checked separately, against the
// nonce store (see src/nonce.js) - the Nonce Endpoint is unauthenticated and
// decoupled from any specific access token, so there's no single "expected"
// nonce to compare against here.
// `allowedAlgorithms` should come from the credential configuration's
// proof_types_supported.jwt.proof_signing_alg_values_supported, so that what
// the metadata advertises and what this accepts cannot drift apart.
// The verified key (`holderJwk`, and `holderKid` when the wallet named it by a
// DID URL) becomes the credential's `cnf` when the configuration binds the
// holder (see src/sdjwt.js).
// `aud` must be the Credential Issuer Identifier (App. F.1); one trailing
// slash more or less is tolerated (UniMe sends `<issuer>/`).
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
  const { holderJwk, holderKid } = holderKeyOf(header)
  // Belt and braces alongside the allowlist above: an asymmetric `alg` can
  // never legitimately arrive with a symmetric key, and the allowlist is
  // caller-supplied.
  if (holderJwk.kty === 'oct') {
    throw new Error('Proof JWT must be signed with an asymmetric key.')
  }

  const key = await importJWK(holderJwk, header.alg)
  const audience = expectedAudience.replace(/\/$/, '')
  const { payload } = await jwtVerify(proofJwt, key, { audience: [audience, `${audience}/`], algorithms })

  if (!payload.nonce) {
    throw new Error('Proof JWT is missing the required nonce claim.')
  }

  return { header, payload, holderJwk, holderKid }
}

const DID_JWK = 'did:jwk:'

// App. F.1 lets the wallet give the key as `jwk`, as `kid` (a DID URL, for
// binding to a DID) or as `x5c`. `jwk` and `did:jwk` URLs are accepted:
// a did:jwk carries the JWK itself, so nothing is fetched (UniMe sends one;
// DIIP v5 requires did:jwk support). When both `jwk` and `kid` are present,
// which the spec forbids, `jwk` wins and `kid` is taken as a plain key id.
function holderKeyOf(header) {
  if (header.jwk) return { holderJwk: header.jwk }
  if (typeof header.kid === 'string' && header.kid.startsWith(DID_JWK)) {
    const [did] = header.kid.split('#')
    let jwk
    try {
      jwk = JSON.parse(Buffer.from(did.slice(DID_JWK.length), 'base64url').toString('utf8'))
    } catch {}
    if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk) || 'd' in jwk) {
      throw new Error('The did:jwk in the proof kid must hold a public JWK.')
    }
    return { holderJwk: jwk, holderKid: header.kid }
  }
  if (header.kid) {
    throw new Error('Unsupported proof kid: only did:jwk DID URLs can be resolved. Put the key in the jwk header instead.')
  }
  throw new Error('Proof JWT must name the holder key, in its jwk header or as a did:jwk kid.')
}
