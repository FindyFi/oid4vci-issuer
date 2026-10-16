// JWT VC Issuer Metadata (IETF SD-JWT VC, section 5): where a verifier finds
// the public key for an SD-JWT's `iss` and the JOSE header's `kid`. The
// issuer is origin-only (enforced in src/app.js), so this is served at plain
// /.well-known/jwt-vc-issuer. After a key rotation, `previousKeys` (public
// JWKs) stay listed after the current key so older credentials still verify.
export function createJwtVcIssuerHandler({ issuer, key, previousKeys = [] }) {
  return function jwtVcIssuerHandler(req, res) {
    res.json({ issuer, jwks: { keys: [key.publicJwk, ...previousKeys.filter(({ kid }) => kid !== key.kid)] } })
  }
}
