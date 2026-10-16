// JWT VC Issuer Metadata (IETF SD-JWT VC, section 5): where a verifier finds
// the public key for an SD-JWT's `iss` and the JOSE header's `kid`. The
// issuer is origin-only (enforced in src/app.js), so this is served at plain
// /.well-known/jwt-vc-issuer.
export function createJwtVcIssuerHandler({ issuer, key }) {
  return function jwtVcIssuerHandler(req, res) {
    res.json({ issuer, jwks: { keys: [key.publicJwk] } })
  }
}
