import { credentialJwks } from './jwt-vc-issuer.js'

// A did:web DID Document for the credential issuer's host, at
// /.well-known/did.json (where wallets look: {credential_issuer}/.well-known/
// did.json, and where did:web resolves), listing the credential-signing keys. Credentials
// keep the plain HTTPS URL as `iss`; this is only for wallets that identify
// every issuer by a DID (UniMe requires it, and DIIP v5 asks for did:web
// support). Each verification method's fragment is the key's kid, the same
// kid as in SD-JWT headers and the JWKS, and earlier keys stay listed so
// older credentials still resolve.
export function didWeb(credentialIssuer) {
  // did:web percent-encodes a port's colon.
  return `did:web:${encodeURIComponent(new URL(credentialIssuer).host)}`
}

export function didDocument({ credentialIssuer, sdJwt }) {
  const id = didWeb(credentialIssuer)
  const verificationMethod = credentialJwks(sdJwt).keys.map((publicKeyJwk) => ({
    id: `${id}#${publicKeyJwk.kid}`,
    type: 'JsonWebKey2020',
    controller: id,
    publicKeyJwk,
  }))
  const ids = verificationMethod.map((method) => method.id)
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    id,
    verificationMethod,
    assertionMethod: ids,
    authentication: ids,
  }
}

export function createDidDocumentHandler(options) {
  return function didDocumentHandler(req, res) {
    res.json(didDocument(options))
  }
}
