import { SDJwtInstance } from '@sd-jwt/core'
import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs'

// Everything specific to the wallet credential format lives in this file:
// a W3C VCDM 2.0 credential secured as an SD-JWT, with no disclosures (we
// use the format for interoperability, not for selective disclosure) and no
// holder binding (no `cnf`). Switching to IETF SD-JWT VC (`dc+sd-jwt`, a
// `vct` and flat claims) should only need changes here.
export const SD_JWT_FORMAT = 'vc+sd-jwt'

function issuerOf(vc) {
  return typeof vc.issuer === 'string' ? vc.issuer : vc.issuer?.id
}

// Checks an unsigned credential at offer creation, so a coordinator learns
// about a mistake right away instead of the wallet getting a 500 later.
// Returns an error message, or undefined if the credential is acceptable.
// The issuer is never silently overwritten: the coordinator must already
// have put this service's SD-JWT issuer URL into the credential.
export function checkVcSdJwtCredential(vc, { issuer }) {
  if (!vc || typeof vc !== 'object' || Array.isArray(vc)) {
    return 'unsignedCredential must be a JSON object.'
  }
  if (issuerOf(vc) !== issuer) {
    return `The credential issuer must be ${issuer}.`
  }
  if (vc.validFrom !== undefined && Number.isNaN(Date.parse(vc.validFrom))) {
    return 'validFrom must be an ISO 8601 date-time.'
  }
}

// Returns a compact SD-JWT, `<jws>~`. The payload is the VC unchanged plus
// the JWT registered claims `iss`, `iat` and (when the VC has `validFrom`)
// `nbf`. With no disclosure frame the library adds neither `_sd` nor `_sd_alg`.
export async function signVcSdJwt(vc, { issuer, key }) {
  const sdjwt = new SDJwtInstance({
    signer: await ES256.getSigner(key.privateJwk),
    signAlg: ES256.alg,
    hasher: digest,
    saltGenerator: generateSalt,
  })
  const payload = { ...vc, iss: issuer, iat: Math.floor(Date.now() / 1000) }
  if (vc.validFrom !== undefined) payload.nbf = Math.floor(Date.parse(vc.validFrom) / 1000)
  return sdjwt.issue(payload, undefined, { header: { typ: SD_JWT_FORMAT, kid: key.kid } })
}
