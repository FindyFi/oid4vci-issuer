import { SDJwtInstance } from '@sd-jwt/core'
import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs'

// Everything specific to the wallet credential formats lives in this file.
// - `vc+sd-jwt`: a W3C VCDM 2.0 credential secured as an SD-JWT with no
//   disclosures (the format for interoperability only).
// - `dc+sd-jwt`: IETF SD-JWT VC, flat claims identified by a `vct`. The
//   coordinator may name top-level claims to make selectively disclosable
//   (`disclosable` in the offer); everything else is always disclosed.
// Holder binding (`cnf.jwk`, the key from the wallet's proof JWT) is added
// when the configuration lists `jwk` in cryptographic_binding_methods_supported.
export const VC_SD_JWT = 'vc+sd-jwt'
export const DC_SD_JWT = 'dc+sd-jwt'
export const SD_JWT_FORMATS = [VC_SD_JWT, DC_SD_JWT]

// Claims this service sets itself; a coordinator must not supply them.
const RESERVED_DC_CLAIMS = ['iss', 'iat', 'nbf', 'exp', 'cnf', '_sd', '_sd_alg', 'vct#integrity', 'fed']
// Claims SD-JWT VC (section 3.2.2) says must never be selectively disclosable,
// among those a coordinator may send.
const ALWAYS_DISCLOSED_DC_CLAIMS = ['vct', 'status']

function issuerOf(vc) {
  return typeof vc.issuer === 'string' ? vc.issuer : vc.issuer?.id
}

export function bindsHolder(configuration) {
  return configuration.cryptographic_binding_methods_supported?.includes('jwk') ?? false
}

// Checks a configuration at startup. Returns an error message or undefined.
export function checkSdJwtConfiguration(configuration) {
  if (configuration.format === DC_SD_JWT && typeof configuration.vct !== 'string') {
    return 'a dc+sd-jwt configuration needs a vct.'
  }
}

// Checks an unsigned credential at offer creation, so a coordinator learns
// about a mistake right away instead of the wallet getting a 500 later.
// Returns an error message, or undefined if the credential is acceptable.
// Nothing is silently overwritten: the coordinator must already have put
// this service's SD-JWT issuer URL (vc+sd-jwt) or the configuration's vct
// (dc+sd-jwt) into the credential.
export function checkSdJwtCredential(credential, configuration, { issuer }, { disclosable } = {}) {
  if (!credential || typeof credential !== 'object' || Array.isArray(credential)) {
    return 'unsignedCredential must be a JSON object.'
  }
  if (configuration.format === DC_SD_JWT) {
    if (credential.vct !== configuration.vct) return `The credential vct must be ${configuration.vct}.`
    const reserved = RESERVED_DC_CLAIMS.filter((claim) => claim in credential)
    if (reserved.length) return `These claims are set by the issuer and must not be in the credential: ${reserved.join(', ')}.`
    return checkDisclosable(disclosable, credential)
  }
  if (disclosable !== undefined) return 'disclosable is only supported for dc+sd-jwt configurations.'
  if (issuerOf(credential) !== issuer) {
    return `The credential issuer must be ${issuer}.`
  }
  if (credential.validFrom !== undefined && Number.isNaN(Date.parse(credential.validFrom))) {
    return 'validFrom must be an ISO 8601 date-time.'
  }
}

// `disclosable`: the names of top-level claims to make selectively
// disclosable. Each must be in the credential (a disclosure frame naming a
// missing claim would silently do nothing) and none may be one that must
// always be disclosed.
function checkDisclosable(disclosable, credential) {
  if (disclosable === undefined) return
  if (!Array.isArray(disclosable) || !disclosable.every((claim) => typeof claim === 'string')) {
    return 'disclosable must be an array of claim names.'
  }
  if (new Set(disclosable).size !== disclosable.length) return 'disclosable must not repeat a claim.'
  const missing = disclosable.filter((claim) => !Object.hasOwn(credential, claim))
  if (missing.length) return `disclosable names claims that are not in the credential: ${missing.join(', ')}.`
  const fixed = disclosable.filter((claim) => ALWAYS_DISCLOSED_DC_CLAIMS.includes(claim))
  if (fixed.length) return `These claims must always be disclosed: ${fixed.join(', ')}.`
}

// Returns a compact SD-JWT: `<jws>~`, or for a dc+sd-jwt with `disclosable`
// claims `<jws>~<disclosure>~…~`, where those claims are replaced by digests
// in `_sd` (with `_sd_alg: sha-256`) and travel as disclosures. The payload is the credential
// unchanged plus `iss`, `iat`, `cnf` (when binding), `vct#integrity` (from
// the configuration, see src/vct-integrity.js), `fed` (dc+sd-jwt) or a
// `termsOfUse` entry (vc+sd-jwt), when federation is on and, for a vc+sd-jwt
// with `validFrom`, `nbf`. With no disclosure frame the library adds
// neither `_sd` nor `_sd_alg`. The header carries `x5c` when a certificate
// chain is configured (see src/x5c.js).
export async function signSdJwt(credential, configuration, { issuer, key, x5c, fed }, { holderJwk, disclosable } = {}) {
  const sdjwt = new SDJwtInstance({
    // key.sign is a local key or KMS (src/keys.js); the library wants base64url.
    signer: async (data) => Buffer.from(await key.sign(Buffer.from(data))).toString('base64url'),
    signAlg: ES256.alg,
    hasher: digest,
    saltGenerator: generateSalt,
  })
  const payload = { ...credential, iss: issuer, iat: Math.floor(Date.now() / 1000) }
  if (configuration.format === VC_SD_JWT && credential.validFrom !== undefined) {
    payload.nbf = Math.floor(Date.parse(credential.validFrom) / 1000)
  }
  if (configuration.format === DC_SD_JWT && configuration['vct#integrity']) {
    payload['vct#integrity'] = configuration['vct#integrity']
  }
  // The OpenID Federation Entity Identifier, when federation is on (DIIP).
  if (configuration.format === DC_SD_JWT && fed) payload.fed = fed
  // The VCDM 2.0 counterpart: a termsOfUse entry, kept next to any the coordinator sent.
  if (configuration.format === VC_SD_JWT && fed) {
    const own = [].concat(credential.termsOfUse ?? [])
    payload.termsOfUse = [...own, { type: 'OpenIDFederation', policyId: fed }]
  }
  if (bindsHolder(configuration)) {
    if (!holderJwk) throw new Error('Holder binding needs the public key from the proof JWT.')
    payload.cnf = { jwk: publicJwk(holderJwk) }
  }
  const header = { typ: configuration.format, kid: key.kid, ...(x5c ? { x5c } : {}) }
  const frame = configuration.format === DC_SD_JWT && disclosable?.length ? { _sd: disclosable } : undefined
  return sdjwt.issue(payload, frame, { header })
}

// Only the public members of the wallet's key, in case a wallet sends extras.
function publicJwk({ kty, crv, x, y, n, e }) {
  return Object.fromEntries(Object.entries({ kty, crv, x, y, n, e }).filter(([, v]) => v !== undefined))
}
