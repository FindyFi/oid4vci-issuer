import { SDJwtInstance } from '@sd-jwt/core'
import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs'

// Everything specific to the wallet credential formats lives in this file.
// Both are SD-JWTs with no disclosures (we use the format for
// interoperability, not for selective disclosure):
// - `vc+sd-jwt`: a W3C VCDM 2.0 credential secured as an SD-JWT.
// - `dc+sd-jwt`: IETF SD-JWT VC, flat claims identified by a `vct`.
// Holder binding (`cnf.jwk`, the key from the wallet's proof JWT) is added
// when the configuration lists `jwk` in cryptographic_binding_methods_supported.
export const VC_SD_JWT = 'vc+sd-jwt'
export const DC_SD_JWT = 'dc+sd-jwt'
export const SD_JWT_FORMATS = [VC_SD_JWT, DC_SD_JWT]

// Claims this service sets itself; a coordinator must not supply them.
const RESERVED_DC_CLAIMS = ['iss', 'iat', 'nbf', 'exp', 'cnf', '_sd', '_sd_alg', 'vct#integrity']

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
export function checkSdJwtCredential(credential, configuration, { issuer }) {
  if (!credential || typeof credential !== 'object' || Array.isArray(credential)) {
    return 'unsignedCredential must be a JSON object.'
  }
  if (configuration.format === DC_SD_JWT) {
    if (credential.vct !== configuration.vct) return `The credential vct must be ${configuration.vct}.`
    const reserved = RESERVED_DC_CLAIMS.filter((claim) => claim in credential)
    if (reserved.length) return `These claims are set by the issuer and must not be in the credential: ${reserved.join(', ')}.`
    return
  }
  if (issuerOf(credential) !== issuer) {
    return `The credential issuer must be ${issuer}.`
  }
  if (credential.validFrom !== undefined && Number.isNaN(Date.parse(credential.validFrom))) {
    return 'validFrom must be an ISO 8601 date-time.'
  }
}

// Returns a compact SD-JWT, `<jws>~`. The payload is the credential
// unchanged plus `iss`, `iat`, `cnf` (when binding), `vct#integrity` (from
// the configuration, see src/vct-integrity.js) and, for a vc+sd-jwt
// with `validFrom`, `nbf`. With no disclosure frame the library adds
// neither `_sd` nor `_sd_alg`. The header carries `x5c` when a certificate
// chain is configured (see src/x5c.js).
export async function signSdJwt(credential, configuration, { issuer, key, x5c }, { holderJwk } = {}) {
  const sdjwt = new SDJwtInstance({
    signer: await ES256.getSigner(key.privateJwk),
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
  if (bindsHolder(configuration)) {
    if (!holderJwk) throw new Error('Holder binding needs the public key from the proof JWT.')
    payload.cnf = { jwk: publicJwk(holderJwk) }
  }
  const header = { typ: configuration.format, kid: key.kid, ...(x5c ? { x5c } : {}) }
  return sdjwt.issue(payload, undefined, { header })
}

// Only the public members of the wallet's key, in case a wallet sends extras.
function publicJwk({ kty, crv, x, y, n, e }) {
  return Object.fromEntries(Object.entries({ kty, crv, x, y, n, e }).filter(([, v]) => v !== undefined))
}

// SD-JWT VC Type Metadata for a dc+sd-jwt configuration, built from its
// credential_metadata.display so the names live in one place. Older drafts
// called the display language `lang`, newer ones `locale`; both are given.
export function typeMetadata(configuration) {
  const display = (configuration.credential_metadata?.display ?? []).map(({ name, description, locale }) => ({
    ...(locale ? { locale, lang: locale } : {}),
    name,
    ...(description ? { description } : {}),
  }))
  return { vct: configuration.vct, ...(display[0]?.name ? { name: display[0].name } : {}), display }
}
