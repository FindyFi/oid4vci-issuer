import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { authorizationServerMetadata, issuerMetadata } from './metadata.js'
import { credentialJwks } from './jwt-vc-issuer.js'

// OpenID Federation 1.0 Entity Configuration, for DIIP v5 and the OpenID
// Federation Wallet Architectures profile. One document at
// /.well-known/openid-federation, a signed JWT whose `iss` and `sub` are the
// Entity Identifier, which is also the credential issuer identifier.

const OPTIONAL_METADATA_STRINGS = ['organization_name', 'homepage_uri', 'logo_uri', 'policy_uri']
const DEFAULT_TTL = 86400

function parseJson(name, value, what) {
  try {
    return JSON.parse(value)
  } catch {
    throw new Error(`${name} must be valid JSON (${what}).`)
  }
}

// Reads FEDERATION_* from `env`. Returns undefined when federation is off
// (FEDERATION_ENTITY_METADATA unset or empty), otherwise
// `{ entityMetadata, authorityHints, trustMarks, ttl }`. Throws a message
// naming the variable on anything invalid, so a mistake stops startup.
export function loadFederationConfig(env) {
  if (!env.FEDERATION_ENTITY_METADATA) {
    for (const name of ['FEDERATION_AUTHORITY_HINTS', 'FEDERATION_TRUST_MARKS', 'FEDERATION_ENTITY_CONFIGURATION_TTL']) {
      if (env[name]) console.warn(`${name} is ignored: federation is off until FEDERATION_ENTITY_METADATA is set.`)
    }
    return undefined
  }
  const entityMetadata = parseJson('FEDERATION_ENTITY_METADATA', env.FEDERATION_ENTITY_METADATA, 'a JSON object')
  const problem = checkEntityMetadata(entityMetadata)
  if (problem) throw new Error(`FEDERATION_ENTITY_METADATA: ${problem}`)

  let authorityHints = []
  if (env.FEDERATION_AUTHORITY_HINTS) {
    authorityHints = parseJson('FEDERATION_AUTHORITY_HINTS', env.FEDERATION_AUTHORITY_HINTS, 'a JSON array of https URLs')
    if (!Array.isArray(authorityHints) || !authorityHints.every((hint) => typeof hint === 'string' && isHttpsUrl(hint))) {
      throw new Error('FEDERATION_AUTHORITY_HINTS must be a JSON array of https URLs.')
    }
  }

  let trustMarks = []
  if (env.FEDERATION_TRUST_MARKS) {
    trustMarks = parseJson('FEDERATION_TRUST_MARKS', env.FEDERATION_TRUST_MARKS, 'a JSON array')
    if (!Array.isArray(trustMarks)) throw new Error('FEDERATION_TRUST_MARKS must be a JSON array.')
  }

  let ttl = DEFAULT_TTL
  if (env.FEDERATION_ENTITY_CONFIGURATION_TTL) {
    ttl = Number(env.FEDERATION_ENTITY_CONFIGURATION_TTL)
    if (!Number.isInteger(ttl) || ttl < 60) throw new Error('FEDERATION_ENTITY_CONFIGURATION_TTL must be a whole number of seconds, at least 60.')
  }
  return { entityMetadata, authorityHints, trustMarks, ttl }
}

function isHttpsUrl(value) {
  return URL.canParse(value) && new URL(value).protocol === 'https:'
}

// The federation_entity metadata: `display_name` is required by DIIP, the
// rest is passed through, but the members we know the shape of are checked.
// Returns an error message or undefined.
export function checkEntityMetadata(metadata) {
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) return 'must be a JSON object.'
  if (typeof metadata.display_name !== 'string' || !metadata.display_name.trim()) return 'needs a display_name (a non-empty string).'
  for (const name of OPTIONAL_METADATA_STRINGS) {
    if (metadata[name] !== undefined && typeof metadata[name] !== 'string') return `${name} must be a string.`
  }
  for (const name of ['homepage_uri', 'logo_uri', 'policy_uri']) {
    if (metadata[name] !== undefined && !isHttpsUrl(metadata[name])) return `${name} must be an https URL.`
  }
  if (metadata.contacts !== undefined && (!Array.isArray(metadata.contacts) || metadata.contacts.some((c) => typeof c !== 'string'))) {
    return 'contacts must be an array of strings.'
  }
}

// What createApp checks about federation next to the SD-JWT setup it builds on.
export function checkFederationSetup({ federation, sdJwt, credentialIssuer }) {
  if (!sdJwt) throw new Error('Federation needs SD_JWT_SIGNING_KEY: the Entity Configuration is signed with it.')
  if (sdJwt.issuer !== credentialIssuer) {
    throw new Error(
      `With federation on, SD_JWT_ISSUER (${sdJwt.issuer}) must equal CREDENTIAL_ISSUER (${credentialIssuer}): the Entity Identifier is also the credential issuer identifier.`
    )
  }
  const problem = checkEntityMetadata(federation.entityMetadata)
  if (problem) throw new Error(`Federation entity metadata: ${problem}`)
}

// Builds and signs the Entity Configuration payload. `federation.key` signs
// it (index.js passes the SD-JWT key for now; a separate federation key is a
// one-line change there). `sdJwt` supplies the credential-signing keys.
async function signEntityConfiguration({ credentialIssuer, credentialConfigurationsSupported, sdJwt, federation, now }) {
  const jwks = credentialJwks(sdJwt)
  const iat = Math.floor(now / 1000)
  const payload = {
    iss: credentialIssuer,
    sub: credentialIssuer,
    iat,
    exp: iat + federation.ttl,
    // The key that signs this statement. Every jwks is a JWK Set (Federation 5.2.1).
    jwks: { keys: [federation.key.publicJwk] },
    ...(federation.authorityHints.length ? { authority_hints: federation.authorityHints } : {}),
    ...(federation.trustMarks.length ? { trust_marks: federation.trustMarks } : {}),
    metadata: {
      federation_entity: federation.entityMetadata,
      // Federation wallet architectures: the credential-signing keys sit in the issuer metadata.
      openid_credential_issuer: { ...issuerMetadata({ credentialIssuer, credentialConfigurationsSupported }), jwks },
      // DIIP: the same keys again, where SD-JWT VC verifiers look.
      vc_issuer: { jwks },
      // DIIP: wallets use only this document's metadata, and 1.0 wallets find the token endpoint here.
      oauth_authorization_server: authorizationServerMetadata({ credentialIssuer }),
    },
  }
  const header = { typ: 'entity-statement+jwt', alg: 'ES256', kid: federation.key.kid }
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url')
  const signingInput = `${encode(header)}.${encode(payload)}`
  const signature = Buffer.from(await federation.key.sign(Buffer.from(signingInput))).toString('base64url')
  return { jws: `${signingInput}.${signature}` }
}

// GET /.well-known/openid-federation. The signed JWS is cached until
// shortly before it expires (the last tenth of its lifetime), so a KMS key
// is not asked to sign on every request.
export function createEntityConfigurationHandler({ credentialIssuer, credentialConfigurationsSupported, sdJwt, federation, now = Date.now }) {
  let cached // { promise, refreshAt }, shared by concurrent requests

  return async function entityConfigurationHandler(req, res) {
    if (!cached || now() >= cached.refreshAt) {
      const issuedAt = now()
      const promise = signEntityConfiguration({ credentialIssuer, credentialConfigurationsSupported, sdJwt, federation, now: issuedAt })
      const entry = { promise, refreshAt: issuedAt + federation.ttl * 900 }
      promise.catch(() => cached === entry && (cached = undefined))
      cached = entry
    }
    const { jws } = await cached.promise
    res.type('application/entity-statement+jwt').send(jws)
  }
}

// ---- Helpers for scripts/federation-metadata.js ----

// Builds FEDERATION_ENTITY_METADATA from answers (empty ones are dropped).
// `contacts` is an array of strings. Throws on an invalid result.
export function buildEntityMetadata({ displayName, organizationName, homepageUri, logoUri, policyUri, contacts = [] }) {
  const metadata = {
    display_name: displayName?.trim(),
    ...(organizationName?.trim() ? { organization_name: organizationName.trim() } : {}),
    ...(contacts.length ? { contacts } : {}),
    ...(homepageUri?.trim() ? { homepage_uri: homepageUri.trim() } : {}),
    ...(logoUri?.trim() ? { logo_uri: logoUri.trim() } : {}),
    ...(policyUri?.trim() ? { policy_uri: policyUri.trim() } : {}),
  }
  const problem = checkEntityMetadata(metadata)
  if (problem) throw new Error(problem)
  return metadata
}

// A `NAME='<json>'` line that dotenv, Docker Compose and a POSIX shell all
// read the same way. Single quotes take everything literally, so the only
// character that needs care is `'` itself, written as the JSON escape '.
export function envLine(name, value) {
  return `${name}='${JSON.stringify(value).replaceAll("'", '\\u0027')}'`
}

// Sets `lines` (NAME='…') in an env file: replaces an existing line for the
// same name (a commented-out `# NAME=` one too) in place, appends the rest.
// Creates the file when missing. Returns the names it replaced and appended.
export function upsertEnvFile(path, lines) {
  const text = existsSync(path) ? readFileSync(path, 'utf8') : ''
  const out = text === '' ? [] : text.replace(/\n$/, '').split('\n')
  const replaced = []
  const appended = []
  for (const line of lines) {
    const name = line.slice(0, line.indexOf('='))
    const at = out.findIndex((existing) => existing.replace(/^#\s*/, '').startsWith(`${name}=`))
    if (at >= 0) {
      out[at] = line
      replaced.push(name)
    } else {
      out.push(line)
      appended.push(name)
    }
  }
  writeFileSync(path, `${out.join('\n')}\n`)
  return { replaced, appended }
}
