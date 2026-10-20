// The document builders are shared with the OpenID Federation Entity
// Configuration (src/federation.js), which embeds both, so there is one
// source for what this service says about itself. The issuer `display` also
// fills in the federation_entity name and logo (withDisplayDefaults there).
export function issuerMetadata({ credentialIssuer, credentialConfigurationsSupported, display }) {
  return {
    credential_issuer: credentialIssuer,
    credential_endpoint: `${credentialIssuer}/credential`,
    token_endpoint: `${credentialIssuer}/token`,
    // Required whenever a credential_configurations_supported entry
    // declares proof_types_supported (OID4VCI 1.0 Section 12.2.4) - this
    // service always requires a proof, so it always advertises this.
    nonce_endpoint: `${credentialIssuer}/nonce`,
    // Who issues, for wallets to show: one entry per locale.
    ...(display ? { display } : {}),
    credential_configurations_supported: credentialConfigurationsSupported,
  }
}

// OID4VCI_ISSUER_METADATA: the issuer metadata members that are configured
// rather than derived. Only `display` so far; anything else is refused, so a
// typo doesn't go unnoticed.
const CONFIGURED_MEMBERS = ['display']
const DISPLAY_MEMBERS = ['locale', 'name', 'logo']
const LOGO_MEMBERS = ['uri', 'alt_text']

// Returns the parsed object ({} when unset). Throws a message naming the
// variable on anything invalid, so a mistake stops startup.
export function loadIssuerMetadataConfig(env) {
  if (!env.OID4VCI_ISSUER_METADATA) return {}
  let config
  try {
    config = JSON.parse(env.OID4VCI_ISSUER_METADATA)
  } catch {
    throw new Error('OID4VCI_ISSUER_METADATA must be valid JSON (a JSON object).')
  }
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('OID4VCI_ISSUER_METADATA must be a JSON object.')
  const unknown = Object.keys(config).filter((name) => !CONFIGURED_MEMBERS.includes(name))
  if (unknown.length) throw new Error(`OID4VCI_ISSUER_METADATA: unsupported ${unknown.join(', ')} (only ${CONFIGURED_MEMBERS.join(', ')}).`)
  const problem = config.display === undefined ? undefined : checkDisplay(config.display)
  if (problem) throw new Error(`OID4VCI_ISSUER_METADATA: ${problem}`)
  return config
}

// The issuer `display` (OID4VCI 1.0 Section 12.2.4): a non-empty array, at
// most one entry per locale (and at most one without), each with a `name`
// and optionally a `logo` whose `uri` is https or a data: URI. Returns an
// error message or undefined.
export function checkDisplay(display) {
  if (!Array.isArray(display) || !display.length) return 'display must be a non-empty array.'
  const locales = new Set()
  for (const [i, entry] of display.entries()) {
    const at = `display[${i}]`
    if (!isObject(entry)) return `${at} must be an object.`
    const unknown = Object.keys(entry).filter((name) => !DISPLAY_MEMBERS.includes(name))
    if (unknown.length) return `${at}: unsupported ${unknown.join(', ')} (only ${DISPLAY_MEMBERS.join(', ')}).`
    if (typeof entry.name !== 'string' || !entry.name.trim()) return `${at} needs a name (a non-empty string).`
    if (entry.locale !== undefined && (typeof entry.locale !== 'string' || !LANGUAGE_TAG.test(entry.locale))) {
      return `${at}.locale must be a language tag such as fi or en-GB.`
    }
    const locale = entry.locale?.toLowerCase() ?? ''
    if (locales.has(locale)) return entry.locale ? `${at}: a second entry for ${entry.locale}.` : `${at}: a second entry without a locale.`
    locales.add(locale)
    if (entry.logo !== undefined) {
      if (!isObject(entry.logo)) return `${at}.logo must be an object.`
      const unknownLogo = Object.keys(entry.logo).filter((name) => !LOGO_MEMBERS.includes(name))
      if (unknownLogo.length) return `${at}.logo: unsupported ${unknownLogo.join(', ')} (only ${LOGO_MEMBERS.join(', ')}).`
      if (!isLogoUri(entry.logo.uri)) return `${at}.logo.uri must be an https URL or a data: URI.`
      if (entry.logo.alt_text !== undefined && typeof entry.logo.alt_text !== 'string') return `${at}.logo.alt_text must be a string.`
    }
  }
}

// BCP 47 in its common shape (language, then subtags); not a full grammar.
const LANGUAGE_TAG = /^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$/

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

function isLogoUri(value) {
  if (typeof value !== 'string' || !URL.canParse(value)) return false
  const { protocol } = new URL(value)
  return protocol === 'https:' || protocol === 'data:'
}

// For scripts/issuer-metadata.js: builds OID4VCI_ISSUER_METADATA from
// answers. `names` and `altTexts` map a locale to its text; one logo serves
// every locale. Empty answers are dropped. Throws on an invalid result.
export function buildIssuerMetadataConfig({ locales, names = {}, logoUri, altTexts = {} }) {
  const display = locales.map((locale) => {
    const altText = altTexts[locale]?.trim()
    return {
      locale,
      name: names[locale]?.trim(),
      ...(logoUri?.trim() ? { logo: { uri: logoUri.trim(), ...(altText ? { alt_text: altText } : {}) } } : {}),
    }
  })
  const problem = checkDisplay(display)
  if (problem) throw new Error(problem)
  return { display }
}

export function createMetadataHandler(options) {
  return function metadataHandler(req, res) {
    res.json(issuerMetadata(options))
  }
}

// RFC 8414 authorization server metadata.
//
// The credential issuer metadata above carries a `token_endpoint`, which is
// enough for a client that reads it directly - but that is not how wallets
// discover the token endpoint. OID4VCI 1.0 Section 11.2.3 says that when the
// issuer metadata has no `authorization_servers`, the credential issuer *is*
// the authorization server, and its metadata is retrieved per RFC 8414 from
// `/.well-known/oauth-authorization-server`. Wallets that follow that path -
// Procivis does - get a 404 and abort the invitation before they ever reach
// `/token`, with an error that only says the metadata download failed.
//
// `/.well-known/openid-configuration` is served from the same document
// because it is the conventional fallback a wallet tries next.
export function authorizationServerMetadata({ credentialIssuer }) {
  return {
    issuer: credentialIssuer,
    // Pre-authorized code is the only flow this service implements, so the
    // authorization endpoint only answers with an error (src/authorize.js)
    // and no response type is supported. RFC 8414 makes
    // `authorization_endpoint` REQUIRED only when a grant uses it, but
    // Toppan rejects metadata without one ("In valid authorization
    // endpoint"); `response_types_supported` is REQUIRED, and the empty list
    // says exactly what we support.
    authorization_endpoint: `${credentialIssuer}/authorize`,
    token_endpoint: `${credentialIssuer}/token`,
    response_types_supported: [],
    grant_types_supported: ['urn:ietf:params:oauth:grant-type:pre-authorized_code'],
    // The token endpoint takes the pre-authorized code itself as the
    // credential; it authenticates no client.
    token_endpoint_auth_methods_supported: ['none'],
    'pre-authorized_grant_anonymous_access_supported': true,
  }
}

export function createAuthorizationServerMetadataHandler(options) {
  return function authorizationServerMetadataHandler(req, res) {
    res.json(authorizationServerMetadata(options))
  }
}
