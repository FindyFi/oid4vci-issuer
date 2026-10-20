import express from 'express'
import { createStore } from './store.js'
import { createOfferHandlers } from './offers.js'
import { createTokenHandler } from './token.js'
import { authorizeHandler } from './authorize.js'
import { createNonceHandler } from './nonce.js'
import { createCredentialHandler } from './credential.js'
import { createNotificationHandler } from './notification.js'
import { checkDisplay, createAuthorizationServerMetadataHandler, createMetadataHandler } from './metadata.js'
import { requireCoordinatorToken } from './auth.js'
import { createSigners } from './signers.js'
import { createJwtVcIssuerHandler } from './jwt-vc-issuer.js'
import { createDidDocumentHandler } from './did-web.js'
import { checkFederationSetup, createEntityConfigurationHandler, withDisplayDefaults } from './federation.js'

// Builds the Express app from explicit config, without reading the
// environment or listening on a port, so tests can start it on a random port
// with a stubbed signing-service. index.js is the only place that reads env
// vars. `signLdpVc` signs `ldp_vc` credentials (signing-service); `sdJwt`
// ({ issuer, key }) signs SD-JWT credentials with this service's own key.
// Throws if a configuration's format can't be served with what was given.
// `display` is the issuer display for the issuer metadata (optional).
export function createApp({ credentialIssuer, credentialConfigurationsSupported, coordinatorToken, signLdpVc, sdJwt, store = createStore(), logRequests = false, federation, display }) {
  if (display !== undefined) {
    const problem = checkDisplay(display)
    if (problem) throw new Error(`Issuer metadata: ${problem}`)
  }
  if (sdJwt) {
    let url
    try {
      url = new URL(sdJwt.issuer)
    } catch {
      throw new Error(`The SD-JWT issuer must be a URL: ${sdJwt.issuer}`)
    }
    // Origin-only, so the JWT VC Issuer Metadata lives at plain
    // /.well-known/jwt-vc-issuer instead of a path-suffixed well-known URL.
    if (url.origin !== sdJwt.issuer) {
      throw new Error(`The SD-JWT issuer must be an origin with no path or trailing slash, e.g. ${url.origin}`)
    }
  }
  // `federation` ({ key, entityMetadata, authorityHints, trustMarks, ttl })
  // turns on the OpenID Federation Entity Configuration, and credentials
  // then carry `fed`.
  if (federation) {
    federation = { ...federation, entityMetadata: withDisplayDefaults(federation.entityMetadata, display) }
    checkFederationSetup({ federation, sdJwt, credentialIssuer })
    sdJwt = { ...sdJwt, fed: credentialIssuer }
  }
  const signers = createSigners({ credentialConfigurationsSupported, signLdpVc, sdJwt })

  const app = express()
  if (logRequests) app.use(requestLogger)
  app.use(express.json())
  app.use(express.urlencoded({ extended: false })) // the token endpoint is a plain OAuth2 form post

  const { createOffer, getOffer, getOfferStatus } = createOfferHandlers({ store, credentialIssuer, checkOffer: signers.checkOffer })
  const tokenHandler = createTokenHandler({ store })
  const nonceHandler = createNonceHandler({ store })
  const credentialHandler = createCredentialHandler({
    store,
    credentialIssuer,
    credentialConfigurationsSupported,
    signCredential: signers.sign,
  })
  const metadataHandler = createMetadataHandler({ credentialIssuer, credentialConfigurationsSupported, display })
  const authorizationServerMetadataHandler = createAuthorizationServerMetadataHandler({ credentialIssuer })
  const coordinatorAuth = requireCoordinatorToken(coordinatorToken)

  app.get('/healthz', (req, res) => res.sendStatus(200))

  // Wallet-facing (public, per spec)
  app.get('/.well-known/openid-credential-issuer', metadataHandler)
  // Both paths serve the same RFC 8414 document: wallets look for the first,
  // and fall back to the second.
  app.get('/.well-known/oauth-authorization-server', authorizationServerMetadataHandler)
  app.get('/.well-known/openid-configuration', authorizationServerMetadataHandler)
  if (sdJwt) app.get('/.well-known/jwt-vc-issuer', createJwtVcIssuerHandler(sdJwt))
  if (sdJwt) app.get('/.well-known/did.json', createDidDocumentHandler({ credentialIssuer, sdJwt }))
  if (federation) {
    app.get(
      '/.well-known/openid-federation',
      createEntityConfigurationHandler({ credentialIssuer, credentialConfigurationsSupported, display, sdJwt, federation })
    )
  }
  app.get('/instance/:tenant/offers/:code', getOffer)
  app.get('/instance/:tenant/offers/:code/status', getOfferStatus)
  app.get('/authorize', authorizeHandler)
  app.post('/token', tokenHandler)
  app.post('/nonce', nonceHandler)
  app.post('/credential', credentialHandler)
  app.post('/notification', createNotificationHandler({ store, logRequests }))

  // Coordinator-facing (should not be publicly exposed; guarded by a shared
  // bearer token when COORDINATOR_TOKEN is set)
  app.post('/instance/:tenant/offers', coordinatorAuth, createOffer)

  return app
}

// Interop debugging aid (LOG_REQUESTS=1): one line per request with the
// request body's shape and, for errors, the JSON error the client got.
// Values are left out; only the proof JWT's protected header is shown.
function requestLogger(req, res, next) {
  let errorBody
  const json = res.json.bind(res)
  res.json = (body) => {
    if (res.statusCode >= 400) errorBody = body
    return json(body)
  }
  res.on('finish', () => {
    const shape = req.body && Object.keys(req.body).length ? ` body=${JSON.stringify(describe(req.body))}` : ''
    const error = errorBody ? ` error=${JSON.stringify(errorBody)}` : ''
    console.log(`${req.method} ${req.originalUrl} -> ${res.statusCode}${shape}${error} ua=${JSON.stringify(req.get('user-agent') || '')}`)
  })
  next()
}

function describe(value) {
  if (Array.isArray(value)) return value.map(describe)
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, describe(v)]))
  if (typeof value === 'string' && value.split('.').length === 3) {
    try {
      return { jwtHeader: JSON.parse(Buffer.from(value.split('.')[0], 'base64url')) }
    } catch {}
  }
  return typeof value
}
