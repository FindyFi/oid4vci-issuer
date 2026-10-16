import express from 'express'
import { createStore } from './store.js'
import { createOfferHandlers } from './offers.js'
import { createTokenHandler } from './token.js'
import { createNonceHandler } from './nonce.js'
import { createCredentialHandler } from './credential.js'
import { createAuthorizationServerMetadataHandler, createMetadataHandler } from './metadata.js'
import { requireCoordinatorToken } from './auth.js'

// Builds the Express app from explicit config, without reading the
// environment or listening on a port, so tests can start it on a random port
// with a stubbed signer. index.js is the only place that reads env vars.
export function createApp({ credentialIssuer, credentialConfigurationsSupported, coordinatorToken, signCredential, store = createStore() }) {
  const app = express()
  app.use(express.json())
  app.use(express.urlencoded({ extended: false })) // the token endpoint is a plain OAuth2 form post

  const { createOffer, getOffer, getOfferStatus } = createOfferHandlers({ store, credentialIssuer })
  const tokenHandler = createTokenHandler({ store })
  const nonceHandler = createNonceHandler({ store })
  const credentialHandler = createCredentialHandler({
    store,
    credentialIssuer,
    credentialConfigurationsSupported,
    signCredential,
  })
  const metadataHandler = createMetadataHandler({ credentialIssuer, credentialConfigurationsSupported })
  const authorizationServerMetadataHandler = createAuthorizationServerMetadataHandler({ credentialIssuer })
  const coordinatorAuth = requireCoordinatorToken(coordinatorToken)

  app.get('/healthz', (req, res) => res.sendStatus(200))

  // Wallet-facing (public, per spec)
  app.get('/.well-known/openid-credential-issuer', metadataHandler)
  // Both paths serve the same RFC 8414 document: wallets look for the first,
  // and fall back to the second.
  app.get('/.well-known/oauth-authorization-server', authorizationServerMetadataHandler)
  app.get('/.well-known/openid-configuration', authorizationServerMetadataHandler)
  app.get('/instance/:tenant/offers/:code', getOffer)
  app.get('/instance/:tenant/offers/:code/status', getOfferStatus)
  app.post('/token', tokenHandler)
  app.post('/nonce', nonceHandler)
  app.post('/credential', credentialHandler)

  // Coordinator-facing (should not be publicly exposed; guarded by a shared
  // bearer token when COORDINATOR_TOKEN is set)
  app.post('/instance/:tenant/offers', coordinatorAuth, createOffer)

  return app
}
