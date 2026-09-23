import 'dotenv/config'
import express from 'express'
import { createStore } from './src/store.js'
import { createOfferHandlers } from './src/offers.js'
import { createTokenHandler } from './src/token.js'
import { createNonceHandler } from './src/nonce.js'
import { createCredentialHandler } from './src/credential.js'
import { createAuthorizationServerMetadataHandler, createMetadataHandler } from './src/metadata.js'
import { callSigningService } from './src/signing.js'
import { requireCoordinatorToken } from './src/auth.js'

const PORT = process.env.PORT || 4007
const CREDENTIAL_ISSUER = process.env.CREDENTIAL_ISSUER

if (!CREDENTIAL_ISSUER) {
  throw new Error("CREDENTIAL_ISSUER must be set to this service's own public base URL.")
}

let credentialConfigurationsSupported
try {
  credentialConfigurationsSupported = JSON.parse(process.env.CREDENTIAL_CONFIGURATIONS_SUPPORTED || '{}')
} catch {
  throw new Error('CREDENTIAL_CONFIGURATIONS_SUPPORTED must be valid JSON.')
}

const app = express()
app.use(express.json())
app.use(express.urlencoded({ extended: false })) // the token endpoint is a plain OAuth2 form post

const store = createStore()

const { createOffer, getOffer, getOfferStatus } = createOfferHandlers({ store, credentialIssuer: CREDENTIAL_ISSUER })
const tokenHandler = createTokenHandler({ store })
const nonceHandler = createNonceHandler({ store })
const credentialHandler = createCredentialHandler({
  store,
  credentialIssuer: CREDENTIAL_ISSUER,
  credentialConfigurationsSupported,
  signCredential: (vc) =>
    callSigningService(vc, {
      baseUrl: process.env.SIGNING_SERVICE_URL,
      instanceId: process.env.SIGNING_SERVICE_INSTANCE,
      suite: process.env.SIGNING_SERVICE_SUITE,
    }),
})
const metadataHandler = createMetadataHandler({
  credentialIssuer: CREDENTIAL_ISSUER,
  credentialConfigurationsSupported,
})
const authorizationServerMetadataHandler = createAuthorizationServerMetadataHandler({
  credentialIssuer: CREDENTIAL_ISSUER,
})
const coordinatorAuth = requireCoordinatorToken(process.env.COORDINATOR_TOKEN)

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

app.listen(PORT, () => {
  console.log(`oid4vci-issuer listening on http://localhost:${PORT}`)
})
