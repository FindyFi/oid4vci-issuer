import 'dotenv/config'
import { createApp } from './src/app.js'
import { callSigningService } from './src/signing.js'
import { loadPreviousKeys, loadSigningKey } from './src/keys.js'
import { loadX5c } from './src/x5c.js'
import { resolveVctIntegrity } from './src/vct-integrity.js'
import { loadFederationConfig } from './src/federation.js'
import { loadIssuerMetadataConfig } from './src/metadata.js'
import { loadEnvManifest, missingRequired } from './src/env-manifest.js'

// Deployed images set NODE_ENV=production: refuse to start with a required
// variable missing, and name all of them at once. Dev keeps its defaults.
if (process.env.NODE_ENV === 'production') {
  const missing = missingRequired(loadEnvManifest(), process.env)
  if (missing.length) {
    console.error(`Missing required environment variables: ${missing.join(', ')}`)
    process.exit(1)
  }
}

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

// Only needed when some configuration has format ldp_vc; createApp refuses
// to start if one does and this is missing.
const signLdpVc = process.env.SIGNING_SERVICE_URL
  ? (vc) =>
      callSigningService(vc, {
        baseUrl: process.env.SIGNING_SERVICE_URL,
        instanceId: process.env.SIGNING_SERVICE_INSTANCE,
        suite: process.env.SIGNING_SERVICE_SUITE,
      })
  : undefined

let sdJwt
if (process.env.SD_JWT_SIGNING_KEY) {
  if (process.env.SD_JWT_SIGNING_KEY === 'generate') {
    console.warn('SD_JWT_SIGNING_KEY=generate: using a fresh SD-JWT signing key. Credentials issued before a restart will no longer verify. Dev only.')
  }
  sdJwt = {
    issuer: process.env.SD_JWT_ISSUER || CREDENTIAL_ISSUER,
    key: await loadSigningKey(process.env.SD_JWT_SIGNING_KEY),
    previousKeys: await loadPreviousKeys(process.env.SD_JWT_PREVIOUS_KEYS),
  }
  if (process.env.SD_JWT_X5C) {
    if (process.env.SD_JWT_X5C === 'generate') {
      console.warn('SD_JWT_X5C=generate: using a self-signed certificate for the SD-JWT signing key. Dev only.')
    }
    sdJwt.x5c = await loadX5c(process.env.SD_JWT_X5C, sdJwt)
  }
}

// The issuer display also fills in the federation name and logo.
const { display } = loadIssuerMetadataConfig(process.env)

// Federation signs the Entity Configuration with the SD-JWT key for now. A
// separate key later means loading it here and passing it as `key`.
const federationConfig = loadFederationConfig(process.env, { display })
const federation = federationConfig && sdJwt ? { ...federationConfig, key: sdJwt.key } : undefined
if (federationConfig && !sdJwt) {
  throw new Error('Federation (FEDERATION_ENTITY_METADATA) needs SD_JWT_SIGNING_KEY: the Entity Configuration is signed with it.')
}

const app = createApp({
  credentialIssuer: CREDENTIAL_ISSUER,
  credentialConfigurationsSupported: await resolveVctIntegrity(credentialConfigurationsSupported),
  coordinatorToken: process.env.COORDINATOR_TOKEN,
  signLdpVc,
  sdJwt,
  federation,
  display,
  logRequests: process.env.LOG_REQUESTS === '1',
})

app.listen(PORT, () => {
  console.log(`oid4vci-issuer listening on http://localhost:${PORT}`)
})
