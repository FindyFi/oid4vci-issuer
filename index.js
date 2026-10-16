import 'dotenv/config'
import { createApp } from './src/app.js'
import { callSigningService } from './src/signing.js'
import { loadSigningKey } from './src/keys.js'
import { loadX5c } from './src/x5c.js'
import { resolveVctIntegrity } from './src/vct-integrity.js'

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
  }
  if (process.env.SD_JWT_X5C) {
    if (process.env.SD_JWT_X5C === 'generate') {
      console.warn('SD_JWT_X5C=generate: using a self-signed certificate for the SD-JWT signing key. Dev only.')
    }
    sdJwt.x5c = await loadX5c(process.env.SD_JWT_X5C, sdJwt)
  }
}

const app = createApp({
  credentialIssuer: CREDENTIAL_ISSUER,
  credentialConfigurationsSupported: await resolveVctIntegrity(credentialConfigurationsSupported),
  coordinatorToken: process.env.COORDINATOR_TOKEN,
  signLdpVc,
  sdJwt,
  logRequests: process.env.LOG_REQUESTS === '1',
})

app.listen(PORT, () => {
  console.log(`oid4vci-issuer listening on http://localhost:${PORT}`)
})
