import 'dotenv/config'
import { createApp } from './src/app.js'
import { callSigningService } from './src/signing.js'

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

const app = createApp({
  credentialIssuer: CREDENTIAL_ISSUER,
  credentialConfigurationsSupported,
  coordinatorToken: process.env.COORDINATOR_TOKEN,
  signCredential: (vc) =>
    callSigningService(vc, {
      baseUrl: process.env.SIGNING_SERVICE_URL,
      instanceId: process.env.SIGNING_SERVICE_INSTANCE,
      suite: process.env.SIGNING_SERVICE_SUITE,
    }),
})

app.listen(PORT, () => {
  console.log(`oid4vci-issuer listening on http://localhost:${PORT}`)
})
