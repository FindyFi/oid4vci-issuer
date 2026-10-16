import { SD_JWT_FORMAT, checkVcSdJwtCredential, signVcSdJwt } from './sdjwt.js'

// Picks how each credential configuration is signed, by its `format`:
// `ldp_vc` goes to signing-service (via the caller-supplied `signLdpVc`),
// and the SD-JWT format is signed here with this service's own key. Runs
// once at startup and throws on anything it can't serve, so a configuration
// mistake stops the service instead of failing a wallet mid-flow.
export function createSigners({ credentialConfigurationsSupported, signLdpVc, sdJwt }) {
  const byConfigurationId = {}

  for (const [id, configuration] of Object.entries(credentialConfigurationsSupported)) {
    const format = configuration?.format
    if (format === 'ldp_vc') {
      if (!signLdpVc) {
        throw new Error(`Credential configuration ${id} has format ldp_vc, but the signing service is not configured (set SIGNING_SERVICE_URL and SIGNING_SERVICE_INSTANCE).`)
      }
      byConfigurationId[id] = { sign: signLdpVc, check: () => undefined }
    } else if (format === SD_JWT_FORMAT) {
      if (!sdJwt?.key || !sdJwt?.issuer) {
        throw new Error(`Credential configuration ${id} has format ${SD_JWT_FORMAT}, but no SD-JWT signing key is configured (set SD_JWT_SIGNING_KEY).`)
      }
      byConfigurationId[id] = {
        sign: (vc) => signVcSdJwt(vc, sdJwt),
        check: (vc) => checkVcSdJwtCredential(vc, sdJwt),
      }
    } else {
      throw new Error(`Credential configuration ${id} has unsupported format ${format}.`)
    }
  }

  return {
    // Returns an error message for an offer this service can't issue, or undefined.
    checkOffer(credentialConfigurationId, unsignedCredential) {
      const signer = byConfigurationId[credentialConfigurationId]
      if (!signer) return `Unknown credentialConfigurationId: ${credentialConfigurationId}.`
      return signer.check(unsignedCredential)
    },
    sign(credentialConfigurationId, unsignedCredential) {
      return byConfigurationId[credentialConfigurationId].sign(unsignedCredential)
    },
  }
}
