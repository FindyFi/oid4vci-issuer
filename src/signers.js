import { SD_JWT_FORMATS, checkSdJwtConfiguration, checkSdJwtCredential, signSdJwt } from './sdjwt.js'

// Picks how each credential configuration is signed, by its `format`:
// `ldp_vc` goes to signing-service (via the caller-supplied `signLdpVc`),
// and the SD-JWT formats are signed here with this service's own key. Runs
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
      byConfigurationId[id] = {
        sign: (vc) => signLdpVc(vc),
        check: (vc, { disclosable, validUntil } = {}) => {
          if (disclosable !== undefined) return 'disclosable is only supported for dc+sd-jwt configurations.'
          // An ldp_vc carries its own expiry, signed into it.
          if (validUntil !== undefined) return 'validUntil is only supported for SD-JWT configurations.'
        },
      }
    } else if (SD_JWT_FORMATS.includes(format)) {
      if (!sdJwt?.key || !sdJwt?.issuer) {
        throw new Error(`Credential configuration ${id} has format ${format}, but no SD-JWT signing key is configured (set SD_JWT_SIGNING_KEY).`)
      }
      const problem = checkSdJwtConfiguration(configuration)
      if (problem) throw new Error(`Credential configuration ${id}: ${problem}`)
      byConfigurationId[id] = {
        sign: (credential, options) => signSdJwt(credential, configuration, sdJwt, options),
        check: (credential, options) => checkSdJwtCredential(credential, configuration, sdJwt, options),
      }
    } else {
      throw new Error(`Credential configuration ${id} has unsupported format ${format}.`)
    }
  }

  return {
    // Returns an error message for an offer this service can't issue, or undefined.
    // `options` is `{ disclosable, validUntil }` from the offer.
    checkOffer(credentialConfigurationId, unsignedCredential, options) {
      const signer = byConfigurationId[credentialConfigurationId]
      if (!signer) return `Unknown credentialConfigurationId: ${credentialConfigurationId}.`
      return signer.check(unsignedCredential, options)
    },
    // `options` is `{ holderJwk, holderKid, disclosable, validUntil }`: the
    // public key from the verified proof JWT (and its DID URL, if the wallet
    // named it by one), and the offer's disclosable claims and expiry.
    sign(credentialConfigurationId, unsignedCredential, options) {
      return byConfigurationId[credentialConfigurationId].sign(unsignedCredential, options)
    },
  }
}
