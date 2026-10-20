import { randomUUID, randomInt } from 'node:crypto'

const OFFER_TTL_MS = 10 * 60 * 1000 // time a wallet has to redeem the offer
const TX_CODE_LENGTH = 5
const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:pre-authorized_code'

export function offerKey(code) {
  return `offer:${code}`
}

// `unsignedCredential` is a fully-built, unsigned Verifiable Credential JSON
// supplied by the coordinator (opintotodiste, issuer-coordinator,
// workflow-coordinator, ...). This service doesn't build or change its
// content; `checkOffer` (see src/signers.js) only rejects what the
// configuration's signer couldn't issue, such as an SD-JWT credential whose
// issuer isn't this service's SD-JWT issuer URL. `disclosable` (optional,
// dc+sd-jwt only) names the top-level claims to make selectively disclosable.
export function createOfferHandlers({ store, credentialIssuer, checkOffer }) {
  function createOffer(req, res) {
    const { credentialConfigurationId, unsignedCredential, txCode, disclosable } = req.body || {}
    if (!credentialConfigurationId || !unsignedCredential) {
      return res.status(400).json({ error: 'credentialConfigurationId and unsignedCredential are required.' })
    }
    const problem = checkOffer(credentialConfigurationId, unsignedCredential, { disclosable })
    if (problem) return res.status(400).json({ error: problem })

    const code = randomUUID()
    const txCodeValue = txCode ? String(randomInt(10 ** (TX_CODE_LENGTH - 1), 10 ** TX_CODE_LENGTH)) : undefined
    store.set(
      offerKey(code),
      { credentialConfigurationId, unsignedCredential, disclosable, txCode: txCodeValue, used: false },
      OFFER_TTL_MS
    )

    const offerUri = `${credentialIssuer}/instance/${req.params.tenant}/offers/${code}`
    res.json({
      preAuthorizedCode: code,
      txCode: txCodeValue,
      offerUri: `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(offerUri)}`,
      expiresIn: OFFER_TTL_MS / 1000,
    })
  }

  function getOffer(req, res) {
    const offer = store.get(offerKey(req.params.code))
    if (!offer) return res.status(404).json({ error: 'Offer not found or expired.' })

    res.json({
      credential_issuer: credentialIssuer,
      credential_configuration_ids: [offer.credentialConfigurationId],
      grants: {
        [GRANT_TYPE]: {
          'pre-authorized_code': req.params.code,
          ...(offer.txCode ? { tx_code: { input_mode: 'numeric', length: TX_CODE_LENGTH } } : {}),
        },
      },
    })
  }

  function getOfferStatus(req, res) {
    const offer = store.get(offerKey(req.params.code))
    if (!offer) return res.status(404).json({ error: 'Offer not found or expired.' })
    // `notification` ({ event }) once the wallet sent one (src/notification.js).
    res.json({ used: offer.used, ...(offer.notification ? { notification: offer.notification } : {}) })
  }

  return { createOffer, getOffer, getOfferStatus }
}
