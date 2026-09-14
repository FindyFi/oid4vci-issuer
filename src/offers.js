import { randomUUID, randomInt } from 'node:crypto'

const OFFER_TTL_MS = 10 * 60 * 1000 // time a wallet has to redeem the offer
const TX_CODE_LENGTH = 5
const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:pre-authorized_code'

export function offerKey(code) {
  return `offer:${code}`
}

// `unsignedCredential` is opaque to this service - a fully-built, unsigned
// Verifiable Credential JSON supplied by the coordinator (opintotodiste,
// issuer-coordinator, workflow-coordinator, ...). This service never
// inspects its shape, only stores and later forwards it to signing-service.
export function createOfferHandlers({ store, credentialIssuer }) {
  function createOffer(req, res) {
    const { credentialConfigurationId, unsignedCredential, txCode } = req.body || {}
    if (!credentialConfigurationId || !unsignedCredential) {
      return res.status(400).json({ error: 'credentialConfigurationId and unsignedCredential are required.' })
    }

    const code = randomUUID()
    const txCodeValue = txCode ? String(randomInt(10 ** (TX_CODE_LENGTH - 1), 10 ** TX_CODE_LENGTH)) : undefined
    store.set(
      offerKey(code),
      { credentialConfigurationId, unsignedCredential, txCode: txCodeValue, used: false },
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
    res.json({ used: offer.used })
  }

  return { createOffer, getOffer, getOfferStatus }
}
