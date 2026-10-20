import { randomUUID } from 'node:crypto'
import { verifyProof } from './proof.js'
import { offerKey } from './offers.js'
import { TOKEN_TTL_MS, accessTokenOf, tokenKey } from './token.js'
import { consumeNonce } from './nonce.js'

// The OID4VCI 1.0 Credential Endpoint. `signCredential(configurationId, vc)`
// picks the signer for the offer's configuration (see src/signers.js) - this
// module only handles token/proof/offer bookkeeping, never the credential
// content itself.
export function createCredentialHandler({
  store,
  credentialIssuer,
  signCredential,
  credentialConfigurationsSupported = {},
}) {
  return async function credentialHandler(req, res) {
    const accessToken = accessTokenOf(req)
    if (!accessToken) return res.status(401).json({ error: 'invalid_token' })

    // A token that already got its credential is kept only for /notification.
    const tokenEntry = store.get(tokenKey(accessToken))
    if (!tokenEntry || tokenEntry.notificationId) return res.status(401).json({ error: 'invalid_token' })

    const offer = store.get(offerKey(tokenEntry.offerCode))
    if (!offer || offer.used) return res.status(400).json({ error: 'invalid_credential_request' })

    // Section 8.2: credential_configuration_id is REQUIRED unless the Token
    // Response returned credential_identifiers (Authorization Details) -
    // this service never does that, so it's always required here.
    if (req.body?.credential_configuration_id !== offer.credentialConfigurationId) {
      return res
        .status(400)
        .json({ error: 'invalid_credential_request', error_description: 'credential_configuration_id is required and must match the offer.' })
    }

    // Section 8.2: request proofs live under the plural "proofs" object,
    // keyed by proof type, each holding an array of proof values - not a
    // singular "proof". This service only ever offers one credential
    // instance per offer, so exactly one "jwt" proof is expected. Pre-1.0
    // wallets (draft 13 and earlier) still send a singular
    // { proof_type: "jwt", jwt }, which is accepted as the same thing.
    const legacyProof = req.body?.proof
    const jwtProofs = req.body?.proofs
      ? req.body.proofs.jwt
      : legacyProof?.proof_type === 'jwt' && typeof legacyProof.jwt === 'string'
        ? [legacyProof.jwt]
        : undefined
    if (!Array.isArray(jwtProofs) || jwtProofs.length !== 1) {
      return res.status(400).json({
        error: 'invalid_credential_request',
        error_description: 'Expected exactly one proof in proofs.jwt (batch issuance is not supported).',
      })
    }

    // The algorithms accepted here are the ones this offer's credential
    // configuration advertises in issuer metadata, so a wallet is held to
    // exactly what it was told - and widening the metadata is the only way
    // to widen what gets accepted.
    const allowedAlgorithms =
      credentialConfigurationsSupported[offer.credentialConfigurationId]?.proof_types_supported?.jwt
        ?.proof_signing_alg_values_supported

    let verified
    try {
      verified = await verifyProof({
        proofJwt: jwtProofs[0],
        expectedAudience: credentialIssuer,
        allowedAlgorithms,
      })
    } catch (err) {
      return res.status(400).json({ error: 'invalid_proof', error_description: err.message })
    }

    if (!consumeNonce(store, verified.payload.nonce)) {
      return res.status(400).json({ error: 'invalid_nonce', error_description: 'Unknown, already-used, or expired nonce.' })
    }

    // Mark the offer consumed (single-use) and the access token spent before
    // signing, so a retried or racing request can't redeem twice. The wallet
    // still needs the token for the Notification Endpoint (section 11), so
    // both are kept one token lifetime from now (src/notification.js).
    const notificationId = randomUUID()
    const keepUntil = Date.now() + TOKEN_TTL_MS
    store.set(offerKey(tokenEntry.offerCode), { ...offer, used: true, keepUntil }, TOKEN_TTL_MS)
    store.set(tokenKey(accessToken), { ...tokenEntry, notificationId }, TOKEN_TTL_MS)

    try {
      const credential = await signCredential(offer.credentialConfigurationId, offer.unsignedCredential, {
        holderJwk: verified.holderJwk,
        holderKid: verified.holderKid,
        disclosable: offer.disclosable,
      })
      // Section 8.3: immediate issuance is a 200 with a `credentials` array of
      // objects, each holding one `credential`; there is no top-level
      // `credential`. `notification_id` is what the wallet notifies about.
      res.set('Cache-Control', 'no-store')
      res.json({ credentials: [{ credential }], notification_id: notificationId })
    } catch (err) {
      store.delete(tokenKey(accessToken))
      res.status(500).json({ error: 'issuance_failed', error_description: err.message })
    }
  }
}
