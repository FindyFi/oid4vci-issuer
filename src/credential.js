import { verifyProof } from './proof.js'
import { offerKey } from './offers.js'
import { tokenKey } from './token.js'
import { consumeNonce } from './nonce.js'

// The OID4VCI 1.0 Credential Endpoint. `signCredential` is caller-supplied
// (opintotodiste, or any other coordinator, wires it to its own
// signing-service instance) - this module only handles token/proof/offer
// bookkeeping, never the credential content itself.
export function createCredentialHandler({ store, credentialIssuer, signCredential }) {
  return async function credentialHandler(req, res) {
    const auth = req.get('authorization') || ''
    const [, accessToken] = auth.match(/^Bearer (.+)$/) || []
    if (!accessToken) return res.status(401).json({ error: 'invalid_token' })

    const tokenEntry = store.get(tokenKey(accessToken))
    if (!tokenEntry) return res.status(401).json({ error: 'invalid_token' })

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
    // instance per offer, so exactly one "jwt" proof is expected.
    const jwtProofs = req.body?.proofs?.jwt
    if (!Array.isArray(jwtProofs) || jwtProofs.length !== 1) {
      return res.status(400).json({
        error: 'invalid_credential_request',
        error_description: 'Expected exactly one proof in proofs.jwt (batch issuance is not supported).',
      })
    }

    let verified
    try {
      verified = await verifyProof({ proofJwt: jwtProofs[0], expectedAudience: credentialIssuer })
    } catch (err) {
      return res.status(400).json({ error: 'invalid_proof', error_description: err.message })
    }

    if (!consumeNonce(store, verified.payload.nonce)) {
      return res.status(400).json({ error: 'invalid_nonce', error_description: 'Unknown, already-used, or expired nonce.' })
    }

    // Mark the offer consumed (single-use) before signing, and drop the
    // access token, so a retried or racing request can't redeem twice.
    store.set(offerKey(tokenEntry.offerCode), { ...offer, used: true }, 60_000)
    store.delete(tokenKey(accessToken))

    try {
      const credential = await signCredential(offer.unsignedCredential)
      res.json({ credential })
    } catch (err) {
      res.status(500).json({ error: 'issuance_failed', error_description: err.message })
    }
  }
}
