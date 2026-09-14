import { randomUUID } from 'node:crypto'
import { offerKey } from './offers.js'

const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:pre-authorized_code'
const TOKEN_TTL_MS = 5 * 60 * 1000

export function tokenKey(accessToken) {
  return `token:${accessToken}`
}

// The OID4VCI token endpoint is a plain OAuth2 token endpoint: form-encoded
// request/response, not JSON - the caller must parse the body with
// express.urlencoded(), not express.json(). Per OID4VCI 1.0 Section 6.2,
// this response no longer carries c_nonce (unlike some pre-1.0 drafts) - a
// wallet gets nonces from the separate, unauthenticated Nonce Endpoint.
export function createTokenHandler({ store }) {
  return function tokenHandler(req, res) {
    const body = req.body || {}
    const code = body['pre-authorized_code']

    if (body.grant_type !== GRANT_TYPE) {
      return res.status(400).json({ error: 'unsupported_grant_type' })
    }

    const offer = store.get(offerKey(code))
    if (!offer || offer.used) {
      return res.status(400).json({ error: 'invalid_grant' })
    }
    if (offer.txCode && offer.txCode !== body.tx_code) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid tx_code.' })
    }

    const accessToken = randomUUID()
    store.set(tokenKey(accessToken), { offerCode: code }, TOKEN_TTL_MS)

    res.json({
      access_token: accessToken,
      token_type: 'bearer',
      expires_in: TOKEN_TTL_MS / 1000,
    })
  }
}
