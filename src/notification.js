import { offerKey } from './offers.js'
import { accessTokenOf, tokenKey } from './token.js'

const EVENTS = ['credential_accepted', 'credential_failure', 'credential_deleted']

// The OID4VCI 1.0 Notification Endpoint (section 11): the wallet says whether
// it kept the credential from a Credential Response, using that response's
// `notification_id` and the access token it was issued with. The latest
// event goes on the offer, for its status. Best-effort, as the spec intends:
// the spent token and the used offer are kept one token lifetime after
// issuance (src/credential.js), after which the token is unknown (401) and
// the offer status 404s, so a `credential_deleted` days later goes unheard.
export function createNotificationHandler({ store, logRequests = false }) {
  return function notificationHandler(req, res) {
    const accessToken = accessTokenOf(req)
    const tokenEntry = accessToken && store.get(tokenKey(accessToken))
    if (!tokenEntry) return res.status(401).json({ error: 'invalid_token' })

    // Unknown members are ignored (section 11.1).
    const { notification_id: notificationId, event, event_description: description } = req.body || {}
    if (typeof notificationId !== 'string' || !EVENTS.includes(event) || !['undefined', 'string'].includes(typeof description)) {
      return res.status(400).json({ error: 'invalid_notification_request' })
    }
    // Only this token's own Credential Response: another offer's id is as
    // unknown here as a made-up one.
    if (notificationId !== tokenEntry.notificationId) {
      return res.status(400).json({ error: 'invalid_notification_id' })
    }

    const offer = store.get(offerKey(tokenEntry.offerCode))
    if (offer) store.set(offerKey(tokenEntry.offerCode), { ...offer, notification: { event } }, offer.keepUntil - Date.now())
    // The wallet's own words, untrusted: quoted and cut short, and only when
    // debugging interop.
    if (logRequests && description) console.log(`notification ${event} description=${JSON.stringify(description.slice(0, 500))}`)
    res.sendStatus(204)
  }
}
