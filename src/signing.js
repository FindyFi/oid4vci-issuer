// Calls a https://github.com/digitalcredentials/signing-service instance to
// add a proof to an unsigned credential. Deliberately duplicated rather than
// shared with any caller's own copy of this logic (e.g. opintotodiste's
// src/badges.js) - this package is an independently deployable service, not
// a library, so it owns its own signing-service client.
export async function callSigningService(vc, { baseUrl, instanceId, suite = 'ed25519' }) {
  if (!baseUrl || !instanceId) {
    throw new Error('The signing service is not configured (set SIGNING_SERVICE_URL and SIGNING_SERVICE_INSTANCE).')
  }
  const url = new URL(`/instance/${instanceId}/credentials/sign`, baseUrl)
  url.searchParams.set('suite', suite)

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(vc),
  })
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new Error(`Signing service responded with ${res.status} ${res.statusText}${text ? `: ${text}` : ''}`)
  }
  return res.json()
}
