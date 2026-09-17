import assert from 'node:assert/strict'
import test, { after, before, describe } from 'node:test'
import { SignJWT, exportJWK, generateKeyPair } from 'jose'

import { CREDENTIAL_CONFIGURATION_ID, startIssuer, startIssuerExpectingFailure } from './helpers/server.js'

const UNSIGNED_CREDENTIAL = {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  type: ['VerifiableCredential', 'OpenBadgeCredential'],
  issuer: 'did:web:example.org',
  credentialSubject: { type: ['AchievementSubject'], id: 'urn:oid:1.2.3' },
}

let issuer

before(async () => {
  issuer = await startIssuer()
})

after(async () => {
  await issuer?.stop()
})

function url(path) {
  return `${issuer.baseUrl}${path}`
}

async function createOffer(body = {}) {
  const res = await fetch(url('/instance/test/offers'), {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${issuer.coordinatorToken}`,
    },
    body: JSON.stringify({
      credentialConfigurationId: CREDENTIAL_CONFIGURATION_ID,
      unsignedCredential: UNSIGNED_CREDENTIAL,
      ...body,
    }),
  })
  return { res, body: await res.json() }
}

async function redeem(preAuthorizedCode, extra = {}) {
  const res = await fetch(url('/token'), {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      'pre-authorized_code': preAuthorizedCode,
      ...extra,
    }),
  })
  return { res, body: await res.json() }
}

async function requestNonce() {
  const res = await fetch(url('/nonce'), { method: 'POST' })
  const { c_nonce: nonce } = await res.json()
  return nonce
}

async function makeProof({ nonce, audience = issuer.credentialIssuer, typ = 'openid4vci-proof+jwt', alg = 'ES256' }) {
  const { publicKey, privateKey } = await generateKeyPair(alg, { extractable: true })
  return new SignJWT({ nonce })
    .setProtectedHeader({ alg, typ, jwk: await exportJWK(publicKey) })
    .setAudience(audience)
    .setIssuedAt()
    .sign(privateKey)
}

// A proof of possession is only worth anything if the key it is checked
// against is one the presenter had to already possess. This builds the
// degenerate case: a symmetric key the "holder" invented and shipped inside
// the very JWT it signs, which anyone can produce.
async function makeSymmetricProof({ nonce, audience = issuer.credentialIssuer }) {
  const secret = crypto.getRandomValues(new Uint8Array(32))
  return new SignJWT({ nonce })
    .setProtectedHeader({
      alg: 'HS256',
      typ: 'openid4vci-proof+jwt',
      jwk: { kty: 'oct', k: Buffer.from(secret).toString('base64url') },
    })
    .setAudience(audience)
    .setIssuedAt()
    .sign(secret)
}

async function requestCredential({ accessToken, proofJwt, ...overrides }) {
  const res = await fetch(url('/credential'), {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {}),
    },
    body: JSON.stringify({
      credential_configuration_id: CREDENTIAL_CONFIGURATION_ID,
      proofs: { jwt: [proofJwt] },
      ...overrides,
    }),
  })
  return { res, body: await res.json() }
}

describe('service basics', () => {
  test('reports healthy', async () => {
    const res = await fetch(url('/healthz'))
    assert.equal(res.status, 200)
  })

  test('publishes issuer metadata pointing at its own endpoints', async () => {
    const res = await fetch(url('/.well-known/openid-credential-issuer'))
    const metadata = await res.json()

    assert.equal(res.status, 200)
    assert.equal(metadata.credential_issuer, issuer.credentialIssuer)
    assert.equal(metadata.credential_endpoint, `${issuer.credentialIssuer}/credential`)
    assert.equal(metadata.token_endpoint, `${issuer.credentialIssuer}/token`)
    // Required because the configuration below declares proof_types_supported.
    assert.equal(metadata.nonce_endpoint, `${issuer.credentialIssuer}/nonce`)
    assert.ok(metadata.credential_configurations_supported[CREDENTIAL_CONFIGURATION_ID])
  })

  test('refuses to start without CREDENTIAL_ISSUER', async () => {
    const { code, stderr } = await startIssuerExpectingFailure({})
    assert.notEqual(code, 0)
    assert.match(stderr, /CREDENTIAL_ISSUER/)
  })

  test('refuses to start with unparseable credential configurations', async () => {
    const { code, stderr } = await startIssuerExpectingFailure({
      CREDENTIAL_ISSUER: 'https://example.org',
      CREDENTIAL_CONFIGURATIONS_SUPPORTED: 'not json',
    })
    assert.notEqual(code, 0)
    assert.match(stderr, /CREDENTIAL_CONFIGURATIONS_SUPPORTED/)
  })
})

describe('offer creation', () => {
  test('requires the coordinator token', async () => {
    const res = await fetch(url('/instance/test/offers'), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        credentialConfigurationId: CREDENTIAL_CONFIGURATION_ID,
        unsignedCredential: UNSIGNED_CREDENTIAL,
      }),
    })
    assert.equal(res.status, 401)
  })

  test('rejects a request missing the credential', async () => {
    const res = await fetch(url('/instance/test/offers'), {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${issuer.coordinatorToken}`,
      },
      body: JSON.stringify({ credentialConfigurationId: CREDENTIAL_CONFIGURATION_ID }),
    })
    assert.equal(res.status, 400)
  })

  test('returns a wallet-ready offer uri', async () => {
    const { res, body } = await createOffer()

    assert.equal(res.status, 200)
    assert.ok(body.preAuthorizedCode)
    assert.equal(body.txCode, undefined)
    assert.ok(body.offerUri.startsWith('openid-credential-offer://?credential_offer_uri='))
    assert.ok(body.expiresIn > 0)

    const offerUri = decodeURIComponent(body.offerUri.split('credential_offer_uri=')[1])
    assert.equal(offerUri, `${issuer.credentialIssuer}/instance/test/offers/${body.preAuthorizedCode}`)
  })

  test('serves the hosted credential offer at that uri', async () => {
    const { body: offer } = await createOffer()
    const res = await fetch(url(`/instance/test/offers/${offer.preAuthorizedCode}`))
    const hosted = await res.json()

    assert.equal(hosted.credential_issuer, issuer.credentialIssuer)
    assert.deepEqual(hosted.credential_configuration_ids, [CREDENTIAL_CONFIGURATION_ID])
    assert.equal(
      hosted.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'],
      offer.preAuthorizedCode
    )
  })

  test('advertises a tx_code when one was requested', async () => {
    const { body: offer } = await createOffer({ txCode: true })
    assert.match(offer.txCode, /^\d{5}$/)

    const res = await fetch(url(`/instance/test/offers/${offer.preAuthorizedCode}`))
    const hosted = await res.json()
    const grant = hosted.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']

    assert.deepEqual(grant.tx_code, { input_mode: 'numeric', length: 5 })
  })

  test('404s an unknown offer', async () => {
    const res = await fetch(url('/instance/test/offers/does-not-exist'))
    assert.equal(res.status, 404)
  })
})

describe('token endpoint', () => {
  test('exchanges a pre-authorized code for an access token', async () => {
    const { body: offer } = await createOffer()
    const { res, body } = await redeem(offer.preAuthorizedCode)

    assert.equal(res.status, 200)
    assert.ok(body.access_token)
    assert.equal(body.token_type, 'bearer')
    // OID4VCI 1.0 moved c_nonce out of the token response.
    assert.equal(body.c_nonce, undefined)
  })

  test('rejects an unsupported grant type', async () => {
    const { body: offer } = await createOffer()
    const res = await fetch(url('/token'), {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        'pre-authorized_code': offer.preAuthorizedCode,
      }),
    })

    assert.equal(res.status, 400)
    assert.equal((await res.json()).error, 'unsupported_grant_type')
  })

  test('rejects an unknown pre-authorized code', async () => {
    const { res, body } = await redeem('nope')
    assert.equal(res.status, 400)
    assert.equal(body.error, 'invalid_grant')
  })

  test('requires a matching tx_code when the offer carries one', async () => {
    const { body: offer } = await createOffer({ txCode: true })

    const wrong = await redeem(offer.preAuthorizedCode, { tx_code: '00000' })
    assert.equal(wrong.res.status, 400)
    assert.equal(wrong.body.error, 'invalid_grant')

    const right = await redeem(offer.preAuthorizedCode, { tx_code: offer.txCode })
    assert.equal(right.res.status, 200)
  })
})

describe('credential issuance', () => {
  test('issues a signed credential for a valid proof', async () => {
    const { body: offer } = await createOffer()
    const { body: token } = await redeem(offer.preAuthorizedCode)
    const proofJwt = await makeProof({ nonce: await requestNonce() })

    const { res, body } = await requestCredential({ accessToken: token.access_token, proofJwt })

    assert.equal(res.status, 200)
    assert.equal(body.credential.issuer, UNSIGNED_CREDENTIAL.issuer)
    assert.ok(body.credential.proof, 'expected the signing service to have added a proof')

    // The issuer must forward exactly what the coordinator handed it.
    const signed = issuer.signingService.requests.at(-1)
    assert.equal(signed.url, '/instance/test/credentials/sign?suite=ed25519')
    assert.deepEqual(signed.credential, UNSIGNED_CREDENTIAL)
  })

  test('marks the offer used afterwards', async () => {
    const { body: offer } = await createOffer()

    const before = await fetch(url(`/instance/test/offers/${offer.preAuthorizedCode}/status`))
    assert.equal((await before.json()).used, false)

    const { body: token } = await redeem(offer.preAuthorizedCode)
    await requestCredential({
      accessToken: token.access_token,
      proofJwt: await makeProof({ nonce: await requestNonce() }),
    })

    const after = await fetch(url(`/instance/test/offers/${offer.preAuthorizedCode}/status`))
    assert.equal((await after.json()).used, true)
  })

  test('rejects a request with no access token', async () => {
    const proofJwt = await makeProof({ nonce: await requestNonce() })
    const { res, body } = await requestCredential({ proofJwt })

    assert.equal(res.status, 401)
    assert.equal(body.error, 'invalid_token')
  })

  test('rejects a reused access token', async () => {
    const { body: offer } = await createOffer()
    const { body: token } = await redeem(offer.preAuthorizedCode)

    const first = await requestCredential({
      accessToken: token.access_token,
      proofJwt: await makeProof({ nonce: await requestNonce() }),
    })
    assert.equal(first.res.status, 200)

    const replay = await requestCredential({
      accessToken: token.access_token,
      proofJwt: await makeProof({ nonce: await requestNonce() }),
    })
    assert.equal(replay.res.status, 401)
  })

  test('rejects a mismatched credential_configuration_id', async () => {
    const { body: offer } = await createOffer()
    const { body: token } = await redeem(offer.preAuthorizedCode)

    const { res, body } = await requestCredential({
      accessToken: token.access_token,
      proofJwt: await makeProof({ nonce: await requestNonce() }),
      credential_configuration_id: 'SomethingElse',
    })

    assert.equal(res.status, 400)
    assert.equal(body.error, 'invalid_credential_request')
  })

  test('rejects batch issuance', async () => {
    const { body: offer } = await createOffer()
    const { body: token } = await redeem(offer.preAuthorizedCode)
    const nonce = await requestNonce()

    const { res, body } = await requestCredential({
      accessToken: token.access_token,
      proofJwt: await makeProof({ nonce }),
      proofs: { jwt: [await makeProof({ nonce }), await makeProof({ nonce })] },
    })

    assert.equal(res.status, 400)
    assert.match(body.error_description, /batch issuance is not supported/i)
  })

  test('rejects a proof made for another audience', async () => {
    const { body: offer } = await createOffer()
    const { body: token } = await redeem(offer.preAuthorizedCode)

    const { res, body } = await requestCredential({
      accessToken: token.access_token,
      proofJwt: await makeProof({ nonce: await requestNonce(), audience: 'https://somewhere.else' }),
    })

    assert.equal(res.status, 400)
    assert.equal(body.error, 'invalid_proof')
  })

  test('rejects a proof with the wrong typ header', async () => {
    const { body: offer } = await createOffer()
    const { body: token } = await redeem(offer.preAuthorizedCode)

    const { res, body } = await requestCredential({
      accessToken: token.access_token,
      proofJwt: await makeProof({ nonce: await requestNonce(), typ: 'JWT' }),
    })

    assert.equal(res.status, 400)
    assert.equal(body.error, 'invalid_proof')
  })

  test('rejects a proof signed with a symmetric key the holder chose', async () => {
    const { body: offer } = await createOffer()
    const { body: token } = await redeem(offer.preAuthorizedCode)

    const { res, body } = await requestCredential({
      accessToken: token.access_token,
      proofJwt: await makeSymmetricProof({ nonce: await requestNonce() }),
    })

    assert.equal(res.status, 400)
    assert.equal(body.error, 'invalid_proof')
  })

  test('rejects an algorithm the issuer metadata does not advertise', async () => {
    // The test configuration advertises ES256 and nothing else, so a
    // perfectly valid RS256 proof must still be turned away.
    const { body: offer } = await createOffer()
    const { body: token } = await redeem(offer.preAuthorizedCode)

    const { res, body } = await requestCredential({
      accessToken: token.access_token,
      proofJwt: await makeProof({ nonce: await requestNonce(), alg: 'RS256' }),
    })

    assert.equal(res.status, 400)
    assert.equal(body.error, 'invalid_proof')
    assert.match(body.error_description, /RS256/)
  })

  test('rejects a nonce this service never issued', async () => {
    const { body: offer } = await createOffer()
    const { body: token } = await redeem(offer.preAuthorizedCode)

    const { res, body } = await requestCredential({
      accessToken: token.access_token,
      proofJwt: await makeProof({ nonce: 'invented-nonce' }),
    })

    assert.equal(res.status, 400)
    assert.equal(body.error, 'invalid_nonce')
  })

  test('rejects a nonce that was already spent', async () => {
    const nonce = await requestNonce()

    const first = await createOffer()
    const firstToken = await redeem(first.body.preAuthorizedCode)
    const ok = await requestCredential({
      accessToken: firstToken.body.access_token,
      proofJwt: await makeProof({ nonce }),
    })
    assert.equal(ok.res.status, 200)

    const second = await createOffer()
    const secondToken = await redeem(second.body.preAuthorizedCode)
    const { res, body } = await requestCredential({
      accessToken: secondToken.body.access_token,
      proofJwt: await makeProof({ nonce }),
    })

    assert.equal(res.status, 400)
    assert.equal(body.error, 'invalid_nonce')
  })

  test('surfaces a signing failure without leaving the offer redeemable', async () => {
    const { body: offer } = await createOffer()
    const { body: token } = await redeem(offer.preAuthorizedCode)
    issuer.signingService.failNext('signing key unavailable')

    const { res, body } = await requestCredential({
      accessToken: token.access_token,
      proofJwt: await makeProof({ nonce: await requestNonce() }),
    })

    assert.equal(res.status, 500)
    assert.equal(body.error, 'issuance_failed')

    const status = await fetch(url(`/instance/test/offers/${offer.preAuthorizedCode}/status`))
    assert.equal((await status.json()).used, true)
  })
})
