import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair, exportJWK, SignJWT } from 'jose'
import { createApp } from '../src/app.js'

const ISSUER = 'https://issuer.example'
const CONFIG_ID = 'OpenBadgeCredential'
const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:pre-authorized_code'
const COORDINATOR_TOKEN = 'secret'

let server
let base
const signed = []

before(async () => {
  const app = createApp({
    credentialIssuer: ISSUER,
    credentialConfigurationsSupported: { [CONFIG_ID]: { format: 'ldp_vc' } },
    coordinatorToken: COORDINATOR_TOKEN,
    // Stub signer: records what it was asked to sign and returns a fake proof.
    signCredential: async (vc) => {
      signed.push(vc)
      return { ...vc, proof: { type: 'DataIntegrityProof' } }
    },
  })
  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', resolve)
  })
  base = `http://127.0.0.1:${server.address().port}`
})

after(() => new Promise((resolve) => server.close(resolve)))

const unsignedCredential = { '@context': ['https://www.w3.org/2018/credentials/v1'], type: ['VerifiableCredential'], credentialSubject: { id: 'urn:x' } }

async function createOffer(body = { credentialConfigurationId: CONFIG_ID, unsignedCredential, txCode: true }) {
  const res = await fetch(`${base}/instance/t1/offers`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${COORDINATOR_TOKEN}` },
    body: JSON.stringify(body),
  })
  return { res, body: await res.json() }
}

// Fake wallet: fetch offer -> token -> nonce -> proof JWT -> credential request.
async function redeem({ preAuthorizedCode, txCode }) {
  const offerRes = await fetch(`${base}/instance/t1/offers/${preAuthorizedCode}`)
  const offer = await offerRes.json()
  const grant = offer.grants[GRANT_TYPE]

  const tokenRes = await fetch(`${base}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: GRANT_TYPE, 'pre-authorized_code': grant['pre-authorized_code'], ...(txCode ? { tx_code: txCode } : {}) }),
  })
  const token = await tokenRes.json()

  const { c_nonce: nonce } = await (await fetch(`${base}/nonce`, { method: 'POST' })).json()

  const { publicKey, privateKey } = await generateKeyPair('ES256')
  const jwk = await exportJWK(publicKey)
  const proof = await new SignJWT({ nonce })
    .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk })
    .setAudience(ISSUER)
    .setIssuedAt()
    .sign(privateKey)

  return { offer, tokenRes, token, nonce, proof }
}

function credentialRequest(accessToken, proof, configId = CONFIG_ID) {
  return fetch(`${base}/credential`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
    body: JSON.stringify({ credential_configuration_id: configId, proofs: { jwt: [proof] } }),
  })
}

test('full pre-authorized code flow returns the 1.0 credentials array', async () => {
  const { res, body: created } = await createOffer()
  assert.equal(res.status, 200)
  assert.match(created.txCode, /^\d{5}$/)

  const { offer, token, proof } = await redeem(created)
  assert.equal(offer.credential_issuer, ISSUER)
  assert.deepEqual(offer.credential_configuration_ids, [CONFIG_ID])
  assert.equal(offer.grants[GRANT_TYPE].tx_code.length, 5)
  assert.equal(token.token_type, 'bearer')
  assert.equal('c_nonce' in token, false)

  const credRes = await credentialRequest(token.access_token, proof)
  assert.equal(credRes.status, 200)
  assert.match(credRes.headers.get('content-type'), /application\/json/)
  assert.equal(credRes.headers.get('cache-control'), 'no-store')
  const body = await credRes.json()
  assert.deepEqual(Object.keys(body), ['credentials'])
  assert.equal(body.credentials.length, 1)
  assert.deepEqual(Object.keys(body.credentials[0]), ['credential'])
  assert.deepEqual(body.credentials[0].credential, { ...unsignedCredential, proof: { type: 'DataIntegrityProof' } })
  assert.deepEqual(signed.at(-1), unsignedCredential)

  const status = await (await fetch(`${base}/instance/t1/offers/${created.preAuthorizedCode}/status`)).json()
  assert.deepEqual(status, { used: true })
})

test('the offer is single-use', async () => {
  const { body: created } = await createOffer({ credentialConfigurationId: CONFIG_ID, unsignedCredential })
  const { token, proof } = await redeem(created)
  assert.equal((await credentialRequest(token.access_token, proof)).status, 200)
  assert.equal((await credentialRequest(token.access_token, proof)).status, 401)
})

test('a wrong tx_code is rejected at the token endpoint', async () => {
  const { body: created } = await createOffer()
  const { tokenRes, token } = await redeem({ ...created, txCode: 'wrong' })
  assert.equal(tokenRes.status, 400)
  assert.equal(token.error, 'invalid_grant')
})

test('a replayed nonce is rejected', async () => {
  const first = await createOffer({ credentialConfigurationId: CONFIG_ID, unsignedCredential })
  const a = await redeem(first.body)
  assert.equal((await credentialRequest(a.token.access_token, a.proof)).status, 200)

  const second = await createOffer({ credentialConfigurationId: CONFIG_ID, unsignedCredential })
  const b = await redeem(second.body)
  const res = await credentialRequest(b.token.access_token, a.proof) // proof carrying a spent nonce
  assert.equal(res.status, 400)
  assert.equal((await res.json()).error, 'invalid_nonce')
})

test('a credential_configuration_id mismatch is rejected', async () => {
  const { body: created } = await createOffer({ credentialConfigurationId: CONFIG_ID, unsignedCredential })
  const { token, proof } = await redeem(created)
  const res = await credentialRequest(token.access_token, proof, 'Other')
  assert.equal(res.status, 400)
  assert.equal((await res.json()).error, 'invalid_credential_request')
})

test('offer creation requires the coordinator token', async () => {
  const res = await fetch(`${base}/instance/t1/offers`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credentialConfigurationId: CONFIG_ID, unsignedCredential }),
  })
  assert.equal(res.status, 401)
})

test('issuer metadata advertises the endpoints', async () => {
  const meta = await (await fetch(`${base}/.well-known/openid-credential-issuer`)).json()
  assert.equal(meta.credential_endpoint, `${ISSUER}/credential`)
  assert.equal(meta.nonce_endpoint, `${ISSUER}/nonce`)
  assert.ok(meta.credential_configurations_supported[CONFIG_ID])
})
