import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair, exportJWK, SignJWT, jwtVerify, createLocalJWKSet, decodeProtectedHeader, calculateJwkThumbprint } from 'jose'
import { SDJwtInstance } from '@sd-jwt/core'
import { ES256, digest } from '@sd-jwt/crypto-nodejs'
import { createApp } from '../src/app.js'
import { loadSigningKey } from '../src/keys.js'

const ISSUER = 'https://issuer.example'
const CONFIG_ID = 'OpenBadgeCredential'
const SD_JWT_CONFIG_ID = 'OpenBadgeCredentialSdJwt'
const DC_CONFIG_ID = 'OpenBadgeCredentialSdJwtVc'
const VCT = `${ISSUER}/vct/OpenBadgeCredential`
const DC_CONFIG = {
  format: 'dc+sd-jwt',
  vct: VCT,
  cryptographic_binding_methods_supported: ['jwk'],
  credential_metadata: { display: [{ name: 'Opintosuoritus', locale: 'fi', description: 'Open Badge' }, { name: 'Study record', locale: 'en' }] },
}
const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:pre-authorized_code'
const COORDINATOR_TOKEN = 'secret'

let server
let base
const signed = []

before(async () => {
  const app = createApp({
    credentialIssuer: ISSUER,
    credentialConfigurationsSupported: { [CONFIG_ID]: { format: 'ldp_vc' }, [SD_JWT_CONFIG_ID]: { format: 'vc+sd-jwt' }, [DC_CONFIG_ID]: DC_CONFIG },
    coordinatorToken: COORDINATOR_TOKEN,
    // Stub signing-service: records what it was asked to sign and returns a fake proof.
    signLdpVc: async (vc) => {
      signed.push(vc)
      return { ...vc, proof: { type: 'DataIntegrityProof' } }
    },
    sdJwt: { issuer: ISSUER, key: await loadSigningKey('generate') },
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

test('a pre-1.0 singular proof is accepted', async () => {
  const { body: created } = await createOffer()
  const { token, proof } = await redeem(created)
  const res = await fetch(`${base}/credential`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token.access_token}` },
    body: JSON.stringify({ credential_configuration_id: CONFIG_ID, proof: { proof_type: 'jwt', jwt: proof } }),
  })
  assert.equal(res.status, 200)
  assert.ok((await res.json()).credentials[0].credential)
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

test('authorization server metadata names the token endpoint and the pre-authorized grant', async () => {
  const meta = await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json()
  assert.equal(meta.issuer, ISSUER)
  assert.equal(meta.token_endpoint, `${ISSUER}/token`)
  assert.deepEqual(meta.grant_types_supported, [GRANT_TYPE])
  assert.equal(meta['pre-authorized_grant_anonymous_access_supported'], true)
})

// The discovery fallback wallets try after oauth-authorization-server. It is
// RFC 8414 metadata, not an OpenID Federation Entity Configuration.
test('openid-configuration serves the same authorization server metadata', async () => {
  const res = await fetch(`${base}/.well-known/openid-configuration`)
  assert.equal(res.status, 200)
  const fallback = await res.json()
  const primary = await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json()
  assert.deepEqual(fallback, primary)
  assert.equal(fallback.token_endpoint, `${ISSUER}/token`)
})

const vcdm2Credential = {
  '@context': ['https://www.w3.org/ns/credentials/v2', 'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json'],
  id: 'urn:uuid:5f0c2a4e-0a8e-4c55-9a43-2f6b0e1c7d11',
  type: ['VerifiableCredential', 'OpenBadgeCredential'],
  issuer: { id: ISSUER, type: ['Profile'], name: 'Test issuer' },
  validFrom: '2024-06-01T00:00:00Z',
  credentialSubject: { type: ['AchievementSubject'], achievement: { id: 'urn:x:a', type: ['Achievement'], name: 'A' } },
}

async function issueSdJwt(unsigned = vcdm2Credential) {
  const { res, body: created } = await createOffer({ credentialConfigurationId: SD_JWT_CONFIG_ID, unsignedCredential: unsigned })
  assert.equal(res.status, 200)
  const { token, proof } = await redeem(created)
  const credRes = await credentialRequest(token.access_token, proof, SD_JWT_CONFIG_ID)
  assert.equal(credRes.status, 200)
  return (await credRes.json()).credentials[0].credential
}

test('vc+sd-jwt: the credential is an SD-JWT with no disclosures that verifies against the published JWKS', async () => {
  const signedBefore = signed.length
  const sdJwt = await issueSdJwt()
  assert.equal(typeof sdJwt, 'string')
  assert.match(sdJwt, /^[\w-]+\.[\w-]+\.[\w-]+~$/)
  assert.equal(signed.length, signedBefore, 'signing-service must not be called')

  const meta = await (await fetch(`${base}/.well-known/jwt-vc-issuer`)).json()
  assert.equal(meta.issuer, ISSUER)
  assert.equal(meta.jwks.keys.length, 1)
  const [jwk] = meta.jwks.keys
  assert.equal(jwk.alg, 'ES256')
  assert.equal(jwk.use, 'sig')
  assert.equal('d' in jwk, false)

  const jws = sdJwt.slice(0, -1)
  const { payload, protectedHeader } = await jwtVerify(jws, createLocalJWKSet(meta.jwks), {
    issuer: ISSUER,
    typ: 'vc+sd-jwt',
    algorithms: ['ES256'],
  })
  assert.deepEqual(protectedHeader, { typ: 'vc+sd-jwt', kid: jwk.kid, alg: 'ES256' })

  const { iss, iat, nbf, ...vc } = payload
  assert.equal(iss, ISSUER)
  assert.ok(Math.abs(iat - Date.now() / 1000) < 60)
  assert.equal(nbf, Date.parse(vcdm2Credential.validFrom) / 1000)
  assert.deepEqual(vc, vcdm2Credential)
  for (const claim of ['cnf', '_sd', '_sd_alg']) assert.equal(claim in payload, false, claim)

  // And an SD-JWT library (as a wallet would use) accepts it, with no disclosures.
  const verifier = new SDJwtInstance({ verifier: await ES256.getVerifier(jwk), hasher: digest })
  const verified = await verifier.verify(sdJwt)
  assert.deepEqual(verified.payload, payload)
  assert.deepEqual(await verifier.getClaims(sdJwt), payload)
})

test('vc+sd-jwt: the kid is the JWK thumbprint', async () => {
  const sdJwt = await issueSdJwt()
  const { kid } = decodeProtectedHeader(sdJwt.slice(0, -1))
  const meta = await (await fetch(`${base}/.well-known/jwt-vc-issuer`)).json()
  const { kty, crv, x, y } = meta.jwks.keys[0]
  assert.equal(kid, await calculateJwkThumbprint({ kty, crv, x, y }, 'sha256'))
})

test('vc+sd-jwt: a string issuer is accepted, and no validFrom means no nbf', async () => {
  const { validFrom, ...rest } = vcdm2Credential
  const sdJwt = await issueSdJwt({ ...rest, issuer: ISSUER })
  const { payload } = await jwtVerify(sdJwt.slice(0, -1), createLocalJWKSet((await (await fetch(`${base}/.well-known/jwt-vc-issuer`)).json()).jwks))
  assert.equal(payload.issuer, ISSUER)
  assert.equal('nbf' in payload, false)
})

test('vc+sd-jwt: an offer with a different issuer is rejected with 400', async () => {
  for (const issuer of ['https://other.example', { id: 'https://other.example', type: ['Profile'] }, undefined]) {
    const { res, body } = await createOffer({
      credentialConfigurationId: SD_JWT_CONFIG_ID,
      unsignedCredential: { ...vcdm2Credential, issuer },
    })
    assert.equal(res.status, 400)
    assert.match(body.error, /issuer/)
  }
})

test('vc+sd-jwt: an offer with an invalid validFrom is rejected with 400', async () => {
  const { res } = await createOffer({
    credentialConfigurationId: SD_JWT_CONFIG_ID,
    unsignedCredential: { ...vcdm2Credential, validFrom: 'yesterday' },
  })
  assert.equal(res.status, 400)
})

test('an offer for an unknown credential configuration is rejected with 400', async () => {
  const { res } = await createOffer({ credentialConfigurationId: 'Nope', unsignedCredential })
  assert.equal(res.status, 400)
})

const dcClaims = { vct: VCT, sub: 'urn:x:subject', awarded_on: '2024-06-01', achievement: { id: 'urn:x:a', name: 'A' } }

async function issueDc(claims = dcClaims) {
  const { res, body: created } = await createOffer({ credentialConfigurationId: DC_CONFIG_ID, unsignedCredential: claims })
  assert.equal(res.status, 200, JSON.stringify(created))
  const { token, proof } = await redeem(created)
  const credRes = await credentialRequest(token.access_token, proof, DC_CONFIG_ID)
  assert.equal(credRes.status, 200)
  return { sdJwt: (await credRes.json()).credentials[0].credential, proof }
}

test('dc+sd-jwt: flat claims plus iss, iat and cnf with the proof key, no disclosures', async () => {
  const { sdJwt, proof } = await issueDc()
  assert.match(sdJwt, /^[\w-]+\.[\w-]+\.[\w-]+~$/)
  const { jwks } = await (await fetch(`${base}/.well-known/jwt-vc-issuer`)).json()
  const { payload, protectedHeader } = await jwtVerify(sdJwt.slice(0, -1), createLocalJWKSet(jwks), { issuer: ISSUER, typ: 'dc+sd-jwt' })
  assert.deepEqual(protectedHeader, { typ: 'dc+sd-jwt', kid: jwks.keys[0].kid, alg: 'ES256' })
  const { iss, iat, cnf, ...claims } = payload
  assert.deepEqual(claims, dcClaims)
  assert.deepEqual(cnf, { jwk: decodeProtectedHeader(proof).jwk })
  for (const claim of ['nbf', '_sd', '_sd_alg', '@context', 'credentialSubject']) assert.equal(claim in payload, false, claim)
})

test('dc+sd-jwt: a wrong vct or an issuer-owned claim is rejected with 400', async () => {
  for (const claims of [{ ...dcClaims, vct: 'https://other.example/vct' }, { ...dcClaims, iss: ISSUER }, { ...dcClaims, cnf: {} }]) {
    const { res } = await createOffer({ credentialConfigurationId: DC_CONFIG_ID, unsignedCredential: claims })
    assert.equal(res.status, 400)
  }
})

test('dc+sd-jwt: type metadata is served at the vct URL', async () => {
  const meta = await (await fetch(`${base}/vct/OpenBadgeCredential`)).json()
  assert.equal(meta.vct, VCT)
  assert.equal(meta.name, 'Opintosuoritus')
  assert.deepEqual(meta.display[1], { locale: 'en', lang: 'en', name: 'Study record' })
})

test('vc+sd-jwt binds the holder only when its configuration lists jwk', async () => {
  const sdJwt = await issueSdJwt()
  assert.equal('cnf' in decodeJwtPayload(sdJwt), false)
})

function decodeJwtPayload(sdJwt) {
  return JSON.parse(Buffer.from(sdJwt.split('.')[1], 'base64url'))
}
