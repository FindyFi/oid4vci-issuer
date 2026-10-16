import { test } from 'node:test'
import assert from 'node:assert/strict'
import { calculateJwkThumbprint, exportJWK, generateKeyPair } from 'jose'
import { createApp } from '../src/app.js'
import { loadSigningKey } from '../src/keys.js'

const base = { credentialIssuer: 'https://issuer.example', coordinatorToken: 'x' }
const signLdpVc = async (vc) => vc

test('an unknown credential format fails at startup', () => {
  assert.throws(
    () => createApp({ ...base, credentialConfigurationsSupported: { A: { format: 'jwt_vc_json' } }, signLdpVc }),
    /unsupported format jwt_vc_json/
  )
})

test('ldp_vc without a signing service fails at startup', () => {
  assert.throws(() => createApp({ ...base, credentialConfigurationsSupported: { A: { format: 'ldp_vc' } } }), /signing service/)
})

test('vc+sd-jwt without a signing key fails at startup', () => {
  assert.throws(() => createApp({ ...base, credentialConfigurationsSupported: { A: { format: 'vc+sd-jwt' } }, signLdpVc }), /SD_JWT_SIGNING_KEY/)
})

test('vc+sd-jwt alone needs no signing service', async () => {
  const key = await loadSigningKey('generate')
  createApp({ ...base, credentialConfigurationsSupported: { A: { format: 'vc+sd-jwt' } }, sdJwt: { issuer: base.credentialIssuer, key } })
})

test('the SD-JWT issuer must be origin-only', async () => {
  const key = await loadSigningKey('generate')
  for (const issuer of ['https://issuer.example/', 'https://issuer.example/tenant', 'not a url']) {
    assert.throws(() => createApp({ ...base, credentialConfigurationsSupported: {}, sdJwt: { issuer, key } }), /SD-JWT issuer/, issuer)
  }
})

test('loadSigningKey reads a private JWK and uses its thumbprint as kid', async () => {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true })
  const jwk = await exportJWK(privateKey)
  const key = await loadSigningKey(JSON.stringify({ ...jwk, kid: 'ignored' }))
  const { kty, crv, x, y } = jwk
  assert.equal(key.kid, await calculateJwkThumbprint({ kty, crv, x, y }, 'sha256'))
  assert.deepEqual(key.publicJwk, { kty, crv, x, y, kid: key.kid, alg: 'ES256', use: 'sig' })
})

test('loadSigningKey rejects anything but a private P-256 JWK', async () => {
  const { publicKey } = await generateKeyPair('ES256')
  const { privateKey: ed } = await generateKeyPair('EdDSA', { extractable: true })
  for (const value of ['nope', JSON.stringify(await exportJWK(publicKey)), JSON.stringify(await exportJWK(ed))]) {
    await assert.rejects(loadSigningKey(value), /SD_JWT_SIGNING_KEY/)
  }
})
