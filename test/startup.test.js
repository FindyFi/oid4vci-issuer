import { test } from 'node:test'
import assert from 'node:assert/strict'
import { calculateJwkThumbprint, exportJWK, generateKeyPair } from 'jose'
import { createApp } from '../src/app.js'
import { loadSigningKey } from '../src/keys.js'
import { loadX5c } from '../src/x5c.js'
import { signSdJwt } from '../src/sdjwt.js'
import { X509Certificate } from 'node:crypto'

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

test('dc+sd-jwt without a vct fails at startup', async () => {
  const sdJwt = { issuer: base.credentialIssuer, key: await loadSigningKey('generate') }
  assert.throws(() => createApp({ ...base, credentialConfigurationsSupported: { A: { format: 'dc+sd-jwt' } }, sdJwt }), /needs a vct/)
})

test('loadX5c generates a self-signed certificate for the signing key, naming the issuer', async () => {
  const key = await loadSigningKey('generate')
  const [der, ...rest] = await loadX5c('generate', { issuer: 'https://issuer.example', key })
  assert.equal(rest.length, 0)
  const certificate = new X509Certificate(Buffer.from(der, 'base64'))
  assert.equal(certificate.subjectAltName, 'URI:https://issuer.example, DNS:issuer.example')
  const jwk = certificate.publicKey.export({ format: 'jwk' })
  assert.equal(await calculateJwkThumbprint(jwk, 'sha256'), key.kid)
})

test('loadX5c rejects a certificate for another key or another issuer', async () => {
  const key = await loadSigningKey('generate')
  const other = await loadSigningKey('generate')
  const pem = (der) => `-----BEGIN CERTIFICATE-----\n${der}\n-----END CERTIFICATE-----`
  const [otherKeysCert] = await loadX5c('generate', { issuer: 'https://issuer.example', key: other })
  await assert.rejects(loadX5c(pem(otherKeysCert), { issuer: 'https://issuer.example', key }), /SD_JWT_SIGNING_KEY public key/)
  const [cert] = await loadX5c('generate', { issuer: 'https://issuer.example', key })
  assert.deepEqual(await loadX5c(pem(cert), { issuer: 'https://issuer.example', key }), [cert])
  await assert.rejects(loadX5c(pem(cert), { issuer: 'https://elsewhere.example', key }), /subjectAltName/)
})

test('signSdJwt puts the x5c chain into the header when configured', async () => {
  const key = await loadSigningKey('generate')
  const issuer = 'https://issuer.example'
  const x5c = await loadX5c('generate', { issuer, key })
  const sdJwt = await signSdJwt({ vct: 'urn:x' }, { format: 'dc+sd-jwt', vct: 'urn:x' }, { issuer, key, x5c })
  const header = JSON.parse(Buffer.from(sdJwt.split('.')[0], 'base64url'))
  assert.deepEqual(header.x5c, x5c)
  assert.equal(header.kid, key.kid)
})
