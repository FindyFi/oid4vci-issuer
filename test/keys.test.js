import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { generateKeyPairSync, verify, X509Certificate } from 'node:crypto'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { calculateJwkThumbprint, compactVerify, createLocalJWKSet, importJWK } from 'jose'
import { GetPublicKeyCommand, SignCommand } from '@aws-sdk/client-kms'
import { derToRaw, loadPreviousKeys, loadSigningKey } from '../src/keys.js'
import { loadX5c, selfSigned } from '../src/x5c.js'
import { signSdJwt } from '../src/sdjwt.js'
import { createJwtVcIssuerHandler } from '../src/jwt-vc-issuer.js'

const KEY_ARN = 'arn:aws:kms:eu-north-1:123456789012:key/11111111-2222-3333-4444-555555555555'
const ISSUER = 'https://issuer.example'
const dir = mkdtempSync(join(tmpdir(), 'oid4vci-kms-'))
after(() => rmSync(dir, { recursive: true, force: true }))

// Behaves like KMS for one P-256 key: GetPublicKey returns DER SPKI, and Sign
// takes a SHA-256 digest (MessageType DIGEST) and returns a DER signature.
// Node can't sign a pre-hashed digest, but `openssl pkeyutl -sign` can.
function fakeKms({ keySpec = 'ECC_NIST_P256', keyUsage = 'SIGN_VERIFY' } = {}) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const keyFile = join(dir, `${Math.random().toString(36).slice(2)}.pem`)
  writeFileSync(keyFile, privateKey.export({ type: 'pkcs8', format: 'pem' }))
  const calls = []
  return {
    publicKey,
    calls,
    async send(command) {
      calls.push(command)
      assert.equal(command.input.KeyId, KEY_ARN)
      if (command instanceof GetPublicKeyCommand) {
        return { PublicKey: new Uint8Array(publicKey.export({ type: 'spki', format: 'der' })), KeySpec: keySpec, KeyUsage: keyUsage }
      }
      if (command instanceof SignCommand) {
        assert.equal(command.input.MessageType, 'DIGEST')
        assert.equal(command.input.SigningAlgorithm, 'ECDSA_SHA_256')
        assert.equal(command.input.Message.length, 32)
        return { Signature: new Uint8Array(execFileSync('openssl', ['pkeyutl', '-sign', '-inkey', keyFile], { input: command.input.Message })) }
      }
      throw new Error(`unexpected command ${command.constructor.name}`)
    },
  }
}

test('a kms: key takes its public JWK and kid from KMS GetPublicKey', async () => {
  const kmsClient = fakeKms()
  const key = await loadSigningKey(`kms:${KEY_ARN}`, { kmsClient })
  const { kty, crv, x, y } = kmsClient.publicKey.export({ format: 'jwk' })
  assert.equal(key.kid, await calculateJwkThumbprint({ kty, crv, x, y }, 'sha256'))
  assert.deepEqual(key.publicJwk, { kty, crv, x, y, kid: key.kid, alg: 'ES256', use: 'sig' })
})

test('a kms: key must be ECC_NIST_P256 for signing', async () => {
  await assert.rejects(loadSigningKey(`kms:${KEY_ARN}`, { kmsClient: fakeKms({ keySpec: 'RSA_2048' }) }), /ECC_NIST_P256/)
  await assert.rejects(loadSigningKey(`kms:${KEY_ARN}`, { kmsClient: fakeKms({ keyUsage: 'ENCRYPT_DECRYPT' }) }), /SIGN_VERIFY/)
})

test('a kms: key signs SD-JWTs that verify against the published JWKS, whatever their size', async () => {
  const kmsClient = fakeKms()
  const key = await loadSigningKey(`kms:${KEY_ARN}`, { kmsClient })
  // Bigger than the 4 KB that KMS accepts as a RAW message.
  const credential = { vct: 'urn:x', padding: 'x'.repeat(5000) }
  const sdJwt = await signSdJwt(credential, { format: 'dc+sd-jwt', vct: 'urn:x' }, { issuer: ISSUER, key })
  const jwks = createLocalJWKSet({ keys: [key.publicJwk] })
  const { payload, protectedHeader } = await compactVerify(sdJwt.slice(0, -1), jwks)
  assert.equal(protectedHeader.kid, key.kid)
  assert.equal(JSON.parse(Buffer.from(payload)).padding.length, 5000)
  assert.equal(kmsClient.calls.filter((c) => c instanceof SignCommand).length, 1)
})

test('a self-signed certificate can be made with a kms: key', async () => {
  const key = await loadSigningKey(`kms:${KEY_ARN}`, { kmsClient: fakeKms() })
  const certificate = await selfSigned({ issuer: ISSUER, key, days: 3650 })
  const pem = certificate.toString('pem')
  const node = new X509Certificate(pem)
  assert.equal(node.verify(node.publicKey), true, 'self-signature verifies')
  assert.equal(node.subjectAltName, 'URI:https://issuer.example, DNS:issuer.example')
  const days = (Date.parse(node.validTo) - Date.parse(node.validFrom)) / 86400000
  assert.ok(Math.abs(days - 3650) < 1, `${days} days`)
  const [der] = await loadX5c(pem, { issuer: ISSUER, key })
  assert.equal(der, Buffer.from(node.raw).toString('base64'))
})

test('a local JWK key signs through the same interface', async () => {
  const key = await loadSigningKey('generate')
  const data = Buffer.from('hello')
  const signature = await key.sign(data)
  assert.equal(signature.length, 64)
  const publicKey = await importJWK(key.publicJwk, 'ES256')
  assert.equal(verify('sha256', data, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature), true)
})

test('derToRaw pads short integers and drops DER sign bytes', () => {
  // r = 0x00 0x80 ... (33 bytes, leading zero), s = 0x01 (1 byte)
  const r = [0x00, 0x80, ...new Array(31).fill(0x11)]
  const der = [0x30, 2 + r.length + 3, 0x02, r.length, ...r, 0x02, 0x01, 0x01]
  const raw = derToRaw(der)
  assert.deepEqual([...raw.subarray(0, 32)], r.slice(1))
  assert.deepEqual([...raw.subarray(32)], [...new Array(31).fill(0), 1])
  assert.throws(() => derToRaw([0x31, 0]), /DER/)
})

test('previous keys are published after the current one, public members only', async () => {
  const current = await loadSigningKey('generate')
  const old = await loadSigningKey('generate')
  const previousKeys = await loadPreviousKeys(JSON.stringify([{ ...old.publicJwk, kid: 'wrong' }, current.publicJwk]))
  assert.deepEqual(previousKeys[0], old.publicJwk, 'kid is recomputed')
  let body
  createJwtVcIssuerHandler({ issuer: ISSUER, key: current, previousKeys })({}, { json: (b) => (body = b) })
  assert.deepEqual(body.jwks.keys, [current.publicJwk, old.publicJwk], 'the current key is not listed twice')
  assert.deepEqual(await loadPreviousKeys(JSON.stringify({ keys: [old.publicJwk] })), [old.publicJwk], 'a JWK Set works too')
  assert.deepEqual(await loadPreviousKeys(undefined), [])
})

test('previous keys refuse private keys and anything but P-256', async () => {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const { publicKey: p384 } = generateKeyPairSync('ec', { namedCurve: 'P-384' })
  await assert.rejects(loadPreviousKeys(JSON.stringify([privateKey.export({ format: 'jwk' })])), /public keys only/)
  await assert.rejects(loadPreviousKeys(JSON.stringify([p384.export({ format: 'jwk' })])), /P-256/)
  await assert.rejects(loadPreviousKeys('nope'), /JSON array/)
  await assert.rejects(loadPreviousKeys('{}'), /JSON array/)
})
