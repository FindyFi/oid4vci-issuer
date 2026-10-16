import { createHash, webcrypto } from 'node:crypto'
import { generateKeyPair, exportJWK, calculateJwkThumbprint } from 'jose'

const EC_P256 = { name: 'ECDSA', namedCurve: 'P-256' }
const KMS_PREFIX = 'kms:'

// Loads the issuer's own ES256 key for signing SD-JWTs. `value` is one of:
// - `kms:<key ARN>`: an AWS KMS key (ECC_NIST_P256, SIGN_VERIFY). The private
//   key never leaves KMS; signing calls KMS `Sign`. Use this in production.
// - a private EC P-256 JWK as a JSON string.
// - `generate` for local dev, which makes a fresh key on every start (wallets
//   holding credentials signed by a previous key can no longer verify them
//   against the published JWKS).
// The kid is always the RFC 7638 thumbprint of the public key, so the same
// key always gets the same kid, whatever the input said.
// Returns `{ kid, publicJwk, sign }`, where `sign(bytes)` resolves to a raw
// 64-byte ES256 signature (r || s), as JWS and WebCrypto want it.
// `kmsClient` is for tests; by default one is made for the key's region.
export async function loadSigningKey(value, { kmsClient } = {}) {
  if (value?.startsWith(KMS_PREFIX)) return loadKmsKey(value.slice(KMS_PREFIX.length), kmsClient)

  let privateJwk
  if (value === 'generate') {
    const { privateKey } = await generateKeyPair('ES256', { extractable: true })
    privateJwk = await exportJWK(privateKey)
  } else {
    try {
      privateJwk = JSON.parse(value)
    } catch {
      throw new Error('SD_JWT_SIGNING_KEY must be "kms:<key ARN>", a private EC P-256 JWK as JSON, or "generate".')
    }
  }

  const { kty, crv, x, y, d } = privateJwk || {}
  if (kty !== 'EC' || crv !== 'P-256' || !x || !y || !d) {
    throw new Error('SD_JWT_SIGNING_KEY must be a private EC P-256 JWK (kty "EC", crv "P-256", with x, y and d).')
  }
  const privateKey = await webcrypto.subtle.importKey('jwk', { kty, crv, x, y, d }, EC_P256, false, ['sign'])
  return withPublicJwk({ kty, crv, x, y }, async (data) =>
    new Uint8Array(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, data))
  )
}

async function loadKmsKey(keyId, kmsClient) {
  const { KMSClient, GetPublicKeyCommand, SignCommand } = await import('@aws-sdk/client-kms')
  // A key or alias ARN names its region; a bare key id uses the SDK default.
  const region = keyId.startsWith('arn:') ? keyId.split(':')[3] : undefined
  const kms = kmsClient ?? new KMSClient(region ? { region } : {})

  const { PublicKey, KeySpec, KeyUsage } = await kms.send(new GetPublicKeyCommand({ KeyId: keyId }))
  if (KeySpec !== 'ECC_NIST_P256' || KeyUsage !== 'SIGN_VERIFY') {
    throw new Error(`SD_JWT_SIGNING_KEY: the KMS key must be ECC_NIST_P256 with usage SIGN_VERIFY, not ${KeySpec} / ${KeyUsage}.`)
  }
  const spki = await webcrypto.subtle.importKey('spki', PublicKey, EC_P256, true, ['verify'])
  const { kty, crv, x, y } = await webcrypto.subtle.exportKey('jwk', spki)

  return withPublicJwk({ kty, crv, x, y }, async (data) => {
    // Hash locally and send only the digest: KMS caps RAW messages at 4 KB,
    // and a credential can be larger than that.
    const { Signature } = await kms.send(
      new SignCommand({
        KeyId: keyId,
        Message: createHash('sha256').update(data).digest(),
        MessageType: 'DIGEST',
        SigningAlgorithm: 'ECDSA_SHA_256',
      })
    )
    return derToRaw(Signature)
  })
}

async function withPublicJwk({ kty, crv, x, y }, sign) {
  const kid = await calculateJwkThumbprint({ kty, crv, x, y }, 'sha256')
  return { kid, publicJwk: { kty, crv, x, y, kid, alg: 'ES256', use: 'sig' }, sign }
}

// KMS returns an ECDSA signature as DER, SEQUENCE { INTEGER r, INTEGER s };
// JWS wants r and s as two 32-byte big-endian numbers. P-256 signatures are
// short enough that every DER length here fits in one byte.
export function derToRaw(der) {
  const bytes = Uint8Array.from(der)
  if (bytes[0] !== 0x30) throw new Error('Not a DER ECDSA signature.')
  const raw = new Uint8Array(64)
  let offset = 2
  for (const position of [0, 32]) {
    if (bytes[offset] !== 0x02) throw new Error('Not a DER ECDSA signature.')
    const length = bytes[offset + 1]
    let integer = bytes.subarray(offset + 2, offset + 2 + length)
    while (integer.length > 32 && integer[0] === 0) integer = integer.subarray(1)
    if (integer.length > 32) throw new Error('Not a P-256 signature.')
    raw.set(integer, position + 32 - integer.length)
    offset += 2 + length
  }
  return raw
}

// Public keys of earlier signing keys, still published in the JWKS so that
// credentials they signed keep verifying after a key rotation. `value` is a
// JSON array of public EC P-256 JWKs (or a JWK Set). Private members are
// refused, so a private key can't be published by mistake. Each kid is
// recomputed as the thumbprint, like the current key's.
export async function loadPreviousKeys(value) {
  if (!value) return []
  let keys
  try {
    keys = JSON.parse(value)
  } catch {
    throw new Error('SD_JWT_PREVIOUS_KEYS must be a JSON array of public EC P-256 JWKs.')
  }
  if (Array.isArray(keys?.keys)) keys = keys.keys
  if (!Array.isArray(keys)) throw new Error('SD_JWT_PREVIOUS_KEYS must be a JSON array of public EC P-256 JWKs.')
  return Promise.all(
    keys.map(async (jwk) => {
      const { kty, crv, x, y } = jwk || {}
      if (kty !== 'EC' || crv !== 'P-256' || !x || !y) {
        throw new Error('SD_JWT_PREVIOUS_KEYS: every key must be a public EC P-256 JWK (kty "EC", crv "P-256", with x and y).')
      }
      if ('d' in jwk) throw new Error('SD_JWT_PREVIOUS_KEYS must hold public keys only; remove "d".')
      return (await withPublicJwk({ kty, crv, x, y })).publicJwk
    })
  )
}
