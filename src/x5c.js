import 'reflect-metadata' // needed by @peculiar/x509 (tsyringe)
import { webcrypto } from 'node:crypto'
import * as x509 from '@peculiar/x509'
import { calculateJwkThumbprint } from 'jose'

x509.cryptoProvider.set(webcrypto)

const EC_P256 = { name: 'ECDSA', namedCurve: 'P-256' }

// Loads the optional X.509 chain that SD-JWT headers carry as `x5c`, next to
// the plain HTTPS `iss`. Some wallets (Credo-based ones such as Paradym)
// resolve an SD-JWT issuer's key only from `x5c` or a DID, not from JWT VC
// Issuer Metadata. `value` is the chain as PEM, leaf first, or `generate` for
// local dev: a self-signed certificate for the signing key, made on every
// start. Returns the chain as base64 DER strings, as x5c wants them.
// The leaf must hold the signing key and name the issuer in its
// subjectAltName (URI = the issuer URL, or DNS = its host), which is how a
// wallet ties the certificate to `iss`.
export async function loadX5c(value, { issuer, key }) {
  const host = new URL(issuer).hostname
  const certificates = value === 'generate' ? [await selfSigned({ issuer, host, key })] : parseChain(value)
  const [leaf] = certificates

  const leafJwk = await webcrypto.subtle.exportKey('jwk', await leaf.publicKey.export(EC_P256, ['verify']))
  if ((await calculateJwkThumbprint(leafJwk, 'sha256')) !== key.kid) {
    throw new Error('SD_JWT_X5C: the first certificate must hold the SD_JWT_SIGNING_KEY public key.')
  }
  const san = leaf.getExtension(x509.SubjectAlternativeNameExtension)?.names.toJSON() ?? []
  if (!san.some(({ type, value }) => (type === 'url' && value === issuer) || (type === 'dns' && value === host))) {
    throw new Error(`SD_JWT_X5C: the first certificate's subjectAltName must contain the URI ${issuer} or the DNS name ${host}.`)
  }
  return certificates.map((certificate) => Buffer.from(certificate.rawData).toString('base64'))
}

function parseChain(pem) {
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g)
  if (!blocks) throw new Error('SD_JWT_X5C must be a PEM certificate chain (leaf first), or "generate".')
  return blocks.map((block) => new x509.X509Certificate(block))
}

// A self-signed certificate for the signing key, valid for `days` from now.
// scripts/self-signed-x5c.js uses it to make a certificate once and keep it,
// which is what production does (a stable SD_JWT_X5C, not `generate`).
// The key may live in KMS, so its private half is never a CryptoKey: the
// generator gets a crypto object whose `sign` calls `key.sign`.
export async function selfSigned({ issuer, host = new URL(issuer).hostname, key, days = 365 }) {
  const { kty, crv, x, y } = key.publicJwk
  const keys = {
    privateKey: { algorithm: EC_P256, type: 'private' },
    publicKey: await webcrypto.subtle.importKey('jwk', { kty, crv, x, y }, EC_P256, true, ['verify']),
  }
  const crypto = {
    getRandomValues: (array) => webcrypto.getRandomValues(array),
    subtle: {
      exportKey: (...args) => webcrypto.subtle.exportKey(...args),
      sign: async (algorithm, privateKey, data) => (await key.sign(new Uint8Array(data))).slice().buffer,
    },
  }
  const notBefore = new Date()
  return x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: Buffer.from(webcrypto.getRandomValues(new Uint8Array(16))).toString('hex').replace(/^[89a-f]/, '1'),
    name: `CN=${host}`,
    notBefore,
    notAfter: new Date(notBefore.getTime() + days * 24 * 60 * 60 * 1000),
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    keys,
    extensions: [
      new x509.SubjectAlternativeNameExtension([
        { type: 'url', value: issuer },
        { type: 'dns', value: host },
      ]),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
    ],
  }, crypto)
}
