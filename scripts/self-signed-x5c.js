// Prints a self-signed certificate (PEM) for the SD-JWT signing key, to keep
// as SD_JWT_X5C. Unlike SD_JWT_X5C=generate, which makes a new certificate on
// every start, the stored one stays the same across restarts, so wallets
// that remember an accepted issuer certificate keep recognising it.
//
//   SD_JWT_SIGNING_KEY=kms:arn:aws:kms:... CREDENTIAL_ISSUER=https://issuer.example \
//     node scripts/self-signed-x5c.js [days] > x5c.pem
//
// With a KMS key this needs AWS credentials allowed kms:GetPublicKey and
// kms:Sign on it. `days` defaults to 3650: when the certificate expires,
// Credo-based wallets stop accepting credentials that carry it.
import 'dotenv/config'
import { loadSigningKey } from '../src/keys.js'
import { loadX5c, selfSigned } from '../src/x5c.js'

const issuer = process.env.SD_JWT_ISSUER || process.env.CREDENTIAL_ISSUER
const value = process.env.SD_JWT_SIGNING_KEY
if (!issuer || !value || value === 'generate') {
  throw new Error('Set SD_JWT_SIGNING_KEY (a stored key, not "generate") and CREDENTIAL_ISSUER (or SD_JWT_ISSUER).')
}
const days = Number(process.argv[2] ?? 3650)
if (!Number.isInteger(days) || days < 1) throw new Error('days must be a positive whole number.')

const key = await loadSigningKey(value)
const pem = (await selfSigned({ issuer, key, days })).toString('pem')
await loadX5c(pem, { issuer, key }) // the same checks the issuer makes at startup
process.stdout.write(`${pem}\n`)
