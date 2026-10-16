import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { jwtVerify, createLocalJWKSet } from 'jose'
import { resolveVctIntegrity, sri } from '../src/vct-integrity.js'
import { signSdJwt, checkSdJwtCredential } from '../src/sdjwt.js'
import { loadSigningKey } from '../src/keys.js'

const BYTES = Buffer.from('{"vct":"x","name":"Stub"}\n')
const HASH = sri(BYTES)

let server
let vct
before(async () => {
  server = http.createServer((req, res) => (req.url === '/vct' ? res.end(BYTES) : res.writeHead(404).end()))
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  vct = `http://127.0.0.1:${server.address().port}/vct`
})
after(() => new Promise((resolve) => server.close(resolve)))

const config = (extra = {}) => ({ format: 'dc+sd-jwt', vct, ...extra })
const resolve = (configurations, warnings = []) => resolveVctIntegrity(configurations, { warn: (m) => warnings.push(m) })

test('unpinned: uses the fetched hash; other configurations are untouched', async () => {
  const ldp = { format: 'ldp_vc' }
  const out = await resolve({ A: config(), B: ldp })
  assert.equal(out.A['vct#integrity'], HASH)
  assert.equal(out.B, ldp)
})

test('pinned and matching: kept', async () => {
  assert.equal((await resolve({ A: config({ 'vct#integrity': HASH }) })).A['vct#integrity'], HASH)
})

test('pinned and different: startup throws', async () => {
  await assert.rejects(resolve({ A: config({ 'vct#integrity': 'sha256-AAAA' }) }), /pinned to sha256-AAAA/)
})

test('pinned and unreachable: starts with the pinned value and warns', async () => {
  const warnings = []
  const unreachable = `${vct}-missing`
  const out = await resolve({ A: config({ vct: unreachable, 'vct#integrity': HASH }) }, warnings)
  assert.equal(out.A['vct#integrity'], HASH)
  assert.equal(warnings.length, 1)
})

test('unpinned and unreachable: no vct#integrity, warns', async () => {
  const warnings = []
  const out = await resolve({ A: config({ vct: `${vct}-missing` }) }, warnings)
  assert.equal('vct#integrity' in out.A, false)
  assert.equal(warnings.length, 1)
})

test('the issuer puts vct#integrity into the credential; a coordinator sending it gets 400', async () => {
  const key = await loadSigningKey('generate')
  const configuration = (await resolve({ A: config() })).A
  const sdJwt = await signSdJwt({ vct }, configuration, { issuer: 'https://issuer.example', key })
  const { payload } = await jwtVerify(sdJwt.slice(0, -1), createLocalJWKSet({ keys: [key.publicJwk] }))
  assert.equal(payload['vct#integrity'], HASH)
  assert.match(checkSdJwtCredential({ vct, 'vct#integrity': HASH }, configuration, {}), /vct#integrity/)
  assert.equal(checkSdJwtCredential({ vct }, configuration, {}), undefined)
})
