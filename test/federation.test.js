import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { generateKeyPair, exportJWK, SignJWT, jwtVerify, createLocalJWKSet, decodeProtectedHeader, decodeJwt } from 'jose'
import { createApp } from '../src/app.js'
import { loadSigningKey } from '../src/keys.js'
import {
  buildEntityMetadata,
  createEntityConfigurationHandler,
  envLine,
  loadFederationConfig,
  upsertEnvFile,
} from '../src/federation.js'
import { startIssuerExpectingFailure } from './helpers/server.js'

const ISSUER = 'https://issuer.example'
const VCT = 'https://vct.example/OpenBadgeVCT'
const DC_CONFIG_ID = 'OpenBadgeCredentialSdJwtVc'
const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:pre-authorized_code'
const COORDINATOR_TOKEN = 'secret'
const CONFIGURATIONS = {
  [DC_CONFIG_ID]: {
    format: 'dc+sd-jwt',
    vct: VCT,
    cryptographic_binding_methods_supported: ['jwk'],
    proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } },
  },
  Vc: { format: 'vc+sd-jwt' },
}
const ENTITY_METADATA = { display_name: 'Example University', organization_name: 'Example University Oy', contacts: ['it@example.org'] }
const TRUST_MARKS = [{ trust_mark_type: 'https://tm.example/type', trust_mark: 'a.b.c' }]

let key
let server
let base
let federation
let sdJwt
let plain // an app without federation

async function listen(app) {
  const instance = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s))
  })
  return { instance, url: `http://127.0.0.1:${instance.address().port}` }
}

before(async () => {
  key = await loadSigningKey('generate')
  sdJwt = { issuer: ISSUER, key, previousKeys: [] }
  federation = { key, entityMetadata: ENTITY_METADATA, authorityHints: ['https://ta.example'], trustMarks: TRUST_MARKS, ttl: 3600 }
  const common = { credentialIssuer: ISSUER, credentialConfigurationsSupported: CONFIGURATIONS, coordinatorToken: COORDINATOR_TOKEN, sdJwt }
  const on = await listen(createApp({ ...common, federation }))
  server = on.instance
  base = on.url
  const off = await listen(createApp(common))
  plain = off
})

after(async () => {
  await new Promise((resolve) => server.close(resolve))
  await new Promise((resolve) => plain.instance.close(resolve))
})

async function entityConfiguration() {
  const res = await fetch(`${base}/.well-known/openid-federation`)
  return { res, jws: await res.text() }
}

test('the Entity Configuration is a JWS that verifies against its own root jwks', async () => {
  const { res, jws } = await entityConfiguration()
  assert.equal(res.status, 200)
  assert.match(res.headers.get('content-type'), /^application\/entity-statement\+jwt/)
  assert.deepEqual(decodeProtectedHeader(jws), { typ: 'entity-statement+jwt', alg: 'ES256', kid: key.kid })

  const { payload } = await jwtVerify(jws, createLocalJWKSet(decodeJwt(jws).jwks), { typ: 'entity-statement+jwt' })
  assert.equal(payload.iss, ISSUER)
  assert.equal(payload.sub, ISSUER)
  assert.equal(payload.exp - payload.iat, 3600)
  assert.deepEqual(payload.jwks, { keys: [key.publicJwk] })
  assert.deepEqual(payload.authority_hints, ['https://ta.example'])
  assert.deepEqual(payload.trust_marks, TRUST_MARKS)
})

test('the metadata carries the issuer metadata, both credential JWKS copies and the AS metadata', async () => {
  const { jws } = await entityConfiguration()
  const { metadata } = decodeJwt(jws)
  assert.deepEqual(metadata.federation_entity, ENTITY_METADATA)

  const issuerMeta = await (await fetch(`${base}/.well-known/openid-credential-issuer`)).json()
  const { jwks: copyA, ...openidCredentialIssuer } = metadata.openid_credential_issuer
  assert.deepEqual(openidCredentialIssuer, issuerMeta)
  assert.equal(openidCredentialIssuer.credential_issuer, ISSUER)
  const { jwks } = await (await fetch(`${base}/.well-known/jwt-vc-issuer`)).json()
  assert.deepEqual(copyA, jwks)
  assert.deepEqual(metadata.vc_issuer, { jwks })
  assert.ok(Array.isArray(jwks.keys), 'a JWK Set, not a bare array')

  const asMeta = await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json()
  assert.deepEqual(metadata.oauth_authorization_server, asMeta)
  assert.equal(metadata.oauth_authorization_server.token_endpoint, `${ISSUER}/token`)
})

test('the signed JWS is cached until shortly before it expires', async () => {
  let now = 1_000_000_000_000
  const sign = []
  const counting = { ...key, sign: async (data) => (sign.push(1), key.sign(data)) }
  const handler = createEntityConfigurationHandler({
    credentialIssuer: ISSUER,
    credentialConfigurationsSupported: CONFIGURATIONS,
    sdJwt: { ...sdJwt, key: counting },
    federation: { ...federation, key: counting, ttl: 1000 },
    now: () => now,
  })
  const call = async () => {
    const out = {}
    await handler({}, { type: () => ({ send: (jws) => (out.jws = jws) }) })
    return out.jws
  }
  const first = await call()
  now += 800_000
  assert.equal(await call(), first)
  assert.equal(sign.length, 1)
  now += 150_000 // inside the last tenth of the lifetime
  assert.notEqual(await call(), first)
  assert.equal(sign.length, 2)
})

test('authority_hints and trust_marks are omitted when empty', async () => {
  const bare = await listen(createApp({ credentialIssuer: ISSUER, credentialConfigurationsSupported: CONFIGURATIONS, sdJwt, federation: { ...federation, authorityHints: [], trustMarks: [] } }))
  const payload = decodeJwt(await (await fetch(`${bare.url}/.well-known/openid-federation`)).text())
  await new Promise((resolve) => bare.instance.close(resolve))
  assert.equal('authority_hints' in payload, false)
  assert.equal('trust_marks' in payload, false)
})

test('the route is absent when federation is off', async () => {
  assert.equal((await fetch(`${plain.url}/.well-known/openid-federation`)).status, 404)
})

// ---- fed in issued credentials ----

async function offerAndRedeem(url, claims) {
  const res = await fetch(`${url}/instance/t1/offers`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${COORDINATOR_TOKEN}` },
    body: JSON.stringify({ credentialConfigurationId: DC_CONFIG_ID, unsignedCredential: claims }),
  })
  const created = await res.json()
  if (res.status !== 200) return { status: res.status }
  const offer = await (await fetch(`${url}/instance/t1/offers/${created.preAuthorizedCode}`)).json()
  const token = await (
    await fetch(`${url}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: GRANT_TYPE, 'pre-authorized_code': offer.grants[GRANT_TYPE]['pre-authorized_code'] }),
    })
  ).json()
  const { c_nonce: nonce } = await (await fetch(`${url}/nonce`, { method: 'POST' })).json()
  const { publicKey, privateKey } = await generateKeyPair('ES256')
  const proof = await new SignJWT({ nonce })
    .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: await exportJWK(publicKey) })
    .setAudience(ISSUER)
    .setIssuedAt()
    .sign(privateKey)
  const credRes = await fetch(`${url}/credential`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token.access_token}` },
    body: JSON.stringify({ credential_configuration_id: DC_CONFIG_ID, proofs: { jwt: [proof] } }),
  })
  return { status: credRes.status, sdJwt: (await credRes.json()).credentials?.[0]?.credential }
}

const claims = { vct: VCT, sub: 'urn:x:subject', achievement: { name: 'A' } }

test('dc+sd-jwt credentials carry fed = the Entity Identifier, only when federation is on', async () => {
  const withFed = await offerAndRedeem(base, claims)
  assert.equal(decodeJwt(withFed.sdJwt.slice(0, -1)).fed, ISSUER)
  const without = await offerAndRedeem(plain.url, claims)
  assert.equal('fed' in decodeJwt(without.sdJwt.slice(0, -1)), false)
})

test('a coordinator sending fed gets 400', async () => {
  for (const url of [base, plain.url]) assert.equal((await offerAndRedeem(url, { ...claims, fed: 'https://other.example' })).status, 400)
})

// ---- configuration and startup ----

test('createApp refuses federation without an SD-JWT key, or with an issuer that differs', () => {
  const common = { credentialIssuer: ISSUER, credentialConfigurationsSupported: {}, federation }
  assert.throws(() => createApp(common), /SD_JWT_SIGNING_KEY/)
  assert.throws(() => createApp({ ...common, sdJwt: { ...sdJwt, issuer: 'https://other.example' } }), /SD_JWT_ISSUER .* must equal CREDENTIAL_ISSUER/)
})

test('loadFederationConfig: off when unset or empty, defaults, and validation', () => {
  assert.equal(loadFederationConfig({}), undefined)
  assert.equal(loadFederationConfig({ FEDERATION_ENTITY_METADATA: '' }), undefined)
  const on = loadFederationConfig({ FEDERATION_ENTITY_METADATA: JSON.stringify(ENTITY_METADATA) })
  assert.deepEqual(on, { entityMetadata: ENTITY_METADATA, authorityHints: [], trustMarks: [], ttl: 86400 })

  const metadata = (m) => ({ FEDERATION_ENTITY_METADATA: JSON.stringify(m) })
  assert.throws(() => loadFederationConfig({ FEDERATION_ENTITY_METADATA: '{nope' }), /FEDERATION_ENTITY_METADATA must be valid JSON/)
  assert.throws(() => loadFederationConfig(metadata({ organization_name: 'x' })), /display_name/)
  assert.throws(() => loadFederationConfig(metadata({ display_name: '  ' })), /display_name/)
  assert.throws(() => loadFederationConfig(metadata({ display_name: 'x', homepage_uri: 'http://insecure.example' })), /homepage_uri must be an https URL/)
  assert.throws(() => loadFederationConfig(metadata({ display_name: 'x', contacts: 'it@example.org' })), /contacts/)
  const ok = metadata(ENTITY_METADATA)
  for (const hints of ['["http://ta.example"]', '"https://ta.example"', '[1]', 'nope']) {
    assert.throws(() => loadFederationConfig({ ...ok, FEDERATION_AUTHORITY_HINTS: hints }), /FEDERATION_AUTHORITY_HINTS/, hints)
  }
  assert.throws(() => loadFederationConfig({ ...ok, FEDERATION_TRUST_MARKS: '{}' }), /FEDERATION_TRUST_MARKS/)
  assert.throws(() => loadFederationConfig({ ...ok, FEDERATION_ENTITY_CONFIGURATION_TTL: '10' }), /FEDERATION_ENTITY_CONFIGURATION_TTL/)
  assert.equal(loadFederationConfig({ ...ok, FEDERATION_ENTITY_CONFIGURATION_TTL: '600' }).ttl, 600)
})

test('startup fails: federation without display_name, with a non-https hint, without a signing key, with a different SD_JWT_ISSUER', async () => {
  const env = {
    CREDENTIAL_ISSUER: ISSUER,
    CREDENTIAL_CONFIGURATIONS_SUPPORTED: '{}',
    SD_JWT_SIGNING_KEY: 'generate',
    COORDINATOR_TOKEN: 'x',
    FEDERATION_ENTITY_METADATA: JSON.stringify(ENTITY_METADATA),
  }
  const cases = [
    [{ FEDERATION_ENTITY_METADATA: '{"organization_name":"x"}' }, /display_name/],
    [{ FEDERATION_AUTHORITY_HINTS: '["http://ta.example"]' }, /FEDERATION_AUTHORITY_HINTS/],
    [{ SD_JWT_SIGNING_KEY: '' }, /SD_JWT_SIGNING_KEY/],
    [{ SD_JWT_ISSUER: 'https://other.example' }, /must equal CREDENTIAL_ISSUER/],
  ]
  for (const [override, message] of cases) {
    const { code, stderr } = await startIssuerExpectingFailure({ ...env, ...override })
    assert.notEqual(code, 0, JSON.stringify(override))
    assert.match(stderr, message, JSON.stringify(override))
  }
})

// ---- the helper script ----

test('buildEntityMetadata drops empty answers and rejects an invalid result', () => {
  assert.deepEqual(buildEntityMetadata({ displayName: ' Uni ', organizationName: '', contacts: [], homepageUri: 'https://uni.example' }), {
    display_name: 'Uni',
    homepage_uri: 'https://uni.example',
  })
  assert.throws(() => buildEntityMetadata({ displayName: '' }), /display_name/)
  assert.throws(() => buildEntityMetadata({ displayName: 'Uni', logoUri: 'ftp://x' }), /logo_uri/)
})

test('envLine survives a single quote and reads back the same in dotenv, with the issuer parsing it', async () => {
  const metadata = buildEntityMetadata({ displayName: "O'Brien's College", contacts: ['a@b.example'] })
  const line = envLine('FEDERATION_ENTITY_METADATA', metadata)
  assert.equal(line.startsWith("FEDERATION_ENTITY_METADATA='{"), true)
  assert.equal(line.slice(0, -1).slice(line.indexOf("='") + 2).includes("'"), false)
  const { parse } = await import('dotenv')
  const env = parse(line)
  assert.deepEqual(loadFederationConfig(env).entityMetadata, metadata)
})

test('upsertEnvFile replaces a line (or its commented-out form) in place and appends the rest', () => {
  const file = join(mkdtempSync(join(tmpdir(), 'fed-')), '.env')
  writeFileSync(file, 'PORT=1\n# FEDERATION_ENTITY_METADATA={}\nOTHER=2\n')
  const result = upsertEnvFile(file, [envLine('FEDERATION_ENTITY_METADATA', { display_name: 'A' }), envLine('FEDERATION_AUTHORITY_HINTS', ['https://ta.example'])])
  assert.deepEqual(result, { replaced: ['FEDERATION_ENTITY_METADATA'], appended: ['FEDERATION_AUTHORITY_HINTS'] })
  assert.equal(
    readFileSync(file, 'utf8'),
    `PORT=1\nFEDERATION_ENTITY_METADATA='{"display_name":"A"}'\nOTHER=2\nFEDERATION_AUTHORITY_HINTS='["https://ta.example"]'\n`
  )
  assert.deepEqual(upsertEnvFile(join(file, '..', 'new.env'), [envLine('X', 1)]), { replaced: [], appended: ['X'] })
})

function runScript(args, options = {}) {
  return spawnSync(process.execPath, ['scripts/federation-metadata.js', ...args], { cwd: new URL('../', import.meta.url), encoding: 'utf8', ...options })
}

test('scripts/federation-metadata.js prints env lines from flags, or writes them to a file', () => {
  const printed = runScript(['--display-name', 'Example University', '--contact', 'it@example.org', '--authority-hint', 'https://ta.example'])
  assert.equal(printed.status, 0, printed.stderr)
  const [metadataLine, hintsLine] = printed.stdout.trim().split('\n')
  assert.equal(metadataLine, `FEDERATION_ENTITY_METADATA='{"display_name":"Example University","contacts":["it@example.org"]}'`)
  assert.equal(hintsLine, `FEDERATION_AUTHORITY_HINTS='["https://ta.example"]'`)

  assert.equal(runScript(['--display-name', 'U', '--json']).stdout.trim(), '{"display_name":"U"}')

  const file = join(mkdtempSync(join(tmpdir(), 'fed-')), 'out.env')
  const written = runScript(['--display-name', 'U', '--write', file])
  assert.equal(written.status, 0, written.stderr)
  assert.equal(readFileSync(file, 'utf8'), `FEDERATION_ENTITY_METADATA='{"display_name":"U"}'\n`)

  const bad = runScript(['--display-name', 'U', '--homepage-uri', 'http://x.example'])
  assert.notEqual(bad.status, 0)
  assert.match(bad.stderr, /homepage_uri/)
  assert.notEqual(runScript([], { input: '' }).status, 0) // no flags and no terminal
})
