import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { decodeJwt } from 'jose'
import { createApp } from '../src/app.js'
import { loadSigningKey } from '../src/keys.js'
import { buildIssuerMetadataConfig, checkDisplay, loadIssuerMetadataConfig } from '../src/metadata.js'
import { buildEntityMetadata, loadFederationConfig, withDisplayDefaults } from '../src/federation.js'
import { startIssuer, startIssuerExpectingFailure } from './helpers/server.js'

const ISSUER = 'https://issuer.example'
const LOGO = 'https://uni.example/logo.png'
const DISPLAY = [
  { locale: 'fi', name: 'Esimerkkiyliopisto', logo: { uri: LOGO, alt_text: 'Esimerkkiyliopiston logo' } },
  { locale: 'en', name: 'Example University', logo: { uri: LOGO, alt_text: 'Example University logo' } },
  { locale: 'sv', name: 'Exempeluniversitetet' },
]

async function listen(app) {
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s))
  })
  return { server, url: `http://127.0.0.1:${server.address().port}` }
}

test('the issuer metadata carries display as configured, and has none without it', async () => {
  const issuer = await startIssuer({ env: { OID4VCI_ISSUER_METADATA: JSON.stringify({ display: DISPLAY }) } })
  try {
    const metadata = await (await fetch(`${issuer.baseUrl}/.well-known/openid-credential-issuer`)).json()
    assert.deepEqual(metadata.display, DISPLAY)
  } finally {
    await issuer.stop()
  }
  const plain = await startIssuer()
  try {
    const metadata = await (await fetch(`${plain.baseUrl}/.well-known/openid-credential-issuer`)).json()
    assert.equal('display' in metadata, false)
  } finally {
    await plain.stop()
  }
})

test('the Entity Configuration embeds display, and federation takes its name and logo from it', async () => {
  const key = await loadSigningKey('generate')
  const federation = { key, entityMetadata: { organization_name: 'Example University Oy' }, authorityHints: [], trustMarks: [], ttl: 3600 }
  const app = createApp({ credentialIssuer: ISSUER, credentialConfigurationsSupported: {}, sdJwt: { issuer: ISSUER, key }, federation, display: DISPLAY })
  const { server, url } = await listen(app)
  try {
    const { metadata } = decodeJwt(await (await fetch(`${url}/.well-known/openid-federation`)).text())
    assert.deepEqual(metadata.openid_credential_issuer.display, DISPLAY)
    assert.deepEqual(metadata.federation_entity, {
      organization_name: 'Example University Oy',
      display_name: 'Example University',
      'display_name#fi': 'Esimerkkiyliopisto',
      'display_name#en': 'Example University',
      'display_name#sv': 'Exempeluniversitetet',
      logo_uri: LOGO,
    })
  } finally {
    await new Promise((resolve) => server.close(resolve))
  }
})

test('withDisplayDefaults keeps what the federation metadata sets, and carries over only an https logo', () => {
  const own = { display_name: 'Uni', logo_uri: 'https://uni.example/own.png' }
  assert.deepEqual(withDisplayDefaults(own, DISPLAY), own)
  assert.deepEqual(withDisplayDefaults({}, undefined), {})

  // No English entry: the first one is the main name; a data: logo isn't an https URL.
  const display = [
    { locale: 'fi', name: 'Yliopisto', logo: { uri: 'data:image/png;base64,AAAA' } },
    { locale: 'sv-FI', name: 'Universitet', logo: { uri: LOGO } },
  ]
  assert.deepEqual(withDisplayDefaults({}, display), {
    display_name: 'Yliopisto',
    'display_name#fi': 'Yliopisto',
    'display_name#sv-FI': 'Universitet',
    logo_uri: LOGO,
  })
  // An entry without a locale gives only the untagged name.
  assert.deepEqual(withDisplayDefaults({}, [{ name: 'Uni' }]), { display_name: 'Uni' })
})

test('loadFederationConfig accepts metadata without display_name only when there is a display', () => {
  const env = { FEDERATION_ENTITY_METADATA: '{}' }
  assert.equal(loadFederationConfig(env, { display: DISPLAY }).entityMetadata.display_name, 'Example University')
  assert.throws(() => loadFederationConfig(env), /display_name .*OID4VCI_ISSUER_METADATA/)
})

test('loadIssuerMetadataConfig: {} when unset, the object when valid, and refuses the rest', () => {
  assert.deepEqual(loadIssuerMetadataConfig({}), {})
  assert.deepEqual(loadIssuerMetadataConfig({ OID4VCI_ISSUER_METADATA: JSON.stringify({ display: DISPLAY }) }), { display: DISPLAY })
  for (const [value, message] of [
    ['not json', /valid JSON/],
    ['[]', /JSON object/],
    ['{"display":[],"x":1}', /unsupported x/],
    ['{"display":[]}', /non-empty array/],
  ]) {
    assert.throws(() => loadIssuerMetadataConfig({ OID4VCI_ISSUER_METADATA: value }), message, value)
  }
})

test('checkDisplay refuses a duplicate locale, a missing name, a bad logo and unknown members', () => {
  assert.equal(checkDisplay(DISPLAY), undefined)
  assert.equal(checkDisplay([{ name: 'Uni', logo: { uri: 'data:image/svg+xml;base64,PHN2Zy8+' } }]), undefined)
  const cases = [
    [[{ locale: 'fi', name: 'A' }, { locale: 'FI', name: 'B' }], /second entry for FI/],
    [[{ name: 'A' }, { name: 'B' }], /second entry without a locale/],
    [[{ locale: 'fi' }], /needs a name/],
    [[{ locale: 'fi', name: ' ' }], /needs a name/],
    [[{ locale: 'f i', name: 'A' }], /language tag/],
    [[{ name: 'A', logo: { uri: 'http://uni.example/logo.png' } }], /https URL or a data: URI/],
    [[{ name: 'A', logo: { uri: 'logo.png' } }], /https URL or a data: URI/],
    [[{ name: 'A', logo: 'https://uni.example/logo.png' }], /logo must be an object/],
    [[{ name: 'A', logo: { uri: LOGO, alt_text: 1 } }], /alt_text/],
    [[{ name: 'A', description: 'x' }], /unsupported description/],
    [[{ name: 'A', logo: { uri: LOGO, url: LOGO } }], /unsupported url/],
    [['A'], /must be an object/],
  ]
  for (const [display, message] of cases) assert.match(checkDisplay(display), message, JSON.stringify(display))
})

test('startup fails on an invalid OID4VCI_ISSUER_METADATA, and createApp on an invalid display', async () => {
  const { code, stderr } = await startIssuerExpectingFailure({
    CREDENTIAL_ISSUER: ISSUER,
    CREDENTIAL_CONFIGURATIONS_SUPPORTED: '{}',
    COORDINATOR_TOKEN: 'x',
    OID4VCI_ISSUER_METADATA: JSON.stringify({ display: [{ locale: 'fi', name: 'A' }, { locale: 'fi', name: 'B' }] }),
  })
  assert.notEqual(code, 0)
  assert.match(stderr, /OID4VCI_ISSUER_METADATA: .*second entry for fi/)
  assert.throws(() => createApp({ credentialIssuer: ISSUER, credentialConfigurationsSupported: {}, display: [] }), /Issuer metadata: display must be a non-empty array/)
})

// ---- the helper scripts ----

test('buildIssuerMetadataConfig: one entry per language in order, one logo for all, empty answers dropped', () => {
  assert.deepEqual(
    buildIssuerMetadataConfig({
      locales: ['fi', 'en'],
      names: { fi: ' Yliopisto ', en: 'University' },
      logoUri: LOGO,
      altTexts: { fi: 'Logo', en: '' },
    }),
    { display: [{ locale: 'fi', name: 'Yliopisto', logo: { uri: LOGO, alt_text: 'Logo' } }, { locale: 'en', name: 'University', logo: { uri: LOGO } }] }
  )
  assert.deepEqual(buildIssuerMetadataConfig({ locales: ['fi'], names: { fi: 'Y' }, logoUri: '' }), { display: [{ locale: 'fi', name: 'Y' }] })
  assert.throws(() => buildIssuerMetadataConfig({ locales: ['fi', 'en'], names: { fi: 'Y' } }), /display\[1\] needs a name/)
  assert.throws(() => buildIssuerMetadataConfig({ locales: [] }), /non-empty/)
})

function run(script, args, options = {}) {
  return spawnSync(process.execPath, [`scripts/${script}`, ...args], {
    cwd: new URL('../', import.meta.url),
    encoding: 'utf8',
    ...options,
    env: { ...process.env, OID4VCI_ISSUER_METADATA: '', ...options.env },
  })
}

test('scripts/issuer-metadata.js builds the display from --lang and per-language flags', () => {
  const printed = run('issuer-metadata.js', ['--lang=en, fi', '--name', 'fi=Yliopisto', '--name', 'en=University', '--logo-uri', LOGO, '--logo-alt', 'en=Logo'])
  assert.equal(printed.status, 0, printed.stderr)
  assert.equal(
    printed.stdout.trim(),
    `OID4VCI_ISSUER_METADATA='{"display":[{"locale":"en","name":"University","logo":{"uri":"${LOGO}","alt_text":"Logo"}},{"locale":"fi","name":"Yliopisto","logo":{"uri":"${LOGO}"}}]}'`
  )

  // Without --lang, the languages and their order come from --name.
  const json = run('issuer-metadata.js', ['--name', 'sv=Universitet', '--name', 'fi=Yliopisto', '--json'])
  assert.deepEqual(JSON.parse(json.stdout), { display: [{ locale: 'sv', name: 'Universitet' }, { locale: 'fi', name: 'Yliopisto' }] })

  const file = join(mkdtempSync(join(tmpdir(), 'display-')), 'out.env')
  writeFileSync(file, 'PORT=1\n# OID4VCI_ISSUER_METADATA={}\n')
  const written = run('issuer-metadata.js', ['--name', 'fi=Y', '--write', file])
  assert.equal(written.status, 0, written.stderr)
  assert.equal(readFileSync(file, 'utf8'), `PORT=1\nOID4VCI_ISSUER_METADATA='{"display":[{"locale":"fi","name":"Y"}]}'\n`)

  const missing = run('issuer-metadata.js', ['--lang=fi,en', '--name', 'fi=Y'])
  assert.notEqual(missing.status, 0)
  assert.match(missing.stderr, /display\[1\] needs a name/)
  assert.match(run('issuer-metadata.js', ['--name', 'Y']).stderr, /<language>=<text>/)
  assert.notEqual(run('issuer-metadata.js', [], { input: '' }).status, 0) // no flags and no terminal
})

test('scripts/federation-metadata.js may leave out the display name when the env file has a display', () => {
  const dir = mkdtempSync(join(tmpdir(), 'display-'))
  const file = join(dir, '.env')
  const issuerLine = `OID4VCI_ISSUER_METADATA='${JSON.stringify({ display: DISPLAY })}'`
  writeFileSync(file, `${issuerLine}\n`)
  const written = run('federation-metadata.js', ['--organization-name', 'Example University Oy', '--write', file])
  assert.equal(written.status, 0, written.stderr)
  assert.equal(readFileSync(file, 'utf8'), `${issuerLine}\nFEDERATION_ENTITY_METADATA='{"organization_name":"Example University Oy"}'\n`)

  const without = run('federation-metadata.js', ['--organization-name', 'Example University Oy', '--write', join(dir, 'other.env')])
  assert.notEqual(without.status, 0)
  assert.match(without.stderr, /display_name/)

  // The environment counts too.
  const fromEnv = run('federation-metadata.js', ['--organization-name', 'X', '--json'], { env: { OID4VCI_ISSUER_METADATA: JSON.stringify({ display: DISPLAY }) } })
  assert.equal(fromEnv.stdout.trim(), '{"organization_name":"X"}')
  assert.deepEqual(buildEntityMetadata({ organizationName: 'X' }, { display: DISPLAY }), { organization_name: 'X' })
})
