import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { loadEnvManifest, missingRequired, parseEnvManifest } from '../src/env-manifest.js'

const root = new URL('..', import.meta.url).pathname

function sourceFiles(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    return statSync(path).isDirectory() ? sourceFiles(path) : path.endsWith('.js') ? [path] : []
  })
}

test('every process.env read outside test/ is listed in .env.example', () => {
  const listed = new Set(loadEnvManifest().map((e) => e.name))
  const files = [join(root, 'index.js'), ...sourceFiles(join(root, 'src')), ...sourceFiles(join(root, 'scripts'))]
  const read = new Set()
  for (const file of files) {
    for (const m of readFileSync(file, 'utf8').matchAll(/process\.env\.([A-Z][A-Z0-9_]*)|process\.env\[['"]([A-Z][A-Z0-9_]*)['"]\]/g)) {
      read.add(m[1] || m[2])
    }
  }
  assert.ok(read.size > 5)
  // NODE_ENV is set by the Dockerfile, not configured.
  const unlisted = [...read].filter((n) => !listed.has(n) && n !== 'NODE_ENV')
  assert.deepEqual(unlisted, [])
})

test('every listed variable has exactly one valid tag, and no tag is orphaned', () => {
  // parseEnvManifest throws on a missing, invalid, doubled or orphaned tag.
  const manifest = loadEnvManifest()
  assert.ok(manifest.length > 5)
  const text = readFileSync(join(root, '.env.example'), 'utf8')
  assert.equal(text.split('\n').filter((l) => /@env/.test(l)).length, manifest.length)
})

test('the manifest marks the settled variables', () => {
  const byName = Object.fromEntries(loadEnvManifest().map((e) => [e.name, e]))
  assert.deepEqual(byName.COORDINATOR_TOKEN, { name: 'COORDINATOR_TOKEN', required: true, secret: true })
  assert.deepEqual(byName.SD_JWT_SIGNING_KEY, { name: 'SD_JWT_SIGNING_KEY', required: true, secret: false })
  assert.equal(byName.CREDENTIAL_ISSUER.required, true)
  assert.equal(byName.CREDENTIAL_CONFIGURATIONS_SUPPORTED.required, true)
  assert.equal(byName.LOG_REQUESTS.required, false)
})

test('the parser rejects a missing, invalid, doubled or orphaned tag', () => {
  assert.throws(() => parseEnvManifest('A=1\n'), /no "# @env" tag/)
  assert.throws(() => parseEnvManifest('# @env mandatory\nA=1\n'), /invalid tag/)
  assert.throws(() => parseEnvManifest('# @env required\n# @env optional\nA=1\n'), /second tag/)
  assert.throws(() => parseEnvManifest('# @env required\n# a comment\nA=1\n'), /directly above/)
  assert.throws(() => parseEnvManifest('# @env required\n'), /ends with a tag/)
  assert.throws(() => parseEnvManifest('# @env required\nA=1\n# @env optional\nA=2\n'), /twice/)
})

test('the parser reads commented-out variables, descriptions and secret', () => {
  const text = '# About A.\n# @env required secret\nA=1\n\n# @env optional\n# B=x\n'
  assert.deepEqual(parseEnvManifest(text), [
    { name: 'A', required: true, secret: true },
    { name: 'B', required: false, secret: false },
  ])
})

test('missingRequired lists unset and empty required variables only', () => {
  const manifest = parseEnvManifest('# @env required\nA=1\n# @env required\nB=1\n# @env required\nC=1\n# @env optional\nD=1\n')
  assert.deepEqual(missingRequired(manifest, { A: 'x', C: '' }), ['B', 'C'])
})

// Run from an empty directory so dotenv doesn't pick up a local .env.
function startIndex(env) {
  const cwd = mkdtempSync(join(tmpdir(), 'issuer-env-'))
  return spawnSync(process.execPath, [join(root, 'index.js')], { cwd, env: { PATH: process.env.PATH, ...env }, encoding: 'utf8', timeout: 20000 })
}

test('in production, startup fails naming every missing required variable', () => {
  const result = startIndex({ NODE_ENV: 'production', PORT: '0', CREDENTIAL_ISSUER: 'https://issuer.example' })
  assert.equal(result.status, 1)
  const required = loadEnvManifest().filter((e) => e.required && e.name !== 'CREDENTIAL_ISSUER').map((e) => e.name)
  assert.match(result.stderr, /Missing required environment variables/)
  for (const name of required) assert.ok(result.stderr.includes(name), name)
  assert.ok(!/Missing required[^\n]*CREDENTIAL_ISSUER/.test(result.stderr))
  assert.ok(!result.stdout.includes('listening'))
})

test('outside production, missing variables keep the current behaviour', () => {
  const result = startIndex({ PORT: '0' })
  assert.equal(result.status, 1)
  assert.match(result.stderr, /CREDENTIAL_ISSUER must be set/)
  assert.ok(!/Missing required environment/.test(result.stderr))
})
