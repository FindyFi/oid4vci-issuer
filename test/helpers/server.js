import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { once } from 'node:events'

const ROOT = new URL('../../', import.meta.url)

export const CREDENTIAL_CONFIGURATION_ID = 'OpenBadgeCredential'

const CREDENTIAL_CONFIGURATIONS_SUPPORTED = {
  [CREDENTIAL_CONFIGURATION_ID]: {
    format: 'ldp_vc',
    credential_definition: {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json',
      ],
      type: ['VerifiableCredential', 'OpenBadgeCredential'],
    },
    proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } },
  },
}

// Asks the OS for a free port, then immediately gives it back. There is a
// window where something else could claim it, but it beats hardcoding ports
// that collide with a developer's running compose stack.
async function freePort() {
  const probe = createServer()
  probe.listen(0, '127.0.0.1')
  await once(probe, 'listening')
  const { port } = probe.address()
  await new Promise((resolve) => probe.close(resolve))
  return port
}

// Stands in for digitalcredentials/signing-service: echoes the credential
// back with a proof stapled on, and records what it was asked to sign so
// tests can assert the issuer forwarded the right thing.
async function startStubSigningService() {
  const requests = []
  const sign = (credential) => ({ ...credential, proof: { type: 'Ed25519Signature2020', proofValue: 'z-stub' } })
  let respond = sign

  const server = createServer((req, res) => {
    let body = ''
    req.on('data', (chunk) => (body += chunk))
    req.on('end', () => {
      const credential = JSON.parse(body || '{}')
      requests.push({ url: req.url, method: req.method, credential })
      let payload
      try {
        payload = respond(credential)
      } catch (err) {
        res.writeHead(500, { 'content-type': 'text/plain' })
        return res.end(err.message)
      }
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify(payload))
    })
  })

  server.listen(await freePort(), '127.0.0.1')
  await once(server, 'listening')

  return {
    url: `http://127.0.0.1:${server.address().port}`,
    requests,
    // One-shot failure, so a test that exercises the error path can't leak
    // a broken signing service into whatever runs next.
    failNext(message) {
      respond = () => {
        respond = sign
        throw new Error(message)
      }
    },
    async stop() {
      await new Promise((resolve) => server.close(resolve))
    },
  }
}

async function waitForHealth(baseUrl, child, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`Server exited early with code ${child.exitCode}`)
    try {
      const res = await fetch(`${baseUrl}/healthz`)
      if (res.ok) return
    } catch {
      // not listening yet
    }
    await new Promise((resolve) => setTimeout(resolve, 50))
  }
  throw new Error(`Server did not become healthy within ${timeoutMs}ms`)
}

/**
 * Boots the real `index.js` in a child process, pointed at a stub
 * signing-service. Testing the published entrypoint rather than importing
 * the handlers means these tests also cover the env-var wiring and startup
 * validation that the container depends on.
 */
export async function startIssuer({ coordinatorToken = 'test-coordinator-token', env = {} } = {}) {
  const signingService = await startStubSigningService()
  const port = await freePort()
  const credentialIssuer = `http://127.0.0.1:${port}`

  const child = spawn(process.execPath, ['index.js'], {
    cwd: ROOT,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...cleanEnv(),
      PORT: String(port),
      CREDENTIAL_ISSUER: credentialIssuer,
      CREDENTIAL_CONFIGURATIONS_SUPPORTED: JSON.stringify(CREDENTIAL_CONFIGURATIONS_SUPPORTED),
      SIGNING_SERVICE_URL: signingService.url,
      SIGNING_SERVICE_INSTANCE: 'test',
      SIGNING_SERVICE_SUITE: 'ed25519',
      COORDINATOR_TOKEN: coordinatorToken,
      ...env,
    },
  })

  let stderr = ''
  child.stderr.on('data', (chunk) => (stderr += chunk))
  child.stdout.resume()

  try {
    await waitForHealth(credentialIssuer, child)
  } catch (err) {
    child.kill('SIGKILL')
    await signingService.stop()
    throw new Error(`${err.message}\n--- server stderr ---\n${stderr}`)
  }

  return {
    baseUrl: credentialIssuer,
    credentialIssuer,
    coordinatorToken,
    signingService,
    get stderr() {
      return stderr
    },
    async stop() {
      child.kill('SIGTERM')
      await once(child, 'exit')
      await signingService.stop()
    },
  }
}

// The app's own configuration, stripped from the inherited environment so a
// developer's exported vars can't mask a test that checks what happens when
// one is missing.
const APP_ENV_KEYS = [
  'PORT',
  'CREDENTIAL_ISSUER',
  'CREDENTIAL_CONFIGURATIONS_SUPPORTED',
  'SIGNING_SERVICE_URL',
  'SIGNING_SERVICE_INSTANCE',
  'SIGNING_SERVICE_SUITE',
  'COORDINATOR_TOKEN',
]

function cleanEnv() {
  const env = { ...process.env }
  for (const key of APP_ENV_KEYS) delete env[key]
  return { ...env, DOTENV_CONFIG_PATH: '/dev/null' }
}

/**
 * Boots `index.js` expecting it to refuse to start, and resolves with what
 * it printed. Used to pin the startup validation the container relies on.
 */
export async function startIssuerExpectingFailure(env) {
  const child = spawn(process.execPath, ['index.js'], {
    cwd: ROOT,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...cleanEnv(), ...env },
  })

  let stderr = ''
  child.stderr.on('data', (chunk) => (stderr += chunk))
  child.stdout.resume()

  const [code] = await once(child, 'exit')
  return { code, stderr }
}
