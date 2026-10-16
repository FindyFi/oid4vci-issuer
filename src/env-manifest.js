import { readFileSync } from 'node:fs'

// .env.example is the env manifest: the comment line directly above each
// variable line (`NAME=value`, or `# NAME=value` when unset by default) is
// `# @env required|optional [secret]`. See "Configuration" in the README.

const TAG = /^#\s*@env\b/
const VALID_TAG = /^#\s*@env (required|optional)( secret)?\s*$/
const VARIABLE = /^(?:#\s*)?([A-Z][A-Z0-9_]*)=/

// Returns [{ name, required, secret }]; throws on a malformed manifest.
export function parseEnvManifest(text) {
  const entries = []
  let pending = null
  const lines = text.replace(/\n$/, '').split('\n')
  lines.forEach((line, i) => {
    const where = `.env.example line ${i + 1}`
    if (TAG.test(line)) {
      const m = VALID_TAG.exec(line)
      if (!m) throw new Error(`${where}: invalid tag "${line}"`)
      if (pending) throw new Error(`${where}: a second tag before a variable line`)
      pending = { required: m[1] === 'required', secret: Boolean(m[2]) }
      return
    }
    const v = VARIABLE.exec(line)
    if (v) {
      if (!pending) throw new Error(`${where}: ${v[1]} has no "# @env" tag directly above it`)
      if (entries.some((e) => e.name === v[1])) throw new Error(`${where}: ${v[1]} is listed twice`)
      entries.push({ name: v[1], ...pending })
    } else if (pending) {
      throw new Error(`${where}: a "# @env" tag must be directly above a variable line`)
    }
    pending = null
  })
  if (pending) throw new Error('.env.example ends with a tag and no variable')
  return entries
}

export function loadEnvManifest(file = new URL('../.env.example', import.meta.url)) {
  return parseEnvManifest(readFileSync(file, 'utf8'))
}

// Names of required variables that are unset or empty in `env`.
export function missingRequired(manifest, env) {
  return manifest.filter((e) => e.required && !env[e.name]).map((e) => e.name)
}
