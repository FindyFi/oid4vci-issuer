// Makes the FEDERATION_* values for the OpenID Federation Entity
// Configuration, so nobody has to hand-write JSON.
//
//   node scripts/federation-metadata.js                  ask questions, print the env lines
//   node scripts/federation-metadata.js --write          ... and put them in ./.env
//   node scripts/federation-metadata.js --write other.env
//   node scripts/federation-metadata.js --json           print only the metadata JSON
//   node scripts/federation-metadata.js --display-name "Example University" \
//     --organization-name "Example University Oy" --contact it@example.org \
//     --homepage-uri https://example.org --authority-hint https://trust-anchor.example
//
// With --display-name (or no terminal) it doesn't ask anything. The prompts go
// to stderr, so stdout can be piped. The printed lines are NAME='<json>',
// which dotenv, Docker Compose and a POSIX shell all read the same way.
import { createInterface } from 'node:readline/promises'
import { parseArgs } from 'node:util'
import { buildEntityMetadata, envLine, upsertEnvFile } from '../src/federation.js'

const { values, positionals } = parseArgs({
  options: {
    'display-name': { type: 'string' },
    'organization-name': { type: 'string' },
    contact: { type: 'string', multiple: true },
    'homepage-uri': { type: 'string' },
    'logo-uri': { type: 'string' },
    'policy-uri': { type: 'string' },
    'authority-hint': { type: 'string', multiple: true },
    write: { type: 'boolean' },
    json: { type: 'boolean' },
    help: { type: 'boolean', short: 'h' },
  },
  allowPositionals: true,
})
const [file = '.env'] = positionals

if (values.help) {
  console.error('Usage: node scripts/federation-metadata.js [--write [file]] [--json] [--display-name … --organization-name … --contact … --homepage-uri … --logo-uri … --policy-uri … --authority-hint …]')
  process.exit(0)
}

let answers = {
  displayName: values['display-name'],
  organizationName: values['organization-name'],
  contacts: values.contact ?? [],
  homepageUri: values['homepage-uri'],
  logoUri: values['logo-uri'],
  policyUri: values['policy-uri'],
  authorityHints: values['authority-hint'] ?? [],
}
if (!answers.displayName) {
  if (!process.stdin.isTTY) {
    console.error('No terminal to ask on: pass --display-name (see --help).')
    process.exit(1)
  }
  answers = await ask(answers)
}

let metadata
try {
  metadata = buildEntityMetadata(answers)
} catch (err) {
  console.error(`Not valid: ${err.message}`)
  process.exit(1)
}
for (const hint of answers.authorityHints) {
  if (!URL.canParse(hint) || new URL(hint).protocol !== 'https:') {
    console.error(`Not valid: authority hint ${hint} must be an https URL.`)
    process.exit(1)
  }
}

if (values.json) {
  console.log(JSON.stringify(metadata))
} else {
  const lines = [envLine('FEDERATION_ENTITY_METADATA', metadata)]
  if (answers.authorityHints.length) lines.push(envLine('FEDERATION_AUTHORITY_HINTS', answers.authorityHints))
  if (values.write) {
    const { replaced, appended } = upsertEnvFile(file, lines)
    console.error(`${file}: ${[...replaced.map((n) => `updated ${n}`), ...appended.map((n) => `added ${n}`)].join(', ')}.`)
    console.error('The issuer also needs SD_JWT_SIGNING_KEY, and SD_JWT_ISSUER (if set) must equal CREDENTIAL_ISSUER.')
  } else {
    console.log(lines.join('\n'))
  }
}

async function ask(defaults) {
  const rl = createInterface({ input: process.stdin, output: process.stderr })
  const line = async (question, { required = false } = {}) => {
    for (;;) {
      const answer = (await rl.question(`${question}${required ? '' : ' (optional, Enter to skip)'}: `)).trim()
      if (answer || !required) return answer
      console.error('  Required.')
    }
  }
  const list = async (question) => (await line(`${question}, comma separated`)).split(',').map((v) => v.trim()).filter(Boolean)
  try {
    console.error('Entity metadata, published at /.well-known/openid-federation. Wallets show the display name.\n')
    return {
      displayName: await line('Display name, e.g. "Example University"', { required: true }),
      organizationName: await line('Organization name, e.g. the legal name'),
      contacts: await list('Contacts (e-mail addresses or URLs)'),
      homepageUri: await line('Homepage (https URL)'),
      logoUri: await line('Logo (https URL)'),
      policyUri: await line('Policy / terms page (https URL)'),
      authorityHints: await list('Trust anchor or intermediate entity IDs above you (https URLs, if you have joined a federation)'),
    }
  } finally {
    rl.close()
  }
}
