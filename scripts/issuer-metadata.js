// Makes OID4VCI_ISSUER_METADATA: the issuer `display` (name and logo per
// language) that wallets show, so nobody has to hand-write JSON. The
// OpenID Federation Entity Configuration takes its display_name and logo_uri
// from it too, unless FEDERATION_ENTITY_METADATA sets them.
//
//   node scripts/issuer-metadata.js                  ask questions, print the env line
//   node scripts/issuer-metadata.js --lang=fi,en,sv  ... with these languages, in this order
//   node scripts/issuer-metadata.js --write          ... and put it in ./.env
//   node scripts/issuer-metadata.js --write other.env
//   node scripts/issuer-metadata.js --json           print only the metadata JSON
//   node scripts/issuer-metadata.js --lang=fi,en --name "fi=Esimerkkiyliopisto" \
//     --name "en=Example University" --logo-uri https://example.org/logo.png \
//     --logo-alt "fi=Esimerkkiyliopiston logo" --logo-alt "en=Example University logo"
//
// With --name (or no terminal) it doesn't ask anything; the languages are then
// --lang, or the ones --name gives, in that order. The prompts go to stderr,
// so stdout can be piped.
import { createInterface } from 'node:readline/promises'
import { parseArgs } from 'node:util'
import { buildIssuerMetadataConfig } from '../src/metadata.js'
import { envLine, upsertEnvFile } from '../src/federation.js'

const { values, positionals } = parseArgs({
  options: {
    lang: { type: 'string', multiple: true },
    name: { type: 'string', multiple: true },
    'logo-uri': { type: 'string' },
    'logo-alt': { type: 'string', multiple: true },
    write: { type: 'boolean' },
    json: { type: 'boolean' },
    help: { type: 'boolean', short: 'h' },
  },
  allowPositionals: true,
})
const [file = '.env'] = positionals

if (values.help) {
  console.error('Usage: node scripts/issuer-metadata.js [--write [file]] [--json] [--lang=fi,en,…] [--name "<lang>=…" … --logo-uri … --logo-alt "<lang>=…" …]')
  process.exit(0)
}

let answers
try {
  answers = {
    locales: splitList(values.lang ?? []),
    names: perLanguage('--name', values.name ?? []),
    logoUri: values['logo-uri'],
    altTexts: perLanguage('--logo-alt', values['logo-alt'] ?? []),
  }
} catch (err) {
  console.error(err.message)
  process.exit(1)
}
if (values.name) {
  if (!answers.locales.length) answers.locales = Object.keys(answers.names)
} else {
  if (!process.stdin.isTTY) {
    console.error('No terminal to ask on: pass --name (see --help).')
    process.exit(1)
  }
  answers = await ask(answers)
}

let metadata
try {
  metadata = buildIssuerMetadataConfig(answers)
} catch (err) {
  console.error(`Not valid: ${err.message}`)
  process.exit(1)
}

if (values.json) {
  console.log(JSON.stringify(metadata))
} else {
  const line = envLine('OID4VCI_ISSUER_METADATA', metadata)
  if (values.write) {
    const { replaced } = upsertEnvFile(file, [line])
    console.error(`${file}: ${replaced.length ? 'updated' : 'added'} OID4VCI_ISSUER_METADATA.`)
  } else {
    console.log(line)
  }
}

// "fi,en" or ["fi, en", "sv"] -> ["fi", "en", "sv"], without repeats.
function splitList(values) {
  return [...new Set(values.flatMap((value) => value.split(',')).map((v) => v.trim()).filter(Boolean))]
}

// ["fi=Text", ...] -> { fi: 'Text' }
function perLanguage(flag, values) {
  const result = {}
  for (const value of values) {
    const at = value.indexOf('=')
    if (at < 1) throw new Error(`${flag} takes <language>=<text>, e.g. ${flag} "fi=…": got ${value}`)
    result[value.slice(0, at).trim()] = value.slice(at + 1)
  }
  return result
}

async function ask({ locales, names, logoUri, altTexts }) {
  const rl = createInterface({ input: process.stdin, output: process.stderr })
  const line = async (question, { required = false } = {}) => {
    for (;;) {
      const answer = (await rl.question(`${question}${required ? '' : ' (optional, Enter to skip)'}: `)).trim()
      if (answer || !required) return answer
      console.error('  Required.')
    }
  }
  try {
    console.error('Issuer display, published in /.well-known/openid-credential-issuer. Wallets show the name and logo.\n')
    if (!locales.length) locales = splitList([await line('Languages, comma separated, e.g. fi, en, sv', { required: true })])
    for (const locale of locales) names[locale] ??= await line(`Name in ${locale}`, { required: true })
    logoUri ??= await line('Logo (https URL or data: URI; PNG shows in the most wallets)')
    if (logoUri) {
      for (const locale of locales) altTexts[locale] ??= await line(`Logo description in ${locale}`)
    }
    return { locales, names, logoUri, altTexts }
  } finally {
    rl.close()
  }
}
