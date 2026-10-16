import { createHash } from 'node:crypto'
import { DC_SD_JWT } from './sdjwt.js'

export const sri = (bytes) => `sha256-${createHash('sha256').update(bytes).digest('base64')}`

// Fills in `vct#integrity` (SRI, sha256 of the exact bytes) for every
// dc+sd-jwt configuration by fetching its `vct`. Runs once at startup, before
// createApp, and returns a copy of the configurations.
// - Pinned (the configuration already has `vct#integrity`): a fetched hash
//   that differs throws, so the service refuses to start; if the fetch fails,
//   the pinned value is kept and a warning is logged.
// - Not pinned (dev): the fetched hash is used; if the fetch fails, the
//   credentials go without `vct#integrity` and a warning is logged.
export async function resolveVctIntegrity(configurations, { fetchImpl = fetch, warn = console.warn } = {}) {
  const resolved = {}
  for (const [id, configuration] of Object.entries(configurations)) {
    resolved[id] = configuration
    if (configuration?.format !== DC_SD_JWT || typeof configuration.vct !== 'string') continue
    const pinned = configuration['vct#integrity']
    let fetched
    try {
      const response = await fetchImpl(configuration.vct, { signal: AbortSignal.timeout(10_000) })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      fetched = sri(Buffer.from(await response.arrayBuffer()))
    } catch (error) {
      warn(`Configuration ${id}: could not fetch ${configuration.vct} (${error.message}); ${pinned ? 'using the pinned vct#integrity' : 'issuing without vct#integrity'}.`)
      continue
    }
    if (pinned && pinned !== fetched) {
      throw new Error(`Configuration ${id}: the vct at ${configuration.vct} hashes to ${fetched}, but vct#integrity is pinned to ${pinned}.`)
    }
    resolved[id] = { ...configuration, 'vct#integrity': fetched }
  }
  return resolved
}
