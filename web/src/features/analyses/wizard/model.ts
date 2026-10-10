import type { TFunction } from 'i18next'

export type Kind = 'code' | 'image' | 'web' | 'api'
export type StepId = 'repositories' | 'images' | 'target' | 'spec' | 'access' | 'context' | 'review'
export type ScanPlan = { languages: { name: string; files: number; rules: number }[]; runs: string[]; skips: string[]; osv_needed: boolean; files: number | null
  manifests: string[]; iac: string[]; pipelines?: string[] }
export type Registry = { registry: string; username: string; last4: string }
// An OpenAPI definition read in the browser (sent base64 with the scan) or a URL the scanner fetches itself.
export type Spec = { mode: 'file'; filename: string; content: string; version: string; endpoints: number } | { mode: 'url'; url: string }
// A host added to the scope by hand (`name` or `*.name`), in or out of this scan.
export type ScopeHost = { host: string; included: boolean }

export const STEPS: Record<Kind, StepId[]> = {
  code: ['repositories', 'context', 'review'],
  image: ['images', 'context', 'review'],
  web: ['target', 'access', 'review'],
  api: ['target', 'spec', 'access', 'review'],
}
export const STEP_LABEL = {
  repositories: 'wizard.steps.repositories', images: 'wizard.steps.images', target: 'wizard.steps.target', spec: 'wizard.steps.spec',
  access: 'wizard.steps.access', context: 'wizard.steps.context', review: 'wizard.steps.review',
} as const
// Optional steps can be skipped with a button; the rest need an answer.
export const OPTIONAL: StepId[] = ['context', 'access']

export const BATCH_LIMIT = 100   // repositories or images picked by hand per batch (a whole organization has no such cap)
export const CONTEXT_MAX = 400
export const SCOPE_MAX = 20
export const SPEC_MAX_BYTES = 5 * 1024 * 1024

// Same rule as the server: optional registry (with a dot, a port or localhost), lowercase repository, tag or digest.
const IMAGE_REFERENCE = /^(?:((?:[a-zA-Z0-9-]+\.)+[a-zA-Z0-9-]+(?::\d{1,5})?|localhost(?::\d{1,5})?|[a-zA-Z0-9-]+:\d{1,5})\/)?[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:\/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*){0,5}(?::([A-Za-z0-9_][A-Za-z0-9_.-]{0,127}))?(@sha256:[0-9a-f]{64})?$/
export const registryOf = (reference: string) => { const match = reference.trim().match(IMAGE_REFERENCE); return match ? (match[1]?.toLowerCase() ?? 'docker.io') : null }
// No tag, or `latest`, without a digest: what was reviewed can change under the same name.
export const floating = (reference: string) => { const match = reference.trim().match(IMAGE_REFERENCE); return !!match && !match[3] && (!match[2] || match[2] === 'latest') }
export const referencesOf = (text: string) => Array.from(new Set(text.split('\n').map(line => line.trim()).filter(Boolean)))

export const listing = (t: TFunction<'analyses'>, names: string[], limit = 3) => names.length <= limit ? names.join(', ') : t('listing_more', { names: names.slice(0, limit).join(', '), rest: names.length - limit })
export const duration = (t: TFunction<'analyses'>, seconds: number) => seconds < 5400 ? t('duration.minutes', { value: Math.max(1, Math.round(seconds / 60)) }) : t('duration.hours', { value: Math.round(seconds / 3600) })

// `name` or `*.name` under `root` (the root itself is always in scope and isn't listed).
const HOST = /^(\*\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/
export function scopeEntry(value: string, root: string): { host: string } | { error: 'invalid' | 'foreign' | 'root' } {
  const host = value.trim().toLowerCase().replace(/\.$/, '')
  if (!HOST.test(host)) return { error: 'invalid' }
  const bare = host.replace(/^\*\./, '')
  if (bare === root && !host.startsWith('*.')) return { error: 'root' }
  if (bare !== root && !bare.endsWith(`.${root}`)) return { error: 'foreign' }
  return { host }
}
export const inScope = (url: string, root: string, hosts: string[]) => {
  try {
    const { protocol, hostname } = new URL(url)
    return protocol === 'https:' && (hostname === root || hosts.some(entry => entry.startsWith('*.') ? hostname.endsWith(entry.slice(1)) : hostname === entry))
  } catch { return false }
}

const METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace']
// A quick read of an OpenAPI 2/3 definition, to say what was picked before sending it; the server parses it properly.
// JSON is read in full; YAML by its version line and its method keys.
export function readSpec(text: string): { version: string; endpoints: number } | { error: 'invalid' | 'no_endpoints' } {
  let version = ''
  let endpoints = 0
  try {
    const document = JSON.parse(text) as { openapi?: unknown; swagger?: unknown; paths?: Record<string, Record<string, unknown>> }
    version = String(document.openapi ?? document.swagger ?? '')
    for (const item of Object.values(document.paths ?? {})) endpoints += Object.keys(item ?? {}).filter(key => METHODS.includes(key.toLowerCase())).length
  } catch {
    version = text.match(/^\s*["']?(?:openapi|swagger)["']?\s*:\s*["']?([0-9.]+)/m)?.[1] ?? ''
    endpoints = text.match(new RegExp(`^\\s+["']?(?:${METHODS.join('|')})["']?\\s*:\\s*(#.*)?$`, 'gim'))?.length ?? 0
  }
  if (!/^[23](\.\d+)*$/.test(version)) return { error: 'invalid' }
  if (!endpoints) return { error: 'no_endpoints' }
  return { version, endpoints }
}
export function toBase64(bytes: Uint8Array) {
  let binary = ''
  for (let index = 0; index < bytes.length; index += 0x8000) binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000))
  return btoa(binary)
}
