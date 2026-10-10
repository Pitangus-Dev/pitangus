import i18n from '@/shared/i18n'
import { formatDay } from '@/shared/i18n/format'
import type { DomainRow } from '@/shared/api/queries'

export type DomainKind = 'web' | 'api' | 'surface'
export type ProofMethod = 'dns' | 'file' | 'meta'
// A registered domain as the API answers it; how to prove it and the saved header names only come to administrators.
export type Domain = DomainRow
export type LastScan = { id: string; status: string; created_at: string; finished_at?: string | null; variant?: string }

// Getters so the label follows the current language wherever it's read.
export const kindLabel: Record<DomainKind, string> = {
  get web() { return i18n.t('sources:domains.kind.web') },
  get api() { return i18n.t('sources:domains.kind.api') },
  get surface() { return i18n.t('sources:domains.kind.surface') },
}
export const kindOf = (domain: Domain) => (domain.kind in kindLabel ? kindLabel[domain.kind as DomainKind] : domain.kind)

const METHOD = { dns: 'sources:domains.method.dns', file: 'sources:domains.method.file', meta: 'sources:domains.method.meta' } as const
export const methodLabel = (method: ProofMethod) => i18n.t(METHOD[method])
// Domains verified before file and meta proofs existed carry no method: theirs was the TXT record.
export const proofOf = (domain: Domain): ProofMethod => domain.proof_method ?? 'dns'
// Only a DNS proof covers subdomains; a file or a meta tag proves the exact host.
export const coversSubdomains = (domain: Domain) => domain.verified && proofOf(domain) === 'dns'
export const lastScanOf = (domain: Domain) => (domain.last_scan ?? null) as LastScan | null
export const untilOf = (domain: Domain) => domain.verified_until ? formatDay(domain.verified_until, { dateStyle: 'medium' }) : ''

// The verification chip: success when the proof is current, warning when pending or lapsed.
export function verification(domain: Domain): { label: string; tone: 'success' | 'warning' } {
  if (domain.verified) return { label: i18n.t('sources:domains.list.verified_by', { method: methodLabel(proofOf(domain)) }), tone: 'success' }
  return { label: i18n.t(domain.expired ? 'sources:domains.list.expired' : 'sources:domains.list.pending'), tone: 'warning' }
}
export const TONE = { success: 'border-success-line bg-success-soft text-success', warning: 'border-warning-line bg-warning-soft text-warning' } as const
