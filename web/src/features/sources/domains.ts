import i18n from '@/shared/i18n'
import type { Response } from '@/shared/api/client'

export type DomainKind = 'web' | 'api' | 'surface'
// A registered domain as the API answers it; the TXT record (`txt_name`, `txt_value`) only comes to administrators.
export type Domain = Response<'/api/domains'>['items'][number]

// Getters so the label follows the current language wherever it's read.
export const kindLabel: Record<DomainKind, string> = {
  get web() { return i18n.t('sources:domains.kind.web') },
  get api() { return i18n.t('sources:domains.kind.api') },
  get surface() { return i18n.t('sources:domains.kind.surface') },
}
export const kindOf = (domain: Domain) => (domain.kind in kindLabel ? kindLabel[domain.kind as DomainKind] : domain.kind)
