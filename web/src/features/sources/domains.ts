import i18n from '@/shared/i18n'

export type DomainKind = 'web' | 'api' | 'surface'
export type Domain = { id: string; host: string; url: string; kind?: DomainKind; context?: string; txt_name: string; txt_value: string; verified: boolean; registered_at?: string; verified_at?: string | null }

// Getters so the label follows the current language wherever it's read.
export const kindLabel: Record<DomainKind, string> = {
  get web() { return i18n.t('sources:domains.kind.web') },
  get api() { return i18n.t('sources:domains.kind.api') },
  get surface() { return i18n.t('sources:domains.kind.surface') },
}
