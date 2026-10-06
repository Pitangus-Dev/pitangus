import i18n from '@/shared/i18n'

export const sevColor: Record<string, string> = { low: 'var(--sev-low)', medium: 'var(--sev-medium)', high: 'var(--sev-high)', critical: 'var(--sev-critical)' }
export const sevName: Record<string, string> = {
  get low() { return i18n.t('common:severity.low') }, get medium() { return i18n.t('common:severity.medium') },
  get high() { return i18n.t('common:severity.high') }, get critical() { return i18n.t('common:severity.critical') },
}
