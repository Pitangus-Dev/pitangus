import { TranslateIcon } from '@phosphor-icons/react'
import { useTranslation } from 'react-i18next'
import { LOCALE_NAMES, LOCALES, currentLocale, isLocale, setLocale } from '@/shared/i18n'
import { SelectField } from '@/shared/ui/select-field'

export function LocaleSwitch({ className = '' }: { className?: string }) {
  const { t } = useTranslation()
  return <div className={`flex items-center gap-2 text-xs text-app-muted ${className}`}>
    <TranslateIcon className="hidden size-4 shrink-0 sm:block" aria-hidden />
    <SelectField aria-label={t('language')} size="sm" align="end" value={currentLocale()} onValueChange={value => { if (isLocale(value)) setLocale(value) }}
      className="w-fit text-app-secondary"
      options={LOCALES.map(locale => ({ value: locale, label: LOCALE_NAMES[locale], lang: locale }))} />
  </div>
}
