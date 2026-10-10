import { intlLocale } from '@/shared/i18n'

export const formatDate = (stamp: string | number | Date, options: Intl.DateTimeFormatOptions = {}) =>
  new Date(stamp).toLocaleString(intlLocale(), timeZoneNameOrStyles(options))
// dateStyle/timeStyle can't be combined with timeZoneName: spelled out instead when a zone name is asked for.
const timeZoneNameOrStyles = (options: Intl.DateTimeFormatOptions): Intl.DateTimeFormatOptions => options.timeZoneName
  ? { year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', ...options }
  : { dateStyle: 'medium', timeStyle: 'short', ...options }
export const formatDay = (stamp: string | number | Date, options: Intl.DateTimeFormatOptions = { dateStyle: 'medium' }) =>
  new Date(stamp).toLocaleDateString(intlLocale(), options)
export const formatNumber = (value: number, options?: Intl.NumberFormatOptions) =>
  new Intl.NumberFormat(intlLocale(), options).format(value)
export const formatPercent = (value: number, digits = 0) =>
  new Intl.NumberFormat(intlLocale(), { style: 'percent', maximumFractionDigits: digits }).format(value)
export const formatTime = (stamp: string | number | Date) =>
  new Date(stamp).toLocaleTimeString(intlLocale(), { hour: '2-digit', minute: '2-digit', second: '2-digit' })
export const formatList = (items: string[]) => new Intl.ListFormat(intlLocale(), { style: 'long', type: 'conjunction' }).format(items)
