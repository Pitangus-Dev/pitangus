import i18n, { intlLocale } from '@/shared/i18n'
import { formatDate, formatList } from '@/shared/i18n/format'
import type { DomainSchedule } from '@/shared/api/queries'

export type Frequency = 'daily' | 'weekly' | 'monthly'
// When a domain's passive scan runs on its own. Weekdays are ISO (1 Monday … 7 Sunday); days of the month go to 28.
export type ScheduleRule = { frequency: Frequency; weekdays: number[]; month_days: number[]; time: string; timezone: string }

const DAY = 86_400_000
export const FREQUENCY = { daily: 'domains.schedule.frequency.daily', weekly: 'domains.schedule.frequency.weekly', monthly: 'domains.schedule.frequency.monthly' } as const
export const WEEKDAYS = [1, 2, 3, 4, 5, 6, 7]
export const MONTH_DAYS = Array.from({ length: 28 }, (_, index) => index + 1)

export function browserZone(): string {
  try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC' } catch { return 'UTC' }
}

// Every IANA zone the browser knows, with the one in use first if the list lacks it (older engines).
export function zones(current: string): string[] {
  let known: string[] = []
  try { known = Intl.supportedValuesOf('timeZone') } catch { /* engines without it: the current zone and UTC */ }
  return Array.from(new Set([current, 'UTC', ...known])).sort((a, b) => a === 'UTC' ? -1 : b === 'UTC' ? 1 : a.localeCompare(b))
}

const formatters = new Map<string, Intl.DateTimeFormat>()
function wall(instant: number, zone: string) {
  let format = formatters.get(zone)
  if (!format) {
    format = new Intl.DateTimeFormat('en-US', { timeZone: zone, hourCycle: 'h23', year: 'numeric', month: 'numeric', day: 'numeric', hour: 'numeric', minute: 'numeric', second: 'numeric' })
    formatters.set(zone, format)
  }
  const part = Object.fromEntries(format.formatToParts(instant).filter(item => item.type !== 'literal').map(item => [item.type, Number(item.value)]))
  return { year: part.year, month: part.month, day: part.day, hour: part.hour % 24, minute: part.minute, second: part.second }
}

const offsetAt = (instant: number, zone: string) => {
  const at = Math.floor(instant / 1000) * 1000
  const local = wall(at, zone)
  return Date.UTC(local.year, local.month - 1, local.day, local.hour, local.minute, local.second) - at
}

// The local calendar day of an instant in `zone`, as the UTC midnight of that date.
export function localDay(instant: number | string | Date, zone: string): number {
  const local = wall(new Date(instant).getTime(), zone)
  return Date.UTC(local.year, local.month - 1, local.day)
}

// The rule's time on `day`, the same way the server does it (pitangus/modules/sources/domain_schedule.py): in a
// spring-forward gap, the offset from before the change; in a fall-back overlap, the first of the two.
function at(rule: ScheduleRule, day: number): number {
  const [hour, minute] = rule.time.split(':').map(Number)
  const naive = day + (hour * 60 + minute) * 60_000
  const before = offsetAt(naive - DAY, rule.timezone)
  const candidates = [before, offsetAt(naive + DAY, rule.timezone)].map(offset => naive - offset)
    .filter(instant => offsetAt(instant, rule.timezone) === naive - instant)
  return candidates.length ? Math.min(...candidates) : naive - before
}

const isoWeekday = (day: number) => (new Date(day).getUTCDay() + 6) % 7 + 1

function matches(rule: ScheduleRule, day: number): boolean {
  if (rule.frequency === 'weekly') return rule.weekdays.includes(isoWeekday(day))
  if (rule.frequency === 'monthly') return rule.month_days.includes(new Date(day).getUTCDate())
  return true
}

export function complete(rule: ScheduleRule): boolean {
  return /^([01]\d|2[0-3]):[0-5]\d$/.test(rule.time) && (rule.frequency !== 'weekly' || rule.weekdays.length > 0)
    && (rule.frequency !== 'monthly' || rule.month_days.length > 0)
}

// The first moment after `after` the rule fires, skipping local days up to `notOn` (at most one scan a day); null
// while the rule is incomplete or its zone unknown.
export function nextRun(rule: ScheduleRule, after: Date, notOn?: number | null): Date | null {
  if (!complete(rule)) return null
  try {
    const start = localDay(after, rule.timezone)
    for (let offset = 0; offset < 70; offset++) {
      const day = start + offset * DAY
      if ((notOn != null && day <= notOn) || !matches(rule, day)) continue
      const moment = at(rule, day)
      if (moment > after.getTime()) return new Date(moment)
    }
  } catch { /* an unknown zone: the server says so when saving */ }
  return null
}

export function defaultRule(now = new Date(), zone = browserZone()): ScheduleRule {
  let day = now.getTime()
  try { day = localDay(now, zone) } catch { zone = 'UTC'; day = localDay(now, zone) }
  return { frequency: 'weekly', weekdays: [isoWeekday(day)], month_days: [Math.min(new Date(day).getUTCDate(), 28)], time: '09:00', timezone: zone }
}

export const ruleOf = (schedule: DomainSchedule): ScheduleRule => ({ frequency: schedule.frequency, weekdays: schedule.weekdays ?? [], month_days: schedule.month_days ?? [],
  time: schedule.time, timezone: schedule.timezone })

// What the server stores: only the list the frequency uses, sorted.
export function normalized(rule: ScheduleRule): ScheduleRule {
  const sorted = (values: number[]) => Array.from(new Set(values)).sort((a, b) => a - b)
  return { ...rule, weekdays: rule.frequency === 'weekly' ? sorted(rule.weekdays) : [], month_days: rule.frequency === 'monthly' ? sorted(rule.month_days) : [] }
}

export const sameRule = (a: ScheduleRule, b: ScheduleRule) => JSON.stringify(normalized(a)) === JSON.stringify(normalized(b))

export const weekdayName = (weekday: number, width: 'long' | 'short' = 'long') =>
  new Intl.DateTimeFormat(intlLocale(), { weekday: width, timeZone: 'UTC' }).format(Date.UTC(2024, 0, weekday))  // 1 Jan 2024 was a Monday

// The time as the reader's locale writes it, and the hour it shows (Spanish says "a la 1:00" but "a las 13:00").
const clock = (time: string) => {
  const [hour, minute] = time.split(':').map(Number)
  const parts = new Intl.DateTimeFormat(intlLocale(), { hour: 'numeric', minute: '2-digit', timeZone: 'UTC' }).formatToParts(Date.UTC(2000, 0, 1, hour, minute))
  return { hour: Number(parts.find(part => part.type === 'hour')?.value ?? hour), text: parts.map(part => part.value).join('') }
}

export const zoneName = (zone: string) => zone.replaceAll('_', ' ')
// When a run happens, in the reader's zone and saying which one: the rule may be written in another.
export const formatRun = (stamp: string | Date) => formatDate(stamp, { timeZoneName: 'short' })

// The rule in plain words: "Every Friday at 9:00 AM (America/Bogota)".
export function describeRule(rule: ScheduleRule): string {
  const time = clock(rule.time)
  const atTime = i18n.t('sources:domains.schedule.at', { count: time.hour, time: time.text })
  const zone = zoneName(rule.timezone)
  const days = normalized(rule)
  if (rule.frequency === 'weekly' && days.weekdays.length < 7) return i18n.t('sources:domains.schedule.describe.weekly', { days: formatList(days.weekdays.map(day => weekdayName(day))), at: atTime, zone })
  if (rule.frequency === 'monthly') {
    return i18n.t('sources:domains.schedule.describe.monthly', { count: days.month_days.length, days: formatList(days.month_days.map(String)), at: atTime, zone })
  }
  return i18n.t('sources:domains.schedule.describe.daily', { at: atTime, zone })
}
