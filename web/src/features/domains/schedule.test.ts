import { afterEach, describe, expect, it } from 'vitest'
import i18n from '@/shared/i18n'
import { describeRule, localDay, nextRun, type ScheduleRule } from '@/features/domains/schedule'

// The same cases as tests/test_domain_schedule.py: the panel's preview and the server's next run must agree.
const rule = (change: Partial<ScheduleRule>): ScheduleRule => ({ frequency: 'daily', weekdays: [], month_days: [], time: '09:00', timezone: 'UTC', ...change })
// Intl puts narrow no-break spaces before AM/PM.
const plain = (text: string) => text.replace(/\s/g, ' ')
const iso = (date: Date | null) => date?.toISOString() ?? null
function runs(schedule: ScheduleRule, start: string, count: number) {
  const moments: string[] = []
  let after = new Date(start)
  for (let index = 0; index < count; index++) {
    after = nextRun(schedule, after) as Date
    moments.push(after.toISOString())
  }
  return moments
}

describe('the next run of a schedule', () => {
  it('is today while the time is ahead, else tomorrow', () => {
    const daily = rule({ timezone: 'America/Bogota' })
    expect(iso(nextRun(daily, new Date('2026-10-09T13:59:00Z')))).toBe('2026-10-09T14:00:00.000Z')
    expect(iso(nextRun(daily, new Date('2026-10-09T14:00:00Z')))).toBe('2026-10-10T14:00:00.000Z')
  })

  it('goes through several weekdays in order', () => {
    const schedule = rule({ frequency: 'weekly', weekdays: [5, 1, 3], time: '18:30', timezone: 'Europe/Madrid' })
    expect(runs(schedule, '2026-10-09T17:00:00Z', 4)).toEqual(['2026-10-12T16:30:00.000Z', '2026-10-14T16:30:00.000Z', '2026-10-16T16:30:00.000Z', '2026-10-19T16:30:00.000Z'])
  })

  it('takes days of the month into the next month, February included', () => {
    const schedule = rule({ frequency: 'monthly', month_days: [28, 1, 15], time: '00:00' })
    expect(runs(schedule, '2027-01-28T00:00:00Z', 4).map(moment => moment.slice(0, 10))).toEqual(['2027-02-01', '2027-02-15', '2027-02-28', '2027-03-01'])
  })

  it('counts days in the schedule zone, not in UTC', () => {
    expect(iso(nextRun(rule({ frequency: 'weekly', weekdays: [1], time: '01:00', timezone: 'Asia/Tokyo' }), new Date('2026-10-09T00:00:00Z')))).toBe('2026-10-11T16:00:00.000Z')
  })

  it('keeps the wall time across DST changes, later by the gap in spring and once in the autumn overlap', () => {
    const newYork = rule({ timezone: 'America/New_York' })
    expect(runs(newYork, '2026-03-07T00:00:00Z', 2)).toEqual(['2026-03-07T14:00:00.000Z', '2026-03-08T13:00:00.000Z'])
    expect(runs(newYork, '2026-10-31T00:00:00Z', 2)).toEqual(['2026-10-31T13:00:00.000Z', '2026-11-01T14:00:00.000Z'])
    expect(iso(nextRun(rule({ time: '02:30', timezone: 'America/New_York' }), new Date('2026-03-08T00:00:00Z')))).toBe('2026-03-08T07:30:00.000Z')
    expect(runs(rule({ time: '01:30', timezone: 'America/New_York' }), '2026-11-01T00:00:00Z', 2)).toEqual(['2026-11-01T05:30:00.000Z', '2026-11-02T06:30:00.000Z'])
    expect(iso(nextRun(rule({ time: '02:15', timezone: 'Europe/Madrid' }), new Date('2026-03-29T00:00:00Z')))).toBe('2026-03-29T01:15:00.000Z')
  })

  it('skips the local day already scanned, and has none while the rule is incomplete', () => {
    const daily = rule({ time: '23:00', timezone: 'America/Bogota' })
    const after = new Date('2026-10-09T15:00:00Z')
    expect(iso(nextRun(daily, after))).toBe('2026-10-10T04:00:00.000Z')
    expect(iso(nextRun(daily, after, localDay(after, 'America/Bogota')))).toBe('2026-10-11T04:00:00.000Z')
    expect(nextRun(rule({ frequency: 'weekly' }), after)).toBeNull()
    expect(nextRun(rule({ frequency: 'monthly' }), after)).toBeNull()
    expect(nextRun(rule({ time: '' }), after)).toBeNull()
  })
})

describe('a schedule in plain words', () => {
  afterEach(() => i18n.changeLanguage('en'))

  it('names the days, the time and the zone in the reader’s language', async () => {
    await i18n.changeLanguage('en')
    expect(plain(describeRule(rule({ frequency: 'weekly', weekdays: [5], timezone: 'America/Bogota' })))).toBe('Every Friday at 9:00 AM (America/Bogota)')
    expect(plain(describeRule(rule({ frequency: 'monthly', month_days: [15, 1], time: '18:00' })))).toBe('On days 1 and 15 of every month at 6:00 PM (UTC)')
    await i18n.changeLanguage('es')
    expect(plain(describeRule(rule({ frequency: 'weekly', weekdays: [5, 1], timezone: 'America/Bogota' })))).toBe('Cada lunes y viernes a las 9:00 a.m. (America/Bogota)')
    expect(plain(describeRule(rule({ time: '13:00' })))).toBe('Todos los días a la 1:00 p.m. (UTC)')
    expect(plain(describeRule(rule({ frequency: 'weekly', weekdays: [1, 2, 3, 4, 5, 6, 7], timezone: 'America/New_York' })))).toBe('Todos los días a las 9:00 a.m. (America/New York)')
    expect(plain(describeRule(rule({ frequency: 'monthly', month_days: [1], time: '00:30' })))).toBe('El día 1 de cada mes a las 12:30 a.m. (UTC)')
  })
})
