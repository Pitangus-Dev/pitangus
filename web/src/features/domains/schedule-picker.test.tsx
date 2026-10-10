import { useState } from 'react'
import { describe, expect, it } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { choose } from '@/shared/test/select'
import { SchedulePicker } from '@/features/domains/schedule-picker'
import { formatRun, localDay, weekdayName, type ScheduleRule } from '@/features/domains/schedule'

const tr = (key: string, options?: Record<string, unknown>) => i18n.t(`sources:${key}`, options)
const NOW = new Date('2026-10-09T12:00:00Z')  // a Friday
const START: ScheduleRule = { frequency: 'weekly', weekdays: [5], month_days: [9], time: '09:00', timezone: 'America/Bogota' }

function Picker({ notOn, seen }: { notOn?: number; seen: ScheduleRule[] }) {
  const [rule, setRule] = useState(START)
  return <SchedulePicker id="rule" value={rule} onChange={next => { seen.push(next); setRule(next) }} now={NOW} notOn={notOn} />
}

const next = (iso: string) => tr('domains.schedule.next', { date: formatRun(iso) })

describe('the schedule picker', () => {
  it('picks weekdays, says when it runs next, and asks for a day when none is left', async () => {
    const user = userEvent.setup()
    const seen: ScheduleRule[] = []
    render(<Picker seen={seen} />)
    expect(screen.getByRole('radio', { name: tr('domains.schedule.frequency.weekly') }).getAttribute('aria-checked')).toBe('true')
    const days = screen.getByRole('group', { name: tr('domains.schedule.weekdays') })
    expect(within(days).getAllByRole('button')).toHaveLength(7)
    expect(within(days).getByRole('button', { name: weekdayName(5) }).getAttribute('aria-pressed')).toBe('true')
    expect(screen.getByRole('status').textContent).toContain(next('2026-10-09T14:00:00Z'))  // today, 9:00 in Bogotá

    await user.click(within(days).getByRole('button', { name: weekdayName(5) }))
    expect(screen.getByRole('status').textContent).toBe(tr('domains.schedule.pick_weekday'))
    await user.click(within(days).getByRole('button', { name: weekdayName(3) }))
    await user.click(within(days).getByRole('button', { name: weekdayName(1) }))
    expect(seen.at(-1)?.weekdays).toEqual([3, 1])
    expect(screen.getByRole('status').textContent).toContain(next('2026-10-12T14:00:00Z'))  // Monday
  })

  it('switches to days of the month and to daily, and follows the time and the zone', async () => {
    const user = userEvent.setup()
    const seen: ScheduleRule[] = []
    render(<Picker seen={seen} />)
    await user.click(screen.getByRole('radio', { name: tr('domains.schedule.frequency.monthly') }))
    const grid = screen.getByRole('group', { name: tr('domains.schedule.month_days') })
    expect(within(grid).getAllByRole('button')).toHaveLength(28)
    await user.click(within(grid).getByRole('button', { name: tr('domains.schedule.month_day', { day: 9 }) }))
    expect(screen.getByRole('status').textContent).toBe(tr('domains.schedule.pick_month_day'))
    await user.click(within(grid).getByRole('button', { name: tr('domains.schedule.month_day', { day: 20 }) }))
    expect(screen.getByRole('status').textContent).toContain(next('2026-10-20T14:00:00Z'))

    await user.click(screen.getByRole('radio', { name: tr('domains.schedule.frequency.daily') }))
    expect(screen.queryByRole('group')).toBeNull()
    fireEvent.change(screen.getByLabelText(tr('domains.schedule.time')), { target: { value: '06:30' } })
    expect(screen.getByRole('status').textContent).toContain(next('2026-10-10T11:30:00Z'))  // 6:30 has passed today
    await choose(user, screen.getByLabelText(tr('domains.schedule.timezone')), 'Asia/Tokyo')
    expect(seen.at(-1)).toEqual({ ...START, frequency: 'daily', month_days: [20], time: '06:30', timezone: 'Asia/Tokyo' })
    expect(screen.getByRole('status').textContent).toContain(next('2026-10-09T21:30:00Z'))
  })

  it('skips a day already scanned and says why', () => {
    render(<Picker seen={[]} notOn={localDay(NOW, 'America/Bogota')} />)
    expect(screen.getByRole('status').textContent).toContain(next('2026-10-16T14:00:00Z'))
    expect(screen.getByText(tr('domains.schedule.once_a_day'))).toBeTruthy()
  })
})
