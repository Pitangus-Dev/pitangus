import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { cn } from 'cn'
import { Input } from '@/shared/ui/input'
import { Segmented } from '@/shared/ui/segmented'
import { SelectField } from '@/shared/ui/select-field'
import { FREQUENCY, MONTH_DAYS, WEEKDAYS, formatRun, nextRun, zoneName, weekdayName, zones, type Frequency, type ScheduleRule } from '@/features/domains/schedule'

const MISSING = { time: 'domains.schedule.pick_time', weekdays: 'domains.schedule.pick_weekday', month_days: 'domains.schedule.pick_month_day' } as const
const TIME = /^([01]\d|2[0-3]):[0-5]\d$/

const toggle = (values: number[], value: number) => values.includes(value) ? values.filter(item => item !== value) : [...values, value]

function DayToggle({ pressed, label, onClick, children }: { pressed: boolean; label: string; onClick: () => void; children: string }) {
  return <button type="button" aria-pressed={pressed} aria-label={label} onClick={onClick}
    className={cn('min-h-8 min-w-8 rounded-md border px-1.5 text-sm tabular-nums motion-safe:transition-colors',
      pressed ? 'border-app-fg bg-app-soft font-medium text-app-fg' : 'border-app-line text-app-muted hover:text-app-fg')}>{children}</button>
}

// How often, which days, at what time and in which zone a domain's passive scan runs, with when it would run next
// (the server computes the same moment when it saves). `notOn`: a local day already scanned, which it skips.
export function SchedulePicker({ id, value, onChange, notOn, now: given }: {
  id: string; value: ScheduleRule; onChange: (rule: ScheduleRule) => void; notOn?: number | null; now?: Date
}) {
  const { t } = useTranslation('sources')
  const [opened] = useState(() => new Date())
  const now = given ?? opened
  const zoneOptions = useMemo(() => zones(value.timezone).map(zone => ({ value: zone, label: zoneName(zone) })), [value.timezone])
  const next = nextRun(value, now, notOn)
  const skipped = !!next && notOn != null && nextRun(value, now)?.getTime() !== next.getTime()
  const missing = !TIME.test(value.time) ? 'time' : value.frequency === 'weekly' && !value.weekdays.length ? 'weekdays'
    : value.frequency === 'monthly' && !value.month_days.length ? 'month_days' : null
  const set = (change: Partial<ScheduleRule>) => onChange({ ...value, ...change })
  return <div className="space-y-4">
    <Segmented label={t('domains.schedule.frequency.label')} value={value.frequency} onChange={(frequency: Frequency) => set({ frequency })}
      options={(['daily', 'weekly', 'monthly'] as const).map(frequency => ({ value: frequency, label: t(FREQUENCY[frequency]) }))} />
    {value.frequency === 'weekly' && <div role="group" aria-label={t('domains.schedule.weekdays')} className="flex flex-wrap gap-1.5">
      {WEEKDAYS.map(day => <DayToggle key={day} pressed={value.weekdays.includes(day)} label={weekdayName(day)} onClick={() => set({ weekdays: toggle(value.weekdays, day) })}>{weekdayName(day, 'short')}</DayToggle>)}
    </div>}
    {value.frequency === 'monthly' && <div role="group" aria-label={t('domains.schedule.month_days')} className="grid w-fit grid-cols-7 gap-1.5">
      {MONTH_DAYS.map(day => <DayToggle key={day} pressed={value.month_days.includes(day)} label={t('domains.schedule.month_day', { day })} onClick={() => set({ month_days: toggle(value.month_days, day) })}>{String(day)}</DayToggle>)}
    </div>}
    <div className="grid gap-3 sm:grid-cols-[8rem_minmax(0,18rem)]">
      <div className="space-y-1.5">
        <label htmlFor={`${id}-time`} className="text-xs text-app-muted">{t('domains.schedule.time')}</label>
        <Input id={`${id}-time`} type="time" required value={value.time} onChange={event => set({ time: event.target.value })} className="border-input bg-card" />
      </div>
      <div className="space-y-1.5">
        <label htmlFor={`${id}-zone`} className="text-xs text-app-muted">{t('domains.schedule.timezone')}</label>
        <SelectField id={`${id}-zone`} value={value.timezone} onValueChange={timezone => { if (timezone) set({ timezone }) }} options={zoneOptions} />
      </div>
    </div>
    <div role="status" className="space-y-0.5">
      <p className="text-sm text-app-secondary">{next ? t('domains.schedule.next', { date: formatRun(next) }) : missing ? t(MISSING[missing]) : null}</p>
      {skipped && <p className="text-xs text-app-muted">{t('domains.schedule.once_a_day')}</p>}
    </div>
  </div>
}
