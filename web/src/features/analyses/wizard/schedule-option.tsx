import { useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Switch } from '@/shared/ui/switch'
import { SchedulePicker } from '@/features/domains/schedule-picker'
import { localDay, type ScheduleRule } from '@/features/domains/schedule'

export type SchedulePlan = { on: boolean; rule: ScheduleRule; alsoNow: boolean }

// "Schedule" in the review of a web scan: off, it's one line; on, how often and when, and whether to scan now as well
// (on by default). Scanning now, or a scan earlier today, moves the first scheduled one to a later day.
export function ScheduleOption({ value, onChange, lastScanAt, hint }: { value: SchedulePlan; onChange: (plan: SchedulePlan) => void; lastScanAt?: string; hint?: ReactNode }) {
  const { t } = useTranslation('sources')
  const [now] = useState(() => new Date())
  const notOn = value.alsoNow ? localDay(now, value.rule.timezone) : lastScanAt ? localDay(lastScanAt, value.rule.timezone) : null
  return <div className="space-y-4">
    <Switch id="schedule-scan" checked={value.on} onCheckedChange={on => onChange({ ...value, on })} label={t('domains.schedule.switch')} hint={hint} />
    {value.on && <div className="space-y-4 border-l border-app-line pl-4 sm:ml-5">
      <SchedulePicker id="schedule-rule" value={value.rule} onChange={rule => onChange({ ...value, rule })} notOn={notOn} now={now} />
      <label className="flex min-h-6 items-center gap-2 text-sm text-app-fg">
        <input type="checkbox" checked={value.alsoNow} onChange={event => onChange({ ...value, alsoNow: event.target.checked })} className="size-4 accent-brand" />
        {t('domains.schedule.also_now')}
      </label>
    </div>}
  </div>
}
