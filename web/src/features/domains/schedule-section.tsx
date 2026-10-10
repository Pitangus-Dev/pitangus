import { useEffect, useRef, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { apiPost } from '@/shared/api/client'
import { keys } from '@/shared/api/queries'
import { Button } from '@/shared/ui/button'
import { SchedulePicker } from '@/features/domains/schedule-picker'
import { complete, defaultRule, describeRule, formatRun, localDay, normalized, ruleOf, type ScheduleRule } from '@/features/domains/schedule'
import { lastScanOf, type Domain } from '@/features/domains/domains'
import { ScheduleAccessPicker } from '@/features/domains/schedule-access'
import { accessOf, describeAccess, usableAccess, useScheduledHosts, type ScheduleAccess } from '@/features/domains/schedule-access-model'

// When the domain's passive scan runs on its own, in plain words, with a way to change it or turn it off. The server
// queues it within minutes of its next run; a lapsed proof pauses it and says so.
export function ScheduleSection({ domain, admin }: { domain: Domain; admin: boolean }) {
  const { t } = useTranslation('sources')
  const queryClient = useQueryClient()
  const [draft, setDraft] = useState<ScheduleRule | null>(null)
  const [access, setAccess] = useState<ScheduleAccess>(() => accessOf(domain.schedule))
  const hosts = useScheduledHosts(domain, admin && !!draft)
  // The button that opened or closed the editor goes away: focus moves to what replaced it once that renders.
  const section = useRef<HTMLElement>(null)
  const pendingFocus = useRef<string | null>(null)
  useEffect(() => {
    if (!pendingFocus.current) return
    const target = section.current?.querySelector<HTMLElement>(pendingFocus.current)
    if (target) { target.focus(); pendingFocus.current = null }
  })
  const edit = (rule: ScheduleRule | null, focus: string) => { save.reset(); pendingFocus.current = focus; setAccess(accessOf(domain.schedule)); setDraft(rule) }
  const save = useMutation({
    mutationFn: (rule: ScheduleRule | null) => apiPost('/api/domains/schedule', 'schedule-domain', { domain_id: domain.id,
      schedule: rule && { ...rule, ...usableAccess(domain, access, hosts) } }),
    onSuccess: async (_, rule) => { await queryClient.invalidateQueries({ queryKey: keys.domains }); pendingFocus.current = rule ? '[data-focus=change]' : '[data-focus=set]'; setDraft(null) },
  })
  const schedule = domain.schedule ?? null
  const last = lastScanOf(domain)
  const editor = '[role=radio][aria-checked=true]'
  return <section ref={section} aria-labelledby="domain-schedule" className="space-y-3">
    <h2 id="domain-schedule" className="text-base font-semibold">{t('domains.schedule.title')}</h2>
    {domain.kind === 'surface' ? <p className="text-sm text-app-muted">{t('domains.schedule.surface')}</p>
      : draft ? <div className="space-y-4">
        <SchedulePicker id={`schedule-${domain.id}`} value={draft} onChange={setDraft} notOn={last ? localDay(last.created_at, draft.timezone) : null} />
        <ScheduleAccessPicker id={`schedule-${domain.id}-access`} domain={domain} value={access} hosts={hosts} onChange={setAccess} />
        <div className="flex flex-wrap gap-2">
          <Button size="sm" disabled={!complete(draft) || save.isPending} onClick={() => save.mutate(normalized(draft))}>{t('domains.schedule.save')}</Button>
          <Button size="sm" variant="ghost" disabled={save.isPending} onClick={() => edit(null, schedule ? '[data-focus=change]' : '[data-focus=set]')}>{t('common:actions.cancel')}</Button>
        </div>
      </div>
      : schedule ? <div className="space-y-1">
        <p className="text-sm text-app-fg">{describeRule(ruleOf(schedule))}</p>
        <p className="text-sm text-app-muted">{describeAccess(t, domain, accessOf(schedule))}</p>
        {schedule.next_run_at && <p className="text-sm text-app-muted">{t('domains.schedule.next', { date: formatRun(schedule.next_run_at) })}</p>}
        {!domain.verified && <p className="text-xs text-warning">{t('domains.schedule.paused')}</p>}
        {domain.verified && schedule.note && <p className="text-xs text-app-muted">{schedule.note}</p>}
        {admin && <div className="flex flex-wrap gap-2 pt-2">
          <Button size="sm" variant="outline" data-focus="change" onClick={() => edit(ruleOf(schedule), editor)}>{t('domains.schedule.change')}</Button>
          <Button size="sm" variant="ghost" disabled={save.isPending} onClick={() => save.mutate(null)}>{t('domains.schedule.turn_off')}</Button>
        </div>}
      </div>
      : <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-app-muted">{t('domains.schedule.none')}</p>
        {admin && <Button size="sm" variant="outline" data-focus="set" onClick={() => edit(defaultRule(), editor)}>{t('domains.schedule.set')}</Button>}
      </div>}
    {save.error && <p role="alert" className="text-xs text-danger">{save.error.message}</p>}
  </section>
}
