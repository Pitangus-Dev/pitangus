import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { apiPost } from '@/shared/api/client'
import { keys } from '@/shared/api/queries'
import { formatDate } from '@/shared/i18n/format'
import { Switch } from '@/shared/ui/switch'
import type { Domain } from '@/features/domains/domains'

// The weekly passive scan of a domain. The server runs it in its hourly round; a lapsed proof pauses it and says so.
export function ScheduleToggle({ domain, admin }: { domain: Domain; admin: boolean }) {
  const { t } = useTranslation('sources')
  const queryClient = useQueryClient()
  const save = useMutation({
    mutationFn: (on: boolean) => apiPost('/api/domains/schedule', 'schedule-domain', { domain_id: domain.id, schedule: on ? 'weekly' : null }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: keys.domains }),
  })
  const on = save.isPending ? !!save.variables : domain.schedule === 'weekly'
  if (domain.kind === 'surface') return <p className="text-sm text-app-muted">{t('domains.schedule.surface')}</p>
  return <div className="space-y-2">
    <Switch id={`schedule-${domain.id}`} checked={on} disabled={!admin || save.isPending} onCheckedChange={next => save.mutate(next)} label={t('domains.schedule.toggle')}
      hint={on && domain.schedule_next_at ? t('domains.schedule.next', { date: formatDate(domain.schedule_next_at) }) : undefined} />
    {on && !domain.verified && <p className="text-xs text-warning">{t('domains.schedule.paused')}</p>}
    {on && domain.verified && domain.schedule_note && <p className="text-xs text-app-muted">{domain.schedule_note}</p>}
    {save.error && <p role="alert" className="text-xs text-danger">{save.error.message}</p>}
  </div>
}
