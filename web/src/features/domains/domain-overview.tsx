import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { formatDay } from '@/shared/i18n/format'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/shared/ui/card'
import { ScheduleToggle } from '@/features/domains/schedule-toggle'
import { coversSubdomains, kindOf, lastScanOf, methodLabel, proofOf, untilOf, verification, type Domain } from '@/features/domains/domains'

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return <div className="grid gap-1 border-b border-app-line py-2.5 last:border-0 sm:grid-cols-[10rem_minmax(0,1fr)] sm:gap-4">
    <dt className="text-xs text-app-muted">{label}</dt><dd className="min-w-0 text-sm break-words text-app-secondary">{children}</dd>
  </div>
}

// What a domain is, how it's proven and what happens to it on its own; removing it sits at the bottom.
export function DomainOverview({ domain, admin, onVerify, onRemove, removing }: { domain: Domain; admin: boolean; onVerify: () => void; onRemove: () => void; removing: boolean }) {
  const { t } = useTranslation('sources')
  const last = lastScanOf(domain)
  const added = domain.registered_at ? formatDay(domain.registered_at, { dateStyle: 'medium' }) : ''
  return <div className="space-y-5">
    <Card className="border-app-line bg-panel"><CardContent className="px-5">
      <dl>
        <Fact label={t('domains.page.type')}>{kindOf(domain)}</Fact>
        <Fact label={t('domains.page.added')}>{domain.registered_by ? t('domains.page.added_by', { date: added, user: domain.registered_by }) : added || '—'}</Fact>
        <Fact label={t('domains.page.verification')}>{domain.verified ? t('domains.page.verification_value', { method: methodLabel(proofOf(domain)), date: untilOf(domain) }) : verification(domain).label}</Fact>
        <Fact label={t('domains.page.last_scan')}>{last ? formatDay(last.created_at, { dateStyle: 'medium' }) : t('domains.list.never')}</Fact>
        <Fact label={t('domains.page.context')}>{domain.context || <span className="text-app-muted">{t('domains.page.no_context')}</span>}</Fact>
      </dl>
    </CardContent></Card>
    <Card className="border-app-line bg-panel"><CardHeader><CardTitle>{t('domains.page.scope_title')}</CardTitle></CardHeader><CardContent className="space-y-3">
      {coversSubdomains(domain) ? <p className="text-sm text-app-secondary">{t('domains.page.scope_dns', { host: domain.host })}</p>
        : <div className="flex flex-wrap items-center justify-between gap-3"><p className="text-sm text-app-secondary">{t('domains.page.scope_exact', { host: domain.host })}</p>
            {admin && <Button variant="outline" size="sm" onClick={onVerify}>{t('domains.page.verify_dns')}</Button>}</div>}
    </CardContent></Card>
    <Card className="border-app-line bg-panel"><CardHeader><CardTitle>{t('domains.page.schedule_title')}</CardTitle></CardHeader><CardContent>
      <ScheduleToggle domain={domain} admin={admin} />
    </CardContent></Card>
    {admin && <Card className="border-danger-line bg-panel"><CardHeader><CardTitle>{t('domains.page.remove_title')}</CardTitle></CardHeader><CardContent className="flex flex-wrap items-center justify-between gap-3">
      <p className="max-w-xl text-sm text-app-muted">{domain.runs ? t('domains.list.confirm_remove_runs', { count: domain.runs }) : t('domains.list.confirm_remove')}</p>
      <Button disabled={removing} onClick={onRemove} className="bg-danger-solid text-on-solid hover:bg-danger-solid/90">{t('domains.list.remove')}</Button>
    </CardContent></Card>}
  </div>
}
