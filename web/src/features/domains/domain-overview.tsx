import { useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { formatDay } from '@/shared/i18n/format'
import { Button } from '@/shared/ui/button'
import { HeadersEditor } from '@/features/domains/headers-editor'
import { ScheduleToggle } from '@/features/domains/schedule-toggle'
import { coversSubdomains, lastScanOf, type Domain } from '@/features/domains/domains'

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return <div className="grid gap-1 border-b border-app-line py-3 last:border-0 sm:grid-cols-[10rem_minmax(0,1fr)] sm:gap-4">
    <dt className="text-sm text-app-muted">{label}</dt><dd className="min-w-0 text-sm break-words text-app-secondary">{children}</dd>
  </div>
}

// Everything about a domain that isn't findings or scans: a few facts, the weekly scan and the headers its scans send.
// Access lives here rather than in its own tab: it's a handful of rows, configured once, like the schedule.
export function DomainOverview({ domain, admin, onVerify }: { domain: Domain; admin: boolean; onVerify: () => void }) {
  const { t } = useTranslation('sources')
  const [addingHeader, setAddingHeader] = useState(false)
  const last = lastScanOf(domain)
  const added = domain.registered_at ? formatDay(domain.registered_at, { dateStyle: 'medium' }) : ''
  const scannable = domain.kind !== 'surface'
  return <div className="max-w-3xl space-y-10">
    <dl className="border-y border-app-line">
      {domain.verified && !coversSubdomains(domain) && <Fact label={t('domains.page.scope')}><span className="flex flex-wrap items-center justify-between gap-3">
        <span>{t('domains.page.scope_exact', { host: domain.host })}</span>
        {admin && <Button variant="outline" size="sm" onClick={onVerify}>{t('domains.page.verify_dns')}</Button>}</span></Fact>}
      <Fact label={t('domains.page.last_scan')}>{last ? formatDay(last.created_at, { dateStyle: 'medium' }) : t('domains.list.never')}</Fact>
      {domain.context && <Fact label={t('domains.page.context')}>{domain.context}</Fact>}
      <Fact label={t('domains.page.added')}>{domain.registered_by ? t('domains.page.added_by', { date: added, user: domain.registered_by }) : added || '—'}</Fact>
    </dl>
    <ScheduleToggle domain={domain} admin={admin} />
    {scannable && <section aria-labelledby="domain-access" className="space-y-3">
      <div className="space-y-1">
        <h2 id="domain-access" className="text-base font-semibold">{t('domains.page.access_title')}</h2>
        <p className="text-sm text-app-muted">{t('domains.page.access_text')}</p>
      </div>
      <HeadersEditor domain={domain} admin={admin} adding={addingHeader} onAddingChange={setAddingHeader} />
    </section>}
  </div>
}
