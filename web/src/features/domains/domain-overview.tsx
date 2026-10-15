import { useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { formatDay } from '@/shared/i18n/format'
import { Button } from '@/shared/ui/button'
import { HeadersEditor, SessionCheck } from '@/features/domains/headers-editor'
import { ScheduleSection } from '@/features/domains/schedule-section'
import { DisconnectDomain } from '@/features/domains/disconnect-domain'
import { coversSubdomains, lastScanOf, type Domain } from '@/features/domains/domains'

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return <div className="grid gap-1 border-b border-app-line py-3 last:border-0 sm:grid-cols-[10rem_minmax(0,1fr)] sm:gap-4">
    <dt className="text-sm text-app-muted">{label}</dt><dd className="min-w-0 text-sm break-words text-app-secondary">{children}</dd>
  </div>
}

// Everything about a domain that isn't findings or scans: a few facts, the scheduled scan and the headers its scans send,
// and, last, disconnecting it. Access lives here rather than in its own tab: it's a handful of rows, configured once.
export function DomainOverview({ domain, admin, onVerify, onDisconnect, disconnecting = false, disconnectError = '' }: {
  domain: Domain; admin: boolean; onVerify: () => void; onDisconnect: () => void; disconnecting?: boolean; disconnectError?: string
}) {
  const { t } = useTranslation('sources')
  const [addingHeader, setAddingHeader] = useState(false)
  const last = lastScanOf(domain)
  const added = domain.registered_at ? formatDay(domain.registered_at, { dateStyle: 'medium' }) : ''
  const scannable = domain.kind !== 'surface'
  return <div className="space-y-10">
    <dl className="border-y border-app-line">
      {domain.verified && !coversSubdomains(domain) && <Fact label={t('domains.page.scope')}><span className="flex flex-wrap items-center justify-between gap-3">
        <span>{t('domains.page.scope_exact', { host: domain.host })}</span>
        {admin && <Button variant="outline" size="sm" onClick={onVerify}>{t('domains.page.verify_dns')}</Button>}</span></Fact>}
      <Fact label={t('domains.page.last_scan')}>{last ? formatDay(last.created_at, { dateStyle: 'medium' }) : t('domains.list.never')}</Fact>
      {last?.technologies && <Fact label={t('domains.page.technologies')}>{last.technologies.items.length
        ? <ul aria-label={t('domains.page.technologies')} className="flex flex-wrap gap-1.5">{last.technologies.items.map(item => <li key={`${item.name}@${item.version ?? ''}`}
          title={item.hosts.join(', ')} className="rounded-sm border border-app-line px-1.5 py-0.5 text-xs">{item.name}{item.version && <span className="ml-1 font-mono text-app-muted">{item.version}</span>}</li>)}</ul>
        : t('domains.page.technologies_none')}
        <span className="mt-1 block text-xs text-app-subtle">{t('domains.page.technologies_seen', { date: formatDay(last.technologies.created_at, { dateStyle: 'medium' }) })}</span></Fact>}
      {domain.context && <Fact label={t('domains.page.context')}>{domain.context}</Fact>}
      <Fact label={t('domains.page.added')}>{domain.registered_by ? t('domains.page.added_by', { date: added, user: domain.registered_by }) : added || '—'}</Fact>
    </dl>
    <ScheduleSection domain={domain} admin={admin} />
    {scannable && <section aria-labelledby="domain-access" className="space-y-3">
      <div className="space-y-1">
        <h2 id="domain-access" className="text-base font-semibold">{t('domains.page.access_title')}</h2>
        <p className="text-sm text-app-muted">{t('domains.page.access_text')}</p>
      </div>
      <HeadersEditor domain={domain} admin={admin} adding={addingHeader} onAddingChange={setAddingHeader} />
      {admin && <SessionCheck domain={domain} />}
    </section>}
    {admin && <DisconnectDomain domain={domain} busy={disconnecting} error={disconnectError} onDisconnect={onDisconnect} />}
  </div>
}
