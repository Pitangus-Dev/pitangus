import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ChevronRight, Globe2, MoreHorizontal, Play, Radar } from 'lucide-react'
import type { SessionUser } from '@/features/auth/session'
import { AnalysisList } from '@/features/analyses/analysis-list'
import { DomainFindings } from '@/features/domains/domain-findings'
import type { DomainTab } from '@/features/domains/domain-list'
import { DomainOverview } from '@/features/domains/domain-overview'
import { TONE, kindOf, verification, type Domain as DomainRow } from '@/features/domains/domains'
import { HeadersEditor } from '@/features/domains/headers-editor'
import { useRemoveDomain } from '@/features/domains/use-remove-domain'
import { VerifyDomainDialog } from '@/features/domains/verify-domain-dialog'
import { domainsQuery, keys, runsQuery } from '@/shared/api/queries'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/shared/ui/card'
import { Skeleton } from '@/shared/ui/loading'
import { Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger } from '@/shared/ui/menu'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/shared/ui/tabs'

const TABS: { id: DomainTab; label: string }[] = [
  { id: 'overview', label: 'domains.page.tabs.overview' }, { id: 'access', label: 'domains.page.tabs.access' },
  { id: 'findings', label: 'domains.page.tabs.findings' }, { id: 'scans', label: 'domains.page.tabs.scans' },
]

// One domain: what it is and how it's proven, the headers its scans send, its findings and its scans.
export function Domain({ domainId, tab, onTab, user, onBack, onNewScan, onOpenRun, onImport, onOpenPolicies }: {
  domainId: string; tab: DomainTab; onTab: (tab: DomainTab) => void; user: SessionUser; onBack: () => void; onNewScan: (domain: DomainRow) => void
  onOpenRun: (id: string) => void; onImport: () => void; onOpenPolicies: () => void
}) {
  const { t } = useTranslation('sources')
  const queryClient = useQueryClient()
  const admin = user.role === 'admin'
  const domains = useQuery(domainsQuery())
  const runs = useQuery(runsQuery())
  const domain = domains.data?.items.find(item => item.id === domainId) ?? null
  const [verifying, setVerifying] = useState(false)
  const [addingHeader, setAddingHeader] = useState(false)
  const { ask, removal } = useRemoveDomain(onBack)

  const crumbs = <nav aria-label={t('domains.page.breadcrumb')} className="flex items-center gap-1.5 text-sm text-app-muted">
    <button type="button" onClick={onBack} className="min-h-6 underline-offset-2 hover:text-app-fg hover:underline">{t('domains.list.title')}</button>
    {domain && <><ChevronRight className="size-3.5" aria-hidden /><span aria-current="page" className="truncate text-app-secondary">{domain.host}</span></>}
  </nav>
  if (domains.isPending) return <div className="space-y-5">{crumbs}<h1 className="sr-only">{t('domains.list.title')}</h1><Skeleton tiles={0} rows={4} /></div>
  if (domains.isError) return <div className="space-y-5">{crumbs}<h1 className="sr-only">{t('domains.list.title')}</h1>
    <div role="alert" className="flex flex-wrap items-center gap-3 rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{t('domains.list.load_failed')}
      <Button size="xs" variant="outline" onClick={() => void domains.refetch()}>{t('common:actions.retry')}</Button></div></div>
  if (!domain) return <div className="space-y-5">{crumbs}<Card className="border-app-line bg-panel"><CardContent className="flex flex-col items-center gap-3 py-14 text-center">
    <Globe2 className="size-7 text-app-muted" aria-hidden /><h1 className="text-base font-medium">{t('domains.page.not_found')}</h1><Button variant="outline" onClick={onBack}>{t('domains.page.back')}</Button>
  </CardContent></Card></div>

  const state = verification(domain)
  const scannable = admin && domain.kind !== 'surface'
  return <div className="space-y-6">
    {crumbs}
    <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div className="min-w-0 space-y-2">
        <h1 className="text-3xl font-semibold tracking-tight break-all sm:text-4xl">{domain.host}</h1>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="rounded-md border border-app-line bg-inset px-1.5 text-app-muted">{kindOf(domain)}</span>
          <span className={`rounded-md border px-1.5 ${TONE[state.tone]}`}>{state.label}</span>
        </div>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        {scannable && <Button onClick={() => onNewScan(domain)}><Play aria-hidden />{t('domains.page.new_scan')}</Button>}
        {admin && <Menu><MenuTrigger render={<Button variant="outline" size="icon" aria-label={t('domains.list.actions_for', { host: domain.host })} />}><MoreHorizontal /></MenuTrigger>
          <MenuContent><MenuItem onClick={() => setVerifying(true)}>{t('domains.page.verify_again')}</MenuItem><MenuSeparator />
            <MenuItem className="text-danger" onClick={() => ask(domain)}>{t('domains.list.remove')}</MenuItem></MenuContent></Menu>}
      </div>
    </div>
    {removal.isError && <p role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{removal.error.message}</p>}
    <Tabs value={tab} onValueChange={value => onTab(value as DomainTab)}>
      <div className="overflow-x-auto"><TabsList variant="line" aria-label={t('domains.page.tabs_label')}>
        {TABS.map(item => <TabsTrigger key={item.id} value={item.id} className="min-h-8 px-3">{t(item.label)}</TabsTrigger>)}
      </TabsList></div>
      <TabsContent value="overview" className="pt-4">
        <DomainOverview domain={domain} admin={admin} onVerify={() => setVerifying(true)} onRemove={() => ask(domain)} removing={removal.isPending} />
      </TabsContent>
      <TabsContent value="access" className="pt-4">
        <Card className="border-app-line bg-panel"><CardHeader><CardTitle>{t('domains.page.access_title')}</CardTitle></CardHeader><CardContent className="space-y-3">
          <p className="text-sm text-app-muted">{t('domains.page.access_text')}</p>
          <HeadersEditor domain={domain} admin={admin} adding={addingHeader} onAddingChange={setAddingHeader} />
        </CardContent></Card>
      </TabsContent>
      <TabsContent value="findings" className="pt-4">
        <DomainFindings domain={domain} user={user} onNewScan={() => onNewScan(domain)} onImport={onImport} onOpenPolicies={onOpenPolicies} />
      </TabsContent>
      <TabsContent value="scans" className="pt-4">
        <AnalysisList asset={domain.key} refreshKey={runs.data?.length ?? 0} onOpen={onOpenRun} onNew={() => onNewScan(domain)} viewer={{ username: user.username, admin }}
          empty={<div className="flex flex-col items-center gap-3 py-14 text-center"><Radar className="size-7 text-app-muted" aria-hidden /><p className="text-sm text-app-muted">{t('domains.page.scans_empty')}</p>
            {scannable && <Button onClick={() => onNewScan(domain)}><Play aria-hidden />{t('domains.page.new_scan')}</Button>}</div>} />
      </TabsContent>
    </Tabs>
    {admin && <VerifyDomainDialog domain={verifying ? domain : null} onOpenChange={open => { if (!open) setVerifying(false) }}
      onVerified={() => void queryClient.invalidateQueries({ queryKey: keys.domains })} onStartScan={scannable ? onNewScan : undefined} />}
  </div>
}
