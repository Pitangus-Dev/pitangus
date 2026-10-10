import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { DotsThreeIcon, GlobeIcon, ScanIcon, ShieldCheckIcon, TargetIcon } from '@phosphor-icons/react'
import type { SessionUser } from '@/features/auth/session'
import { AnalysisList } from '@/features/analyses/analysis-list'
import { DomainFindings } from '@/features/domains/domain-findings'
import type { DomainTab } from '@/features/domains/domain-list'
import { DomainOverview } from '@/features/domains/domain-overview'
import { DomainScopeEditor } from '@/features/domains/domain-scope'
import { TestUsersPanel } from '@/features/domains/test-users'
import { TONE, kindOf, untilOf, verification, type Domain as DomainRow } from '@/features/domains/domains'
import { useRemoveDomain } from '@/features/domains/use-remove-domain'
import { VerifyDomainDialog } from '@/features/domains/verify-domain-dialog'
import { domainsQuery, keys, runsQuery } from '@/shared/api/queries'
import { Button } from '@/shared/ui/button'
import { Card, CardContent } from '@/shared/ui/card'
import { Skeleton } from '@/shared/ui/loading'
import { Menu, MenuContent, MenuItem, MenuTrigger } from '@/shared/ui/menu'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/shared/ui/tabs'

const TABS: { id: DomainTab; label: string }[] = [
  { id: 'overview', label: 'domains.page.tabs.overview' }, { id: 'findings', label: 'domains.page.tabs.findings' }, { id: 'scans', label: 'domains.page.tabs.scans' },
  { id: 'scope', label: 'domains.page.tabs.scope' }, { id: 'users', label: 'domains.page.tabs.users' },
]

// One domain: its kind and proof in one line under the name, then its overview (with headers), findings, scans, the
// scope its scans reach and the test users they sign in with. The scope has its own tab: discovery can list dozens of hosts, unlike the few rows of access.
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
  const { ask, removal } = useRemoveDomain(onBack)

  if (domains.isPending) return <div className="space-y-5"><h1 className="sr-only">{t('domains.list.title')}</h1><Skeleton tiles={0} rows={4} /></div>
  if (domains.isError) return <div className="space-y-5"><h1 className="sr-only">{t('domains.list.title')}</h1>
    <div role="alert" className="flex flex-wrap items-center gap-3 rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{t('domains.list.load_failed')}
      <Button size="xs" variant="outline" onClick={() => void domains.refetch()}>{t('common:actions.retry')}</Button></div></div>
  if (!domain) return <div className="space-y-5"><Card className="border-app-line bg-panel"><CardContent className="flex flex-col items-center gap-3 py-14 text-center">
    <GlobeIcon className="size-7 text-app-muted" aria-hidden /><h1 className="text-base font-medium">{t('domains.page.not_found')}</h1><Button variant="outline" onClick={onBack}>{t('domains.page.back')}</Button>
  </CardContent></Card></div>

  const state = verification(domain)
  const scannable = admin && domain.kind !== 'surface'
  const until = domain.verified ? untilOf(domain) : ''
  // A surface isn't scanned: no scope to reach, nobody to sign in as.
  const tabs = TABS.filter(item => (item.id !== 'scope' && item.id !== 'users') || domain.kind !== 'surface')
  return <div className="space-y-8">
    
    <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div className="min-w-0 space-y-2">
        <h1 className="text-3xl font-semibold tracking-tight break-all sm:text-4xl">{domain.host}</h1>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="rounded-md border border-app-line px-1.5 text-app-muted">{kindOf(domain)}</span>
          <span className={`rounded-md border px-1.5 ${TONE[state.tone]}`}>{state.label}</span>
          {until && <span className="text-app-muted">{t('domains.page.until', { date: until })}</span>}
        </div>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        {scannable && (domain.verified
          ? <Button variant="outline" onClick={() => onNewScan(domain)}><ScanIcon aria-hidden />{t('domains.page.new_scan')}</Button>
          : <Button onClick={() => setVerifying(true)}><ShieldCheckIcon aria-hidden />{t('domains.list.verify')}</Button>)}
        {/* Disconnecting lives at the bottom of the overview, where it says what goes with it. */}
        {admin && (domain.verified || !scannable) && <Menu><MenuTrigger render={<Button variant="outline" size="icon" aria-label={t('domains.list.actions_for', { host: domain.host })} />}><DotsThreeIcon /></MenuTrigger>
          <MenuContent><MenuItem onClick={() => setVerifying(true)}>{t(domain.verified ? 'domains.page.verify_again' : 'domains.list.verify')}</MenuItem></MenuContent></Menu>}
      </div>
    </div>
    <Tabs value={tabs.some(item => item.id === tab) ? tab : 'overview'} onValueChange={value => onTab(value as DomainTab)}>
      <div className="overflow-x-auto border-b border-app-line"><TabsList variant="line" aria-label={t('domains.page.tabs_label')}>
        {tabs.map(item => <TabsTrigger key={item.id} value={item.id} className="min-h-8 px-3">{t(item.label)}</TabsTrigger>)}
      </TabsList></div>
      <TabsContent value="overview" className="pt-6">
        <DomainOverview domain={domain} admin={admin} onVerify={() => setVerifying(true)} onDisconnect={() => ask(domain)} disconnecting={removal.isPending}
          disconnectError={removal.isError ? removal.error.message : ''} />
      </TabsContent>
      <TabsContent value="findings" className="pt-6">
        <DomainFindings domain={domain} user={user} onNewScan={() => onNewScan(domain)} onImport={onImport} onOpenPolicies={onOpenPolicies} />
      </TabsContent>
      {domain.kind !== 'surface' && <TabsContent value="users" className="pt-6">
        <TestUsersPanel domain={domain} admin={admin} />
      </TabsContent>}
      {domain.kind !== 'surface' && <TabsContent value="scope" className="pt-6">
        <div><DomainScopeEditor domain={domain} admin={admin} autoSearch onVerify={() => setVerifying(true)} heading="h2" /></div>
      </TabsContent>}
      <TabsContent value="scans" className="pt-6">
        <AnalysisList asset={domain.key} refreshKey={runs.data?.length ?? 0} onOpen={onOpenRun} onNew={() => onNewScan(domain)} viewer={{ username: user.username, admin }}
          empty={<div className="flex flex-col items-center gap-3 py-14 text-center"><TargetIcon className="size-7 text-app-muted" aria-hidden /><p className="text-sm text-app-muted">{t('domains.page.scans_empty')}</p>
            {scannable && <Button onClick={() => onNewScan(domain)}><ScanIcon aria-hidden />{t('domains.page.new_scan')}</Button>}</div>} />
      </TabsContent>
    </Tabs>
    {admin && <VerifyDomainDialog domain={verifying ? domain : null} onOpenChange={open => { if (!open) setVerifying(false) }}
      onVerified={() => void queryClient.invalidateQueries({ queryKey: keys.domains })} onStartScan={scannable ? onNewScan : undefined} />}
  </div>
}
