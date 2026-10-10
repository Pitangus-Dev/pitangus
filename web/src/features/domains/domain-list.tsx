import { useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Globe2, MoreHorizontal, Plus, Search } from 'lucide-react'
import { domainsQuery, keys } from '@/shared/api/queries'
import { formatDay } from '@/shared/i18n/format'
import { Button } from '@/shared/ui/button'
import { Card, CardContent } from '@/shared/ui/card'
import { Input } from '@/shared/ui/input'
import { SkeletonTable } from '@/shared/ui/loading'
import { Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger } from '@/shared/ui/menu'
import { Pagination } from '@/shared/ui/pagination'
import { AddDomainDialog } from '@/features/domains/add-domain-dialog'
import { VerifyDomainDialog } from '@/features/domains/verify-domain-dialog'
import { useRemoveDomain } from '@/features/domains/use-remove-domain'
import { TONE, kindOf, lastScanOf, untilOf, verification, type Domain } from '@/features/domains/domains'

const PAGE = 25
export type DomainTab = 'overview' | 'findings' | 'scans'

// The sites and APIs a team controls, alike: kind as a tag, whether the proof is current, the last scan (and whether it
// repeats weekly) and open findings. Administrators add, verify and remove; everyone else reads.
export function DomainList({ admin, onOpenDomain, onNewScan }: { admin: boolean; onOpenDomain: (domain: Domain, tab?: DomainTab) => void; onNewScan: (domain: Domain) => void }) {
  const { t } = useTranslation('sources')
  const queryClient = useQueryClient()
  const addOpener = useRef<HTMLButtonElement>(null)
  const [adding, setAdding] = useState(false)
  const [verifying, setVerifying] = useState<Domain | null>(null)
  const [notice, setNotice] = useState('')
  const [search, setSearch] = useState('')
  const [offset, setOffset] = useState(0)
  const domains = useQuery(domainsQuery())
  const items = domains.data?.items ?? []
  const needle = search.trim().toLowerCase()
  const matching = needle ? items.filter(domain => domain.host.includes(needle)) : items
  const start = offset < matching.length ? offset : 0
  const shown = matching.slice(start, start + PAGE)
  const refresh = () => void queryClient.invalidateQueries({ queryKey: keys.domains })
  const { ask, removal } = useRemoveDomain(domain => { setNotice(t('domains.list.removed', { host: domain.host })); addOpener.current?.focus() })
  const add = <Button ref={addOpener} onClick={() => setAdding(true)}><Plus aria-hidden />{t('domains.list.add')}</Button>

  return <Card className="border-app-line bg-panel"><CardContent className="space-y-4 p-5">
    <div className="flex flex-wrap items-center justify-between gap-3">
      {items.length > PAGE ? <div className="relative w-full sm:max-w-xs"><Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-app-muted" aria-hidden />
        <Input aria-label={t('domains.list.search')} placeholder={t('domains.list.search')} value={search} onChange={event => { setSearch(event.target.value); setOffset(0) }} className="border-app-line bg-app-soft pl-9" /></div>
        : <span />}
      {admin && items.length > 0 && add}
    </div>
    {!admin && <p className="text-sm text-app-muted">{t('domains.list.read_only')}</p>}
    <div role="status">{notice && <p className="rounded-xl border border-success-line bg-success-soft px-3 py-2 text-sm text-success">{notice}</p>}</div>
    {removal.isError && <p role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{removal.error.message}</p>}
    {domains.isError ? <div role="alert" className="flex flex-wrap items-center gap-3 rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{t('domains.list.load_failed')}
        <Button size="xs" variant="outline" onClick={() => void domains.refetch()}>{t('common:actions.retry')}</Button></div>
    : !domains.data ? <SkeletonTable rows={3} columns={4} label={t('domains.list.loading')} />
    : !items.length ? <div className="flex flex-col items-center gap-3 py-14 text-center"><Globe2 className="size-7 text-app-muted" aria-hidden />
        <p className="font-medium">{t('domains.list.empty_title')}</p><p className="max-w-sm text-sm text-app-muted">{t('domains.list.empty_text')}</p>{admin && add}</div>
    : <div className="-mx-5 overflow-x-auto"><table className={`w-full text-sm motion-safe:transition-opacity ${domains.isFetching ? 'opacity-70' : ''}`} aria-busy={domains.isFetching || undefined}>
      <thead><tr className="border-b border-app-line text-left text-xs text-app-muted">
        <th scope="col" className="px-5 py-3 font-normal">{t('domains.list.col_domain')}</th>
        <th scope="col" className="hidden px-3 py-3 font-normal md:table-cell">{t('domains.list.col_verification')}</th>
        <th scope="col" className="hidden px-3 py-3 font-normal md:table-cell">{t('domains.list.col_last_scan')}</th>
        <th scope="col" className="px-3 py-3 text-right font-normal">{t('domains.list.col_open')}</th>
        <th scope="col" className="w-12 px-4 py-3"><span className="sr-only">{t('domains.list.col_actions')}</span></th>
      </tr></thead>
      <tbody>{shown.map(domain => {
        const state = verification(domain)
        const last = lastScanOf(domain)
        const chip = <span title={domain.verified ? untilOf(domain) : undefined} className={`rounded-md border px-1.5 text-xs ${TONE[state.tone]}`}>{state.label}</span>
        return <tr key={domain.id} className="border-b border-app-line last:border-0">
          <td className="px-5 py-3"><div className="flex min-w-0 flex-col gap-1">
            <span className="flex min-w-0 flex-wrap items-center gap-2">
              <button type="button" onClick={() => onOpenDomain(domain)} className="min-h-6 truncate text-left font-medium text-app-fg underline-offset-2 hover:underline">{domain.host}</button>
              <span className="rounded-md border border-app-line px-1.5 text-xs text-app-muted">{kindOf(domain)}</span></span>
            <span className="md:hidden">{chip}</span></div></td>
          <td className="hidden px-3 py-3 md:table-cell">{chip}</td>
          <td className="hidden px-3 py-3 text-xs text-app-muted md:table-cell">{last ? formatDay(last.created_at, { dateStyle: 'medium' }) : t('domains.list.never')}{domain.schedule === 'weekly' && <span className="block">{t('domains.list.weekly')}</span>}</td>
          <td className="px-3 py-3 text-right">{domain.open
            ? <button type="button" onClick={() => onOpenDomain(domain, 'findings')} aria-label={t('domains.list.open_for', { host: domain.host, count: domain.open })} className="min-h-6 min-w-6 font-mono text-app-fg underline-offset-2 hover:underline">{domain.open}</button>
            : <span className="font-mono text-app-muted">0</span>}</td>
          <td className="px-4 py-2 text-right">{admin && <Menu><MenuTrigger render={<Button size="icon-sm" variant="ghost" aria-label={t('domains.list.actions_for', { host: domain.host })} disabled={removal.isPending && removal.variables?.id === domain.id} />}><MoreHorizontal /></MenuTrigger>
            <MenuContent>
              {domain.kind !== 'surface' && <MenuItem onClick={() => onNewScan(domain)}>{t('domains.list.new_scan')}</MenuItem>}
              <MenuItem onClick={() => setVerifying(domain)}>{t('domains.list.verify')}</MenuItem>
              <MenuSeparator />
              <MenuItem className="text-danger" onClick={() => ask(domain)}>{t('domains.list.remove')}</MenuItem>
            </MenuContent></Menu>}</td>
        </tr>
      })}</tbody>
    </table>
    {matching.length > PAGE && <div className="border-t border-app-line"><Pagination total={matching.length} limit={PAGE} offset={start} onPrev={() => setOffset(Math.max(0, start - PAGE))} onNext={() => setOffset(start + PAGE)} noun={t('domains.list.noun')} /></div>}
    </div>}
    <AddDomainDialog open={adding} onOpenChange={setAdding} onAdded={domain => { refresh(); setNotice(t('domains.list.added', { host: domain.host })); setVerifying(domain) }} />
    <VerifyDomainDialog domain={verifying} onOpenChange={open => { if (!open) setVerifying(null) }} onStartScan={onNewScan}
      onVerified={domain => { refresh(); setNotice(t('domains.list.verified_notice', { host: domain.host, date: untilOf(domain) })) }} />
  </CardContent></Card>
}
