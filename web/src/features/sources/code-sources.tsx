import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { imagesQuery } from '@/shared/api/queries'
import { useTranslation } from 'react-i18next'
import { api } from '@/shared/api/http'
import { ChevronDown, FileCheck2, GitBranch, Layers3, LoaderCircle, LockKeyhole, RefreshCw, Search } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { Input } from '@/shared/ui/input'
import { type GitHubStatus } from '@/features/sources/github-setup'
import { Pager } from '@/features/sources/source-search'
import { SkeletonList } from '@/shared/ui/loading'
import { BatchPanel, OrganizationScanDialog } from '@/features/analyses/batches'
import { useBatches } from '@/features/analyses/use-batches'
import { AuditReportDialog } from '@/features/findings/audit-report'
import { Menu, MenuContent, MenuItem, MenuTrigger } from '@/shared/ui/menu'
import { formatDay } from '@/shared/i18n/format'
import { useSourcePage } from '@/features/sources/sources'
import { ScanBranchEdit, ScanBranchEditor, ScanBranchLabel } from '@/features/sources/scan-branch'

export type { Source, SourcePage } from '@/features/sources/sources'
type Run = { created_at: string; source?: { id?: string; name: string } }

const PAGE_SIZE = 25

export function CodeSources({ onScan, onImages, runs = [], canManage = false }: { onScan?: (id: string) => void; onImages?: (repository: { key: string; name: string }) => void; runs?: Run[]; canManage?: boolean }) {
  const { t } = useTranslation('sources')
  // Images built from each repository (by their key), so each row can say how many and open them.
  const linkedImages = useQuery(imagesQuery({ limit: 1 }))
  const imageCount = useMemo(() => new Map(Object.entries(linkedImages.data?.repositories ?? {})), [linkedImages.data])
  const [github, setGithub] = useState<GitHubStatus | null>(null)
  const [filter, setFilter] = useState('')
  const [accountFilter, setAccountFilter] = useState('')
  const [page, setPage] = useState(1)
  const [error, setError] = useState('')
  // Varios repositorios de una vez: selección a mano (lote) o una organización entera (administración).
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [organization, setOrganization] = useState<string | null>(null)
  const [reportFor, setReportFor] = useState<string | null>(null)
  const [starting, setStarting] = useState(false)
  const [editingBranch, setEditingBranch] = useState<string | null>(null)
  // Closing the branch editor gives focus back to its Edit button, so keyboard users keep their place in the list.
  const editButtons = useRef(new Map<string, HTMLButtonElement>())
  const editButton = (id: string) => (element: HTMLButtonElement | null) => { if (element) editButtons.current.set(id, element); else editButtons.current.delete(id) }
  const closeBranchEditor = (id: string) => { setEditingBranch(null); window.setTimeout(() => editButtons.current.get(id)?.focus(), 0) }
  const { active: batch, last: lastBatch, reload: reloadBatches } = useBatches()
  const startSelected = async () => {
    setStarting(true); setError('')
    try { await api.post('/api/repositories/batches', 'scan-batch', { source_ids: [...selected] }); setSelected(new Set()); void reloadBatches() }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setStarting(false) }
  }
  // Solo la página visible: con cientos de repositorios la respuesta tarda lo mismo que con diez.
  const { data, error: sourcesError, loading, reload } = useSourcePage({ query: filter, account: accountFilter || undefined, page, perPage: PAGE_SIZE })
  useEffect(() => { void api.get<GitHubStatus>('/api/integrations/github').then(setGithub).catch(caught => setError(String(caught))) }, [])

  const installations = github?.installations ?? []
  const selectable = (data?.sources ?? []).filter(source => source.installation_id).map(source => source.id)
  const accounts = Array.from(new Set([...installations.map(item => item.account), ...(data?.accounts ?? [])].filter((account): account is string => !!account))).sort()

  return <div className="space-y-5">
    <p className="text-sm text-app-muted">{t('providers.accounts_connected', { count: installations.length })} · <a className="font-medium text-brand hover:underline" href="#/integrations">{t('providers.manage_github')}</a></p>
    {(error || sourcesError) && <div role="alert" className="rounded-xl border border-danger-line bg-danger-soft p-3 text-sm text-danger">{error || sourcesError}</div>}
    {data?.providers.github?.error && <div role="alert" className="rounded-xl border border-warning-line bg-warning-soft p-3 text-sm text-warning">{data.providers.github.error}</div>}

    <Card className="border-app-line bg-panel">
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3"><div><CardTitle>{t('repositories.title')}</CardTitle><CardDescription>{t('repositories.description')}</CardDescription></div><Button variant="outline" disabled={loading} onClick={() => reload(true)} className="border-app-line bg-app-soft"><RefreshCw className={loading ? 'animate-spin' : ''} /> {t('repositories.refresh')}</Button>
        {canManage && accounts.length > 0 && <Menu><MenuTrigger render={<Button variant="outline" disabled={!!batch} className="border-app-line bg-app-soft" />}><Layers3 />{t('repositories.scan_organization')}<ChevronDown className="size-3.5" /></MenuTrigger>
          <MenuContent>{accounts.map(account => <MenuItem key={account} onClick={() => setOrganization(account)}>{account}</MenuItem>)}</MenuContent></Menu>}
        {accounts.length > 0 && <Menu><MenuTrigger render={<Button variant="outline" className="border-app-line bg-app-soft" />}><FileCheck2 />{t('repositories.organization_report')}<ChevronDown className="size-3.5" /></MenuTrigger>
          <MenuContent>{accounts.map(account => <MenuItem key={account} onClick={() => setReportFor(account)}>{account}</MenuItem>)}</MenuContent></Menu>}</CardHeader>
      <CardContent className="space-y-4">
        <BatchPanel active={batch} last={lastBatch} onChanged={() => void reloadBatches()} />
        <div className="flex flex-wrap items-center gap-3"><div className="relative w-full max-w-sm"><Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-app-subtle" /><Input aria-label={t('repositories.search')} placeholder={t('repositories.search_placeholder')} value={filter} onChange={event => { setFilter(event.target.value); setPage(1) }} className="border-app-line bg-app-soft pl-9" /></div>
          {data && <span className="text-xs text-app-muted">{t('common:count.repositories', { count: data.total })}{data.partial ? ` · ${t('repositories.partial')}` : ''}</span>}</div>
        {accounts.length > 1 && <div role="group" aria-label={t('repositories.filter_by_organization')} className="flex flex-wrap gap-2">
          <Button size="sm" aria-pressed={accountFilter === ''} variant={accountFilter === '' ? 'default' : 'outline'} onClick={() => { setAccountFilter(''); setPage(1) }}>{t('repositories.all_organizations')}</Button>
          {accounts.map(account => <Button key={account} size="sm" aria-pressed={accountFilter === account} variant={accountFilter === account ? 'default' : 'outline'} onClick={() => { setAccountFilter(account); setPage(1) }}>{account}</Button>)}
        </div>}
        {selected.size > 0 && <div className="sticky top-16 z-10 flex flex-wrap items-center gap-3 rounded-xl border border-brand/30 bg-panel px-4 py-2.5 shadow-md">
          <span className="text-sm font-medium">{t('repositories.selected', { count: selected.size })}</span>
          <Button size="sm" disabled={starting || !!batch || selected.size > 100} onClick={() => void startSelected()} className="bg-primary text-primary-foreground hover:bg-primary/90">{starting && <LoaderCircle className="animate-spin" />}{t('repositories.scan_selected')}</Button>
          {(batch || selected.size > 100) && <span className="text-xs text-app-muted">{batch ? t('repositories.batch_running') : t('repositories.batch_limit')}</span>}
          <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())} className="ml-auto">{t('repositories.clear_selection')}</Button>
        </div>}
        <div className="overflow-hidden rounded-xl border border-app-line">
          <div className="hidden grid-cols-[20px_minmax(0,1fr)_minmax(0,170px)_120px_130px_130px] items-center gap-3 border-b border-app-line px-4 py-3 text-xs text-app-subtle md:grid">
            <input type="checkbox" aria-label={t('repositories.select_page')} className="size-4 accent-brand" checked={selectable.length > 0 && selectable.every(id => selected.has(id))}
              onChange={event => setSelected(previous => { const next = new Set(previous); for (const id of selectable) { if (event.target.checked) next.add(id); else next.delete(id) } return next })} />
            <span>{t('repositories.columns.repository')}</span><span>{t('repositories.columns.branch')}</span><span>{t('repositories.columns.origin')}</span><span>{t('repositories.columns.last_scan')}</span><span>{t('repositories.columns.action')}</span></div>
          {!data && <SkeletonList rows={8} action label={t('repositories.loading')} />}
          {data?.sources.map(source => {
            const last = runs.find(run => run.source?.name === source.name)
            return <div key={source.id} className="grid gap-2 border-b border-app-line px-4 py-3 last:border-b-0 md:grid-cols-[20px_minmax(0,1fr)_minmax(0,170px)_120px_130px_130px] md:items-center">
              {source.installation_id ? <input type="checkbox" aria-label={t('repositories.select_one', { name: source.name })} className="size-4 accent-brand" checked={selected.has(source.id)}
                onChange={event => setSelected(previous => { const next = new Set(previous); if (event.target.checked) next.add(source.id); else next.delete(source.id); return next })} /> : <span />}
              <div className="min-w-0"><div className="flex min-w-0 items-center gap-2"><GitBranch className="size-4 shrink-0 text-app-muted" /><span className="truncate text-sm font-medium">{source.name}</span>{source.private && <LockKeyhole className="size-3 shrink-0 text-app-subtle" />}</div>
                {onImages && source.uid && (imageCount.get(source.uid) || (canManage && last)) ? <button type="button" onClick={() => onImages({ key: source.uid ?? '', name: source.name })}
                  aria-label={imageCount.get(source.uid) ? t('images.count_for', { count: imageCount.get(source.uid), name: source.name }) : t('images.link_for', { name: source.name })}
                  className="ml-6 min-h-6 text-xs text-brand underline-offset-2 hover:underline">{imageCount.get(source.uid) ? t('images.count', { count: imageCount.get(source.uid) }) : t('images.link_from_repository')}</button> : null}</div>
              <div className="flex min-w-0 items-center gap-1"><span className="text-xs text-app-subtle md:sr-only">{t('repositories.columns.branch')}</span><ScanBranchLabel source={source} />{canManage && source.installation_id && source.uid && <ScanBranchEdit source={source} ref={editButton(source.id)} expanded={editingBranch === source.id} onEdit={() => setEditingBranch(current => current === source.id ? null : source.id)} />}</div>
              <span className="text-xs text-app-muted">{source.account ?? source.provider.toUpperCase()}</span>
              <span className="text-xs text-app-muted">{last ? formatDay(last.created_at, { dateStyle: 'short' }) : t('repositories.not_scanned')}</span>
              <Button variant="outline" size="sm" onClick={() => onScan?.(source.id)} className="w-fit border-app-line bg-app-soft">{t('repositories.scan')}</Button>
              {editingBranch === source.id && <ScanBranchEditor source={source} onClose={() => closeBranchEditor(source.id)} onSaved={() => reload()} />}
            </div>
          })}
          {data && !data.sources.length && !loading && <p className="p-6 text-center text-sm text-app-muted">{t('repositories.no_match')}</p>}
        </div>
        {data && <Pager page={page} perPage={PAGE_SIZE} total={data.total} onPage={setPage} loading={loading} />}
      </CardContent>
    </Card>
    <OrganizationScanDialog account={organization} onClose={() => setOrganization(null)} onStarted={() => void reloadBatches()} />
    {reportFor && <AuditReportDialog open onClose={() => setReportFor(null)} target={{ account: reportFor }} name={reportFor} selected={[]} filtered={[]} total={0} />}
  </div>
}

