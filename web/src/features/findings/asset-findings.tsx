import { useCallback, useEffect, useRef } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { LoaderCircle, TriangleAlert } from 'lucide-react'
import type { SessionUser } from '@/features/auth/session'
import { RunProgress } from '@/features/analyses/run-progress'
import { assetOption, type Asset } from '@/features/sources/asset-option'
import { Button } from '@/shared/ui/button'
import { Combobox, type ComboOption } from '@/shared/ui/combobox'
import { Skeleton } from '@/shared/ui/loading'
import { assetRunsQuery, assetSearchQuery, assetStateQuery, invalidateFindings, keys, runQuery } from '@/shared/api/queries'
import { formatDate } from '@/shared/lib/types'
import { RepositoryResult } from '@/features/findings/repository-result'
import { RepositorySettings } from '@/features/findings/repository-settings'
import { FindingTabs } from '@/features/findings/finding-tabs'
import { CURRENT, runOption, type AssetSelection, type RunDetail } from '@/features/findings/asset-selection'
import type { FindingTab } from '@/features/findings/finding-model'

const active = (status?: string) => status === 'queued' || status === 'running'

// The asset and run pickers.
export function AssetPickers({ selection }: { selection: AssetSelection }) {
  const { t } = useTranslation('findings')
  const queryClient = useQueryClient()
  const { asset, run, runLabel, pickRun, pick } = selection
  // The same query as the findings below: the label follows the run's status and counts.
  const detail = useQuery({ ...runQuery<RunDetail>(run), enabled: run !== CURRENT }).data
  const searchAssets = useCallback(async (text: string) => {
    const page = await queryClient.fetchQuery(assetSearchQuery<Asset>(text))
    return { options: page.items.map(assetOption), total: page.total, items: page.items }
  }, [queryClient])
  const searchRuns = useCallback(async (text: string) => {
    if (!asset) return { options: [], total: 0 }
    const page = await queryClient.fetchQuery(assetRunsQuery(asset.key, text))
    const current: ComboOption = { id: CURRENT, label: t('page.current'), hint: t('page.current_hint') }
    return { options: [...(text ? [] : [current]), ...page.items.map(runOption)], total: page.total + (text ? 0 : 1) }
  }, [asset, queryClient, t])
  return <div className="grid gap-3 md:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
    <div className="space-y-1"><span className="text-xs text-app-muted">{t('page.asset')}</span><Combobox label={t('page.asset')} placeholder={t('page.asset_placeholder')} value={asset ? assetOption(asset) : null}
      search={searchAssets} onSelect={option => { void searchAssets(option.label).then(result => { const next = result.items.find(item => item.key === option.id); if (next) pick(next) }) }} /></div>
    <div className="space-y-1"><span className="text-xs text-app-muted">{t('page.run')}</span><Combobox label={t('page.run')} placeholder={run === CURRENT ? t('page.current') : run}
      value={run === CURRENT ? { id: CURRENT, label: t('page.current'), hint: t('page.current_hint_short') } : detail ? runOption(detail) : runLabel}
      search={searchRuns} onSelect={pickRun} emptyText={t('page.no_runs')} /></div>
  </div>
}

function Failed({ message, busy, onRetry }: { message: string; busy: boolean; onRetry: () => void }) {
  const { t } = useTranslation('findings')
  return <p role="alert" className="flex flex-wrap items-center gap-2 rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">
    {message}<Button size="xs" variant="outline" disabled={busy} onClick={onRetry}>{busy && <LoaderCircle className="motion-safe:animate-spin" />}{t('common:actions.retry')}</Button></p>
}

// One asset's findings: its current state (the registry: scans and pull requests together, by tab) with its own
// settings, or one of its runs as it was.
export function AssetFindings({ selection, tab, onTab, user, onNew, onOpenPolicies }: {
  selection: AssetSelection; tab: FindingTab; onTab: (tab: FindingTab) => void; user: SessionUser; onNew: () => void; onOpenPolicies: () => void
}) {
  const { asset, run, focus } = selection
  const { t } = useTranslation('findings')
  const queryClient = useQueryClient()
  const key = asset?.key ?? ''
  const state = useQuery({ ...assetStateQuery<RunDetail>(key, tab), enabled: !!asset && run === CURRENT,
    // Another tab of the same asset keeps the counts while it loads.
    placeholderData: (previous, previousQuery) => previousQuery?.queryKey[2] === key ? previous : undefined })
  const one = useQuery({ ...runQuery<RunDetail>(run), enabled: !!asset && run !== CURRENT })
  const result = run === CURRENT ? state : one
  const detail = result.data
  const reload = useCallback(() => {
    void invalidateFindings(queryClient)
    if (run !== CURRENT) void queryClient.invalidateQueries({ queryKey: keys.run(run) })
  }, [queryClient, run])
  // A run that finishes changes the asset's state and its counts.
  const status = one.data?.status
  const was = useRef(status)
  useEffect(() => {
    if (active(was.current) && !active(status)) void invalidateFindings(queryClient)
    was.current = status
  }, [status, queryClient])
  const admin = user.role === 'admin'
  const body = !asset ? selection.failed ? <Failed message={t('page.assets_failed', { error: selection.failed.message })} busy={selection.retrying} onRetry={selection.retry} />
      : selection.starting ? <Skeleton tiles={6} rows={5} /> : null
    : !detail || result.isPlaceholderData ? result.isError ? null : <Skeleton tiles={6} rows={5} />
    : active(detail.status) || detail.status === 'failed' ? <RunProgress run={detail} />
    : <RepositoryResult key={`${run}:${tab}`} run={detail} onNew={onNew} canAccept={admin} canManage={admin} onChanged={reload} initialView={run === CURRENT && tab !== 'open' ? 'all' : 'active'} exportStatus={tab}
        focus={run === CURRENT && focus.repo === asset.key ? focus.finding : null} />
  return <>
    {asset?.removed_at && <div role="alert" className="flex items-start gap-2 rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger"><TriangleAlert className="mt-0.5 size-4 shrink-0" /><span>{t('page.removed', { date: formatDate(asset.removed_at) })}</span></div>}
    {/* This asset's own settings in one strip: the findings list is what matters. Global policies live in Policies. */}
    {run === CURRENT && asset && <RepositorySettings key={asset.key} assetKey={asset.key} name={asset.name} secrets={!asset.key.startsWith('image:')}
      canEdit={admin} onOpenPolicies={onOpenPolicies} />}
    {run === CURRENT && asset && <FindingTabs tab={tab} counts={detail?.summary.lifecycle} onChange={onTab} />}
    {asset && result.isError && <Failed message={t('page.load_failed', { error: result.error.message })} busy={result.isFetching} onRetry={() => void result.refetch()} />}
    {body}
  </>
}
