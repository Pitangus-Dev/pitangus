import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { TriangleAlert } from 'lucide-react'
import type { SessionUser } from '@/features/auth/session'
import { RunProgress, type RunningRun } from '@/features/analyses/run-progress'
import { assetOption, type Asset } from '@/features/sources/asset-option'
import { Combobox, type ComboOption } from '@/shared/ui/combobox'
import { Skeleton } from '@/shared/ui/loading'
import { api, query } from '@/shared/api/http'
import { formatDate, type Page, type RunRow } from '@/shared/lib/types'
import { RepositoryResult } from '@/features/findings/repository-result'
import { RepositorySettings } from '@/features/findings/repository-settings'
import { FindingTabs } from '@/features/findings/finding-tabs'
import { CURRENT, runOption, type AssetSelection, type RunDetail } from '@/features/findings/asset-selection'
import type { FindingTab } from '@/features/findings/finding-model'

// The asset and run pickers.
export function AssetPickers({ selection }: { selection: AssetSelection }) {
  const { t } = useTranslation('findings')
  const { asset, assetView, run, runLabel, setRun, setRunLabel, pick } = selection
  const searchAssets = useCallback(async (text: string) => {
    const page = await api.get<Page<Asset>>(`/api/assets?${query({ q: text || undefined, limit: 50 })}`)
    return { options: page.items.map(assetOption), total: page.total, items: page.items }
  }, [])
  const searchRuns = useCallback(async (text: string) => {
    if (!asset) return { options: [], total: 0 }
    const page = await api.get<Page<RunRow>>(`/api/runs/page?${query({ asset: asset.key, type: 'repository_scan,image_scan,pr_review,sarif_import', q: text || undefined, limit: 50 })}`)
    const current: ComboOption = { id: CURRENT, label: t('page.current'), hint: t('page.current_hint') }
    return { options: [...(text ? [] : [current]), ...page.items.map(runOption)], total: page.total + (text ? 0 : 1) }
  }, [asset, t])
  return <div className="grid gap-3 md:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
    <div className="space-y-1"><span className="text-xs text-app-muted">{t('page.asset')}</span><Combobox label={t('page.asset')} placeholder={t('page.asset_placeholder')} value={asset ? assetOption(assetView?.key === asset.key ? assetView : asset) : null}
      search={searchAssets} onSelect={option => { void searchAssets(option.label).then(result => { const next = result.items.find(item => item.key === option.id); if (next) pick(next) }) }} /></div>
    <div className="space-y-1"><span className="text-xs text-app-muted">{t('page.run')}</span><Combobox label={t('page.run')} placeholder={t('page.current')} value={run === CURRENT ? { id: CURRENT, label: t('page.current'), hint: t('page.current_hint_short') } : runLabel}
      search={searchRuns} onSelect={option => { setRun(option.id); setRunLabel(option.id === CURRENT ? null : option) }} emptyText={t('page.no_runs')} /></div>
  </div>
}

// One asset's findings: its current state (the registry: scans and pull requests together, by tab) with its own
// settings, or one of its runs as it was.
export function AssetFindings({ selection, tab, onTab, user, onNew, onOpenPolicies }: {
  selection: AssetSelection; tab: FindingTab; onTab: (tab: FindingTab) => void; user: SessionUser; onNew: () => void; onOpenPolicies: () => void
}) {
  const { asset, run, setAssetView, setRunLabel, focus } = selection
  const { t } = useTranslation('findings')
  const [detail, setDetail] = useState<RunDetail | null>(null)
  // Loading means waiting for this selection's detail; it only stops when that load fails (the skeleton needs no detail).
  const [failed, setFailed] = useState<{ asset: Asset; run: string; tab: FindingTab } | null>(null)
  const loading = !!asset && !(failed?.asset === asset && failed.run === run && failed.tab === tab)
  const load = useCallback(() => {
    if (!asset) return Promise.resolve()
    const request = run === CURRENT
      ? api.get<RunDetail>(`/api/assets/state?${query({ key: asset.key, status: tab })}`)
      : api.get<RunDetail>(`/api/runs/${encodeURIComponent(run)}`)
    return request.then(async next => {
      setDetail(next)
      if (run !== CURRENT) setRunLabel(runOption(next))
      const fresh = (await api.get<Page<Asset>>(`/api/assets?${query({ key: asset.key, limit: 1 })}`).catch(() => null))?.items[0]
      setAssetView(fresh ?? asset)
    }, caught => { setFailed({ asset, run, tab }); throw caught })
  }, [asset, run, tab, setAssetView, setRunLabel])
  useEffect(() => { void load() }, [load])
  const reload = () => { setFailed(null); void load() }
  const admin = user.role === 'admin'
  return <>
    {asset?.removed_at && <div role="alert" className="flex items-start gap-2 rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger"><TriangleAlert className="mt-0.5 size-4 shrink-0" /><span>{t('page.removed', { date: formatDate(asset.removed_at) })}</span></div>}
    {/* This asset's own settings in one strip: the findings list is what matters. Global policies live in Policies. */}
    {run === CURRENT && asset && <RepositorySettings key={asset.key} assetKey={asset.key} name={asset.name} secrets={!asset.key.startsWith('image:')}
      canEdit={admin} onChanged={reload} onOpenPolicies={onOpenPolicies} />}
    {run === CURRENT && <FindingTabs tab={tab} counts={detail?.summary.lifecycle} onChange={onTab} />}
    {loading && !detail ? <Skeleton tiles={6} rows={5} />
      : detail && (detail.status === 'queued' || detail.status === 'running' || detail.status === 'failed')
        ? <RunProgress run={detail as unknown as RunningRun} onFinished={reload} />
        : detail ? <RepositoryResult key={`${run}:${tab}`} run={detail} onNew={onNew} canAccept={admin} canManage={admin} onChanged={reload} initialView={run === CURRENT && tab !== 'open' ? 'all' : 'active'} exportStatus={tab}
          focus={run === CURRENT && asset && focus.repo === asset.key ? focus.finding : null} /> : null}
  </>
}
