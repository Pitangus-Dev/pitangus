import { useCallback, useEffect, useState } from 'react'
import type { Asset } from '@/features/sources/asset-option'
import type { ComboOption } from '@/shared/ui/combobox'
import { api, query } from '@/shared/api/http'
import { readRoute, setRouteParam } from '@/shared/lib/route'
import { formatDate, type Page, type RunRow } from '@/shared/lib/types'
import i18n from '@/shared/i18n'
import type { RepositoryRun } from '@/features/findings/finding-model'

export type RunDetail = RepositoryRun & { type: string }
export const CURRENT = '__current__'
const RUN_STATUS: Record<string, string> = {
  completed: 'common:run_status.completed', incomplete: 'common:run_status.incomplete', failed: 'common:run_status.failed',
  queued: 'common:run_status.queued', running: 'common:run_status.running',
}

export type AssetSelection = ReturnType<typeof useAssetSelection>

// Which asset and which of its runs the page shows (the current state by default). On arrival: the requested run's
// asset (from the dashboard or Scans), the one in the address, or the most recently active one.
export function useAssetSelection(requestedRun: string | null) {
  const [asset, setAsset] = useState<Asset | null>(null)
  // The asset as the picker shows it: refreshed after each load (e.g. when a scan finishes) without triggering one.
  const [assetView, setAssetView] = useState<Asset | null>(null)
  const [run, setRun] = useState<string>(CURRENT)
  const [runLabel, setRunLabel] = useState<ComboOption | null>(null)
  const [empty, setEmpty] = useState(false)
  // A finding linked from outside (a Jira issue: #/findings?repo=…&finding=…), opened once its repository loads.
  const [focus, setFocus] = useState(() => ({ repo: readRoute().params.get('repo'), finding: readRoute().params.get('finding') }))
  useEffect(() => {
    (async () => {
      if (requestedRun) {
        const target = await api.get<RunDetail>(`/api/runs/${encodeURIComponent(requestedRun)}`).catch(() => null)
        if (target?.source) {
          // By identity, not by name: a renamed repository is still found.
          const found = (await api.get<Page<Asset>>(`/api/assets?${query({ key: target.source.uid || target.source.id, limit: 1 })}`)).items[0]
          if (found) { setAsset(found); setRun(requestedRun); setRunLabel(runOption(target)); return }
        }
      }
      const wanted = readRoute().params.get('repo')
      const first = (await api.get<Page<Asset>>(`/api/assets?${query({ key: wanted || undefined, limit: 1 })}`)).items[0]
        ?? (await api.get<Page<Asset>>('/api/assets?limit=1')).items[0]
      if (first) setAsset(first); else setEmpty(true)
    })().catch(() => setEmpty(true))
  }, [requestedRun])
  // Another asset, at its current state.
  const open = useCallback((next: Asset) => { setAsset(next); setRun(CURRENT); setRunLabel(null) }, [])
  const pick = (next: Asset) => {
    open(next)
    if (focus.finding) { setFocus({ repo: null, finding: null }); setRouteParam('finding', null) }
  }
  return { asset, assetView, setAssetView, run, setRun, runLabel, setRunLabel, empty, focus, open, pick }
}

export function runOption(row: RunRow | RunDetail): ComboOption {
  const pull = (row as RunDetail).pull_request ?? (row as RunRow & { pull_request?: { number: number; title: string } }).pull_request
  const kind = row.type === 'pr_review' ? (pull ? i18n.t('findings:page.kind_pr_number', { number: pull.number }) : i18n.t('findings:page.kind_pr'))
    : row.type === 'advisory_watch' ? i18n.t('findings:page.kind_advisory')
    : row.type === 'sarif_import' ? i18n.t('findings:page.kind_import', { tool: row.trigger?.tool ?? 'SARIF' }) : i18n.t('findings:page.kind_scan')
  const status = RUN_STATUS[row.status] ? i18n.t(RUN_STATUS[row.status]) : row.status
  return { id: row.id, label: `${kind} · ${formatDate(row.created_at)}`, hint: `${status} · ${i18n.t('common:count.findings', { count: row.summary?.candidates ?? 0 })}${pull?.title ? ` · ${pull.title}` : ''}` }
}
