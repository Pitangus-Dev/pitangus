import { useCallback, useState } from 'react'
import { useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query'
import type { Asset } from '@/features/sources/asset-option'
import type { ComboOption } from '@/shared/ui/combobox'
import { api } from '@/shared/api/http'
import { assetQuery, runQuery } from '@/shared/api/queries'
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

type Shown = { asset: Asset; run: string; label: ComboOption | null }
export type AssetSelection = ReturnType<typeof useAssetSelection>

// On arrival: the requested run's asset (from the dashboard or Scans), the one in the address, or the most recently
// active one. Through the query cache, so the views below reuse what was fetched here.
async function arrival(client: QueryClient, requestedRun: string | null, wanted: string | null): Promise<Shown | null> {
  if (requestedRun) {
    const target = await client.fetchQuery(runQuery<RunDetail>(requestedRun)).catch(() => null)
    // By identity, not by name: a renamed repository is still found.
    const key = target?.source?.uid || target?.source?.id
    const found = key ? await client.fetchQuery(assetQuery<Asset>(key)) : null
    if (found) return { asset: found, run: requestedRun, label: null }
  }
  const first = (wanted ? await client.fetchQuery(assetQuery<Asset>(wanted)) : null)
    ?? (await api.get<Page<Asset>>('/api/assets?limit=1')).items[0]
  return first ? { asset: first, run: CURRENT, label: null } : null
}

// Which asset and which of its runs the page shows (the current state by default).
export function useAssetSelection(requestedRun: string | null) {
  const client = useQueryClient()
  const [wanted] = useState(() => readRoute().params.get('repo'))
  const [chosen, setChosen] = useState<Shown | null>(null)
  // Resolved once per visit (the page remounts for another requested run); a choice makes it irrelevant.
  const start = useQuery({ queryKey: ['findings-arrival', requestedRun, wanted], queryFn: () => arrival(client, requestedRun, wanted),
    staleTime: Infinity, gcTime: 0, enabled: !chosen })
  const shown = chosen ?? start.data ?? null
  const run = shown?.run ?? CURRENT
  // The asset as the picker and the alert show it: refreshed when its findings change (see invalidateFindings).
  const fresh = useQuery({ ...assetQuery<Asset>(shown?.asset.key ?? ''), enabled: !!shown, initialData: shown?.asset }).data
  const asset = shown ? fresh ?? shown.asset : null
  // A finding linked from outside (a Jira issue: #/findings?repo=…&finding=…), opened once its repository loads.
  const [focus, setFocus] = useState(() => ({ repo: readRoute().params.get('repo'), finding: readRoute().params.get('finding') }))
  // Another asset, at its current state.
  const open = useCallback((next: Asset) => setChosen({ asset: next, run: CURRENT, label: null }), [])
  const pick = (next: Asset) => {
    open(next)
    if (focus.finding) { setFocus({ repo: null, finding: null }); setRouteParam('finding', null) }
  }
  const pickRun = (option: ComboOption) => { if (shown) setChosen({ asset: shown.asset, run: option.id, label: option.id === CURRENT ? null : option }) }
  return {
    asset, run, runLabel: shown?.label ?? null, focus, open, pick, pickRun,
    empty: !shown && start.data === null,
    starting: !shown && start.isPending, failed: shown ? null : start.error, retrying: start.isFetching, retry: () => void start.refetch(),
  }
}

export function runOption(row: RunRow | RunDetail): ComboOption {
  const pull = (row as RunDetail).pull_request ?? (row as RunRow & { pull_request?: { number: number; title: string } }).pull_request
  const kind = row.type === 'pr_review' ? (pull ? i18n.t('findings:page.kind_pr_number', { number: pull.number }) : i18n.t('findings:page.kind_pr'))
    : row.type === 'advisory_watch' ? i18n.t('findings:page.kind_advisory')
    : row.type === 'sarif_import' ? i18n.t('findings:page.kind_import', { tool: row.trigger?.tool ?? 'SARIF' }) : i18n.t('findings:page.kind_scan')
  const status = RUN_STATUS[row.status] ? i18n.t(RUN_STATUS[row.status]) : row.status
  return { id: row.id, label: `${kind} · ${formatDate(row.created_at)}`, hint: `${status} · ${i18n.t('common:count.findings', { count: row.summary?.candidates ?? 0 })}${pull?.title ? ` · ${pull.title}` : ''}` }
}
