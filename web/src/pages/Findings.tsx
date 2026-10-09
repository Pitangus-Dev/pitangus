import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import type { SessionUser } from '@/features/auth/session'
import { AssetFindings, AssetPickers } from '@/features/findings/asset-findings'
import { CURRENT, useAssetSelection } from '@/features/findings/asset-selection'
import { ScopeFindings } from '@/features/findings/scope-findings'
import { useScopeFindings } from '@/features/findings/scope-query'
import type { FindingTab } from '@/features/findings/finding-model'
import { ScopePicker } from '@/features/scope/scope-picker'
import { Card, CardContent } from '@/shared/ui/card'
import { Bone } from '@/shared/ui/loading'
import { evidenceQuery } from '@/shared/api/queries'
import { readRoute, setRouteParam } from '@/shared/lib/route'
import { ALL, scopeFromParams, scopeParams, withNames, type Scope } from '@/shared/lib/scope'

// Findings of one asset (its current state, or one of its runs) or of several at once (an organization, a chosen set,
// everything). The scope travels in the address, so a reload or a shared link lands on the same view.
export function Findings({ user, requestedRun, onNew, onOpenPolicies }: { user: SessionUser; requestedRun: string | null; onNew: () => void; onOpenPolicies: () => void }) {
  const { t } = useTranslation('findings')
  const [scope, setScope] = useState<Scope>(() => scopeFromParams(readRoute().params) ?? { ...ALL, kind: 'one' })
  const multi = scope.kind !== 'one'
  const [tab, setTab] = useState<FindingTab>('open')
  const selection = useAssetSelection(requestedRun)
  const { asset, run } = selection
  const overview = useQuery(evidenceQuery())
  const scoped = useScopeFindings(scope, tab)
  useEffect(() => { if (multi) setRouteParam('repo', null); else if (asset) setRouteParam('repo', asset.key) }, [asset, multi])
  useEffect(() => { setRouteParam('run', run === CURRENT || multi ? null : run) }, [run, multi])
  useEffect(() => { for (const [name, value] of Object.entries(scopeParams(scope))) setRouteParam(name, value) }, [scope])

  if (selection.empty) return <Card className="border-app-line bg-panel"><CardContent className="py-14 text-center text-sm text-app-muted">{t('page.empty')}</CardContent></Card>
  const pickers = <AssetPickers selection={selection} />
  return <div className="space-y-5">
    {/* The picker needs the organizations and the asset count: no "nothing yet" while they load. */}
    {overview.data ? <ScopePicker scope={withNames(scope, scoped.data?.by_asset)} accounts={overview.data.accounts} total={overview.data.assets} one={pickers} onChange={setScope} />
      : overview.isError ? <div className="space-y-3"><p role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{t('scope.picker_failed')}</p>{!multi && pickers}</div>
      : <div className="space-y-3"><Bone className="h-4 w-24" /><Bone className="h-11 w-full max-w-md rounded-xl" />{!multi && pickers}</div>}
    {multi
      ? <ScopeFindings scope={scope} tab={tab} onTab={setTab} result={scoped} user={user} onOpenAsset={next => { selection.open(next); setScope(current => ({ ...current, kind: 'one' })) }} />
      : <AssetFindings selection={selection} tab={tab} onTab={setTab} user={user} onNew={onNew} onOpenPolicies={onOpenPolicies} />}
  </div>
}
