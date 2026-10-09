import { useCallback } from 'react'
import { useMutation, useQueryClient, type UseQueryResult } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import type { SessionUser } from '@/features/auth/session'
import type { Asset } from '@/features/sources/asset-option'
import { Card, CardContent } from '@/shared/ui/card'
import { Skeleton } from '@/shared/ui/loading'
import { assetQuery, findingsScopeKey, type ScopedFindings } from '@/shared/api/queries'
import { scopeQuery, scopeReady, type Scope } from '@/shared/lib/scope'
import { FindingTabs } from '@/features/findings/finding-tabs'
import { ScopeResult } from '@/features/findings/scope-result'
import type { FindingTab } from '@/features/findings/finding-model'

class AssetGone extends Error {}

// Several assets at once (an organization, a chosen set, everything): their current state combined, without runs or
// settings, which belong to each asset (`onOpenAsset` goes to one).
export function ScopeFindings({ scope, tab, onTab, result, user, onOpenAsset }: {
  scope: Scope; tab: FindingTab; onTab: (tab: FindingTab) => void; result: UseQueryResult<ScopedFindings>; user: SessionUser; onOpenAsset: (asset: Asset) => void
}) {
  const { t } = useTranslation('findings')
  const queryClient = useQueryClient()
  const reload = useCallback(() => { void queryClient.invalidateQueries({ queryKey: findingsScopeKey }) }, [queryClient])
  const opening = useMutation({
    mutationFn: async (key: string) => {
      const found = await queryClient.fetchQuery(assetQuery<Asset>(key))
      if (!found) throw new AssetGone(key)
      return found
    },
    onSuccess: asset => { onOpenAsset(asset); window.scrollTo?.({ top: 0 }) },
  })
  const name = scope.kind === 'account' ? scope.account : scope.kind === 'assets' ? t('scope.chosen', { count: scope.assets.length }) : t('scope.everything')
  const data = result.data
  return <>
    <p className="text-xs text-app-subtle">{t('scope.one_asset_only')}</p>
    <FindingTabs tab={tab} counts={data?.summary.lifecycle} onChange={onTab} />
    {!scopeReady(scope) ? <p className="rounded-xl border border-dashed border-app-line px-4 py-6 text-center text-sm text-app-muted">{t('scope:incomplete')}</p>
      : result.isError ? <div role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{t('scope.failed', { error: result.error.message })}</div>
      : !data ? <Skeleton tiles={6} rows={5} />
      : data.by_asset.length === 0 ? <Card className="border-app-line bg-panel"><CardContent className="py-14 text-center text-sm text-app-muted">{t('scope:nothing')}</CardContent></Card>
      : <ScopeResult key={`${scopeQuery(scope)}:${tab}`} scope={data} name={name} tab={tab} canAccept={user.role === 'admin'} canManage={user.role === 'admin'} onChanged={reload}
          onOpenAsset={key => opening.mutate(key)} opening={{ pending: opening.isPending,
            error: !opening.error ? '' : opening.error instanceof AssetGone ? t('scope.open_gone') : t('scope.open_failed', { error: opening.error.message }) }} />}
  </>
}
