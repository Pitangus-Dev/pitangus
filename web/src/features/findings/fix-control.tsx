import { useMutation } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { CircleNotchIcon } from '@phosphor-icons/react'
import { apiPost } from '@/shared/api/client'
import { formatDate } from '@/shared/lib/types'
import { formatNumber, formatPercent } from '@/shared/i18n/format'
import { Button } from '@/shared/ui/button'
import { useConfirm } from '@/shared/ui/confirm'
import { Notice } from '@/shared/ui/notice'
import type { components } from '@/shared/api/schema'
import type { LifecycleCounts } from '@/features/findings/finding-model'

export type FixControl = components['schemas']['FixControl']

// How the asset's findings get fixed, when it needs saying: fixes a scan held back for closing too much at once, and
// why (the next complete scan confirms them; an admin can apply them now), findings a change of configuration left
// unchecked (a rule or an engine off, a rule updated) and findings no scan could check for a while.
export function FixControlNotices({ assetKey, control, counts, admin, onChanged }: {
  assetKey: string; control?: FixControl | null; counts?: LifecycleCounts | null; admin: boolean; onChanged: () => void
}) {
  const { t } = useTranslation('findings')
  const confirm = useConfirm()
  const release = useMutation({
    mutationFn: () => apiPost('/api/assets/fix-hold', 'release-fix-hold', { asset: assetKey }),
    onSuccess: onChanged,
  })
  const held = control?.hold
  const why = held?.reason
  const stale = counts?.unverified_stale ?? 0
  const configuration = counts?.unverified_configuration ?? 0
  if (!held && !stale && !configuration) return null
  const apply = () => void confirm({ title: t('control.release_title', { count: held?.count ?? 0 }), description: t('control.release_confirm'),
    confirmLabel: t('control.release') }).then(ok => { if (ok) release.mutate() })
  return <div className="space-y-2">
    {held && <Notice role="status" tone="attention">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <p className="min-w-0 grow basis-64">{why
          ? t('control.held_reason', { count: held.count, number: formatNumber(held.count), date: formatDate(held.at), tripped: formatDate(why.at), fixed: formatNumber(why.count),
            open: formatNumber(why.open), minimum: formatNumber(why.minimum), percent: formatPercent(why.percent / 100) })
          : t('control.held', { count: held.count, number: formatNumber(held.count), date: formatDate(held.at) })}</p>
        {admin && <Button size="xs" variant="outline" disabled={release.isPending || release.isSuccess} onClick={apply}>
          {release.isPending && <CircleNotchIcon className="motion-safe:animate-spin" aria-hidden />}{t('control.release')}</Button>}
      </div>
    </Notice>}
    {release.error && <p role="alert" className="text-sm text-danger">{release.error.message}</p>}
    {configuration > 0 && <Notice role="status" tone="attention">{t('control.configuration', { count: configuration, number: formatNumber(configuration) })}</Notice>}
    {stale > 0 && <Notice role="status" tone="attention">{t('control.unverified', { count: stale, number: formatNumber(stale), scans: control?.unseen_warn_scans ?? 3 })}</Notice>}
  </div>
}
