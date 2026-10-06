import i18n from '@/shared/i18n'
import type { ComboOption } from '@/shared/ui/combobox'

export type Asset = { key: string; name: string; provider: string; scans: number; pr_reviews: number; last_activity: string; removed_at: string | null
  latest_scan: { run_id: string; created_at: string } | null; open: { total: number; critical: number; high: number; medium: number; low: number; from_pr?: number; fixed?: number; suppressed?: number } | null }

export const assetOption = (asset: Asset): ComboOption => {
  const open = asset.open
  const status = open
    ? [i18n.t('sources:asset.open', { count: open.total }), ...(open.critical ? [i18n.t('sources:asset.critical', { count: open.critical })] : [])]
    : [i18n.t('sources:asset.no_findings')]
  return {
    id: asset.key, label: asset.name,
    hint: [...status, i18n.t('sources:asset.scans', { count: asset.scans }), i18n.t('sources:asset.pr_reviews', { count: asset.pr_reviews })].join(' · '),
    badge: asset.removed_at ? <span className="shrink-0 rounded border border-danger-line px-1.5 text-[11px] text-danger">{i18n.t('sources:asset.removed')}</span> : undefined,
  }
}
