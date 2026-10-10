import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { FileUp, ShieldCheck } from 'lucide-react'
import type { SessionUser } from '@/features/auth/session'
import { AssetFindings } from '@/features/findings/asset-findings'
import { CURRENT, type AssetSelection } from '@/features/findings/asset-selection'
import type { FindingTab } from '@/features/findings/finding-model'
import type { Asset } from '@/features/sources/asset-option'
import { assetQuery } from '@/shared/api/queries'
import { Button } from '@/shared/ui/button'
import { Skeleton } from '@/shared/ui/loading'
import type { Domain } from '@/features/domains/domains'

const SEVERITIES = [
  ['critical', 'common:severity.critical', 'bg-danger-solid text-on-solid'], ['high', 'common:severity.high', 'bg-danger-soft text-danger'],
  ['medium', 'common:severity.medium', 'bg-attention-soft text-attention'], ['low', 'common:severity.low', 'bg-info-soft text-info'],
] as const
const NOTHING = () => {}

// A domain's findings: its open counts by severity, then the same findings view as everywhere else, fixed to its asset.
export function DomainFindings({ domain, user, onNewScan, onImport, onOpenPolicies }: { domain: Domain; user: SessionUser; onNewScan: () => void; onImport: () => void; onOpenPolicies: () => void }) {
  const { t } = useTranslation('sources')
  const [tab, setTab] = useState<FindingTab>('open')
  const asset = useQuery(assetQuery<Asset>(domain.key))
  if (asset.isPending) return <Skeleton tiles={4} rows={4} />
  if (asset.isError) return <div role="alert" className="flex flex-wrap items-center gap-3 rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{asset.error.message}
    <Button size="xs" variant="outline" onClick={() => void asset.refetch()}>{t('common:actions.retry')}</Button></div>
  if (!asset.data) return <div className="flex flex-col items-center gap-3 py-14 text-center">
    <ShieldCheck className="size-7 text-app-muted" aria-hidden />
    <p className="max-w-md text-sm text-app-muted">{t('domains.page.findings_empty')}</p>
    <div className="flex flex-wrap justify-center gap-2">
      {user.role === 'admin' && domain.kind !== 'surface' && <Button onClick={onNewScan}>{t('domains.page.start_scan')}</Button>}
      <Button variant="outline" onClick={onImport}><FileUp aria-hidden />{t('domains.page.import_results')}</Button>
    </div>
  </div>
  const open = asset.data.open
  const selection: AssetSelection = {
    asset: asset.data, run: CURRENT, runLabel: null, focus: { repo: null, finding: null }, open: NOTHING, pick: NOTHING, pickRun: NOTHING,
    empty: false, starting: false, failed: null, retrying: false, retry: () => undefined,
  }
  return <div className="space-y-4">
    {open && <ul aria-label={t('domains.page.open_by_severity')} className="flex flex-wrap gap-2">{SEVERITIES.map(([level, label, tone]) =>
      <li key={level} className={`rounded-lg px-2.5 py-1 text-sm ${tone}`}>{t(label)} <span className="tabular-nums">{open[level]}</span></li>)}</ul>}
    <AssetFindings selection={selection} tab={tab} onTab={setTab} user={user} onNew={onNewScan} onOpenPolicies={onOpenPolicies} />
  </div>
}
