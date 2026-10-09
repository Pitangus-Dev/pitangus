import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { FileCheck2 } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { formatNumber } from '@/shared/i18n/format'
import { SCOPE_MAX } from '@/shared/lib/scope'
import type { ScopedFindings } from '@/shared/api/queries'
import { FindingsTable } from '@/features/findings/findings-table'
import { LifecycleSummary } from '@/features/findings/lifecycle-summary'
import type { FindingTab, RepositoryFinding, ScopeAsset } from '@/features/findings/finding-model'

const ASSETS_SHOWN = 12

// The findings of several assets at once (an organization, a chosen set, everything): their current states combined,
// each finding naming its asset. `name`: what the scope is called; `onOpenAsset`: from an asset to its own view, with
// how that is going (`opening`).
export function ScopeResult({ scope, name, tab, canAccept, canManage = canAccept, onChanged, onOpenAsset, opening }: {
  scope: ScopedFindings; name: string; tab: FindingTab; canAccept: boolean; canManage?: boolean; onChanged: () => void; onOpenAsset: (key: string) => void
  opening: { pending: boolean; error: string }
}) {
  const { t } = useTranslation('findings')
  const keys = scope.by_asset.map(asset => asset.key)
  // The API documents the fields of a finding readers rely on; the table reads them in the panel's fuller shape.
  const findings = scope.findings as RepositoryFinding[]
  return <div className="space-y-6">
    <FindingsTable findings={findings} kpis={scope.summary.kpis} header={<ScopeHeader scope={scope} name={name} />}
      aside={<>
        {scope.truncated && <p role="status" className="rounded-xl border border-warning-line bg-warning-soft px-4 py-3 text-sm text-warning">{t('scope.truncated', { shown: formatNumber(findings.length), total: formatNumber(scope.total) })}</p>}
        {scope.by_asset.length > 0 && <ScopeByAsset assets={scope.by_asset} onOpen={onOpenAsset} opening={opening} />}
      </>}
      column={{ label: t('scope.asset'), text: finding => finding.asset?.name ?? '',
        cell: finding => <span className="min-w-0 truncate text-xs text-app-secondary"><span className="md:hidden">{t('scope.asset_inline', { name: finding.asset?.name ?? '' })}</span><span className="hidden md:inline">{finding.asset?.name}</span></span> }}
      exports={openAudit => <ScopeExports assets={keys.length} onAudit={openAudit} />}
      audit={{ name, target: { assets: keys, status: tab === 'open' ? 'open' : 'all' }, fromSelection: false }}
      jira={{ selection: { byAsset: true }, asset: null }}
      runId={scope.id} canAccept={canAccept} canManage={canManage} initialView={tab !== 'open' ? 'all' : 'active'} onChanged={onChanged} />
  </div>
}

function ScopeHeader({ scope, name }: { scope: ScopedFindings; name: string }) {
  const { t } = useTranslation('findings')
  return <div className="space-y-2 rounded-2xl border border-app-line bg-panel p-5">
    <div className="text-xs font-semibold tracking-[0.18em] text-brand uppercase">{t('scope.eyebrow', { count: scope.by_asset.length, value: formatNumber(scope.by_asset.length) })}</div>
    <h2 className="truncate text-xl font-semibold">{name}</h2>
    <LifecycleSummary counts={scope.summary.lifecycle} />
    <p className="text-xs text-app-subtle">{t('scope.help')}</p>
  </div>
}

// Each asset with its pending work, the most critical first; one opens that asset with its runs and settings.
function ScopeByAsset({ assets, onOpen, opening }: { assets: ScopeAsset[]; onOpen: (key: string) => void; opening: { pending: boolean; error: string } }) {
  const { t } = useTranslation('findings')
  const [all, setAll] = useState(false)
  return <section aria-labelledby="scope-by-asset" className="space-y-3 rounded-2xl border border-app-line bg-panel p-5">
    <div><h3 id="scope-by-asset" className="text-sm font-semibold">{t('scope.by_asset.title')}</h3><p className="text-xs text-app-subtle">{t('scope.by_asset.hint')}</p></div>
    <ul aria-busy={opening.pending || undefined} className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">{(all ? assets : assets.slice(0, ASSETS_SHOWN)).map(asset => <li key={asset.key} className="min-w-0">
      <button type="button" disabled={opening.pending} onClick={() => onOpen(asset.key)} className="flex min-h-11 w-full items-center justify-between gap-3 rounded-xl border border-app-line bg-inset px-3 py-2 text-left motion-safe:transition hover:bg-app-soft disabled:opacity-60">
        <span className="min-w-0"><span className="block truncate text-sm font-medium">{asset.name}</span><span className="block text-xs text-app-subtle">{asset.kind === 'image' ? t('scope.by_asset.image') : t('scope.by_asset.repository')}<span className="sr-only"> · {t('scope.by_asset.open')}</span></span></span>
        <span className="shrink-0 text-right text-xs"><span className="block text-app-secondary tabular-nums">{t('scope.by_asset.pending', { count: asset.open, value: formatNumber(asset.open) })}</span>{asset.critical > 0 && <span className="block text-danger tabular-nums">{t('scope.by_asset.critical', { count: asset.critical, value: formatNumber(asset.critical) })}</span>}</span>
      </button></li>)}</ul>
    {opening.error && <p role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{opening.error}</p>}
    {assets.length > ASSETS_SHOWN && <Button type="button" variant="ghost" size="sm" aria-expanded={all} onClick={() => setAll(!all)}>{all ? t('scope.by_asset.fewer') : t('scope.by_asset.all', { count: assets.length, value: formatNumber(assets.length) })}</Button>}
  </section>
}

// Only the consolidated audit evidence: the files of one asset (PDF, SARIF, SBOM…) come from that asset.
function ScopeExports({ assets, onAudit }: { assets: number; onAudit: () => void }) {
  const { t } = useTranslation('findings')
  return <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
    <Button variant="outline" size="sm" disabled={assets === 0 || assets > SCOPE_MAX} aria-describedby="scope-exports" className="border-app-line bg-app-soft" onClick={onAudit}><FileCheck2 />{t('export.audit')}</Button>
    <p id="scope-exports" className="text-xs text-app-subtle">{assets > SCOPE_MAX ? t('scope.audit_too_many', { max: formatNumber(SCOPE_MAX) }) : t('scope.exports_one')}</p>
  </div>
}
