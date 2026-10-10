import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { CircleDashed, Clock3, TriangleAlert } from 'lucide-react'
import { AssetPicker } from '@/features/sources/asset-picker'
import type { Asset } from '@/features/sources/asset-option'
import { StepList } from '@/features/findings/step-list'
import { Skeleton } from '@/shared/ui/loading'
import { api } from '@/shared/api/http'
import { Badge } from '@/shared/ui/badge'
import { assetKindOf, type AssetKind } from '@/shared/lib/asset-kind'
import { formatDate, type OwaspCoverage, type RunRow, type ScanStep } from '@/shared/lib/types'

// What a scan of each kind leaves out, said for that kind: a code scan, an image scan or a passive web scan.
const GAP = {
  repository_scan: ['not_covered.title_code', 'not_covered.note_code'],
  image_scan: ['not_covered.title_image', 'not_covered.note_image'],
  dast_scan: ['not_covered.title_web', 'not_covered.note_web'],
} as const
const NO_SCAN: Record<AssetKind, 'no_full_scan.repository' | 'no_full_scan.image' | 'no_full_scan.domain'> = {
  repository: 'no_full_scan.repository', image: 'no_full_scan.image', domain: 'no_full_scan.domain',
}

// The selected run's coverage: what each engine did and which OWASP categories it touched, with numbers.
export function Coverage({ run, coverage, steps }: { run: RunRow | null; coverage: OwaspCoverage[]; steps: ScanStep[] }) {
  const { t } = useTranslation('coverage')
  const partial = coverage.filter(item => item.status === 'partial').length
  const notTested = coverage.filter(item => item.status === 'not_tested')
  const gap = run && run.type in GAP ? GAP[run.type as keyof typeof GAP] : GAP.repository_scan
  return <div className="grid gap-8 xl:grid-cols-[1.15fr_1fr]">
    <section aria-labelledby="coverage-owasp" className="min-w-0 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3"><h2 id="coverage-owasp" className="text-base font-medium">OWASP Top 10:2025</h2>
        <Badge variant="outline" className={partial >= 7 ? 'border-success-line text-success' : 'border-attention-line text-attention'}>{t('tested', { tested: partial, total: 10 })}</Badge></div>
      <p className="text-sm text-app-muted">{t('description')}</p>
      <ul className="divide-y divide-app-line rounded-xl border border-app-line bg-panel px-4">{coverage.map(item => <li key={item.id} className="flex items-start gap-3 py-3">
        <span className={`mt-0.5 font-mono text-xs text-app-muted`}>{item.id}</span>
        <div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2 text-sm">{item.title}{item.status === 'partial' && item.findings ? <Badge variant="outline" className="text-[11px]">{t('common:count.findings', { count: item.findings })}</Badge> : null}{item.rules ? <span className="text-[11px] text-app-subtle">{t('rules', { count: item.rules })}</span> : null}</div>
          <div className="text-xs leading-5 text-app-subtle">{item.reason}</div></div>
        {item.status === 'partial' ? <CircleDashed aria-hidden className="size-4 shrink-0 text-attention" /> : item.status === 'inconclusive' ? <TriangleAlert aria-hidden className="size-4 shrink-0 text-attention" /> : <Clock3 aria-hidden className="size-4 shrink-0 text-app-subtle" />}
      </li>)}</ul>
    </section>
    <div className="min-w-0 space-y-8">
      <section aria-labelledby="coverage-run" className="space-y-2">
        <h2 id="coverage-run" className="text-base font-medium">{t('run.title')}</h2>
        <p className="text-sm text-app-muted">{run ? `${run.source?.name ?? run.target} · ${formatDate(run.created_at)}` : t('run.none')}</p>
        {steps.length ? <StepList steps={steps} className="border-y border-app-line" /> : <p className="text-sm text-app-muted">{t('run.pick')}</p>}
      </section>
      {notTested.length > 0 && <section aria-labelledby="coverage-gaps" className="space-y-2">
        <h2 id="coverage-gaps" className="text-base font-medium">{t(gap[0])}</h2>
        <ul className="space-y-2 text-sm text-app-muted">{notTested.map(item => <li key={item.id}><span className="font-mono text-xs text-app-subtle">{item.id}</span> {item.reason}</li>)}</ul>
        <p className="text-xs leading-5 text-app-subtle">{t(gap[1])}</p>
      </section>}
    </div>
  </div>
}

const OWASP_TOP10 = [['A01', 'Broken Access Control'], ['A02', 'Security Misconfiguration'], ['A03', 'Software Supply Chain Failures'],
  ['A04', 'Cryptographic Failures'], ['A05', 'Injection'], ['A06', 'Insecure Design'], ['A07', 'Authentication Failures'],
  ['A08', 'Software or Data Integrity Failures'], ['A09', 'Security Logging & Alerting Failures'], ['A10', 'Mishandling of Exceptional Conditions']] as const

// Coverage per asset, measured on its latest full scan (code, image or web), not on the latest run of any kind.
export function CoverageView() {
  const { t } = useTranslation('coverage')
  const [asset, setAsset] = useState<Asset | null>(null)
  // The last answer, tagged with the run it belongs to: another run is loading until its own answer arrives.
  const [result, setResult] = useState<{ runId: string; detail: (RunRow & { owasp_coverage?: OwaspCoverage[]; steps?: ScanStep[] }) | null } | null>(null)
  // Nothing to measure until the picker has resolved the asset: no provisional "no scan".
  const [resolved, setResolved] = useState(false)
  const runId = asset?.latest_scan?.run_id
  const detail = runId && result?.runId === runId ? result.detail : null
  const loading = !!runId && result?.runId !== runId
  useEffect(() => {
    if (!runId) return
    let current = true
    api.get<RunRow & { owasp_coverage?: OwaspCoverage[]; steps?: ScanStep[] }>(`/api/runs/${encodeURIComponent(runId)}`)
      .catch(() => null).then(next => { if (current) setResult({ runId, detail: next }) })
    return () => { current = false }
  }, [runId])
  // A run that didn't measure coverage (an older one) isn't the same as no scan at all.
  const missing = detail ? t('not_measured') : t(NO_SCAN[assetKindOf(asset?.key)])
  const coverage = OWASP_TOP10.map(([id, title]) => detail?.owasp_coverage?.find(item => item.id === id) ?? { id, title, status: 'not_tested' as const, reason: missing })
  return <div className="space-y-6">
    <div className="max-w-xl space-y-1"><span className="text-xs text-app-muted">{t('asset')}</span><AssetPicker label={t('asset')} value={asset} onChange={value => { setAsset(value); setResolved(true) }} /></div>
    {!resolved ? <Skeleton rows={6} label={t('loading')} />
      : !asset ? <p className="py-10 text-center text-sm text-app-muted">{t('empty.no_assets')}</p>
      : !runId ? <p className="py-10 text-center text-sm text-app-muted">{t('empty.no_full_scan')}</p>
      : loading ? <Skeleton rows={6} label={t('loading')} />
      : <Coverage run={detail} coverage={coverage} steps={detail?.steps ?? []} />}
  </div>
}
