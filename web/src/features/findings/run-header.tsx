import { Trans, useTranslation } from 'react-i18next'
import { ArrowRight, ExternalLink } from 'lucide-react'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { formatDate } from '@/shared/i18n/format'
import { LifecycleSummary } from '@/features/findings/lifecycle-summary'
import type { RepositoryRun } from '@/features/findings/finding-model'

// What the findings below are: an asset's current state, a pull request review, an import from another tool or a scan.
export function RunHeader({ run, onNew }: { run: RepositoryRun; onNew: () => void }) {
  const { t } = useTranslation('findings')
  if (run.type === 'asset_state') return <div className="space-y-2 rounded-2xl border border-app-line bg-panel p-5">
    <div className="text-xs font-semibold tracking-[0.18em] text-brand uppercase">{t('state.eyebrow', { provider: ({ github: 'GitHub', registry: t('state.provider.registry'), local: t('state.provider.local'), gitlab: 'GitLab' } as Record<string, string>)[run.source?.provider ?? ''] ?? t('state.provider.repository') })}</div>
    <h2 className="truncate text-xl font-semibold">{run.source?.name ?? t('scan.repository')}</h2>
    {run.summary.lifecycle && <LifecycleSummary counts={run.summary.lifecycle} />}
    <p className="text-xs text-app-subtle">{t('state.help')}</p>
  </div>
  if (run.type === 'pr_review' && run.pull_request) return <div className="space-y-3 rounded-2xl border border-app-line bg-panel p-5">
    <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between"><div className="min-w-0"><div className="mb-1 text-xs font-semibold tracking-[0.18em] text-brand uppercase">{t('pr.eyebrow', { name: run.source?.name ?? '' })}</div><a href={run.pull_request.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 text-xl font-semibold hover:underline">#{run.pull_request.number} {run.pull_request.title}<ExternalLink className="size-4 text-app-subtle" /></a><p className="mt-1 text-xs text-app-subtle">{run.pull_request.author} · {run.pull_request.head_ref} → {run.pull_request.base_ref} · commit <span className="font-mono">{run.pull_request.head_sha.slice(0, 7)}</span> · {t('pr.changed_files', { count: run.summary.changed_files ?? 0 })}</p></div>
      {run.review && <Badge variant="outline" className={run.review.verdict.state === 'failure' ? 'border-transparent bg-danger-solid text-on-solid' : 'border-success-line text-success'}>{run.review.verdict.state === 'failure' ? t('pr.blocks') : t('pr.passes')} · {run.review.verdict.description}</Badge>}</div>
    <p className="text-sm text-app-muted">{run.summary.preexisting ? <Trans t={t} i18nKey="pr.scope_preexisting" count={run.summary.preexisting} components={{ strong: <strong /> }} /> : <Trans t={t} i18nKey="pr.scope" components={{ strong: <strong /> }} />}{run.review && !run.review.baseline_run ? ` ${t('pr.no_baseline')}` : ''}</p>
    {run.review?.delivery && <p className="text-xs text-app-subtle">{t('pr.delivery', { comment: run.review.delivery.comment ?? '—', status: run.review.delivery.status ?? '—' })}</p>}
  </div>
  if (run.type === 'sarif_import') return <ImportHeader run={run} onNew={onNew} />
  return <div className="flex flex-col gap-4 rounded-2xl border border-app-line bg-panel p-5 sm:flex-row sm:items-center sm:justify-between"><div className="min-w-0"><div className="mb-1 text-xs font-semibold tracking-[0.18em] text-brand uppercase">{run.type === 'image_scan' ? t('scan.image') : t('scan.code')} · {({ github: 'GitHub', registry: t('scan.provider.registry'), local: t('scan.provider.local'), gitlab: 'GitLab' } as Record<string, string>)[run.source?.provider ?? 'local'] ?? run.source?.provider}</div><h2 className="truncate text-xl font-semibold">{run.source?.name ?? t('scan.repository')}</h2><p className="mt-1 text-xs text-app-subtle">{formatDate(run.created_at)} · {run.source?.image
        ? <><span className="font-mono">{run.source.image.reference}</span>{run.source.image.resolved_digest ? <> · {t('scan.digest')} <span className="font-mono">{run.source.image.resolved_digest.slice(7, 19)}</span></> : null}{run.source.image.os ? ` · ${run.source.image.os}` : ''} · {t('scan.user', { user: run.source.image.user ?? 'root' })}{run.summary.agreement ? ` · ${t('scan.agreement', { count: run.summary.agreement.both })}` : ''}</>
        : <>{run.source?.branch && <>{run.source.commit
          ? <Trans t={t} i18nKey="scan.branch_commit" values={{ branch: run.source.branch, commit: run.source.commit.slice(0, 7) }} components={{ code: <span className="font-mono" /> }} />
          : <Trans t={t} i18nKey="scan.branch" values={{ branch: run.source.branch }} components={{ code: <span className="font-mono" /> }} />} · </>}{t('scan.snapshot')} <span className="font-mono">{run.source?.sha256?.slice(0, 12) ?? '—'}</span> · {t('scan.files', { count: run.summary.files ?? 0 })} · {t('scan.dependencies', { count: run.summary.dependencies ?? 0 })}</>}</p>{run.context && <p className="mt-2 text-sm text-app-muted">{run.context}</p>}</div><Button variant="outline" onClick={onNew} className="shrink-0 border-app-line bg-app-soft">{t('scan.new')} <ArrowRight /></Button></div>
}

// Another tool's findings: which one, how far the import vouches for it, and against which code.
function ImportHeader({ run, onNew }: { run: RepositoryRun; onNew: () => void }) {
  const { t } = useTranslation('findings')
  const trigger = run.trigger ?? { kind: 'import' }
  const tool = trigger.tool || 'SARIF'
  const branch = trigger.branch ?? run.source?.branch
  const commit = trigger.commit ?? run.source?.commit
  const code = <span className="font-mono" />
  return <div className="flex flex-col gap-4 rounded-2xl border border-app-line bg-panel p-5 sm:flex-row sm:items-center sm:justify-between"><div className="min-w-0">
    <div className="mb-1 text-xs font-semibold tracking-[0.18em] text-brand uppercase">{t('import.eyebrow', { tool })}</div>
    <h2 className="truncate text-xl font-semibold">{run.source?.name ?? t('scan.repository')}</h2>
    <p className="mt-1 text-xs text-app-subtle">{formatDate(run.created_at)} · {trigger.scope === 'partial' ? t('import.partial') : t('import.full')}{branch || commit ? ' · ' : ''}{branch
      ? commit ? <Trans t={t} i18nKey="scan.branch_commit" values={{ branch, commit: commit.slice(0, 7) }} components={{ code }} /> : <Trans t={t} i18nKey="scan.branch" values={{ branch }} components={{ code }} />
      : commit ? <Trans t={t} i18nKey="import.commit" values={{ commit: commit.slice(0, 7) }} components={{ code }} /> : null}</p>
    <p className="mt-2 text-sm text-app-muted">{trigger.scope === 'partial' ? t('import.help_partial', { tool }) : t('import.help_full', { tool })}</p>
  </div><Button variant="outline" onClick={onNew} className="shrink-0 border-app-line bg-app-soft">{t('import.new')} <ArrowRight /></Button></div>
}
