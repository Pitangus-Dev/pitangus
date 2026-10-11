import type { TFunction } from 'i18next'
import { Trans, useTranslation } from 'react-i18next'
import { ArrowSquareOutIcon, CheckCircleIcon, WarningIcon } from '@phosphor-icons/react'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { formatDate } from '@/shared/i18n/format'
import { LifecycleSummary } from '@/features/findings/lifecycle-summary'
import { toolName, type RepositoryRun, type SignIn } from '@/features/findings/finding-model'
import { assetKindOf } from '@/shared/lib/asset-kind'

// What the findings below are: an asset's current state, a pull request review, an import from another tool or a scan.
export function RunHeader({ run, onNew }: { run: RepositoryRun; onNew: () => void }) {
  const { t } = useTranslation('findings')
  if (run.type === 'asset_state') {
    // A domain's or an image's state has no pull requests and no provider: it says what it is instead.
    const kind = assetKindOf(run.source?.id)
    const provider = kind === 'domain' ? t('state.provider.domain') : kind === 'image' ? t('state.provider.registry')
      : ({ github: 'GitHub', local: t('state.provider.local'), gitlab: 'GitLab' } as Record<string, string>)[run.source?.provider ?? ''] ?? t('state.provider.repository')
    return <div className="space-y-2 rounded-lg border border-app-line bg-panel p-5">
      <div className="text-xs text-app-muted">{t('state.eyebrow', { provider })}</div>
      <h2 className="truncate text-xl font-semibold">{run.source?.name ?? t('scan.repository')}</h2>
      {run.summary.lifecycle && <LifecycleSummary counts={run.summary.lifecycle} />}
      <p className="text-xs text-app-subtle">{kind === 'domain' ? t('state.help_domain') : kind === 'image' ? t('state.help_image') : t('state.help')}</p>
    </div>
  }
  if (run.type === 'pr_review' && run.pull_request) return <div className="space-y-3 rounded-lg border border-app-line bg-panel p-5">
    <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between"><div className="min-w-0"><div className="mb-1 text-xs text-app-muted">{t('pr.eyebrow', { name: run.source?.name ?? '' })}</div><a href={run.pull_request.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 text-xl font-semibold hover:underline">#{run.pull_request.number} {run.pull_request.title}<ArrowSquareOutIcon className="size-4 text-app-subtle" /></a><p className="mt-1 text-xs text-app-subtle">{run.pull_request.author} · {run.pull_request.head_ref} → {run.pull_request.base_ref} · commit <span className="font-mono">{run.pull_request.head_sha.slice(0, 7)}</span> · {t('pr.changed_files', { count: run.summary.changed_files ?? 0 })}</p></div>
      {run.review && <Badge variant="outline" className={run.review.verdict.state === 'failure' ? 'border-danger-line bg-danger-soft text-danger' : 'border-success-line text-success'}>{run.review.verdict.state === 'failure' ? t('pr.blocks') : t('pr.passes')} · {run.review.verdict.description}</Badge>}</div>
    <p className="text-sm text-app-muted">{run.summary.preexisting ? <Trans t={t} i18nKey="pr.scope_preexisting" count={run.summary.preexisting} components={{ strong: <strong /> }} /> : <Trans t={t} i18nKey="pr.scope" components={{ strong: <strong /> }} />}{run.review && !run.review.baseline_run ? ` ${t('pr.no_baseline')}` : ''}</p>
    {run.review?.delivery && <p className="text-xs text-app-subtle">{t('pr.delivery', { comment: run.review.delivery.comment ?? '—', status: run.review.delivery.status ?? '—' })}</p>}
  </div>
  if (run.type === 'sarif_import') return <ImportHeader run={run} onNew={onNew} />
  if (run.type === 'dast_scan') return <div className="flex flex-col gap-4 rounded-lg border border-app-line bg-panel p-5 sm:flex-row sm:items-center sm:justify-between"><div className="min-w-0">
    <div className="mb-1 text-xs text-app-muted">{t('web.eyebrow', { tools: webTools(t, run) })}</div>
    <h2 className="truncate text-xl font-semibold">{run.source?.name ?? run.target ?? '—'}</h2>
    <p className="mt-1 text-xs text-app-subtle">{formatDate(run.created_at)}{run.target ? <> · <span className="font-mono">{run.target}</span></> : null}</p>
    <p className="mt-2 text-sm text-app-muted">{t('web.help')}</p>
    {run.logins?.length ? <SignIns logins={run.logins} /> : null}
  </div><Button variant="outline" onClick={onNew} className="shrink-0">{t('scan.new')}</Button></div>
  return <div className="flex flex-col gap-4 rounded-lg border border-app-line bg-panel p-5 sm:flex-row sm:items-center sm:justify-between"><div className="min-w-0"><div className="mb-1 text-xs text-app-muted">{run.type === 'image_scan' ? t('scan.image') : t('scan.code')} · {({ github: 'GitHub', registry: t('scan.provider.registry'), local: t('scan.provider.local'), gitlab: 'GitLab' } as Record<string, string>)[run.source?.provider ?? 'local'] ?? run.source?.provider}</div><h2 className="truncate text-xl font-semibold">{run.source?.name ?? t('scan.repository')}</h2><p className="mt-1 text-xs text-app-subtle">{formatDate(run.created_at)} · {run.source?.image
        ? <><span className="font-mono">{run.source.image.reference}</span>{run.source.image.resolved_digest ? <> · {t('scan.digest')} <span className="font-mono">{run.source.image.resolved_digest.slice(7, 19)}</span></> : null}{run.source.image.os ? ` · ${run.source.image.os}` : ''} · {t('scan.user', { user: run.source.image.user ?? 'root' })}{run.summary.agreement ? ` · ${t('scan.agreement', { count: run.summary.agreement.both })}` : ''}</>
        : <>{run.source?.branch && <>{run.source.commit
          ? <Trans t={t} i18nKey="scan.branch_commit" values={{ branch: run.source.branch, commit: run.source.commit.slice(0, 7) }} components={{ code: <span className="font-mono" /> }} />
          : <Trans t={t} i18nKey="scan.branch" values={{ branch: run.source.branch }} components={{ code: <span className="font-mono" /> }} />} · </>}{t('scan.snapshot')} <span className="font-mono">{run.source?.sha256?.slice(0, 12) ?? '—'}</span> · {t('scan.files', { count: run.summary.files ?? 0 })} · {t('scan.dependencies', { count: run.summary.dependencies ?? 0 })}</>}</p>{run.context && <p className="mt-2 text-sm text-app-muted">{run.context}</p>}</div><Button variant="outline" onClick={onNew} className="shrink-0">{t('scan.new')}</Button></div>
}

// Whether each test user signed in, right where the results are read: a failed sign-in makes the coverage partial,
// so few or no findings behind that login prove nothing.
function SignIns({ logins }: { logins: SignIn[] }) {
  const { t } = useTranslation('findings')
  const failed = logins.some(login => login.status !== 'signed_in')
  return <div className="mt-3 space-y-1.5">
    <ul aria-label={t('web.sign_ins')} className="space-y-1 text-sm">{logins.map(login => <li key={login.name} className="flex items-start gap-2">
      {login.status === 'signed_in'
        ? <><CheckCircleIcon className="mt-0.5 size-4 shrink-0 text-success" aria-hidden /><span className="text-app-secondary">{t('web.signed_in', { name: login.name })}</span></>
        : <><WarningIcon className="mt-0.5 size-4 shrink-0 text-attention" aria-hidden /><span className="text-app-secondary">{t('web.sign_in_failed', { name: login.name, reason: login.reason ?? '' })}</span></>}
    </li>)}</ul>
    {failed && <p className="text-xs text-attention">{t('web.partial')}</p>}
  </div>
}

// Another tool's findings: which one, how far the import vouches for it, and against which code.
function ImportHeader({ run, onNew }: { run: RepositoryRun; onNew: () => void }) {
  const { t } = useTranslation('findings')
  const trigger = run.trigger ?? { kind: 'import' }
  const tool = trigger.tool || 'SARIF'
  const branch = trigger.branch ?? run.source?.branch
  const commit = trigger.commit ?? run.source?.commit
  const code = <span className="font-mono" />
  return <div className="flex flex-col gap-4 rounded-lg border border-app-line bg-panel p-5 sm:flex-row sm:items-center sm:justify-between"><div className="min-w-0">
    <div className="mb-1 text-xs text-app-muted">{t('import.eyebrow', { tool })}</div>
    <h2 className="truncate text-xl font-semibold">{run.source?.name ?? t('scan.repository')}</h2>
    <p className="mt-1 text-xs text-app-subtle">{formatDate(run.created_at)} · {trigger.scope === 'partial' ? t('import.partial') : t('import.full')}{branch || commit ? ' · ' : ''}{branch
      ? commit ? <Trans t={t} i18nKey="scan.branch_commit" values={{ branch, commit: commit.slice(0, 7) }} components={{ code }} /> : <Trans t={t} i18nKey="scan.branch" values={{ branch }} components={{ code }} />
      : commit ? <Trans t={t} i18nKey="import.commit" values={{ commit: commit.slice(0, 7) }} components={{ code }} /> : null}</p>
    <p className="mt-2 text-sm text-app-muted">{trigger.scope === 'partial' ? t('import.help_partial', { tool }) : t('import.help_full', { tool })}</p>
  </div><Button variant="outline" onClick={onNew} className="shrink-0">{t('import.new')}</Button></div>
}

// The tools a web scan ran, in its order: ZAP and each of the others whose step wasn't skipped ("ZAP + katana + nuclei").
function webTools(t: TFunction, run: RepositoryRun) {
  const others = (run.steps ?? []).filter(step => step.id.startsWith('dast-') && step.id !== 'dast-merge' && step.status !== 'skipped')
  return [toolName(t, 'zap'), ...others.map(step => toolName(t, step.id.slice('dast-'.length)))].join(' + ')
}
