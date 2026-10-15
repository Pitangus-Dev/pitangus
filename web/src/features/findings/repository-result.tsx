import { useTranslation } from 'react-i18next'
import { CaretRightIcon } from '@phosphor-icons/react'
import { formatTime } from '@/shared/i18n/format'
import { FindingsTable } from '@/features/findings/findings-table'
import { RunHeader } from '@/features/findings/run-header'
import { RunExports } from '@/features/findings/run-exports'
import { StepList } from '@/features/findings/step-list'
import type { FindingTab, RepositoryRun } from '@/features/findings/finding-model'

// The findings of one run or of one asset's current state (`asset_state`), with that asset's files, the run's log and
// what each engine covered. `focus`: a finding to open (links from Jira issues carry its fingerprint).
// `tab`: the state's tab shown (none for a run).
export function RepositoryResult({ run, onNew, onChanged, canAccept, canManage = canAccept, tab, focus = null }: {
  run: RepositoryRun; onNew: () => void; onChanged: () => void; canAccept: boolean; canManage?: boolean; tab?: FindingTab; focus?: string | null
}) {
  const { t } = useTranslation('findings')
  const source = run.source
  const state = run.type === 'asset_state'
  const exportStatus = tab ?? 'open'
  // Its Jira issues go where the server routes the asset (by its key and name).
  return <div className="space-y-6">
    <FindingsTable findings={run.findings ?? []} kpis={run.summary.kpis} header={<RunHeader run={run} onNew={onNew} />}
      exports={openAudit => <RunExports run={run} status={exportStatus} onAudit={openAudit} />}
      audit={{ name: source?.name ?? t('export.file_fallback'), fromSelection: true,
        target: state ? { asset: source?.id ?? '', status: exportStatus === 'fixed' || exportStatus === 'all' ? exportStatus : 'open' } : { runId: run.id } }}
      jira={{ selection: state && source?.id ? { asset: source.id } : { runId: run.id }, asset: source ? { key: source.uid || source.id || source.name, name: source.name } : null }}
      runId={run.id} assetKey={source?.id} canAccept={canAccept} canManage={canManage} tab={state ? exportStatus : undefined} focus={focus} onChanged={onChanged} />
    {run.progress?.length ? <RunLog run={run} progress={run.progress} /> : null}
    <RunCoverage run={run} />
  </div>
}

function RunLog({ run, progress }: { run: RepositoryRun; progress: NonNullable<RepositoryRun['progress']> }) {
  const { t } = useTranslation('findings')
  return <details className="group rounded-lg border border-app-line bg-panel"><summary className="flex cursor-pointer list-none items-center gap-2 px-5 py-4 text-sm font-medium"><CaretRightIcon className="size-4 text-app-subtle motion-safe:transition group-open:rotate-90" />{t('log.title')}<span className="ml-2 text-xs font-normal text-app-subtle">{t('log.events', { count: progress.length })}{run.started_at && run.finished_at ? ` · ${t('log.seconds', { seconds: Math.round((Date.parse(run.finished_at) - Date.parse(run.started_at)) / 1000) })}` : ''}</span></summary><div className="space-y-1 px-5 pb-5 font-mono text-xs leading-6">{progress.map((event, index) => <div key={index} className="flex gap-3"><span className="shrink-0 text-app-subtle">{formatTime(event.at)}</span><span className={event.level === 'ok' ? 'text-brand' : event.level === 'warn' ? 'text-attention' : event.level === 'error' ? 'text-danger' : 'text-app-secondary'}>{event.message}</span></div>)}</div></details>
}

// Hidden when there are no steps: an asset's current state joins several runs and has none of its own.
function RunCoverage({ run }: { run: RepositoryRun }) {
  const { t } = useTranslation('findings')
  if (!run.steps?.length) return null
  return <details className="group rounded-lg border border-app-line bg-panel"><summary className="flex cursor-pointer list-none items-center gap-2 px-5 py-4 text-sm font-medium"><CaretRightIcon className="size-4 text-app-subtle motion-safe:transition group-open:rotate-90" />{t('coverage.title')}<span className="ml-2 text-xs font-normal text-app-subtle">{t('coverage.steps', { done: run.steps.filter(step => step.status === 'completed' || step.status === 'partial').length, total: run.steps.length })}</span></summary>
    <StepList steps={run.steps} className="mx-5 mb-3 border-t border-app-line" /></details>
}
