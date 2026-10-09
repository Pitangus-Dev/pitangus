import { useTranslation } from 'react-i18next'
import { ChevronRight } from 'lucide-react'
import { Badge } from '@/shared/ui/badge'
import { formatTime } from '@/shared/i18n/format'
import { FindingsTable } from '@/features/findings/findings-table'
import { RunHeader } from '@/features/findings/run-header'
import { RunExports } from '@/features/findings/run-exports'
import { labelOf, type FindingTab, type RepositoryRun } from '@/features/findings/finding-model'

const STEP_LABEL: Record<string, string> = { completed: 'step.completed', partial: 'step.partial', not_tested: 'step.not_tested', inconclusive: 'step.inconclusive', pending: 'step.pending' }

// The findings of one run or of one asset's current state (`asset_state`), with that asset's files, the run's log and
// what each engine covered. `focus`: a finding to open (links from Jira issues carry its fingerprint).
export function RepositoryResult({ run, onNew, onChanged, canAccept, canManage = canAccept, initialView = 'active', exportStatus = 'open', focus = null }: {
  run: RepositoryRun; onNew: () => void; onChanged: () => void; canAccept: boolean; canManage?: boolean; initialView?: string; exportStatus?: FindingTab; focus?: string | null
}) {
  const { t } = useTranslation('findings')
  const source = run.source
  const state = run.type === 'asset_state'
  // Its Jira issues go where the server routes the asset (by its key and name).
  return <div className="space-y-6">
    <FindingsTable findings={run.findings ?? []} kpis={run.summary.kpis} header={<RunHeader run={run} onNew={onNew} />}
      exports={openAudit => <RunExports run={run} status={exportStatus} onAudit={openAudit} />}
      audit={{ name: source?.name ?? t('export.file_fallback'), fromSelection: true,
        target: state ? { asset: source?.id ?? '', status: exportStatus === 'fixed' || exportStatus === 'all' ? exportStatus : 'open' } : { runId: run.id } }}
      jira={{ selection: state && source?.id ? { asset: source.id } : { runId: run.id }, asset: source ? { key: source.uid || source.id || source.name, name: source.name } : null }}
      runId={run.id} assetKey={source?.id} canAccept={canAccept} canManage={canManage} initialView={initialView} focus={focus} onChanged={onChanged} />
    {run.progress?.length ? <RunLog run={run} progress={run.progress} /> : null}
    <RunCoverage run={run} />
  </div>
}

function RunLog({ run, progress }: { run: RepositoryRun; progress: NonNullable<RepositoryRun['progress']> }) {
  const { t } = useTranslation('findings')
  return <details className="group rounded-2xl border border-app-line bg-panel"><summary className="flex cursor-pointer list-none items-center gap-2 px-5 py-4 text-sm font-medium"><ChevronRight className="size-4 text-app-subtle motion-safe:transition group-open:rotate-90" />{t('log.title')}<span className="ml-2 text-xs font-normal text-app-subtle">{t('log.events', { count: progress.length })}{run.started_at && run.finished_at ? ` · ${t('log.seconds', { seconds: Math.round((Date.parse(run.finished_at) - Date.parse(run.started_at)) / 1000) })}` : ''}</span></summary><div className="space-y-1 px-5 pb-5 font-mono text-xs leading-6">{progress.map((event, index) => <div key={index} className="flex gap-3"><span className="shrink-0 text-app-subtle">{formatTime(event.at)}</span><span className={event.level === 'ok' ? 'text-brand' : event.level === 'warn' ? 'text-warning' : event.level === 'error' ? 'text-danger' : 'text-app-secondary'}>{event.message}</span></div>)}</div></details>
}

function RunCoverage({ run }: { run: RepositoryRun }) {
  const { t } = useTranslation('findings')
  return <details className="group rounded-2xl border border-app-line bg-panel"><summary className="flex cursor-pointer list-none items-center gap-2 px-5 py-4 text-sm font-medium"><ChevronRight className="size-4 text-app-subtle motion-safe:transition group-open:rotate-90" />{t('coverage.title')}<span className="ml-2 text-xs font-normal text-app-subtle">{t('coverage.steps', { done: run.steps?.filter(step => step.status === 'completed' || step.status === 'partial').length ?? 0, total: run.steps?.length ?? 0 })}</span></summary><div className="space-y-2 px-5 pb-5">{run.steps?.map(step => <div key={step.id} className="flex flex-wrap items-start justify-between gap-2 rounded-lg border border-app-line bg-inset p-3 text-sm"><span className="min-w-0"><span className="font-medium">{step.name}</span><span className="mt-0.5 block text-xs leading-5 text-app-muted">{step.detail}</span></span><Badge variant="outline" className={`shrink-0 text-[11px] ${step.status === 'completed' ? 'border-brand/30 text-brand' : step.status === 'partial' ? 'border-warning-line text-warning' : 'border-app-line text-app-subtle'}`}>{labelOf(t, STEP_LABEL, step.status)}</Badge></div>)}</div></details>
}
