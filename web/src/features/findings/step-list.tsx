import { useTranslation } from 'react-i18next'
import { cn } from 'cn'
import { labelOf } from '@/features/findings/finding-model'
import type { ScanStep } from '@/shared/lib/types'

const STEP_LABEL: Record<string, string> = { completed: 'step.completed', partial: 'step.partial', not_tested: 'step.not_tested', inconclusive: 'step.inconclusive', pending: 'step.pending', skipped: 'step.skipped', failed: 'step.failed' }
const STEP_TONE: Record<string, string> = { completed: 'text-success', partial: 'text-warning', inconclusive: 'text-warning', failed: 'text-danger' }

// What each engine of a run did, as ruled rows: name and detail on the left, the status as coloured text on the right.
export function StepList({ steps, className }: { steps: ScanStep[]; className?: string }) {
  const { t } = useTranslation('findings')
  return <ul className={cn('divide-y divide-app-line', className)}>{steps.map(step => <li key={step.id} className="flex items-start justify-between gap-4 py-2.5 text-sm">
    <span className="min-w-0"><span className="font-medium">{step.name}</span>
      {typeof step.tool?.duration_s === 'number' && <span className="ml-2 text-xs text-app-subtle tabular-nums">{t('log.seconds', { seconds: step.tool.duration_s })}</span>}
      {step.detail && <span className="mt-0.5 block text-xs leading-5 text-app-muted">{step.detail}</span>}</span>
    <span className={cn('shrink-0 text-xs font-medium', STEP_TONE[step.status] ?? 'text-app-muted')}>{labelOf(t, STEP_LABEL, step.status)}</span>
  </li>)}</ul>
}
