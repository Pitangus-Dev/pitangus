import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Boxes, ChevronRight, Code2, Globe2, Layers3, LoaderCircle } from 'lucide-react'
import { formatList } from '@/shared/i18n/format'
import { Button } from '@/shared/ui/button'
import { Bone } from '@/shared/ui/loading'
import { Switch } from '@/shared/ui/switch'
import { AiAssistSlot, StepFrame } from '@/features/analyses/wizard/step-frame'
import type { Kind, ScanPlan } from '@/features/analyses/wizard/model'

export type ReviewRow = { label: string; value: ReactNode; step?: number }
const ICON = { code: Code2, image: Boxes, web: Globe2 } as const

// "What it looks for", from the server's plan of this repository, in words rather than engine names.
export function LooksFor({ plan, failed, batch, osv }: { plan: ScanPlan | undefined; failed: boolean; batch: boolean; osv: boolean }) {
  const { t } = useTranslation('analyses')
  if (batch) return t('review.looks.generic')
  if (failed) return t('review.plan_failed')
  if (!plan) return <Bone className="h-4 w-56" />
  const languages = plan.languages.filter(item => item.rules).map(item => item.name)
  const dependencies = plan.manifests.length > 0 && (!plan.osv_needed || osv)
  return formatList([
    languages.length ? t('review.looks.code', { languages: formatList(languages) }) : t('review.looks.code_plain'),
    t('review.looks.secrets'),
    dependencies ? t('review.looks.dependencies') : t('review.looks.no_dependencies'),
    ...(plan.iac.length || plan.pipelines?.length ? [t('review.looks.infrastructure')] : []),
  ])
}

function Row({ row, onChange }: { row: ReviewRow; onChange: (step: number) => void }) {
  const { t } = useTranslation('analyses')
  return <div className="flex flex-col gap-1 border-b border-app-line py-3 last:border-0 sm:flex-row sm:items-start sm:gap-4">
    <dt className="w-28 shrink-0 pt-0.5 text-xs text-app-muted">{row.label}</dt>
    <dd className="flex min-w-0 flex-1 items-start justify-between gap-3">
      <span className="min-w-0 text-sm break-words text-app-secondary">{row.value}</span>
      {row.step !== undefined && <Button variant="ghost" size="sm" aria-label={t('review.change_for', { label: row.label })} onClick={() => onChange(row.step as number)}>{t('review.change')}</Button>}
    </dd>
  </div>
}

// Ready to launch: fixed rows with short values (each one jumps back to its step), the few options that matter,
// and, for code and images, what runs folded under "Technical details".
export function ReviewStep({ kind, rows, options, notes, details, error, busy, launchLabel, batch, onChange, onBack, onLaunch }: {
  kind: Kind; rows: ReviewRow[]; options?: ReactNode; notes?: ReactNode; details?: ReactNode; error: string; busy: boolean; launchLabel: string; batch: boolean
  onChange: (step: number) => void; onBack: () => void; onLaunch: () => void
}) {
  const { t } = useTranslation('analyses')
  const Icon = batch ? Layers3 : ICON[kind]
  return <StepFrame title={t('review.title')} onBack={onBack}
    primary={<Button onClick={onLaunch} disabled={busy}>{busy ? <LoaderCircle className="motion-safe:animate-spin" aria-hidden /> : <Icon aria-hidden />}{busy ? t('launch.queuing') : launchLabel}</Button>}
    note={<>
      {error && <p role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{error}</p>}
      {kind === 'web' && <p className="text-xs text-app-muted md:text-right">{t('review.authorization')}</p>}
    </>}>
    <dl className="border-y border-app-line">{rows.map(row => <Row key={row.label} row={row} onChange={onChange} />)}</dl>
    {options && <div className="space-y-4">{options}</div>}
    <AiAssistSlot step="review" />
    {notes && <div className="space-y-2">{notes}</div>}
    {details && <Foldout title={t('details.title')}><div className="space-y-3">{details}</div></Foldout>}
  </StepFrame>
}

export function OsvOption({ checked, onChange }: { checked: boolean; onChange: (checked: boolean) => void }) {
  const { t } = useTranslation('analyses')
  return <Switch id="allow-osv" checked={checked} onCheckedChange={onChange} label={t('review.osv_label')} hint={t('review.osv_hint')} />
}

// A small fold for what only some people need: closed, it's one muted line.
function Foldout({ title, children }: { title: string; children: ReactNode }) {
  return <details className="group text-sm text-app-muted">
    <summary className="flex min-h-6 cursor-pointer list-none items-center gap-1.5 text-app-secondary"><ChevronRight className="size-4 motion-safe:transition group-open:rotate-90" aria-hidden />{title}</summary>
    <div className="mt-2 pl-5.5">{children}</div>
  </details>
}

export function DetailList({ title, items }: { title: string; items: string[] }) {
  return <div className="space-y-1"><p className="text-xs font-medium text-app-secondary">{title}</p>
    <ul className="list-disc space-y-0.5 pl-5">{items.map(item => <li key={item}>{item}</li>)}</ul></div>
}
