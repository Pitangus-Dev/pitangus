import { useEffect, useRef, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { ArrowLeftIcon, CheckIcon } from '@phosphor-icons/react'
import { Button } from '@/shared/ui/button'
import { STEP_LABEL, type StepId } from '@/features/analyses/wizard/model'

// One step: its question as a heading (focused when the step opens), its content, and the actions in a fixed order
// (Back, Skip, Continue). Below 768 px the actions stick to the bottom of the screen.
export function StepFrame({ title, description, children, onBack, backLabel, onSkip, onContinue, continueDisabled, primary, note }: {
  title: string; description?: string; children: ReactNode; onBack: () => void; backLabel?: string; onSkip?: () => void; onContinue?: () => void
  continueDisabled?: boolean; primary?: ReactNode; note?: ReactNode
}) {
  const { t } = useTranslation('analyses')
  const heading = useRef<HTMLHeadingElement>(null)
  useEffect(() => { heading.current?.focus() }, [])
  return <section aria-labelledby="wizard-step-title" className="min-w-0 space-y-5">
    <div className="space-y-1">
      <h2 id="wizard-step-title" ref={heading} tabIndex={-1} className="text-xl font-semibold tracking-tight">{title}</h2>
      {description && <p className="max-w-2xl text-sm text-app-muted">{description}</p>}
    </div>
    {children}
    <div className="sticky bottom-0 z-10 -mx-4 space-y-2 border-t border-app-line bg-app px-4 py-3 sm:-mx-8 sm:px-8 md:static md:mx-0 md:bg-transparent md:px-0 md:pt-5 md:pb-0">
      <div className="flex items-center justify-between gap-3">
        <Button variant="ghost" onClick={onBack}>{!backLabel && <ArrowLeftIcon aria-hidden />}{backLabel ?? t('wizard.back')}</Button>
        <div className="flex items-center gap-2">
          {onSkip && <Button variant="outline" onClick={onSkip}>{t('wizard.skip')}</Button>}
          {primary ?? (onContinue && <Button onClick={onContinue} disabled={continueDisabled}>{t('wizard.continue')}</Button>)}
        </div>
      </div>
      {note}
    </div>
  </section>
}

// Where the person is: one light line of steps above the question (done steps take you back), a bar below 768 px.
export function StepRail({ steps, current, onJump, vertical = false }: { steps: StepId[]; current: number; onJump: (index: number) => void; vertical?: boolean }) {
  const { t } = useTranslation('analyses')
  const label = t(STEP_LABEL[steps[current]])
  return <div>
    <div className={vertical ? 'hidden' : 'space-y-2 md:hidden'}>
      <p className="text-sm text-app-muted">{t('wizard.step_of', { current: current + 1, total: steps.length, label })}</p>
      <div role="progressbar" aria-label={t('wizard.progress')} aria-valuemin={1} aria-valuemax={steps.length} aria-valuenow={current + 1} aria-valuetext={t('wizard.step_of', { current: current + 1, total: steps.length, label })}
        className="h-1 overflow-hidden rounded-full bg-app-soft"><div className="h-full rounded-full bg-brand motion-safe:transition-[width]" style={{ width: `${((current + 1) / steps.length) * 100}%` }} /></div>
    </div>
    <ol aria-label={t('wizard.progress')} className={vertical ? 'hidden flex-col gap-1 text-sm xl:flex' : 'hidden flex-wrap items-center gap-x-2 gap-y-1 text-sm md:flex xl:hidden'}>{steps.map((id, index) => {
      const done = index < current
      const body = <><span className={`flex size-6 shrink-0 items-center justify-center rounded-full border text-xs tabular-nums ${index === current ? 'border-app-fg bg-app-fg text-app' : done ? 'border-app-faint text-app-secondary' : 'border-app-line text-app-muted'}`}>
        {done ? <CheckIcon className="size-3" aria-hidden /> : index + 1}</span>{t(STEP_LABEL[id])}</>
      return <li key={id} aria-current={index === current ? 'step' : undefined} className="flex items-center gap-2">
        {index > 0 && !vertical && <span aria-hidden className="h-px w-6 bg-app-line" />}
        {done
          ? <button type="button" onClick={() => onJump(index)} className="flex min-h-8 items-center gap-2 rounded-lg px-1.5 text-app-secondary hover:text-app-fg">{body}</button>
          : <span className={`flex min-h-8 items-center gap-2 px-1.5 ${index === current ? 'font-medium text-app-fg' : 'text-app-muted'}`}>{body}</span>}
      </li>
    })}</ol>
  </div>
}

// Reserved for AI help in a step (context, review options). Nothing renders until that exists.
export function AiAssistSlot(_props: { step: StepId }) {
  return null
}
