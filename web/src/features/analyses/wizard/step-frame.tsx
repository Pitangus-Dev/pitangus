import { useEffect, useRef, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { ArrowLeft, ArrowRight, Check } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { STEP_LABEL, type StepId } from '@/features/analyses/wizard/model'

// One step: its question as a heading (focused when the step opens), its content, and the actions in a fixed order
// (Back, Skip, Continue). Below 768 px the actions stick to the bottom of the screen.
export function StepFrame({ title, description, children, onBack, onSkip, onContinue, continueDisabled, primary, note }: {
  title: string; description?: string; children: ReactNode; onBack: () => void; onSkip?: () => void; onContinue?: () => void
  continueDisabled?: boolean; primary?: ReactNode; note?: ReactNode
}) {
  const { t } = useTranslation('analyses')
  const heading = useRef<HTMLHeadingElement>(null)
  useEffect(() => { heading.current?.focus() }, [])
  return <section aria-labelledby="wizard-step-title" className="min-w-0 space-y-5">
    <div className="space-y-1">
      <h2 id="wizard-step-title" ref={heading} tabIndex={-1} className="text-xl font-semibold tracking-tight">{title}</h2>
      {description && <p className="text-sm text-app-muted">{description}</p>}
    </div>
    {children}
    <div className="sticky bottom-0 z-10 -mx-4 space-y-2 border-t border-app-line bg-app px-4 py-3 sm:-mx-8 sm:px-8 md:static md:mx-0 md:bg-transparent md:px-0 md:pt-5 md:pb-0">
      <div className="flex items-center justify-between gap-3">
        <Button variant="ghost" onClick={onBack}><ArrowLeft aria-hidden />{t('wizard.back')}</Button>
        <div className="flex items-center gap-2">
          {onSkip && <Button variant="outline" onClick={onSkip}>{t('wizard.skip')}</Button>}
          {primary ?? (onContinue && <Button onClick={onContinue} disabled={continueDisabled}>{t('wizard.continue')}<ArrowRight aria-hidden /></Button>)}
        </div>
      </div>
      {note}
    </div>
  </section>
}

// Where the person is: a list beside the step from 1280 px (done steps take you back), one line with a bar below 768 px.
export function StepRail({ steps, current, onJump }: { steps: StepId[]; current: number; onJump: (index: number) => void }) {
  const { t } = useTranslation('analyses')
  const label = t(STEP_LABEL[steps[current]])
  return <div className="order-first xl:order-none">
    <div className="space-y-2 md:hidden">
      <p className="text-sm text-app-muted">{t('wizard.step_of', { current: current + 1, total: steps.length, label })}</p>
      <div role="progressbar" aria-label={t('wizard.progress')} aria-valuemin={1} aria-valuemax={steps.length} aria-valuenow={current + 1} aria-valuetext={t('wizard.step_of', { current: current + 1, total: steps.length, label })}
        className="h-1 overflow-hidden rounded-full bg-app-soft"><div className="h-full rounded-full bg-brand motion-safe:transition-[width]" style={{ width: `${((current + 1) / steps.length) * 100}%` }} /></div>
    </div>
    <ol aria-label={t('wizard.progress')} className="hidden space-y-1 md:block">{steps.map((id, index) => {
      const done = index < current
      const body = <><span className={`flex size-6 shrink-0 items-center justify-center rounded-full border font-mono text-xs ${index === current ? 'border-brand bg-brand/15 text-brand' : done ? 'border-brand/40 bg-brand/10 text-brand' : 'border-app-line text-app-muted'}`}>
        {done ? <Check className="size-3" aria-hidden /> : index + 1}</span>{t(STEP_LABEL[id])}</>
      return <li key={id} aria-current={index === current ? 'step' : undefined}>{done
        ? <button type="button" onClick={() => onJump(index)} className="flex min-h-8 w-full items-center gap-3 rounded-lg px-2 py-1.5 text-left text-sm text-app-secondary hover:bg-app-soft">{body}</button>
        : <span className={`flex min-h-8 items-center gap-3 px-2 py-1.5 text-sm ${index === current ? 'font-medium text-app-fg' : 'text-app-muted'}`}>{body}</span>}</li>
    })}</ol>
  </div>
}

// Reserved for AI help in a step (context, review options). Nothing renders until that exists.
export function AiAssistSlot(_props: { step: StepId }) {
  return null
}
