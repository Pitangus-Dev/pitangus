import { useTranslation } from 'react-i18next'
import { AiAssistSlot, StepFrame } from '@/features/analyses/wizard/step-frame'
import { CONTEXT_MAX } from '@/features/analyses/wizard/model'

// A note for the report, in the team's words. Skipping it changes nothing about what runs, so there is no warning.
export function ContextStep({ value, onChange, onBack, onContinue }: { value: string; onChange: (value: string) => void; onBack: () => void; onContinue: () => void }) {
  const { t } = useTranslation('analyses')
  return <StepFrame title={t('context.title')} onBack={onBack} onSkip={() => { onChange(''); onContinue() }} onContinue={onContinue}>
    <div className="space-y-1.5">
      <label htmlFor="run-context" className="text-sm text-app-secondary">{t('context.label')}</label>
      <textarea id="run-context" rows={5} maxLength={CONTEXT_MAX} value={value} onChange={event => onChange(event.target.value)} aria-describedby="run-context-help"
        placeholder={t('context.placeholder')} className="w-full rounded-xl border border-app-line bg-app-soft p-3 text-sm focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50" />
      <p id="run-context-help" className="flex justify-between gap-3 text-xs text-app-muted"><span>{t('context.help')}</span>
        {value.length >= 300 && <span className="shrink-0 tabular-nums">{t('context.counter', { length: value.length, max: CONTEXT_MAX })}</span>}</p>
    </div>
    <AiAssistSlot step="context" />
  </StepFrame>
}
