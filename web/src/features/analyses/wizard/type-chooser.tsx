import { useRef, type KeyboardEvent } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import { ArrowRight, Boxes, Check, Code2, FileUp, Globe2 } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { StepFrame } from '@/features/analyses/wizard/step-frame'
import type { Kind } from '@/features/analyses/wizard/model'

const CARDS = [
  { id: 'code', icon: Code2, title: 'wizard.kinds.code.title', line: 'wizard.kinds.code.line' },
  { id: 'image', icon: Boxes, title: 'wizard.kinds.image.title', line: 'wizard.kinds.image.line' },
  { id: 'web', icon: Globe2, title: 'wizard.kinds.web.title', line: 'wizard.kinds.web.line' },
] as const

// What to check: three cards, one line each, and importing as a secondary link. A web scan (sites and APIs) sends
// traffic to a live site: off unless the server enables it, and launched by admins only.
export function TypeChooser({ choice, onChoose, onContinue, onImport, onCancel, dast, isAdmin }: {
  choice: Kind; onChoose: (kind: Kind) => void; onContinue: () => void; onImport: () => void; onCancel: () => void; dast: boolean | undefined; isAdmin: boolean
}) {
  const { t } = useTranslation('analyses')
  const cards = useRef<(HTMLDivElement | null)[]>([])
  const off = (id: Kind) => id === 'web' && dast === false
  const enabled = CARDS.filter(card => !off(card.id))
  const adminOnly = !isAdmin && choice === 'web'
  const move = (event: KeyboardEvent, id: Kind) => {
    const step = event.key === 'ArrowDown' || event.key === 'ArrowRight' ? 1 : event.key === 'ArrowUp' || event.key === 'ArrowLeft' ? -1 : 0
    if (step) {
      event.preventDefault()
      const at = enabled.findIndex(card => card.id === id)
      const next = enabled[(at + step + enabled.length) % enabled.length]
      onChoose(next.id)
      cards.current[CARDS.findIndex(card => card.id === next.id)]?.focus()
    } else if (event.key === ' ') { event.preventDefault(); if (!off(id)) onChoose(id) }
    else if (event.key === 'Enter' && !off(id) && !(!isAdmin && id === 'web')) { event.preventDefault(); onChoose(id); onContinue() }
  }

  return <StepFrame title={t('chooser.title')} onBack={onCancel}
    primary={<Button onClick={onContinue} disabled={off(choice) || adminOnly}>{t('wizard.continue')}<ArrowRight aria-hidden /></Button>}
    note={adminOnly ? <p role="status" className="text-right text-xs text-app-muted">{t('chooser.admin_only')}</p> : undefined}>
    <div role="radiogroup" aria-labelledby="wizard-step-title" className="grid gap-3 md:grid-cols-3">
      {CARDS.map((card, index) => {
        const selected = choice === card.id
        const disabled = off(card.id)
        return <div key={card.id} ref={node => { cards.current[index] = node }} role="radio" aria-checked={selected} aria-disabled={disabled || undefined}
          aria-labelledby={`kind-${card.id}`} aria-describedby={`kind-${card.id}-line`} tabIndex={selected ? 0 : -1}
          onClick={() => { if (!disabled) onChoose(card.id) }} onKeyDown={event => move(event, card.id)}
          className={`rounded-2xl border p-5 text-left motion-safe:transition ${disabled ? 'cursor-not-allowed border-dashed border-app-line' : selected ? 'cursor-pointer border-brand/60 bg-brand/[0.07]' : 'cursor-pointer border-app-line hover:border-brand/30'}`}>
          <div className="flex items-start justify-between gap-3">
            <card.icon aria-hidden className={`size-5 ${disabled ? 'text-app-muted' : 'text-brand'}`} />
            <span aria-hidden className={`flex size-4 items-center justify-center rounded-full border ${selected ? 'border-brand bg-brand' : 'border-app-faint'}`}>{selected && <Check className="size-3 text-on-solid" />}</span>
          </div>
          <h3 id={`kind-${card.id}`} className={`mt-6 text-base font-semibold ${disabled ? 'text-app-muted' : ''}`}>{t(card.title)}</h3>
          <p id={`kind-${card.id}-line`} className="mt-1 text-sm text-app-muted">{disabled ? t('chooser.off') : t(card.line)}</p>
        </div>
      })}
    </div>
    {dast === false && isAdmin && <details className="text-sm text-app-muted">
      <summary className="min-h-6 cursor-pointer">{t('chooser.off_how')}</summary>
      <p className="mt-1"><Trans t={t} i18nKey="chooser.off_admin" components={{ mono: <code className="font-mono text-app-secondary" /> }} /></p>
    </details>}
    <p className="flex flex-wrap items-center gap-2 text-sm text-app-muted"><FileUp className="size-4 shrink-0" aria-hidden />
      <span><Trans t={t} i18nKey="chooser.import" components={{ go: <button type="button" onClick={onImport} className="min-h-6 font-medium text-brand underline underline-offset-2" /> }} /></span>
      <span className="text-xs">{t('chooser.import_tools')}</span></p>
  </StepFrame>
}
