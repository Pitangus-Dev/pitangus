import { useRef, type KeyboardEvent } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import { CodeIcon, EyeIcon, GlobeIcon, PackageIcon, UploadSimpleIcon } from '@phosphor-icons/react'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { STATE_CLASS } from '@/shared/ui/severity'
import { StepFrame } from '@/features/analyses/wizard/step-frame'
import type { Kind } from '@/features/analyses/wizard/model'

const CARDS = [
  { id: 'code', icon: CodeIcon, title: 'wizard.kinds.code.title', line: 'wizard.kinds.code.line', points: 'wizard.kinds.code.points' },
  { id: 'image', icon: PackageIcon, title: 'wizard.kinds.image.title', line: 'wizard.kinds.image.line', points: 'wizard.kinds.image.points' },
  { id: 'exposure', icon: EyeIcon, title: 'wizard.kinds.exposure.title', line: 'wizard.kinds.exposure.line', points: 'wizard.kinds.exposure.points' },
  { id: 'web', icon: GlobeIcon, title: 'wizard.kinds.web.title', line: 'wizard.kinds.web.line', points: 'wizard.kinds.web.points' },
] as const

// What to check: a card each, one line each, and importing as a secondary link. Both domain checks send traffic to a
// live site and are launched by admins only: the light exposure check always; the full web scan (sites and APIs),
// experimental, only when the server enables it.
export function TypeChooser({ choice, onChoose, onContinue, onImport, onCancel, dast, isAdmin }: {
  choice: Kind; onChoose: (kind: Kind) => void; onContinue: () => void; onImport: () => void; onCancel: () => void; dast: boolean | undefined; isAdmin: boolean
}) {
  const { t } = useTranslation('analyses')
  const cards = useRef<(HTMLDivElement | null)[]>([])
  const off = (id: Kind) => id === 'web' && dast === false
  const enabled = CARDS.filter(card => !off(card.id))
  const live = (id: Kind) => id === 'web' || id === 'exposure'
  const adminOnly = !isAdmin && live(choice)
  const move = (event: KeyboardEvent, id: Kind) => {
    const step = event.key === 'ArrowDown' || event.key === 'ArrowRight' ? 1 : event.key === 'ArrowUp' || event.key === 'ArrowLeft' ? -1 : 0
    if (step) {
      event.preventDefault()
      const at = enabled.findIndex(card => card.id === id)
      const next = enabled[(at + step + enabled.length) % enabled.length]
      onChoose(next.id)
      cards.current[CARDS.findIndex(card => card.id === next.id)]?.focus()
    } else if (event.key === ' ') { event.preventDefault(); if (!off(id)) onChoose(id) }
    else if (event.key === 'Enter' && !off(id) && !(!isAdmin && live(id))) { event.preventDefault(); onChoose(id); onContinue() }
  }

  return <StepFrame title={t('chooser.title')} onBack={onCancel} backLabel={t('common:actions.cancel')}
    primary={<Button onClick={onContinue} disabled={off(choice) || adminOnly}>{t('wizard.continue')}</Button>}
    note={adminOnly ? <p role="status" className="text-right text-xs text-app-muted">{t('chooser.admin_only')}</p> : undefined}>
    <div role="radiogroup" aria-labelledby="wizard-step-title" className="grid gap-3 md:grid-cols-2">
      {CARDS.map((card, index) => {
        const selected = choice === card.id
        const disabled = off(card.id)
        const listed: unknown = disabled ? [] : t(card.points, { returnObjects: true })
        const points = Array.isArray(listed) ? listed.map(String) : []
        return <div key={card.id} ref={node => { cards.current[index] = node }} role="radio" aria-checked={selected} aria-disabled={disabled || undefined}
          aria-labelledby={`kind-${card.id}`} aria-describedby={[...(card.id === 'web' ? ['kind-web-tag'] : []), `kind-${card.id}-line`, ...(points.length ? [`kind-${card.id}-points`] : [])].join(' ')} tabIndex={selected ? 0 : -1}
          onClick={() => { if (!disabled) onChoose(card.id) }} onKeyDown={event => move(event, card.id)}
          className={`rounded-lg border p-4 text-left motion-safe:transition-colors ${disabled ? 'cursor-not-allowed border-dashed border-app-line' : selected ? 'cursor-pointer border-app-fg bg-app-soft' : 'cursor-pointer border-app-line hover:border-app-faint'}`}>
          <div className="flex flex-wrap items-center gap-2.5">
            <span aria-hidden className={`grid size-4 shrink-0 place-items-center rounded-full border ${selected ? 'border-app-fg' : 'border-app-faint'}`}>{selected && <span className="size-2 rounded-full bg-app-fg" />}</span>
            <h3 id={`kind-${card.id}`} className={`min-w-0 text-sm font-semibold ${disabled ? 'text-app-muted' : ''}`}>{t(card.title)}</h3>
            {card.id === 'web' && <Badge id="kind-web-tag" variant="outline" className={STATE_CLASS.neutral}>{t('chooser.experimental')}</Badge>}
            <card.icon aria-hidden className="ml-auto size-4 text-app-subtle" />
          </div>
          <p id={`kind-${card.id}-line`} className="mt-2 text-sm text-app-muted">{disabled ? t('chooser.off') : t(card.line)}</p>
          {points.length > 0 && <ul id={`kind-${card.id}-points`} className={`mt-3 space-y-1 border-t border-app-line pt-3 text-sm text-app-secondary ${selected ? '' : 'max-sm:hidden'}`}>{points.map(point =>
            <li key={point} className="flex gap-2"><span aria-hidden className="text-app-faint">–</span>{point}</li>)}</ul>}
        </div>
      })}
    </div>
    {dast === false && isAdmin && <details className="text-sm text-app-muted">
      <summary className="min-h-6 cursor-pointer">{t('chooser.off_how')}</summary>
      <p className="mt-1">{t('chooser.off_admin')}</p>
    </details>}
    <p className="flex flex-wrap items-center gap-2 text-sm text-app-muted"><UploadSimpleIcon className="size-4 shrink-0" aria-hidden />
      <span><Trans t={t} i18nKey="chooser.import" components={{ go: <button type="button" onClick={onImport} className="min-h-6 font-medium text-brand underline underline-offset-2" /> }} /></span>
      <span className="text-xs">{t('chooser.import_tools')}</span></p>
  </StepFrame>
}
