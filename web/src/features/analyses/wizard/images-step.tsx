import { Trans, useTranslation } from 'react-i18next'
import { StepFrame } from '@/features/analyses/wizard/step-frame'
import { BATCH_LIMIT, floating, listing, referencesOf, registryOf, type Registry } from '@/features/analyses/wizard/model'

const SAMPLES = [['nginx:1.21', 'images.samples.old'], ['nginx:1.27-alpine', 'images.samples.recent'], ['vulnerables/web-dvwa', 'images.samples.vulnerable']] as const

// Which images, one reference per line. Advice shows up only when it applies: a floating tag, a private registry.
export function ImagesStep({ text, onText, registries, batchBusy, onManageConnections, onBack, onContinue }: {
  text: string; onText: (text: string) => void; registries: Registry[] | undefined; batchBusy: boolean; onManageConnections: () => void; onBack: () => void; onContinue: () => void
}) {
  const { t } = useTranslation('analyses')
  const references = referencesOf(text)
  const invalid = references.filter(item => !registryOf(item))
  const hosts = Array.from(new Set(references.map(registryOf).filter((item): item is string => !!item)))
  const batch = references.length > 1
  const ready = references.length > 0 && references.length <= BATCH_LIMIT && !invalid.length && !(batch && batchBusy)
  const registryLines = registries ? hosts.flatMap(host => registries.some(entry => entry.registry === host) ? [{ host, saved: true }] : host === 'docker.io' ? [] : [{ host, saved: false }]) : []

  return <StepFrame title={t('images.title')} onBack={onBack} onContinue={onContinue} continueDisabled={!ready}>
    <div className="space-y-1.5">
      <label htmlFor="image-reference" className="text-sm text-app-secondary">{t('images.label')}</label>
      <textarea id="image-reference" aria-invalid={invalid.length > 0 || references.length > BATCH_LIMIT} aria-describedby="image-reference-help"
        rows={Math.min(8, Math.max(3, references.length + 1))} value={text} onChange={event => onText(event.target.value)} maxLength={30_000} spellCheck={false} autoComplete="off"
        placeholder={t('images.placeholder')} className="w-full rounded-xl border border-app-line bg-app-soft p-3 font-mono text-sm focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50" />
      <div id="image-reference-help" role="status" className="space-y-1 text-sm">
        {invalid.length > 0 && <p className="text-danger"><Trans t={t} i18nKey="images.invalid" values={{ names: listing(t, invalid) }} components={{ mono: <span className="font-mono" /> }} /></p>}
        {references.length > BATCH_LIMIT && <p className="text-danger">{t('images.over_limit', { limit: BATCH_LIMIT })}</p>}
        {batch && !invalid.length && <p className="text-app-muted">{batchBusy ? t('repos.batch_busy') : t('images.batch_note')}</p>}
        {references.some(floating) && <p className="text-app-muted">{t('images.pin_hint')}</p>}
        {registryLines.map(line => <p key={line.host} className="text-app-muted">{line.saved ? t('images.registry_saved', { registry: line.host })
          : <Trans t={t} i18nKey="images.registry_public" values={{ registry: line.host }} components={{ go: <button type="button" onClick={onManageConnections} className="min-h-6 underline underline-offset-2" /> }} />}</p>)}
      </div>
      {!text.trim() && <div className="flex flex-wrap items-center gap-1.5 pt-1 text-xs text-app-muted"><span>{t('images.try_public')}</span>
        {SAMPLES.map(([value, hint]) => <button key={value} type="button" onClick={() => onText(value)} title={t(hint)}
          className="min-h-6 rounded-md border border-app-line bg-app-soft px-2 font-mono text-xs text-app-secondary hover:border-app-faint">{value}</button>)}</div>}
    </div>
  </StepFrame>
}
