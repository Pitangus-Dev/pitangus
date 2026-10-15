import { useId } from 'react'
import { PlusIcon, TrashIcon } from '@phosphor-icons/react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/shared/ui/button'
import { CustomPropertiesField } from '@/features/threats/threat-properties'
import { newId, type Assumption, type Model } from '@/features/threats/threat-model-types'

// What frames the analysis, whatever the approach: the assumptions the model takes for granted, and the model's own
// properties and sections (anything an imported model brought that isn't one of Pitangus' fields).

const ASSUMPTION_LIMIT = 100

export function ModelContext({ model, setModel }: { model: Model; setModel: (model: Model) => void }) {
  const { t } = useTranslation('threats')
  const heading = useId()
  const assumptions = model.assumptions ?? []
  const setAssumptions = (next: Assumption[]) => setModel({ ...model, assumptions: next })
  const update = (id: string, change: Partial<Assumption>) => setAssumptions(assumptions.map(item => item.id === id ? { ...item, ...change } : item))
  const add = () => setAssumptions([...assumptions, { id: newId('a', assumptions.map(item => item.id)), text: '' }])
  return <div className="space-y-5">
    <section aria-labelledby={heading} className="space-y-3 rounded-lg border border-app-line bg-panel p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div><h3 id={heading} className="text-base font-semibold">{t('context.assumptions')}</h3><p className="max-w-prose text-xs leading-5 text-app-muted">{t('context.assumptions_hint')}</p></div>
        <Button size="sm" variant="outline" disabled={assumptions.length >= ASSUMPTION_LIMIT} onClick={add}><PlusIcon />{t('context.add_assumption')}</Button>
      </div>
      {assumptions.length === 0 ? <p className="py-4 text-sm text-app-subtle">{t('context.no_assumptions')}</p>
        : <ol className="space-y-2">{assumptions.map((item, index) => <li key={item.id} className="space-y-1.5">
          <div className="flex items-start gap-2">
            <span className="mt-1.5 w-6 shrink-0 text-right text-xs text-app-subtle tabular-nums">{index + 1}.</span>
            <textarea aria-label={t('context.assumption', { number: index + 1 })} rows={1} maxLength={1000} value={item.text} placeholder={t('context.assumption_placeholder')}
              onChange={event => update(item.id, { text: event.target.value })} className="field-sizing-content min-h-8 w-full rounded-lg border border-input bg-card px-3 py-1.5 text-sm text-app-fg" />
            <Button size="icon-sm" variant="ghost" aria-label={t('context.remove_assumption', { number: index + 1 })} onClick={() => setAssumptions(assumptions.filter(entry => entry.id !== item.id))}><TrashIcon /></Button>
          </div>
          {Object.keys(item.custom_properties ?? {}).length > 0 && <div className="ml-8"><CustomPropertiesField compact value={item.custom_properties} onChange={custom_properties => update(item.id, { custom_properties })} /></div>}
        </li>)}</ol>}
    </section>
    <section className="space-y-2 rounded-lg border border-app-line bg-panel p-4">
      <div><h3 className="text-base font-semibold">{t('context.properties')}</h3><p className="max-w-prose text-xs leading-5 text-app-muted">{t('context.properties_hint')}</p></div>
      <CustomPropertiesField value={model.custom_properties} onChange={custom_properties => setModel({ ...model, custom_properties })} />
    </section>
  </div>
}
