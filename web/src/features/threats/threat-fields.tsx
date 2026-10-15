import { useId } from 'react'
import { XIcon } from '@phosphor-icons/react'
import { useTranslation } from 'react-i18next'
import { ValueCombobox, type ValueOption } from '@/shared/ui/value-combobox'
import type { Catalog, Component, Flow, Kind } from '@/features/threats/threat-model-types'

// Fields backed by our lists, which are suggestions: the team can always use its own value. Pitangus only reasons about
// the values it knows, so a field with an own value says what it won't check.

const PROTOCOL_LIMIT = 24
const DATA_LIMIT = 40

function useGroups() {
  const { t } = useTranslation('threats')
  return { ours: t('values.ours'), workspace: t('values.workspace') }
}

const own = (values: string[] | undefined, known: (value: string) => boolean, group: string): ValueOption[] =>
  (values ?? []).filter(value => !known(value)).map(value => ({ value, label: value, group }))

export function ProtocolField({ flow, catalog, onChange, size }: { flow: Flow; catalog: Catalog; onChange: (change: Partial<Flow>) => void; size?: 'sm' | 'xs' }) {
  const { t } = useTranslation('threats')
  const groups = useGroups()
  const hint = useId()
  const known = (value: string) => catalog.protocols.includes(value.toLowerCase())
  const options = [...catalog.protocols.map(value => ({ value, label: value.toUpperCase(), group: groups.ours })), ...own(catalog.workspace?.protocols, known, groups.workspace)]
  const custom = !!flow.protocol && !known(flow.protocol)
  return <div className="space-y-1">
    <ValueCombobox label={t('inspector.protocol')} value={flow.protocol} options={options} maxLength={PROTOCOL_LIMIT} size={size} describedBy={custom ? hint : undefined}
      onChange={protocol => onChange({ protocol: known(protocol) ? protocol.toLowerCase() : protocol })} />
    {custom && <p id={hint} className="text-[11px] leading-4 text-app-subtle">{t('values.custom_protocol_hint')}</p>}
  </div>
}

export function KindField({ component, catalog, onChange, size }: { component: Component; catalog: Catalog; onChange: (change: Partial<Component>) => void; size?: 'sm' | 'xs' }) {
  const { t } = useTranslation('threats')
  const groups = useGroups()
  const hint = useId()
  const kinds = Object.entries(catalog.kinds).filter(([key]) => key !== 'custom')
  const knownLabels = new Set(kinds.map(([, label]) => label.toLowerCase()))
  const options = [...kinds.map(([value, label]) => ({ value, label, group: groups.ours })),
    ...own(catalog.workspace?.kinds, value => knownLabels.has(value.toLowerCase()), groups.workspace)]
  const value = component.kind === 'custom' ? component.custom_kind ?? '' : component.kind
  const choose = (next: string) => {
    const match = kinds.find(([key, label]) => key === next || label.toLowerCase() === next.toLowerCase())
    onChange(match ? { kind: match[0] as Kind, custom_kind: '', custom_base: undefined }
      : { kind: 'custom', custom_kind: next, custom_base: component.custom_base || 'service' })
  }
  return <div className="space-y-1">
    <ValueCombobox label={t('inspector.kind_label')} value={value} options={options} maxLength={80} size={size} onChange={choose} describedBy={component.kind === 'custom' ? hint : undefined} />
    {component.kind === 'custom' && <p id={hint} className="text-[11px] leading-4 text-app-subtle">{t('values.custom_kind_hint')}</p>}
  </div>
}

export function DataField({ value, catalog, onChange, label }: { value: string[]; catalog: Catalog; onChange: (next: string[]) => void; label: string }) {
  const { t, i18n } = useTranslation('threats')
  const groups = useGroups()
  const hint = useId()
  const known = (item: string) => item in catalog.classifications
  const custom = value.filter(item => !known(item))
  const chosen = new Set(value.map(item => item.toLowerCase()))
  const suggestions = own(catalog.workspace?.data, item => known(item) || chosen.has(item.toLowerCase()), groups.workspace)
  const add = (item: string) => {
    const key = Object.entries(catalog.classifications).find(([code, name]) => code === item.toLowerCase() || name.toLowerCase() === item.toLowerCase())?.[0] ?? item
    if (!chosen.has(key.toLowerCase())) onChange([...value, key])
  }
  return <div className="space-y-1.5" role="group" aria-label={label} aria-describedby={custom.length ? hint : undefined}>
    <div className="flex flex-wrap gap-1">
      {Object.entries(catalog.classifications).map(([key, name]) => <button key={key} type="button" aria-pressed={value.includes(key)} onClick={() => onChange(value.includes(key) ? value.filter(item => item !== key) : [...value, key])}
        className={`min-h-6 rounded border px-2 py-0.5 text-[11px] ${value.includes(key) ? 'border-app-fg bg-app-soft text-app-fg' : 'border-app-line text-app-subtle'}`}>{name}</button>)}
      {custom.map(item => <button key={item} type="button" aria-label={t('values.remove_data', { value: item })} onClick={() => onChange(value.filter(entry => entry !== item))}
        className="inline-flex min-h-6 items-center gap-1 rounded border border-app-fg bg-app-soft px-2 py-0.5 text-[11px] text-app-fg">{item}<XIcon className="size-3" /></button>)}
    </div>
    <ValueCombobox label={t('values.add_data')} placeholder={t('values.add_data_placeholder')} value="" options={suggestions} maxLength={DATA_LIMIT} size="xs" onChange={add} />
    {custom.length > 0 && <p id={hint} className="text-[11px] leading-4 text-app-subtle">{t('values.custom_data_hint', { values: new Intl.ListFormat(i18n.language, { type: 'conjunction' }).format(custom) })}</p>}
  </div>
}
