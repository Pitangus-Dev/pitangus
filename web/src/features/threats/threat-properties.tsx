import { useId, useState } from 'react'
import { PlusIcon, TrashIcon } from '@phosphor-icons/react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import type { CustomProperties } from '@/features/threats/threat-model-types'
import { headingOf, isPlain, valueText } from '@/features/threats/property-values'

// Custom properties: the fields an imported model brought that Pitangus doesn't know. Saved means shown: they are
// listed, editable (add, rename, remove; text values in place) and go back to the JSON where they came from.

const NAME_LIMIT = 60
const VALUE_LIMIT = 2000


// A nested value as the reports show it: a list of objects as a table, an object as name/value rows, a list as bullets.
export function ValueView({ value }: { value: unknown }) {
  if (isPlain(value) || value === null) return <span className="break-words text-app-secondary">{valueText(value)}</span>
  if (Array.isArray(value) && value.every(item => item && typeof item === 'object' && !Array.isArray(item))) {
    const rows = value as Record<string, unknown>[]
    const columns = [...new Set(rows.flatMap(row => Object.keys(row)))].slice(0, 6)
    return <div className="overflow-x-auto"><table className="w-full border-t border-app-line text-xs">
      <thead><tr className="text-left text-app-subtle">{columns.map(column => <th key={column} scope="col" className="px-2 py-1.5 font-medium">{headingOf(column)}</th>)}</tr></thead>
      <tbody className="divide-y divide-app-line">{rows.map((row, index) => <tr key={index}>{columns.map(column => <td key={column} className="px-2 py-1.5 align-top text-app-secondary">{row[column] === undefined ? '' : valueText(row[column])}</td>)}</tr>)}</tbody>
    </table></div>
  }
  if (Array.isArray(value)) return <ul className="list-disc space-y-0.5 pl-5 text-app-secondary">{value.map((item, index) => <li key={index}>{valueText(item)}</li>)}</ul>
  return <dl className="grid grid-cols-[minmax(0,10rem)_minmax(0,1fr)] gap-x-3 gap-y-1">{Object.entries(value as Record<string, unknown>).map(([key, item]) => [
    <dt key={`k-${key}`} className="text-app-muted">{headingOf(key)}</dt>, <dd key={`v-${key}`} className="min-w-0 break-words text-app-secondary">{valueText(item)}</dd>])}</dl>
}

// Read-only list, for places where the object isn't edited (a threat's detail).
export function PropertyList({ value }: { value?: CustomProperties }) {
  const { t } = useTranslation('threats')
  const entries = Object.entries(value ?? {})
  if (!entries.length) return null
  return <div className="space-y-1"><p className="text-xs font-medium text-app-muted">{t('properties.title')}</p>
    <dl className="grid grid-cols-[minmax(0,10rem)_minmax(0,1fr)] gap-x-3 gap-y-1 text-xs">{entries.map(([key, item]) => [
      <dt key={`k-${key}`} className="break-words text-app-muted">{key}</dt>, <dd key={`v-${key}`} className="min-w-0"><ValueView value={item} /></dd>])}</dl></div>
}

export function CustomPropertiesField({ value, onChange, compact = false }: { value?: CustomProperties; onChange: (next: CustomProperties) => void; compact?: boolean }) {
  const { t } = useTranslation('threats')
  const heading = useId()
  const entries = Object.entries(value ?? {})
  const [names, setNames] = useState<Record<string, string>>({})
  const set = (next: [string, unknown][]) => onChange(Object.fromEntries(next))
  // A name already used (or empty) can't be taken: what was typed stays, with the reason next to it.
  const clash = (from: string) => { const to = (names[from] ?? from).trim(); return to !== from && (!to || entries.some(([key]) => key === to)) }
  const rename = (from: string) => {
    const to = (names[from] ?? from).trim().slice(0, NAME_LIMIT)
    if (clash(from)) return
    setNames(previous => { const next = { ...previous }; delete next[from]; return next })
    if (to !== from) set(entries.map(([key, item]) => [key === from ? to : key, item]))
  }
  const add = () => {
    const base = t('properties.new_name')
    let name = base, number = 2
    while (entries.some(([key]) => key === name)) name = `${base} ${number++}`
    set([...entries, [name, '']])
  }
  return <section aria-labelledby={heading} className="space-y-1.5">
    <div className="flex items-center justify-between gap-2"><h4 id={heading} className="text-[11px] font-medium text-app-muted">{t('properties.title')}</h4>
      <Button size="xs" variant="ghost" onClick={add}><PlusIcon />{t('properties.add')}</Button></div>
    {entries.length === 0 && !compact && <p className="text-[11px] leading-4 text-app-subtle">{t('properties.empty')}</p>}
    {entries.length > 0 && <div className="divide-y divide-app-line">{entries.map(([key, item]) => { const invalid = clash(key)
      return <div key={key} className="space-y-1 py-2 first:pt-0 last:pb-0">
      <div className="flex items-center gap-1">
        <Input aria-label={t('properties.name')} value={names[key] ?? key} maxLength={NAME_LIMIT} onChange={event => setNames({ ...names, [key]: event.target.value })}
          aria-invalid={invalid || undefined} aria-describedby={invalid ? `${heading}-${key}` : undefined}
          onBlur={() => rename(key)} onKeyDown={event => { if (event.key === 'Enter') rename(key) }} className="h-7 min-w-0 flex-1 border-input bg-card text-xs font-medium" />
        <Button size="icon-sm" variant="ghost" aria-label={t('properties.remove', { name: key })} onClick={() => set(entries.filter(([other]) => other !== key))}><TrashIcon /></Button>
      </div>
      {invalid && <p id={`${heading}-${key}`} className="text-[11px] text-danger">{(names[key] ?? '').trim() ? t('properties.name_taken') : t('properties.name_required')}</p>}
      {isPlain(item) || item === null
        ? <textarea aria-label={t('properties.value', { name: key })} rows={1} maxLength={VALUE_LIMIT} value={item === null ? '' : String(item)}
            onChange={event => set(entries.map(([other, current]) => [other, other === key ? event.target.value : current]))}
            className="field-sizing-content w-full rounded-lg border border-input bg-card px-2 py-1 text-xs text-app-fg" />
        : <div className="text-xs"><ValueView value={item} /><p className="mt-1 text-[11px] text-app-subtle">{t('properties.structured')}</p></div>}
    </div> })}</div>}
  </section>
}
