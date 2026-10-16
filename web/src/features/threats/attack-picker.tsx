import { useMemo, useState } from 'react'
import { CaretRightIcon, CheckIcon, MagnifyingGlassIcon, PlusIcon } from '@phosphor-icons/react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/shared/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, dialogFullOnMobile } from '@/shared/ui/dialog'
import { FilterChip } from '@/shared/ui/filter-chip'
import { Input } from '@/shared/ui/input'
import { SelectField } from '@/shared/ui/select-field'
import { currentLocale } from '@/shared/i18n'
import { basisOf, matches, suggestedFor, tacticTranslation, translationOf, type AttackCatalog } from '@/features/threats/attack-catalog'
import type { Component } from '@/features/threats/threat-model-types'

export const TECHNIQUE_ID = /^T\d{4}(\.\d{3})?$/

type Props = {
  attack: AttackCatalog; elements: { id: string; label: string }[]; components: Component[]; workspace?: string[]
  isMapped: (id: string, element: string) => boolean; onPick: (id: string, element: string) => void; describe: (id: string) => string; onClose: () => void
}

// The whole ATT&CK Enterprise catalog, by tactic, searchable; for a component, what MITRE lists for its platforms on top.
export function AttackPicker({ attack, elements, components, workspace = [], isMapped, onPick, describe, onClose }: Props) {
  const { t } = useTranslation('threats')
  const locale = currentLocale()
  const [element, setElement] = useState('')
  const [query, setQuery] = useState('')
  const [tactic, setTactic] = useState('')
  const [open, setOpen] = useState<Record<string, boolean>>({})
  const needle = query.trim().toLowerCase()
  const subs = useMemo(() => {
    const byParent: Record<string, string[]> = {}
    for (const id of Object.keys(attack.techniques)) if (id.includes('.')) (byParent[id.split('.')[0]] ??= []).push(id)
    return byParent
  }, [attack])
  const parents = useMemo(() => Object.keys(attack.techniques).filter(id => !id.includes('.')), [attack])
  const component = components.find(item => item.id === element)
  const basis = component ? basisOf(attack, component) : null
  const inTactic = (id: string) => !tactic || attack.techniques[id][1].includes(tactic)
  const hit = (id: string) => matches(attack, locale, id, needle)
  const suggested = component ? suggestedFor(attack, component).filter(id => inTactic(id) && hit(id)) : []
  // Without a tactic chosen, each technique sits under its first tactic (the others are on its second line).
  const sections = Object.keys(attack.tactics).filter(key => !tactic || key === tactic).map(key => ({
    key, ids: parents.filter(id => (tactic ? attack.techniques[id][1].includes(key) : attack.techniques[id][1][0] === key)
      && (hit(id) || (needle && (subs[id] ?? []).some(hit)))),
  })).filter(section => section.ids.length)
  const typed = query.trim().toUpperCase()
  const outside = TECHNIQUE_ID.test(typed) && !attack.techniques[typed] ? typed : null
  const own = workspace.filter(id => !attack.techniques[id] && id !== outside && (!needle || id.toLowerCase().includes(needle)))
  const found = sections.reduce((total, section) => total + section.ids.length, 0)
  const target = element ? elements.find(item => item.id === element)?.label ?? element : t('manual.whole_system')

  const row = (id: string, depth = 0) => {
    const entry = attack.techniques[id]
    const translation = entry ? translationOf(attack, locale, id) : undefined
    const mapped = isMapped(id, element)
    const parent = depth === 0 && !needle ? subs[id] ?? [] : []
    const shownSubs = depth === 0 && needle ? (subs[id] ?? []).filter(hit) : []
    const expanded = !!open[id]
    return <li key={id}>
      <div className={`flex items-start gap-3 py-2 pr-1 ${depth ? 'pl-6' : 'pl-1'}`}>
        <div className="min-w-0 flex-1">
          <p className="text-sm"><span className="mr-1.5 font-mono text-xs text-app-muted">{id}</span>{entry ? entry[0] : describe(id)}</p>
          {translation && <p lang={locale} className="text-xs text-app-muted">{translation}</p>}
          {entry && <p className="text-[11px] text-app-subtle">{entry[1].map(key => attack.tactics[key] ?? key).join(', ')}</p>}
          {parent.length > 0 && <button type="button" aria-expanded={expanded} onClick={() => setOpen({ ...open, [id]: !expanded })}
            className="mt-0.5 inline-flex min-h-6 items-center gap-1 text-xs text-app-secondary hover:underline">
            <CaretRightIcon className={`size-3 motion-safe:transition-transform ${expanded ? 'rotate-90' : ''}`} />{t('attack.picker.subtechniques', { count: parent.length })}</button>}
        </div>
        {mapped ? <span className="inline-flex min-h-7 items-center gap-1 text-xs text-app-muted"><CheckIcon className="size-3.5" />{t('attack.picker.mapped')}</span>
          : <Button size="xs" variant="outline" aria-label={t('attack.picker.map_to', { id, name: target })} onClick={() => onPick(id, element)}><PlusIcon />{t('attack.picker.map')}</Button>}
      </div>
      {(expanded ? parent : shownSubs).length > 0 && <ul className="divide-y divide-app-line border-t border-app-line">{(expanded ? parent : shownSubs).map(sub => row(sub, 1))}</ul>}
    </li>
  }

  return <Dialog open onOpenChange={next => { if (!next) onClose() }}>
    <DialogContent className={`max-w-3xl gap-4 sm:h-[min(52rem,90vh)] ${dialogFullOnMobile}`}>
      <DialogHeader>
        <DialogTitle>{t('attack.picker.title')}</DialogTitle>
        <DialogDescription>{t('attack.picker.source', { version: attack.version, total: attack.counts.total, techniques: attack.counts.techniques, subtechniques: attack.counts.subtechniques })}</DialogDescription>
      </DialogHeader>
      <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
        <label className="space-y-1"><span className="text-xs font-medium text-app-muted">{t('attack.picker.element')}</span>
          <SelectField aria-label={t('attack.picker.element')} value={element} onValueChange={setElement} placeholder={t('manual.whole_system')} className="text-sm" options={elements.map(item => ({ value: item.id, label: item.label }))} /></label>
        <label className="space-y-1"><span className="text-xs font-medium text-app-muted">{t('attack.picker.search')}</span>
          <span className="relative block"><MagnifyingGlassIcon className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-app-subtle" />
            <Input type="search" autoComplete="off" spellCheck={false} value={query} onChange={event => setQuery(event.target.value)} placeholder={t('attack.picker.search_placeholder')} className="h-8 border-input bg-card pl-8 text-sm" /></span></label>
      </div>
      <div role="group" aria-label={t('attack.picker.tactics')} className="flex gap-1.5 max-sm:-mx-1 max-sm:overflow-x-auto max-sm:px-1 max-sm:pb-1 sm:flex-wrap">
        <FilterChip pressed={!tactic} onClick={() => setTactic('')} className="min-h-6 px-2 text-xs">{t('attack.picker.all_tactics')}</FilterChip>
        {Object.entries(attack.tactics).map(([key, name]) => <FilterChip key={key} pressed={tactic === key} onClick={() => setTactic(tactic === key ? '' : key)} className="min-h-6 px-2 text-xs"
          title={tacticTranslation(attack, locale, key)}>{name}</FilterChip>)}
      </div>
      <div className="-mx-1 min-h-48 flex-1 scroll-pt-9 overflow-y-auto px-1">
        {component && <section aria-labelledby="attack-suggested" className="mb-4">
          <div className="border-b border-app-line py-1.5">
            <h3 id="attack-suggested" className="text-sm font-medium">{t('attack.picker.suggested_for', { name: component.name })}</h3>
            <p className="text-xs text-app-muted">{basis ? t('attack.picker.basis', { platforms: basis.platforms.join(', '), tactics: basis.tactics.map(key => attack.tactics[key]).join(', ') })
              : t(component.kind === 'actor' ? 'attack.picker.no_platform_actor' : 'attack.picker.no_platform_custom')}</p>
          </div>
          {basis && (suggested.length ? <ul className="divide-y divide-app-line">{suggested.map(id => row(id, 0))}</ul>
            : <p className="py-2 text-xs text-app-muted">{t('attack.picker.nothing_suggested')}</p>)}
        </section>}
        {sections.map(section => <section key={section.key} aria-labelledby={`attack-tactic-${section.key}`} className="mb-3">
          <h3 id={`attack-tactic-${section.key}`} className="sticky top-0 z-10 border-b border-app-line bg-panel py-1.5 text-xs font-medium text-app-secondary">
            {attack.tactics[section.key]}{tacticTranslation(attack, locale, section.key) && <span lang={locale} className="font-normal text-app-muted"> · {tacticTranslation(attack, locale, section.key)}</span>}
            <span className="font-normal text-app-muted"> · {t('attack.picker.results', { count: section.ids.length })}</span></h3>
          <ul className="divide-y divide-app-line">{section.ids.map(id => row(id))}</ul>
        </section>)}
        {(outside || own.length > 0) && <section aria-labelledby="attack-outside" className="mb-3">
          <h3 id="attack-outside" className="border-b border-app-line py-1.5 text-xs font-medium text-app-secondary">{t('attack.picker.outside', { version: attack.version })}</h3>
          <ul className="divide-y divide-app-line">{[...(outside ? [outside] : []), ...own].map(id => row(id))}</ul>
        </section>}
        {found === 0 && !outside && !own.length && <p role="status" className="py-6 text-center text-sm text-app-muted">{/^T\d/.test(typed) ? t('attack.technique_format') : t('attack.picker.nothing')}</p>}
      </div>
      <DialogFooter><Button variant="outline" onClick={onClose}>{t('attack.picker.done')}</Button></DialogFooter>
    </DialogContent>
  </Dialog>
}
