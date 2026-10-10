import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Search } from 'lucide-react'
import { assetSearchQuery, domainsQuery, runSearchQuery } from '@/shared/api/queries'
import { useDebounced } from '@/shared/lib/useDebounced'
import { formatDate } from '@/shared/i18n/format'
import { Dialog, DialogContent, DialogTitle } from '@/shared/ui/dialog'
import { Kbd, Keys } from '@/shared/ui/kbd'
import type { Asset } from '@/features/sources/asset-option'
import type { RunRow } from '@/shared/lib/types'
import { visibleNavigation, type View } from '@/app/navigation'

type Item = { id: string; label: string; hint?: string; keywords?: string; keys?: string[]; run: () => void; opensDialog?: boolean }
type Group = { id: string; label: string; items: Item[] }

export type PaletteProps = {
  open: boolean
  onOpenChange: (open: boolean) => void
  admin: boolean
  onView: (view: View) => void
  onImport: () => void
  onAddDomain: () => void
  onHelp: () => void
  onOpenRun: (id: string) => void
  onOpenDomain: (id: string) => void
  onOpenAsset: (key: string) => void
}

const ENTITY_LIMIT = 5
const RUN_TYPE = { repository_scan: 'analyses:run_type.repository_scan', image_scan: 'analyses:run_type.image_scan', dast_scan: 'analyses:run_type.dast_scan', pr_review: 'analyses:run_type.pr_review', advisory_watch: 'analyses:run_type.advisory_watch', sarif_import: 'analyses:run_type.sarif_import' } as const

// Accents and case don't matter: "analisis" finds "Análisis".
const fold = (text: string) => text.normalize('NFD').replace(/\p{Diacritic}/gu, '').toLowerCase()
const matches = (needle: string, ...texts: (string | undefined)[]) => {
  const words = fold(needle).split(/\s+/).filter(Boolean)
  const haystack = fold(texts.filter(Boolean).join(' '))
  return words.every(word => haystack.includes(word))
}

export function CommandPalette(props: PaletteProps) {
  const { open, onOpenChange } = props
  // Opened from the keyboard there is no trigger to go back to: remember the last focus outside any dialog, and return
  // it on close, unless the chosen action opened a dialog of its own.
  const lastFocus = useRef<HTMLElement | null>(null)
  const handedOff = useRef(false)
  useEffect(() => {
    if (open) return
    handedOff.current = false
    const remember = (element: EventTarget | null) => {
      if (element instanceof HTMLElement && element !== document.body && !element.closest('[role="dialog"], [role="alertdialog"]')) lastFocus.current = element
    }
    const track = (event: FocusEvent) => remember(event.target)
    remember(document.activeElement)
    document.addEventListener('focusin', track)
    return () => document.removeEventListener('focusin', track)
  }, [open])
  const finalFocus = () => handedOff.current ? false : lastFocus.current?.isConnected ? lastFocus.current : true
  return <Dialog open={open} onOpenChange={onOpenChange}>
    <DialogContent showCloseButton={false} finalFocus={finalFocus}
      className="top-[12vh] max-h-[76vh] max-w-xl translate-y-0 gap-0 overflow-hidden rounded-xl p-0">
      {open && <PaletteBody {...props} onHandOff={() => { handedOff.current = true }} />}
    </DialogContent>
  </Dialog>
}

function PaletteBody({ admin, onOpenChange, onView, onImport, onAddDomain, onHelp, onOpenRun, onOpenDomain, onOpenAsset, onHandOff }: PaletteProps & { onHandOff: () => void }) {
  const { t } = useTranslation('nav')
  const [text, setText] = useState('')
  const needle = text.trim()
  const q = useDebounced(needle, 200)
  const listId = useId(), inputId = useId()
  const runs = useQuery(runSearchQuery(q, ENTITY_LIMIT))
  const assets = useQuery({ ...assetSearchQuery<Asset>(q), enabled: q.length > 0 })
  const domains = useQuery({ ...domainsQuery(), enabled: q.length > 0 })

  const groups = useMemo<Group[]>(() => {
    const close = (run: () => void, dialog = false) => () => { if (dialog) onHandOff(); onOpenChange(false); run() }
    const actions: Item[] = [
      { id: 'action-new', label: t('palette.actions.new_scan'), keys: ['N'], run: close(() => onView('new')) },
      { id: 'action-import', label: t('palette.actions.import_sarif'), run: close(onImport) },
      ...(admin ? [{ id: 'action-domain', label: t('palette.actions.add_domain'), run: close(onAddDomain, true), opensDialog: true }] : []),
      { id: 'action-connect', label: t('palette.actions.connect_provider'), run: close(() => onView('integrations')) },
      { id: 'action-help', label: t('palette.actions.shortcuts'), keys: ['?'], run: close(onHelp, true), opensDialog: true },
    ]
    const pages: Item[] = visibleNavigation(admin).flatMap(group => group.items.map(item => ({
      id: `page-${item.id}`, label: t(item.label), keywords: t(group.label), keys: ['G', item.go.toUpperCase()], run: close(() => onView(item.id)),
    })))
    const filter = (items: Item[]) => needle ? items.filter(item => matches(needle, item.label, item.keywords)) : items
    // Entities only once the debounced search caught up, so a stale page doesn't flash under a new query.
    const settled = q === needle
    const runItems: Item[] = settled ? (runs.data?.items ?? []).map((run: RunRow) => ({
      id: `run-${run.id}`, label: run.source?.name ?? run.target ?? run.id.slice(0, 8),
      hint: `${run.type in RUN_TYPE ? t(RUN_TYPE[run.type as keyof typeof RUN_TYPE]) : run.type} · ${formatDate(run.created_at)}`,
      run: close(() => onOpenRun(run.id)),
    })) : []
    const assetItems: Item[] = settled && q ? (assets.data?.items ?? []).slice(0, ENTITY_LIMIT).map(asset => ({
      id: `asset-${asset.key}`, label: asset.name, hint: asset.open ? t('palette.open_findings', { count: asset.open.total }) : undefined,
      run: close(() => onOpenAsset(asset.key)),
    })) : []
    const domainRows = settled && q ? (domains.data?.items ?? []).filter(domain => matches(q, domain.host, domain.url)) : []
    const domainItems: Item[] = domainRows.slice(0, ENTITY_LIMIT).map(domain => ({ id: `domain-${domain.id}`, label: domain.host, hint: domain.url, run: close(() => onOpenDomain(domain.id)) }))
    const viewAll = (view: View, label: string, total: number, shown: number): Item[] =>
      total > shown ? [{ id: `all-${view}`, label, run: close(() => onView(view)) }] : []
    return [
      { id: 'actions', label: t('palette.groups.actions'), items: filter(actions) },
      { id: 'runs', label: needle ? t('palette.groups.runs') : t('palette.groups.recent_runs'), items: [...runItems, ...viewAll('analyses', t('palette.view_all.runs'), runs.data?.total ?? 0, runItems.length)] },
      { id: 'assets', label: t('palette.groups.assets'), items: [...assetItems, ...viewAll('repositories', t('palette.view_all.repositories'), assets.data?.total ?? 0, assetItems.length)] },
      { id: 'domains', label: t('palette.groups.domains'), items: [...domainItems, ...viewAll('domains', t('palette.view_all.domains'), domainRows.length, domainItems.length)] },
      { id: 'pages', label: t('palette.groups.pages'), items: filter(pages) },
    ].filter(group => group.items.length > 0)
  }, [t, admin, needle, q, runs.data, assets.data, domains.data, onOpenChange, onView, onImport, onAddDomain, onHelp, onOpenRun, onOpenDomain, onOpenAsset, onHandOff])

  const flat = useMemo(() => groups.flatMap(group => group.items), [groups])
  const [activeId, setActiveId] = useState<string | null>(null)
  // The highlight follows the results: the first one when what was highlighted is gone.
  const active = flat.find(item => item.id === activeId) ?? flat[0]
  const optionId = (item: Item) => `${listId}-${item.id}`
  const activeOption = active ? optionId(active) : undefined
  useEffect(() => { if (activeOption) document.getElementById(activeOption)?.scrollIntoView?.({ block: 'nearest' }) }, [activeOption])

  const move = (step: number) => {
    if (!flat.length) return
    const index = active ? flat.indexOf(active) : -1
    setActiveId(flat[(index + step + flat.length) % flat.length].id)
  }
  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown') { event.preventDefault(); move(1) }
    else if (event.key === 'ArrowUp') { event.preventDefault(); move(-1) }
    else if (event.key === 'Enter' && active) { event.preventDefault(); active.run() }
  }

  const searching = needle.length > 0 && (q !== needle || runs.isFetching || assets.isFetching || domains.isFetching)
  return <>
    <DialogTitle className="sr-only">{t('palette.title')}</DialogTitle>
    <div className="flex items-center gap-2 border-b border-app-line px-4 has-[input:focus-visible]:border-app-fg">
      <Search aria-hidden className="size-4 shrink-0 text-app-subtle" />
      <label htmlFor={inputId} className="sr-only">{t('palette.search_label')}</label>
      <input id={inputId} autoFocus value={text} onChange={event => { setText(event.target.value); setActiveId(null) }} onKeyDown={onKeyDown}
        role="combobox" aria-expanded="true" aria-controls={listId} aria-autocomplete="list" aria-activedescendant={activeOption}
        data-bare placeholder={t('palette.placeholder')} autoComplete="off" spellCheck={false}
        className="h-12 min-w-0 flex-1 bg-transparent text-sm text-app-fg placeholder:text-app-subtle" />
    </div>
    <div id={listId} role="listbox" aria-label={t('palette.results')} className="min-h-0 flex-1 overflow-y-auto p-2">
      {groups.map(group => <div key={group.id} role="group" aria-labelledby={`${listId}-${group.id}-label`} className="py-1">
        <div id={`${listId}-${group.id}-label`} role="presentation" className="px-2 pt-1 pb-1.5 text-xs text-app-subtle">{group.label}</div>
        {group.items.map(item => {
          const selected = item.id === active?.id
          return <div key={item.id} id={optionId(item)} role="option" aria-selected={selected}
            onPointerMove={() => { if (!selected) setActiveId(item.id) }} onPointerDown={event => event.preventDefault()} onClick={item.run}
            className={`flex min-h-8 cursor-pointer items-center gap-3 rounded-lg px-2 py-1.5 text-sm ${selected ? 'bg-app-soft text-app-fg shadow-[inset_2px_0_0_var(--brand)] ring-1 ring-app-line' : 'text-app-secondary'}`}>
            <span className="min-w-0 flex-1 truncate">{item.label}{item.opensDialog && '…'}</span>
            {item.hint && <span className="hidden max-w-[45%] truncate text-xs text-app-subtle sm:block">{item.hint}</span>}
            {item.keys && <Keys keys={item.keys} />}
          </div>
        })}
      </div>)}
      {!groups.length && !searching && <p className="px-2 py-6 text-center text-sm text-app-muted">{t('palette.empty', { query: needle })}</p>}
    </div>
    <div className="flex items-center justify-between gap-3 border-t border-app-line px-4 py-2 text-xs text-app-subtle">
      <span role="status" aria-live="polite">{searching ? t('palette.searching') : needle ? t('palette.count', { count: flat.length }) : ''}</span>
      <span aria-hidden className="hidden items-center gap-3 sm:flex">
        <span className="inline-flex items-center gap-1"><Kbd>↑</Kbd><Kbd>↓</Kbd>{t('palette.hint.move')}</span>
        <span className="inline-flex items-center gap-1"><Kbd>↵</Kbd>{t('palette.hint.open')}</span>
        <span className="inline-flex items-center gap-1"><Kbd>Esc</Kbd>{t('palette.hint.close')}</span>
      </span>
    </div>
  </>
}
