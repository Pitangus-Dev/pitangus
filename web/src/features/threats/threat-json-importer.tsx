import { useEffect, useMemo, useRef, useState, type ChangeEvent, type ClipboardEvent, type UIEvent } from 'react'
import { ArrowSquareOutIcon, BracketsCurlyIcon, CaretDownIcon, CaretRightIcon, CheckCircleIcon, CircleNotchIcon, ClipboardTextIcon, DownloadSimpleIcon, FileCodeIcon, InfoIcon, ListPlusIcon, UploadSimpleIcon, WarningIcon, XCircleIcon } from '@phosphor-icons/react'
import { Trans, useTranslation } from 'react-i18next'
import { Button } from '@/shared/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, dialogFullOnMobile } from '@/shared/ui/dialog'
import { Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger } from '@/shared/ui/menu'
import { api, ApiError } from '@/shared/api/http'
import { formatNumber } from '@/shared/i18n/format'
import { methodName, METHOD_ORDER, type Methodology } from '@/features/threats/threat-guides'
import type { View } from '@/features/threats/threat-model-types'
import { IMPORT_SCHEMA, promptValues } from '@/features/threats/import-contract'
import { lineColumn, locate, spanOf, type Span } from '@/features/threats/json-locate'
import { currentLocale, type Locale } from '@/shared/i18n'
import strideEn from '@/examples/threat-models/en/stride.json'
import linddunEn from '@/examples/threat-models/en/linddun.json'
import pastaEn from '@/examples/threat-models/en/pasta.json'
import attackTreesEn from '@/examples/threat-models/en/attack_trees.json'
import attackEn from '@/examples/threat-models/en/attack.json'
import customEn from '@/examples/threat-models/en/custom.json'
import strideEs from '@/examples/threat-models/es/stride.json'
import linddunEs from '@/examples/threat-models/es/linddun.json'
import pastaEs from '@/examples/threat-models/es/pasta.json'
import attackTreesEs from '@/examples/threat-models/es/attack_trees.json'
import attackEs from '@/examples/threat-models/es/attack.json'
import customEs from '@/examples/threat-models/es/custom.json'

const MAX_BYTES = 600_000
export const CHECK_DELAY = 400
const EXAMPLES: Partial<Record<Locale, Record<Methodology, unknown>>> & { en: Record<Methodology, unknown> } = {
  en: { stride: strideEn, linddun: linddunEn, pasta: pastaEn, attack_trees: attackTreesEn, attack: attackEn, custom: customEn },
  es: { stride: strideEs, linddun: linddunEs, pasta: pastaEs, attack_trees: attackTreesEs, attack: attackEs, custom: customEs },
}
const example = (method: Methodology) => (EXAMPLES[currentLocale()] ?? EXAMPLES.en)[method]
const EXAMPLE_HINTS: Record<Methodology, string> = {
  stride: 'importer.hints.stride', linddun: 'importer.hints.linddun', pasta: 'importer.hints.pasta',
  attack_trees: 'importer.hints.attack_trees', attack: 'importer.hints.attack', custom: 'importer.hints.custom',
}

// A problem from the server (a JSON Pointer into the document) or from parsing (a character offset).
// An error blocks the import; a warning means something that matters was changed or couldn't be used; an info is a
// harmless normalization (a synonym read, a field kept as a custom property). `code` is shared by identical problems.
export type Problem = { severity: 'error' | 'warning' | 'info'; path: string; id?: string | null; code?: string; message: string; offset?: number }
type Located = Problem & { span: Span | null; line: number | null; index: number }
type Group = { key: string; severity: Problem['severity']; message: string; items: Located[]; where: string | null }
// Where a group of problems is, by the list their paths go through: «… in 15 flows».
const PLACES: Record<string, string> = { components: 'count.components', flows: 'count.flows', boundaries: 'count.boundaries', manual_threats: 'count.manual_threats',
  attack_trees: 'count.trees', nodes: 'count.steps', attack_mappings: 'count.techniques', assumptions: 'count.assumptions' }
const placeOf = (path: string) => { const parts = path.split('/'); for (let index = parts.length - 2; index >= 0; index -= 1) if (PLACES[parts[index]] && /^\d+$/.test(parts[index + 1] ?? '')) return parts[index]; return null }
type Preview = {
  name: string; methodology: Methodology; components: number; flows: number; boundaries: number
  repository_refs: number; assumptions?: number; manual_threats: number; attack_trees: number; attack_mappings: number; pasta_stages: number; relayout?: boolean
  problems?: Problem[]
}
// What the automatic check knows about the current text.
type Check = { state: 'idle' } | { state: 'checking' } | { state: 'done'; text: string; document: unknown; preview: Preview | null }
  | { state: 'failed'; message: string }

const formatted = (document: unknown) => `${JSON.stringify(document, null, 2)}\n`
const isProblems = (value: unknown): value is Problem[] => Array.isArray(value) && value.every(item => item && typeof item === 'object' && typeof (item as Problem).message === 'string')
// Minified or one-line JSON: a paste worth pretty-printing.
const hasLongLine = (value: string) => value.split('\n').some(line => line.length > 120)

function download(content: string, name: string) {
  const url = URL.createObjectURL(new Blob([content], { type: 'application/json' }))
  const link = document.createElement('a')
  link.href = url; link.download = name
  document.body.append(link); link.click(); link.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 60_000)
}

export function ThreatJsonImporter({ onClose, onImported }: { onClose: () => void; onImported: (id: string) => void }) {
  const { t } = useTranslation('threats')
  const [selected, setSelected] = useState<Methodology | null>(null)
  const [text, setText] = useState('')
  const [check, setCheck] = useState<Check>({ state: 'idle' })
  const [problems, setProblems] = useState<Problem[]>([])
  const [active, setActive] = useState<number | null>(null)
  const [importing, setImporting] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const fileInput = useRef<HTMLInputElement>(null)
  const editor = useRef<HTMLTextAreaElement>(null)
  const backdrop = useRef<HTMLDivElement>(null)
  const timer = useRef<number | undefined>(undefined)
  const sequence = useRef(0)
  useEffect(() => () => window.clearTimeout(timer.current), [])

  // Where each problem is in the current text: by its pointer while the JSON parses, by its offset otherwise.
  const located = useMemo(() => {
    const parsed = problems.some(item => item.offset === undefined) ? locate(text) : null
    const order = { error: 0, warning: 1, info: 2 }
    return [...problems].sort((a, b) => order[a.severity] - order[b.severity]).map((item, index): Located => {
      const span: Span | null = item.offset !== undefined ? { start: item.offset, end: item.offset + 1 }
        : parsed?.ok ? spanOf(parsed.spans, item.path) : null
      return { ...item, span, line: span ? lineColumn(text, span.start).line : null, index }
    })
  }, [problems, text])
  const errors = located.filter(item => item.severity === 'error')
  const warnings = located.filter(item => item.severity === 'warning')
  const infos = located.filter(item => item.severity === 'info')
  const ordered = located
  // Identical problems (same code) read as one row, «… in 15 flows», that opens to each place.
  const grouped = (items: Located[]): Group[] => {
    const groups = new Map<string, Located[]>()
    for (const item of items) { const key = item.code || item.message; groups.set(key, [...(groups.get(key) ?? []), item]) }
    return [...groups.entries()].map(([key, members]) => {
      const places = new Set(members.map(member => placeOf(member.path)))
      const place = places.size === 1 ? [...places][0] : null
      return { key, severity: members[0].severity, message: members[0].message, items: members,
               where: members.length < 2 ? null : place ? t('importer.group_in', { place: t(PLACES[place], { count: members.length }) }) : t('importer.group_times', { count: members.length }) }
    })
  }
  const ready = check.state === 'done' && check.text === text && check.preview !== null && errors.length === 0

  // Parses locally first (a syntax error gets its line and column without asking the server), then asks the server.
  const runCheck = async (value: string) => {
    const run = ++sequence.current
    if (new Blob([value]).size > MAX_BYTES) { setProblems([]); setCheck({ state: 'failed', message: t('importer.json_too_large') }); return }
    const parsed = locate(value)
    if (!parsed.ok) {
      const { line, column } = lineColumn(value, parsed.offset)
      setProblems([{ severity: 'error', path: '', message: t('importer.parse_error', { line, column }), offset: parsed.offset }])
      setCheck({ state: 'done', text: value, document: null, preview: null })
      return
    }
    try {
      const preview = await api.post<Preview>('/api/threat-models/validate', 'validate-threat-model', parsed.value)
      if (run !== sequence.current) return
      setProblems(preview.problems ?? []); setCheck({ state: 'done', text: value, document: parsed.value, preview })
    } catch (caught) {
      if (run !== sequence.current) return
      if (caught instanceof ApiError && isProblems(caught.details) && caught.details.length) {
        setProblems(caught.details); setCheck({ state: 'done', text: value, document: parsed.value, preview: null })
      } else { setProblems([]); setCheck({ state: 'failed', message: caught instanceof Error ? caught.message : String(caught) }) }
    }
  }
  const changeText = (value: string, delay = CHECK_DELAY) => {
    setText(value); setActive(null); setError('')
    window.clearTimeout(timer.current)
    sequence.current += 1
    if (!value.trim()) { setProblems([]); setCheck({ state: 'idle' }); return }
    setCheck({ state: 'checking' })
    timer.current = window.setTimeout(() => void runCheck(value), delay)
  }
  const toTop = () => window.requestAnimationFrame(() => {
    const area = editor.current
    if (!area) return
    area.setSelectionRange(0, 0); area.scrollTop = 0; area.scrollLeft = 0; syncBackdrop(area)
  })
  const chooseExample = (method: Methodology) => {
    setSelected(method); setNotice('')
    changeText(formatted(example(method)), 0)
    toTop()
  }
  const loadFile = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    if (file.size > MAX_BYTES) { setError(t('importer.file_too_large')); return }
    const content = await file.text()
    const parsed = locate(content)
    setSelected(null)
    changeText(parsed.ok && hasLongLine(content) ? formatted(parsed.value) : content, 0)
    setNotice(t('importer.file_loaded', { name: file.name }))
    toTop()
  }
  // Pasting minified JSON that parses: pretty-print it so it can be read, and start at the top.
  const paste = (event: ClipboardEvent<HTMLTextAreaElement>) => {
    const pasted = event.clipboardData.getData('text/plain')
    const area = event.currentTarget
    const whole = area.selectionStart === 0 && area.selectionEnd === area.value.length
    const next = area.value.slice(0, area.selectionStart) + pasted + area.value.slice(area.selectionEnd)
    if (!whole && !hasLongLine(pasted)) return
    const parsed = locate(next)
    if (!parsed.ok) return
    event.preventDefault()
    if (whole) setSelected(null)
    setNotice('')
    changeText(formatted(parsed.value))
    toTop()
  }
  const formatJson = () => {
    const parsed = locate(text)
    if (!parsed.ok) { void runCheck(text); return }
    changeText(formatted(parsed.value), 0)
    setNotice(t('importer.formatted'))
  }
  const importModel = async () => {
    if (!ready || check.state !== 'done') return
    setImporting(true); setError('')
    try {
      const imported = await api.post<View>('/api/threat-models/import', 'import-threat-model', check.document)
      onImported(imported.model.id)
    } catch (caught) {
      if (caught instanceof ApiError && isProblems(caught.details) && caught.details.length) setProblems(caught.details)
      setError(caught instanceof Error ? caught.message : String(caught))
    } finally { setImporting(false) }
  }
  const copy = async (value: string, message: string) => {
    try { await navigator.clipboard.writeText(value); setNotice(message); setError('') }
    catch { setError(t('importer.copy_failed')) }
  }
  const prompt = t('importer.ai_prompt', promptValues(currentLocale(), text.trim()))

  const goTo = (index: number) => {
    const item = ordered[index]
    setActive(index)
    const area = editor.current
    if (!item?.span || !area) return
    area.focus()
    area.setSelectionRange(item.span.start, Math.max(item.span.start, Math.min(item.span.end, text.length)))
    // The line's mark in the backdrop has the same geometry as the text: scroll so it sits in the upper third.
    window.requestAnimationFrame(() => {
      const mark = backdrop.current?.querySelector<HTMLElement>('[data-active]')
      if (mark) area.scrollTop = Math.max(0, mark.offsetTop - area.clientHeight / 3)
      syncBackdrop(area)
    })
  }
  // The highlights move with the text by translation, not by scrolling a second box: a scrolling box stops at its own
  // limits (it has no scrollbars), so on long lines it drifted away from the text.
  const syncBackdrop = (area: HTMLTextAreaElement) => {
    if (backdrop.current) backdrop.current.style.transform = `translate(${-area.scrollLeft}px, ${-area.scrollTop}px)`
  }
  const activeLine = active !== null ? ordered[active]?.line ?? null : null
  const marks = marked(text, ordered.filter(item => item.line !== null && item.severity !== 'info').map(item => ({ line: item.line!, severity: item.severity as 'error' | 'warning' })))
  const preview = check.state === 'done' && check.text === text ? check.preview : null
  const counts = preview ? [
    t('count.components', { count: preview.components }), t('count.flows', { count: preview.flows }),
    ...([['count.boundaries', preview.boundaries], ['count.assumptions', preview.assumptions ?? 0], ['count.manual_threats', preview.manual_threats], ['count.trees', preview.attack_trees],
      ['count.techniques', preview.attack_mappings], ['count.pasta_stages', preview.pasta_stages], ['count.pending_refs', preview.repository_refs]] as const)
      .filter(([, count]) => count > 0).map(([key, count]) => t(key, { count })),
  ] : []

  const help = <p className="text-xs leading-5 text-app-muted"><Trans t={t} i18nKey="importer.how" components={{
    code: <code className="font-mono text-app-secondary" />,
    docs: <a href={t('importer.docs_url')} target="_blank" rel="noopener noreferrer" className="inline-flex min-h-6 items-center gap-1 text-brand underline underline-offset-2" />,
    external: <><ArrowSquareOutIcon className="size-3" /><span className="sr-only">{t('sources:new_tab')}</span></>,
  }} /></p>

  return <Dialog open onOpenChange={next => { if (!next && !importing) onClose() }}>
    <DialogContent className={`h-[min(calc(100dvh-2rem),54rem)] max-h-[calc(100dvh-2rem)] max-w-6xl gap-0 overflow-hidden p-0 ${dialogFullOnMobile}`}>
      <DialogHeader className="border-b border-app-line pt-4 pr-12 pb-3 pl-4 sm:pl-6">
        <DialogTitle className="flex items-center gap-2"><FileCodeIcon className="size-5 shrink-0 text-brand" />{t('importer.title')}</DialogTitle>
        <DialogDescription>{t('importer.description')}</DialogDescription>
      </DialogHeader>
      <div className="flex min-h-0 flex-1 flex-col overflow-y-auto px-4 py-4 sm:px-6">
        <div className="flex flex-1 flex-col gap-4 lg:flex-row lg:gap-6">
          <section aria-labelledby="import-examples" className="space-y-2 lg:flex lg:w-56 lg:shrink-0 lg:flex-col">
            <h3 id="import-examples" className="text-sm font-semibold">{t('importer.examples_heading')}</h3>
            <div className="flex flex-wrap gap-1.5 lg:flex-col lg:flex-nowrap">{METHOD_ORDER.map(method => <button key={method} type="button" aria-pressed={selected === method} onClick={() => chooseExample(method)}
              className={`min-h-7 rounded-md border px-2.5 py-1 text-left lg:py-2 ${selected === method ? 'border-app-fg bg-app-soft' : 'border-input bg-card hover:bg-app-soft'}`}>
              <span className="block text-xs font-medium lg:text-sm">{methodName(method)}</span><span className="mt-0.5 hidden text-xs leading-4 text-app-muted lg:block">{t(EXAMPLE_HINTS[method])}</span>
            </button>)}</div>
            <div className="hidden pt-2 lg:mt-auto lg:block">{help}</div>
          </section>
          <section aria-labelledby="import-editor" className="flex min-h-0 min-w-0 flex-1 flex-col gap-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h3 id="import-editor" className="text-sm font-semibold">{t('importer.edit_heading')}</h3>
              <input ref={fileInput} type="file" accept=".json,application/json" className="hidden" aria-label={t('importer.file_label')} onChange={event => void loadFile(event)} />
              <div className="flex flex-wrap gap-2">
                <Button size="sm" variant="outline" onClick={() => void copy(prompt, t('importer.prompt_copied'))}><ListPlusIcon />{t('importer.copy_prompt')}</Button>
                <Button size="sm" variant="outline" className="max-sm:hidden" onClick={() => fileInput.current?.click()}><UploadSimpleIcon />{t('importer.load_file')}</Button>
                <Menu><MenuTrigger render={<Button size="sm" variant="outline" />}>{t('importer.more')}<CaretDownIcon /></MenuTrigger>
                  <MenuContent>
                    <MenuItem className="sm:hidden" onClick={() => fileInput.current?.click()}><UploadSimpleIcon />{t('importer.load_file')}</MenuItem>
                    <MenuItem disabled={!text.trim()} onClick={formatJson}><BracketsCurlyIcon />{t('importer.format')}</MenuItem>
                    <MenuItem disabled={!text.trim()} onClick={() => void copy(text, t('importer.json_copied'))}><ClipboardTextIcon />{t('importer.copy_json')}</MenuItem>
                    <MenuItem disabled={!text.trim()} onClick={() => download(text, t('importer.file_name', { method: selected ?? t('importer.file_edited') }))}><DownloadSimpleIcon />{t('importer.download_json')}</MenuItem>
                    <MenuSeparator />
                    <MenuItem onClick={() => download(`${JSON.stringify(IMPORT_SCHEMA, null, 2)}\n`, t('importer.schema_file_name'))}><DownloadSimpleIcon />{t('importer.download_schema')}</MenuItem>
                  </MenuContent>
                </Menu>
              </div>
            </div>
            <div className="relative min-h-56 flex-1 overflow-hidden rounded-lg border border-input bg-card focus-within:border-focus focus-within:shadow-[inset_0_0_0_1px_var(--focus)]">
              <div ref={backdrop} aria-hidden className="pointer-events-none absolute top-0 left-0 p-3 font-mono text-[11px] leading-[1.55] whitespace-pre text-transparent">
                {marks.map((piece, index) => piece.severity ? <mark key={index} data-active={piece.line === activeLine || undefined}
                  className={`rounded-sm text-transparent ${piece.severity === 'error' ? 'bg-danger-soft' : 'bg-attention-soft'} ${piece.line === activeLine ? (piece.severity === 'error' ? 'outline outline-1 outline-danger-line' : 'outline outline-1 outline-attention-line') : ''}`}>{piece.text}</mark> : piece.text)}{'\n'}
              </div>
              {!text && <p id="import-empty" className="pointer-events-none absolute inset-x-0 top-0 p-3 text-sm text-app-muted">{t('importer.empty_state')}</p>}
              <textarea ref={editor} aria-label={t('importer.editor')} aria-describedby={text ? 'import-status' : 'import-empty'} aria-invalid={errors.length > 0 || undefined} spellCheck={false} wrap="off" value={text}
                onChange={event => { setNotice(''); changeText(event.target.value) }} onPaste={paste} onScroll={(event: UIEvent<HTMLTextAreaElement>) => syncBackdrop(event.currentTarget)}
                className="absolute inset-0 h-full w-full resize-none overflow-auto bg-transparent p-3 font-mono text-[11px] leading-[1.55] whitespace-pre text-app-fg outline-none" />
            </div>
            <div id="import-status" role="status" className="min-h-6 text-sm">
              {check.state === 'checking' && <p className="flex items-center gap-2 text-app-muted"><CircleNotchIcon className="size-4 shrink-0 motion-safe:animate-spin" />{t('importer.status_checking')}</p>}
              {check.state === 'failed' && <p className="flex flex-wrap items-center gap-x-2"><XCircleIcon className="size-4 shrink-0 text-danger" />{check.message}
                <Button size="xs" variant="ghost" onClick={() => { setCheck({ state: 'checking' }); void runCheck(text) }}>{t('common:actions.retry')}</Button></p>}
              {check.state === 'done' && check.text === text && (errors.length > 0 || preview) && <>
                <p className="flex items-start gap-2 font-medium">
                  {errors.length ? <XCircleIcon className="mt-0.5 size-4 shrink-0 text-danger" /> : warnings.length ? <WarningIcon className="mt-0.5 size-4 shrink-0 text-attention" /> : <CheckCircleIcon className="mt-0.5 size-4 shrink-0 text-success" />}
                  {errors.length ? t('importer.status_errors', { count: errors.length }) : warnings.length ? t('importer.status_ready_warnings', { count: warnings.length }) : t('importer.status_ready')}
                </p>
                {preview && !errors.length && <p className="pl-6 text-xs leading-5 text-app-muted">{t('importer.summary', { name: preview.name, method: methodName(preview.methodology), counts: new Intl.ListFormat(currentLocale(), { type: 'conjunction' }).format(counts) })}</p>}
                {preview?.relayout && !errors.length && <p className="pl-6 text-xs leading-5 text-app-muted">{t('importer.relayout')}</p>}
              </>}
            </div>
            {ordered.length > 0 && check.state === 'done' && <section aria-label={t('importer.problems_title')} className="max-h-48 shrink-0 overflow-y-auto rounded-lg border border-app-line bg-panel p-1">
              {([['error', errors, 'importer.errors_heading'], ['warning', warnings, 'importer.warnings_heading']] as const).map(([severity, items, heading]) => items.length > 0 && <div key={severity}>
                <h4 className="px-2 pt-1.5 pb-1 text-xs font-medium text-app-muted">{t(heading)}</h4>
                <ul>{grouped(items).map(group => <ProblemGroup key={group.key} group={group} active={active} onGo={goTo} />)}</ul>
              </div>)}
              {infos.length > 0 && <details className="group/infos">
                <summary className="flex min-h-6 cursor-pointer list-none items-center gap-1.5 px-2 py-1.5 text-xs text-app-muted [&::-webkit-details-marker]:hidden">
                  <CaretRightIcon className="size-3 motion-safe:transition-transform group-open/infos:rotate-90" />{t('importer.minor', { count: infos.length })}</summary>
                <ul>{grouped(infos).map(group => <ProblemGroup key={group.key} group={group} active={active} onGo={goTo} />)}</ul>
              </details>}
            </section>}
            <details className="group text-xs lg:hidden"><summary className="flex min-h-6 cursor-pointer list-none items-center gap-1 text-app-muted [&::-webkit-details-marker]:hidden"><CaretRightIcon className="size-3 motion-safe:transition-transform group-open:rotate-90" />{t('importer.how_title')}</summary><div className="pt-1">{help}</div></details>
          </section>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-2 border-t border-app-line px-4 py-3 sm:px-6">
        <div className="mr-auto min-w-0 text-xs">
          <p role="alert" className="text-danger empty:hidden">{error}</p>
          <p role="status" className="text-app-muted empty:hidden">{error ? '' : notice}</p>
          {!error && !notice && <p className="text-app-muted tabular-nums max-sm:hidden">{t('importer.size', { size: formatNumber(new Blob([text]).size), max: formatNumber(MAX_BYTES) })}</p>}
        </div>
        <div className="ml-auto flex gap-2"><Button variant="ghost" disabled={importing} onClick={onClose}>{t('common:actions.cancel')}</Button>
        <Button disabled={importing || !ready} onClick={() => void importModel()}>{importing ? <CircleNotchIcon className="motion-safe:animate-spin" /> : <UploadSimpleIcon />}{t('importer.import')}</Button></div>
      </div>
    </DialogContent>
  </Dialog>
}

// One problem, or several identical ones: the row says how many and where, and opens to each place.
function ProblemGroup({ group, active, onGo }: { group: Group; active: number | null; onGo: (index: number) => void }) {
  const { t } = useTranslation('threats')
  const [open, setOpen] = useState(false)
  const Icon = group.severity === 'error' ? XCircleIcon : group.severity === 'warning' ? WarningIcon : InfoIcon
  const tone = group.severity === 'error' ? 'text-danger' : group.severity === 'warning' ? 'text-attention' : 'text-info'
  const where = (item: Located) => item.line ? (item.id ? t('importer.location_id', { line: item.line, id: item.id }) : t('importer.location', { line: item.line })) : null
  const row = 'flex w-full items-start gap-2 rounded-md border px-2.5 py-1.5 text-left text-xs hover:bg-app-soft'
  if (group.items.length === 1) {
    const [item] = group.items
    const place = where(item)
    return <li><button type="button" aria-current={active === item.index || undefined} onClick={() => onGo(item.index)} aria-label={place ? t('importer.go_to', { location: place, message: item.message }) : item.message}
      className={`${row} ${active === item.index ? 'border-app-fg bg-app-soft' : 'border-transparent'}`}>
      <Icon aria-hidden className={`mt-px size-4 shrink-0 ${tone}`} />
      <span className="min-w-0 flex-1"><span className="block text-app-fg">{item.message}</span>{place && <span className="block text-[11px] text-app-subtle">{place}{item.path && <span className="font-mono"> · {item.path}</span>}</span>}</span>
    </button></li>
  }
  return <li>
    <button type="button" aria-expanded={open} onClick={() => setOpen(!open)} className={`${row} border-transparent`}>
      <Icon aria-hidden className={`mt-px size-4 shrink-0 ${tone}`} />
      <span className="min-w-0 flex-1"><span className="block text-app-fg">{group.message}</span><span className="block text-[11px] text-app-subtle">{group.where}</span></span>
      <CaretDownIcon aria-hidden className={`mt-0.5 size-3.5 shrink-0 text-app-subtle motion-safe:transition-transform ${open ? 'rotate-180' : ''}`} />
    </button>
    {open && <ul className="ml-6">{group.items.map(item => { const place = where(item) ?? item.path
      return <li key={item.index}><button type="button" aria-current={active === item.index || undefined} onClick={() => onGo(item.index)} aria-label={t('importer.go_to', { location: place, message: item.message })}
        className={`${row} py-1 ${active === item.index ? 'border-app-fg bg-app-soft' : 'border-transparent'}`}>
        <span className="min-w-0 flex-1 text-[11px] text-app-secondary">{place}{item.path && <span className="font-mono text-app-subtle"> · {item.path}</span>}</span>
      </button></li> })}</ul>}
  </li>
}

// The text split so the lines with problems can be painted behind the editor (errors win over warnings).
function marked(text: string, lines: { line: number; severity: 'error' | 'warning' }[]) {
  const worst = new Map<number, 'error' | 'warning'>()
  for (const item of lines) if (worst.get(item.line) !== 'error') worst.set(item.line, item.severity)
  if (!worst.size) return [{ text, severity: null, line: 0 }]
  const pieces: { text: string; severity: 'error' | 'warning' | null; line: number }[] = []
  let start = 0, line = 1, plain = 0
  for (let index = 0; index <= text.length; index += 1) {
    if (index < text.length && text[index] !== '\n') continue
    const severity = worst.get(line)
    if (severity) {
      if (start > plain) pieces.push({ text: text.slice(plain, start), severity: null, line: 0 })
      pieces.push({ text: text.slice(start, index) || ' ', severity, line })
      plain = index
    }
    start = index + 1
    line += 1
  }
  if (plain < text.length) pieces.push({ text: text.slice(plain), severity: null, line: 0 })
  return pieces
}
