import { useState, type FormEvent, type ReactNode } from 'react'
import { ArrowSquareOutIcon, BookOpenIcon, CaretRightIcon, CircleNotchIcon, GitBranchIcon, PlusIcon, TargetIcon, TrashIcon, XIcon } from '@phosphor-icons/react'
import { useTranslation } from 'react-i18next'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { Input } from '@/shared/ui/input'
import { SelectField } from '@/shared/ui/select-field'
import { ValueCombobox } from '@/shared/ui/value-combobox'
import { currentLocale } from '@/shared/i18n'
import { attackUrl, guideOf, methodName, METHOD_ORDER, type Methodology } from '@/features/threats/threat-guides'
import { baseKind } from '@/features/threats/threat-layout'
import { elementsOf, newId, type AttackMapping, type AttackTree, type Catalog, type Level, type LevelEquivalents, type ManualThreat, type Model, type Threat, type TreeNode } from '@/features/threats/threat-model-types'
import { CustomPropertiesField, ValueView } from '@/features/threats/threat-properties'
import { headingOf } from '@/features/threats/property-values'

// Each modeling approach's own sections and its reference guide.

const select = 'text-xs'
const inline = 'w-fit text-xs'
const area = 'w-full rounded-lg border border-input bg-card px-3 py-2 text-sm leading-6 text-app-fg'
// Catalog keys: levels in `threats`, severities in `common`.
const LEVELS: Record<Level, string> = { low: 'level.low', medium: 'level.medium', high: 'level.high' }
const SEVERITIES = { critical: 'common:severity.critical', high: 'common:severity.high', medium: 'common:severity.medium', low: 'common:severity.low' } as const
const SEVERITY_COUNT = { critical: 'pasta.severity_count.critical', high: 'pasta.severity_count.high', medium: 'pasta.severity_count.medium', low: 'pasta.severity_count.low' } as const

// The server sends the English ATT&CK name plus a Spanish one.
const TECHNIQUE_ID = /^T\d{4}(\.\d{3})?$/
const techniqueName = (item?: { name: string; name_es?: string }) => item ? (currentLocale() === 'es' && item.name_es ? item.name_es : item.name) : undefined


// ------------------------------------------------------------------ choosing an approach

export function MethodPicker({ value, onChange }: { value: Methodology; onChange: (next: Methodology) => void }) {
  const { t } = useTranslation('threats')
  return <div role="radiogroup" aria-label={t('methods.picker_label')} className="grid gap-2 sm:grid-cols-2">
    {METHOD_ORDER.map(key => <button key={key} type="button" role="radio" aria-checked={value === key} onClick={() => onChange(key)}
      className={`rounded-xl border p-3 text-left transition ${value === key ? 'border-app-fg bg-app-soft' : 'border-input bg-card hover:border-app-faint'}`}>
      <span className="flex items-center justify-between gap-2"><span className="text-sm font-semibold">{methodName(key)}</span>{key === 'stride' && <Badge variant="outline" className="border-app-line text-[11px] text-app-subtle">{t('methods.recommended')}</Badge>}</span>
      <span className="mt-1 block text-xs leading-5 text-app-muted">{guideOf(key).purpose}</span>
    </button>)}
  </div>
}

export function MethodDialog({ current, onClose, onPick }: { current: Methodology; onClose: () => void; onPick: (next: Methodology) => void }) {
  const { t } = useTranslation('threats')
  const [value, setValue] = useState<Methodology>(current)
  return <Dialog open onOpenChange={next => { if (!next) onClose() }}><DialogContent className="max-w-2xl">
    <DialogHeader><DialogTitle>{t('methods.dialog_title')}</DialogTitle><DialogDescription>{t('methods.dialog_description')}</DialogDescription></DialogHeader>
    <MethodPicker value={value} onChange={setValue} />
    <DialogFooter><Button variant="ghost" onClick={onClose}>{t('common:actions.cancel')}</Button><Button onClick={() => onPick(value)}>{t('methods.use', { name: methodName(value) })}</Button></DialogFooter>
  </DialogContent></Dialog>
}

// ------------------------------------------------------------------ reference guide

export function GuidePanel({ methodology, onClose }: { methodology: Methodology; onClose: () => void }) {
  const { t } = useTranslation('threats')
  const guide = guideOf(methodology)
  return <aside aria-label={t('guide.title', { name: guide.name })} className="space-y-4 rounded-lg border border-app-line bg-panel p-4 text-sm xl:sticky xl:top-20 xl:max-h-[calc(100vh-6rem)] xl:overflow-y-auto">
    <div className="flex items-start justify-between gap-2"><p className="flex items-center gap-2 font-semibold"><BookOpenIcon className="size-4 text-brand" />{t('guide.title', { name: guide.name })}</p>
      <Button size="icon-sm" variant="ghost" aria-label={t('guide.close')} onClick={onClose}><XIcon /></Button></div>
    <p className="text-app-secondary">{guide.purpose}</p>
    <p className="text-xs leading-5 text-app-muted"><strong className="font-medium text-app-secondary">{t('guide.when')} </strong>{guide.when}</p>
    {guide.categories && <div className="space-y-2">{guide.categories.map(item => <div key={item.code} className="rounded-lg border border-app-line bg-inset px-3 py-2">
      <p className="text-xs font-semibold"><span className="mr-1.5 inline-block min-w-6 rounded-sm border border-app-line px-1 text-center">{item.code}</span>{item.name}{item.original && item.original !== item.name && <span className="font-normal text-app-subtle"> · {item.original}</span>}</p>
      <p className="mt-1 text-xs leading-5 text-app-muted">{item.question}{item.property && <span className="text-app-subtle"> {t('guide.property', { property: item.property.toLowerCase() })}</span>}</p>
    </div>)}</div>}
    <details open={!guide.categories}><summary className="cursor-pointer text-xs font-medium text-app-secondary">{t('guide.how')}</summary>
      <ol className="mt-2 list-decimal space-y-1.5 pl-4 text-xs leading-5 text-app-muted">{guide.steps.map(step => <li key={step}>{step}</li>)}</ol></details>
    {guide.tips.map(tip => <p key={tip} className="rounded-lg bg-app-soft px-3 py-2 text-xs leading-5 text-app-muted">{tip}</p>)}
    {guide.source && <a href={guide.source.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-brand underline underline-offset-2">{guide.source.label}<ArrowSquareOutIcon className="size-3" /></a>}
  </aside>
}


// ------------------------------------------------------------------ the team's threats

export function ManualThreatDialog({ model, initial, methodology, onClose, onSave, busy, workspace }: {
  model: Model; initial?: ManualThreat; methodology: Methodology; onClose: () => void; onSave: (threat: ManualThreat, equivalents: LevelEquivalents) => void; busy: boolean
  workspace?: Catalog['workspace']
}) {
  const [draft, setDraft] = useState<ManualThreat>(() => initial ?? { id: newId('amenaza', (model.manual_threats ?? []).map(item => item.id)), title: '', severity: 'medium' })
  const [equivalents, setEquivalents] = useState<LevelEquivalents>(() => model.level_equivalents ?? {})
  const { t } = useTranslation('threats')
  const set = (change: Partial<ManualThreat>) => setDraft(previous => ({ ...previous, ...change }))
  const categories = guideOf(methodology === 'pasta' ? 'stride' : methodology).categories ?? []
  // STRIDE and LINDDUN have their own categories; any other approach takes the team's.
  const strict = methodology === 'stride' || methodology === 'linddun'
  const ownSeverity = !!draft.severity && !(draft.severity in SEVERITIES)
  const submit = (event: FormEvent) => { event.preventDefault(); onSave(draft, equivalents) }
  return <Dialog open onOpenChange={next => { if (!next) onClose() }}><DialogContent className="max-h-[92vh] max-w-xl overflow-y-auto">
    <DialogHeader><DialogTitle>{initial ? t('manual.edit_title') : t('manual.add_title')}</DialogTitle><DialogDescription>{t('manual.description')}</DialogDescription></DialogHeader>
    <form className="space-y-3" onSubmit={submit}>
      <Field label={t('manual.title')}><Input required maxLength={160} value={draft.title} onChange={event => set({ title: event.target.value })} placeholder={t('manual.title_placeholder')} className="border-input bg-card" /></Field>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label={t('manual.category')}>{strict
          ? <SelectField value={draft.category ?? ''} onValueChange={category => set({ category })} className={select} placeholder={t('manual.no_category')} options={categories.map(item => ({ value: item.code, label: `${item.code} · ${item.name}` }))} />
          : <ValueCombobox label={t('manual.category')} value={draft.category ?? ''} maxLength={40} onChange={category => set({ category })} placeholder={t('manual.category_placeholder')}
              options={[...categories.map(item => ({ value: item.code, label: `${item.code} · ${item.name}`, group: t('values.ours') })),
                ...(workspace?.categories ?? []).filter(item => !categories.some(category => category.code === item)).map(item => ({ value: item, label: item, group: t('values.workspace') }))]} />}</Field>
        <Field label={t('manual.element')}><SelectField value={draft.element ?? ''} onValueChange={element => set({ element })} className={select} placeholder={t('manual.whole_system')} options={elementsOf(model).map(item => ({ value: item.id, label: item.label }))} /></Field>
      </div>
      <Field label={t('manual.scenario')}><textarea rows={3} maxLength={1500} value={draft.scenario ?? ''} onChange={event => set({ scenario: event.target.value })} className={area} placeholder={t('manual.scenario_placeholder')} /></Field>
      <div className="grid gap-3 sm:grid-cols-4">
        <Field label={t('manual.severity')}><OwnValueField label={t('manual.severity')} value={draft.severity} known={SEVERITIES} own={workspace?.severities} onChange={severity => set({ severity: severity || 'medium' })} /></Field>
        <Field label={t('manual.likelihood')}><OwnValueField label={t('manual.likelihood')} value={draft.likelihood ?? ''} known={LEVELS} own={workspace?.levels} placeholder={t('level.unset')} onChange={likelihood => set({ likelihood: likelihood || null })} /></Field>
        <Field label={t('manual.impact')}><OwnValueField label={t('manual.impact')} value={draft.impact ?? ''} known={LEVELS} own={workspace?.levels} placeholder={t('level.unset')} onChange={impact => set({ impact: impact || null })} /></Field>
        <Field label={t('manual.owner')}><Input maxLength={80} value={draft.owner ?? ''} onChange={event => set({ owner: event.target.value })} className="h-8 border-input bg-card" /></Field>
      </div>
      {ownSeverity && <Field label={t('manual.equivalent', { value: draft.severity })}>
        <SelectField value={equivalents.severity?.[draft.severity] ?? ''} placeholder={t('manual.equivalent_none')} className={select}
          onValueChange={level => { const scale = { ...(equivalents.severity ?? {}) }; if (level) scale[draft.severity] = level; else delete scale[draft.severity]; setEquivalents({ ...equivalents, severity: scale }) }}
          options={Object.entries(SEVERITIES).map(([key, text]) => ({ value: key, label: t(text) }))} />
        <span className="block text-[11px] leading-4 text-app-subtle">{t('manual.equivalent_hint')}</span></Field>}
      <Field label={t('manual.mitigation')}><textarea rows={2} maxLength={1500} value={draft.mitigation ?? ''} onChange={event => set({ mitigation: event.target.value })} className={area} /></Field>
      <CustomPropertiesField compact value={draft.custom_properties} onChange={custom_properties => set({ custom_properties })} />
      <DialogFooter><Button type="button" variant="ghost" onClick={onClose}>{t('common:actions.cancel')}</Button><Button type="submit" disabled={busy || !draft.title.trim()}>{busy && <CircleNotchIcon className="animate-spin" />}{t('common:actions.save')}</Button></DialogFooter>
    </form>
  </DialogContent></Dialog>
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return <label className="block space-y-1"><span className="text-[11px] font-medium text-app-muted">{label}</span>{children}</label>
}

// A field of a list the team can extend: our values (translated), the ones the workspace already uses, and its own.
export function OwnValueField({ label, value, known, own, onChange, placeholder, size }: {
  label: string; value: string; known: Record<string, string>; own?: string[]; onChange: (next: string) => void; placeholder?: string; size?: 'sm' | 'xs'
}) {
  const { t } = useTranslation('threats')
  const options = [...Object.entries(known).map(([key, text]) => ({ value: key, label: t(text), group: t('values.ours') })),
    ...[...new Set([...(own ?? []), ...(value && !(value in known) ? [value] : [])])].filter(item => !(item in known)).map(item => ({ value: item, label: item, group: t('values.workspace') }))]
  const pick = (next: string) => onChange(Object.entries(known).find(([key, text]) => key === next.toLowerCase() || t(text).toLowerCase() === next.toLowerCase())?.[0] ?? next)
  return <ValueCombobox label={label} value={value} options={options} maxLength={40} placeholder={placeholder} size={size} onChange={pick} />
}

// ------------------------------------------------------------------ PASTA

const STAGE_HINTS: Record<string, string> = {
  objectives: 'pasta.hints.objectives', scope: 'pasta.hints.scope', decomposition: 'pasta.hints.decomposition', threats: 'pasta.hints.threats',
  vulnerabilities: 'pasta.hints.vulnerabilities', attacks: 'pasta.hints.attacks', risk: 'pasta.hints.risk',
}

export function PastaStages({ model, setModel, threats, catalog, onGo }: { model: Model; setModel: (model: Model) => void; threats: Threat[]; catalog: Catalog; onGo: (tab: string) => void }) {
  const { t } = useTranslation('threats')
  const notes = model.pasta ?? {}
  const note = (key: string) => { const value = notes[key]; return typeof value === 'string' ? value : '' }
  const extra = notes.custom_properties ?? {}
  const [open, setOpen] = useState<string>(catalog.methods.pasta_stages.find(stage => !note(stage.key))?.key ?? 'objectives')
  const withEvidence = threats.filter(row => row.status === 'evidenced')
  const findings = withEvidence.reduce((total, row) => total + row.evidence_count, 0)
  const pending = threats.filter(row => row.status === 'evidenced' || row.status === 'open')
  const auto: Record<string, ReactNode> = {
    decomposition: <Auto>{t('pasta.auto.decomposition', { components: t('count.components', { count: model.components.length }), flows: t('count.flows', { count: model.flows.length }), boundaries: t('count.boundaries', { count: model.boundaries.length }) })} <Go onClick={() => onGo('diagram')}>{t('pasta.auto.open_diagram')}</Go></Auto>,
    threats: <Auto>{t('pasta.auto.threats', { threats: t('count.threats', { count: threats.length }), count: threats.filter(row => row.framework === 'manual').length })} <Go onClick={() => onGo('threats')}>{t('pasta.auto.view_threats')}</Go></Auto>,
    vulnerabilities: <Auto>{withEvidence.length ? t('pasta.auto.evidence', { threats: t('count.threats', { count: withEvidence.length }), findings: t('count.open_findings', { count: findings }), titles: `${withEvidence.slice(0, 4).map(row => row.title).join(' · ')}${withEvidence.length > 4 ? '…' : ''}` }) : t('pasta.auto.no_evidence')} <Go onClick={() => onGo('threats')}>{t('pasta.auto.view_evidence')}</Go></Auto>,
    attacks: <Auto>{t('pasta.auto.trees', { count: (model.attack_trees ?? []).length })} <Go onClick={() => onGo('trees')}>{t('pasta.auto.open_trees')}</Go></Auto>,
    risk: <Auto>{t('pasta.auto.risk', { count: pending.length, breakdown: (['critical', 'high', 'medium', 'low'] as const).map(level => t(SEVERITY_COUNT[level], { count: pending.filter(row => row.severity === level).length })).join(' · ') })}</Auto>,
  }
  return <div className="space-y-2">{catalog.methods.pasta_stages.map(stage => { const expanded = open === stage.key
    return <div key={stage.key} className="rounded-xl border border-app-line bg-panel">
      <button type="button" aria-expanded={expanded} onClick={() => setOpen(expanded ? '' : stage.key)} className="flex w-full items-center gap-2 px-4 py-3 text-left"><CaretRightIcon className={`size-4 text-app-subtle transition ${expanded ? 'rotate-90' : ''}`} /><span className="flex-1 text-sm font-medium">{stage.title}</span>{note(stage.key) && <Badge variant="outline" className="border-brand/30 text-[11px] text-brand">{t('pasta.has_notes')}</Badge>}</button>
      {expanded && <div className="space-y-3 border-t border-app-line px-4 py-4">
        {STAGE_HINTS[stage.key] && <p className="text-xs leading-5 text-app-subtle">{t(STAGE_HINTS[stage.key])}</p>}
        {auto[stage.key]}
        <textarea aria-label={stage.title} rows={4} maxLength={4000} value={note(stage.key)} onChange={event => setModel({ ...model, pasta: { ...notes, [stage.key]: event.target.value } })} className={area} placeholder={t('pasta.notes_placeholder')} />
      </div>}
    </div> })}
    {/* Sections the imported model brought that aren't PASTA's stages: kept, shown and editable after them. */}
    {Object.entries(extra).map(([key, value]) => <section key={key} aria-label={headingOf(key)} className="space-y-2 rounded-xl border border-app-line bg-panel px-4 py-3">
      <p className="text-sm font-medium">{headingOf(key)} <span className="text-xs font-normal text-app-subtle">· {t('pasta.own_section')}</span></p>
      {typeof value === 'string' ? <textarea aria-label={headingOf(key)} rows={3} maxLength={4000} value={value} onChange={event => setModel({ ...model, pasta: { ...notes, custom_properties: { ...extra, [key]: event.target.value } } })} className={area} />
        : <div className="text-xs"><ValueView value={value} /></div>}
    </section>)}
  </div>
}

function Auto({ children }: { children: ReactNode }) {
  return <p className="rounded-lg border border-app-line bg-inset px-3 py-2 text-xs leading-5 text-app-muted">{children}</p>
}
function Go({ onClick, children }: { onClick: () => void; children: ReactNode }) {
  return <button type="button" onClick={onClick} className="text-brand underline underline-offset-2">{children}</button>
}

// ------------------------------------------------------------------ attack trees

export function AttackTrees({ model, setModel, levels }: { model: Model; setModel: (model: Model) => void; levels?: string[] }) {
  const { t } = useTranslation('threats')
  const goals: unknown = t('trees.goals', { returnObjects: true })
  const trees = model.attack_trees ?? []
  const setTrees = (next: AttackTree[]) => setModel({ ...model, attack_trees: next })
  const add = (goal: string) => setTrees([...trees, { id: newId(goal || 'arbol', trees.map(item => item.id)), goal: goal || t('trees.new_goal'), nodes: [] }])
  return <div className="space-y-4">
    <div className="flex flex-wrap items-center gap-2">
      <Button size="sm" variant="outline" onClick={() => add('')}><PlusIcon />{t('trees.tree')}</Button>
      <SelectField aria-label={t('trees.common_goals')} value="" onValueChange={goal => { if (goal) add(goal) }} className={inline} placeholder={t('trees.start_from_goal')} options={(Array.isArray(goals) ? goals.map(String) : []).map(goal => ({ value: goal, label: goal }))} />
    </div>
    {trees.length === 0 && <p className="rounded-xl border border-dashed border-app-line px-4 py-10 text-center text-sm text-app-subtle">{t('trees.empty')}</p>}
    {trees.map(tree => <TreeEditor key={tree.id} tree={tree} model={model} levels={levels} onChange={next => setTrees(trees.map(item => item.id === tree.id ? next : item))} onRemove={() => setTrees(trees.filter(item => item.id !== tree.id))} />)}
  </div>
}

// An AND branch is cut when one of its steps is mitigated; an OR one, only when all are (as open_paths in methods.py).
function blocked(node: TreeNode, children: Record<string, TreeNode[]>): boolean {
  const kids = children[node.id] ?? []
  if (node.mitigated) return true
  if (!kids.length) return false
  return node.gate === 'and' ? kids.some(kid => blocked(kid, children)) : kids.every(kid => blocked(kid, children))
}

function TreeEditor({ tree, model, levels, onChange, onRemove }: { tree: AttackTree; model: Model; levels?: string[]; onChange: (tree: AttackTree) => void; onRemove: () => void }) {
  const { t } = useTranslation('threats')
  const children: Record<string, TreeNode[]> = {}
  for (const node of tree.nodes) (children[node.parent ?? 'root'] ??= []).push(node)
  const roots = children.root ?? []
  const open = roots.filter(node => !blocked(node, children)).length
  const addNode = (parent: string | null) => onChange({ ...tree, nodes: [...tree.nodes, { id: newId('paso', tree.nodes.map(item => item.id)), parent, text: t('trees.new_step'), gate: 'or', mitigated: false }] })
  const update = (id: string, change: Partial<TreeNode>) => onChange({ ...tree, nodes: tree.nodes.map(item => item.id === id ? { ...item, ...change } : item) })
  const remove = (id: string) => { const gone = new Set([id]); let grew = true
    while (grew) { grew = false; for (const node of tree.nodes) if (node.parent && gone.has(node.parent) && !gone.has(node.id)) { gone.add(node.id); grew = true } }
    onChange({ ...tree, nodes: tree.nodes.filter(item => !gone.has(item.id)) }) }
  const elements = elementsOf(model)
  const render = (node: TreeNode, depth: number): ReactNode => {
    const kids = children[node.id] ?? []
    const cut = blocked(node, children)
    return <div key={node.id} style={{ marginLeft: depth ? 20 : 0 }} className="space-y-1.5">
      <div className={`flex flex-wrap items-center gap-2 rounded-lg border px-2 py-1.5 ${cut ? 'border-input bg-card opacity-70' : 'border-app-line bg-panel'}`}>
        <GitBranchIcon className="size-3.5 shrink-0 text-app-subtle" />
        <Input aria-label={t('trees.step')} value={node.text} maxLength={200} onChange={event => update(node.id, { text: event.target.value })} className={`h-7 min-w-48 flex-1 border-input bg-card text-sm ${cut ? 'line-through' : ''}`} />
        {kids.length > 0 && <SelectField aria-label={t('trees.gate')} value={node.gate} onValueChange={gate => update(node.id, { gate: gate as 'and' | 'or' })} className={inline} title={t('trees.gate_hint')} options={[{ value: 'or', label: t('trees.gate_or') }, { value: 'and', label: t('trees.gate_and') }]} />}
        <div className="w-32"><OwnValueField size="xs" label={t('trees.difficulty')} value={node.difficulty ?? ''} known={LEVELS} own={levels} placeholder={t('trees.difficulty')} onChange={difficulty => update(node.id, { difficulty: difficulty || null })} /></div>
        <SelectField aria-label={t('manual.element')} value={node.element ?? ''} onValueChange={element => update(node.id, { element })} className={`${inline} max-w-40`} placeholder={t('trees.no_element')} options={elements.map(item => ({ value: item.id, label: item.label }))} />
        <label className="flex items-center gap-1 text-xs text-app-muted"><input type="checkbox" className="size-3.5 accent-brand" checked={node.mitigated} onChange={event => update(node.id, { mitigated: event.target.checked })} />{t('trees.mitigated')}</label>
        <Button size="xs" variant="ghost" onClick={() => addNode(node.id)} aria-label={t('trees.add_step')}><PlusIcon />{t('trees.step')}</Button>
        <Button size="xs" variant="ghost" onClick={() => remove(node.id)} aria-label={t('trees.remove_step')}><TrashIcon /></Button>
      </div>
      {Object.keys(node.custom_properties ?? {}).length > 0 && <div className="ml-6"><CustomPropertiesField compact value={node.custom_properties} onChange={custom_properties => update(node.id, { custom_properties })} /></div>}
      {kids.map(kid => render(kid, depth + 1))}
    </div>
  }
  return <div className="space-y-3 rounded-lg border border-app-line bg-panel p-4">
    <div className="flex flex-wrap items-center gap-2"><TargetIcon className="size-4 text-brand" /><Input aria-label={t('trees.goal')} value={tree.goal} maxLength={200} onChange={event => onChange({ ...tree, goal: event.target.value })} className="h-8 min-w-64 flex-1 border-input bg-card font-medium" />
      <span className="text-xs text-app-subtle">{roots.length ? t('trees.paths', { open, count: roots.length }) : t('trees.no_paths')}</span>
      <Button size="xs" variant="ghost" onClick={onRemove} aria-label={t('trees.remove_tree')}><TrashIcon /></Button></div>
    <div className="space-y-1.5">{roots.map(node => render(node, 0))}</div>
    <Button size="sm" variant="outline" onClick={() => addNode(null)}><PlusIcon />{t('trees.path')}</Button>
    <CustomPropertiesField compact value={tree.custom_properties} onChange={custom_properties => onChange({ ...tree, custom_properties })} />
  </div>
}

// ------------------------------------------------------------------ MITRE ATT&CK

const MAPPING_STATUS = { relevant: 'attack.status.relevant', mitigated: 'attack.status.mitigated', not_applicable: 'attack.status.not_applicable' } as const

export function AttackMappings({ model, setModel, catalog }: { model: Model; setModel: (model: Model) => void; catalog: Catalog }) {
  const { t } = useTranslation('threats')
  const { techniques, tactics, suggestions } = catalog.methods
  const rows = model.attack_mappings ?? []
  const setRows = (next: AttackMapping[]) => setModel({ ...model, attack_mappings: next })
  const [technique, setTechnique] = useState('')
  const [element, setElement] = useState('')
  const elements = elementsOf(model)
  const label = Object.fromEntries(elements.map(item => [item.id, item.label]))
  const has = (id: string, target: string) => rows.some(row => row.technique === id && (row.element ?? '') === target)
  const add = (id: string, target: string) => { if (id && !has(id, target)) setRows([...rows, { technique: id, element: target, status: 'relevant' }]) }
  // Suggestions by component kind (a custom one by its base kind); never added on their own.
  const proposals = model.components.flatMap(component => {
    const kind = baseKind(component)
    const keys = [kind, ...(component.internet_facing && ['web_app', 'api', 'service', 'function'].includes(kind) ? ['internet_process'] : []),
                  ...(['web_app', 'api', 'service', 'function'].includes(kind) ? ['process'] : [])]
    return [...new Set(keys.flatMap(key => suggestions[key] ?? []))].filter(id => !has(id, component.id)).map(id => ({ id, component }))
  }).slice(0, 24)
  const full = catalog.methods.attack
  const groups = { workspace: t('values.workspace'), all: full ? t('attack.all_techniques', { version: full.version }) : t('attack.all_techniques_unversioned') }
  // Ours first, by tactic (with the Spanish interpretation); then every other ATT&CK technique by its official name.
  const options = [...Object.entries(tactics).flatMap(([key, name]) => Object.entries(techniques).filter(([, item]) => item.tactics[0] === key)
    .map(([id, item]) => ({ value: id, label: `${id} · ${techniqueName(item) ?? ''}`, group: `${name} (${key})` }))),
  ...Object.entries(full?.techniques ?? {}).filter(([id]) => !techniques[id]).map(([id, [name]]) => ({ value: id, label: `${id} · ${name}`, group: groups.all })),
  ...(catalog.workspace?.techniques ?? []).filter(id => !techniques[id] && !full?.techniques[id]).map(id => ({ value: id, label: id, hint: describe(id), group: groups.workspace }))]
  // Any well-formed ATT&CK ID works: one that isn't in ATT&CK keeps its ID and says so.
  const check = (text: string) => TECHNIQUE_ID.test(text.toUpperCase()) ? null : t('attack.technique_format')
  const lookup = (id: string) => techniques[id] ? { name: techniqueName(techniques[id]) ?? id, official: techniques[id].name, tactics: techniques[id].tactics }
    : full?.techniques[id] ? { name: full.techniques[id][0], official: full.techniques[id][0], tactics: full.techniques[id][1] } : null
  function describe(id: string) {
    if (full && id in full.revoked) return full.revoked[id] ? t('attack.revoked', { replacement: full.revoked[id] }) : t('attack.revoked_alone')
    if (full && id in full.deprecated) return t('attack.deprecated', { name: full.deprecated[id] })
    return t('attack.not_found', { version: full?.version ?? '' })
  }
  return <div className="space-y-4">
    <div className="flex flex-wrap items-end gap-2 rounded-lg border border-app-line bg-panel p-4">
      <label className="min-w-64 flex-1 space-y-1"><span className="text-[11px] font-medium text-app-muted">{t('attack.technique')}</span>
        <ValueCombobox label={t('attack.technique_label')} value={technique} onChange={value => setTechnique(value.trim().toUpperCase())} options={options} check={check} maxLength={9} placeholder={t('attack.type_technique')} /></label>
      <label className="min-w-48 space-y-1"><span className="text-[11px] font-medium text-app-muted">{t('manual.element')}</span>
        <SelectField value={element} onValueChange={setElement} className={select} placeholder={t('manual.whole_system')} options={elements.map(item => ({ value: item.id, label: item.label }))} /></label>
      <Button size="sm" variant="outline" disabled={!technique} onClick={() => { add(technique, element); setTechnique('') }}><PlusIcon />{t('attack.map')}</Button>
    </div>
    {proposals.length > 0 && <details className="rounded-lg border border-app-line bg-panel p-4"><summary className="cursor-pointer text-sm font-medium">{t('attack.suggestions', { count: proposals.length })}</summary>
      <p className="mt-1 text-xs text-app-subtle">{t('attack.suggestions_hint')}</p>
      <div className="mt-3 flex flex-wrap gap-1.5">{proposals.map(({ id, component }) => <button key={`${id}:${component.id}`} onClick={() => add(id, component.id)} className="inline-flex items-center gap-1 rounded-lg border border-input bg-card px-2 py-1 text-xs text-app-muted hover:border-app-faint hover:underline"><PlusIcon className="size-3" /><span className="font-mono">{id}</span> {techniqueName(techniques[id])} → {component.name}</button>)}</div>
    </details>}
    {rows.length === 0 ? <p className="rounded-xl border border-dashed border-app-line px-4 py-10 text-center text-sm text-app-subtle">{t('attack.empty')}</p>
      : <div className="divide-y divide-app-line overflow-hidden rounded-lg border border-app-line bg-panel">{rows.map((row, index) => { const item = lookup(row.technique)
        const parent = item ?? lookup(row.technique.split('.')[0])
        const change = (next: Partial<AttackMapping>) => setRows(rows.map((entry, position) => position === index ? { ...entry, ...next } : entry))
        return <div key={`${row.technique}:${row.element}`} className="grid gap-2 px-4 py-3 md:grid-cols-[minmax(0,1.2fr)_minmax(0,0.8fr)_150px_minmax(0,1fr)_36px] md:items-start">
          <div className="min-w-0"><a href={attackUrl(row.technique)} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-sm font-medium hover:underline"><span className="font-mono text-xs text-app-subtle">{row.technique}</span>{item ? item.name : describe(row.technique)}<ArrowSquareOutIcon className="size-3 text-app-subtle" /><span className="sr-only">{t('sources:new_tab')}</span></a>
            <p className="text-[11px] text-app-subtle">{[item && item.name !== item.official ? item.official : '', parent?.tactics.map(key => tactics[key] ?? key).join(', ')].filter(Boolean).join(' · ')}</p></div>
          <p className="text-xs text-app-muted">{row.element ? label[row.element] ?? '—' : t('manual.whole_system')}</p>
          <OwnValueField size="xs" label={t('attack.status_label')} value={row.status} known={MAPPING_STATUS} own={catalog.workspace?.statuses} onChange={status => change({ status: status || 'relevant' })} />
          <Input aria-label={t('attack.note')} value={row.note ?? ''} maxLength={600} placeholder={t('attack.note_placeholder')} onChange={event => setRows(rows.map((entry, position) => position === index ? { ...entry, note: event.target.value } : entry))} className="h-8 border-input bg-card text-xs" />
          <Button size="icon-sm" variant="ghost" aria-label={t('common:actions.remove')} onClick={() => setRows(rows.filter((_, position) => position !== index))}><TrashIcon /></Button>
          {Object.keys(row.custom_properties ?? {}).length > 0 && <div className="md:col-span-5"><CustomPropertiesField compact value={row.custom_properties} onChange={custom_properties => change({ custom_properties })} /></div>}
        </div> })}</div>}
    <p className="text-[11px] text-app-subtle">{t('attack.trademark')}</p>
  </div>
}
