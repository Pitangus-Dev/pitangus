import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { ChevronRight, FileCheck2, Search, ShieldCheck, SlidersHorizontal, Ticket } from 'lucide-react'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { Card, CardContent } from '@/shared/ui/card'
import { Input } from '@/shared/ui/input'
import { Pagination } from '@/shared/ui/pagination'
import { Select, SelectContent, SelectItem, SelectTrigger } from '@/shared/ui/select'
import { formatNumber } from '@/shared/i18n/format'
import { byAsset } from '@/shared/lib/selection'
import { SlaPill } from '@/features/findings/sla-pill'
import { AuditReportDialog, type AuditTarget } from '@/features/findings/audit-report'
import { FindingDetail } from '@/features/findings/finding-detail'
import { KpiTiles } from '@/features/findings/kpi-tiles'
import { TriageActions, TriageBadge, TriageDialog, type TriageSelection } from '@/features/findings/triage'
import { SUPPRESSED, TRIAGE_LABEL, type TriageStatus } from '@/features/findings/triage-status'
import { ACTION_LABEL, SCANNER_LABEL, SEVERITY_LABEL, actionClass, groupFindings, idOf, inView, isPending, labelOf, severityClass, stateId, statusOf, toolsOf,
  type FindingKpis, type RepositoryFinding } from '@/features/findings/finding-model'
import { JIRA_QUEUE_MAX, JiraExportDialog, JiraFindingAction, type JiraSelection } from '@/features/integrations/jira-export'
import { useJiraAvailability } from '@/features/integrations/jira-availability'
import { useJiraSettled } from '@/features/integrations/jira-batches'

const PAGE = 50
const DEMO_SOURCE = 'local:demo-ejemplos'

// An extra column, after the finding (with several assets: the asset). `text` names it in the row's accessible name.
export type FindingsColumn = { label: string; text: (finding: RepositoryFinding) => string; cell: (finding: RepositoryFinding) => ReactNode }

// The findings of a run, an asset's state or several assets: tiles, filters, the grouped table with its selection, and
// what is done with it (triage, Jira, the audit report). What differs comes in: the `header`, what goes between the
// tiles and the table (`aside`), an extra `column` and the `exports`, which get how to open the audit report.
// `runId`: the run or state the findings come from (a finding that names its asset uses that asset's state instead);
// `assetKey`: the one asset, if any; `focus`: a finding to open and scroll to (links from Jira issues carry it).
export function FindingsTable({ findings, kpis, header, aside, column, exports, audit, jira, runId, assetKey = '', canAccept, canManage = canAccept, initialView = 'active', focus = null, onChanged }: {
  findings: RepositoryFinding[]; kpis?: FindingKpis; header: ReactNode; aside?: ReactNode; column?: FindingsColumn; exports: (openAudit: () => void) => ReactNode
  audit: { name: string; target: AuditTarget; fromSelection: boolean }; jira: { selection: JiraSelection; asset: { key: string; name?: string } | null }
  runId: string; assetKey?: string; canAccept: boolean; canManage?: boolean; initialView?: string; focus?: string | null; onChanged: () => void
}) {
  const { t } = useTranslation('findings')
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('all')
  const [action, setAction] = useState('all')
  const [scanner, setScanner] = useState('all')
  const [deadline, setDeadline] = useState('all')
  const byId = useMemo(() => new Map(findings.map(item => [idOf(item), item])), [findings])
  // A linked finding opens in its group and page, with the status view that shows it (computed once, on arrival).
  const [arrival] = useState(() => {
    const target = focus ? findings.find(item => item.fingerprint === focus) : undefined
    if (!target) return null
    const view = initialView !== 'all' && !inView(target, initialView) ? 'all' : initialView
    const list = groupFindings(findings.filter(item => inView(item, view)), t)
    const index = list.findIndex(group => group.findings.some(item => item.fingerprint === target.fingerprint))
    return index < 0 ? null : { view, open: list[index].key, offset: Math.floor(index / PAGE) * PAGE, fingerprint: target.fingerprint }
  })
  const [open, setOpen] = useState<string | null>(arrival?.open ?? null)
  const [triageView, setTriageView] = useState(arrival?.view ?? initialView)
  const [auditOpen, setAuditOpen] = useState(false)
  // Secondary filters folded away; how many are in use shows on the button.
  const hiddenActive = Number(triageView !== initialView) + Number(action !== 'all') + Number(scanner !== 'all') + Number(deadline !== 'all')
  const [moreFilters, setMoreFilters] = useState(false)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [decision, setDecision] = useState<{ status: TriageStatus; ids: string[] } | null>(null)
  const [exporting, setExporting] = useState<string[] | null>(null)
  const availability = useJiraAvailability(canManage, jira.asset)
  // Issues queued in the background land in the findings when their batch finishes.
  useJiraSettled(() => onChanged())
  const [offset, setOffset] = useState(arrival?.offset ?? 0)
  // Due dates only exist in a registry's state (pending work with a detection date), not in a single run.
  const hasSla = kpis?.has_sla ?? false
  const dismissed = useMemo(() => findings.filter(item => SUPPRESSED.includes(statusOf(item))).length, [findings])
  const groups = useMemo(() => groupFindings(findings.filter(item =>
    inView(item, triageView)
    && (severity === 'all' || item.severity === severity) && (action === 'all' || item.priority?.action === action) && (scanner === 'all' || item.scanner === scanner)
    && (deadline === 'all' || (deadline === 'overdue' ? item.sla?.state === 'overdue' : item.sla?.state === 'overdue' || item.sla?.state === 'soon'))
    && (!query.trim() || `${item.title} ${item.package?.name ?? ''} ${item.path} ${item.cve.join(' ')} ${item.ghsa.join(' ')} ${item.asset?.name ?? ''}`.toLowerCase().includes(query.trim().toLowerCase()))), t), [findings, triageView, severity, action, scanner, deadline, query, t])
  const page = groups.slice(offset, offset + PAGE)
  useEffect(() => {
    if (!arrival) return
    const element = document.getElementById(`finding-${arrival.fingerprint}`)
    element?.scrollIntoView?.({ block: 'center' }); element?.focus({ preventScroll: true })
  }, [arrival])
  const pageIds = page.flatMap(group => group.findings.map(idOf))
  const toggle = (ids: string[], on: boolean) => setSelected(previous => { const next = new Set(previous); for (const item of ids) { if (on) next.add(item); else next.delete(item) } return next })
  // Why the selection can't go to Jira, said next to the button (a title alone reaches neither keyboard nor touch).
  const jiraBlocked = availability.blocked ?? (selected.size > JIRA_QUEUE_MAX ? t('selection.jira_max', { max: formatNumber(JIRA_QUEUE_MAX) })
    : findings.some(item => selected.has(idOf(item)) && !isPending(item)) ? t('selection.jira_dismissed') : null)
  const allOnPage = pageIds.length > 0 && pageIds.every(item => selected.has(item))
  const selectedAssets = new Set([...selected].map(id => byId.get(id)?.asset?.key).filter(Boolean)).size
  const refs = (ids: string[]) => ids.flatMap(id => { const item = byId.get(id); return item ? [item] : [] })
  // Findings that name their asset are decided per asset, against each asset's state.
  const triageParts = (ids: string[]): TriageSelection[] | undefined => {
    const items = refs(ids)
    if (!items.some(item => item.asset)) return undefined
    const names = new Map(items.map(item => [item.asset?.key, item.asset?.name ?? '']))
    return byAsset(items.map(item => ({ fingerprint: item.fingerprint, asset: item.asset?.key }))).map(part => ({ ...part, name: names.get(part.asset) ?? part.asset }))
  }
  const decided = () => { setDecision(null); setSelected(new Set()); onChanged() }
  // While a verification is running the view refreshes (once for every finding).
  const verifying = findings.some(item => item.verification?.state === 'running')
  useEffect(() => { if (!verifying) return; const timer = window.setInterval(onChanged, 10_000); return () => window.clearInterval(timer) }, [verifying, onChanged])
  const grid = column ? 'md:grid-cols-[120px_90px_minmax(0,1fr)_minmax(0,0.5fr)_80px_110px]' : 'md:grid-cols-[120px_90px_minmax(0,1fr)_110px_110px]'

  return <>
    {header}
    {kpis && <KpiTiles kpis={kpis} />}
    {aside}

    <Card className="border-app-line bg-panel"><CardContent className="space-y-4 p-5">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
        <div className="relative min-w-0 flex-1 lg:max-w-sm"><Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-app-subtle" /><Input aria-label={t('filters.search')} placeholder={t('filters.search_placeholder')} value={query} onChange={event => setQuery(event.target.value)} className="border-app-line bg-app-soft pl-9" /></div>
        <Filter label={t('filters.severity')} value={severity} onChange={setSeverity} all={t('filters.any_severity')} options={[['critical', t('common:severity.critical')], ['high', t('common:severity.high')], ['medium', t('common:severity.medium')], ['low', t('common:severity.low')]]} />
        {/* Hick's law: search and severity in sight; the rest on demand, saying how many are in use. */}
        <Button type="button" size="sm" variant="outline" aria-expanded={moreFilters} aria-controls="more-filters" onClick={() => setMoreFilters(!moreFilters)} className="w-fit border-app-line bg-app-soft"><SlidersHorizontal />{t('filters.more')}{hiddenActive ? ` · ${hiddenActive}` : ''}</Button>
      </div>
      {moreFilters && <div id="more-filters" className="flex flex-wrap gap-3">
        <Filter label={t('filters.status')} value={triageView} onChange={value => { setTriageView(value === 'all' ? 'all' : value); setOffset(0) }} all={t('filters.any_status')} options={[['active', t('filters.status_options.active')], ['open', t('filters.status_options.open')], ['in_progress', t('filters.status_options.in_progress')], ['fixed', t('filters.status_options.fixed')], ['false_positive', t('filters.status_options.false_positive')], ['accepted', t('filters.status_options.accepted')]]} />
        <Filter label={t('filters.priority')} value={action} onChange={setAction} all={t('filters.any_priority')} options={[['act', t('common:priority.act')], ['attend', t('common:priority.attend')], ['track', t('common:priority.track')]]} />
        <Filter label={t('filters.source')} value={scanner} onChange={setScanner} all={t('filters.any_source')} options={[['sca', t('filters.source_options.sca')], ['sast', t('filters.source_options.sast')], ['iac', t('filters.source_options.iac')], ['cicd', t('filters.source_options.cicd')], ['secrets', t('filters.source_options.secrets')]]} />
        {hasSla && <Filter label={t('filters.deadline')} value={deadline} onChange={value => { setDeadline(value); setOffset(0) }} all={t('filters.any_deadline')} options={[['overdue', t('filters.deadline_options.overdue')], ['soon', t('filters.deadline_options.soon')]]} />}
      </div>}
      {selected.size > 0 && <div className="sticky top-16 z-10 flex flex-wrap items-center gap-3 rounded-xl border border-brand/30 bg-panel px-4 py-2.5 shadow-lg">
        <span className="text-sm font-medium">{selectedAssets > 1 ? t('scope.selected', { count: selected.size, value: formatNumber(selected.size), assets: formatNumber(selectedAssets) }) : t('selection.count', { count: selected.size })}</span>
        <TriageActions canAccept={canAccept} onPick={status => setDecision({ status, ids: [...selected] })} />
        {availability.configured && <span className="inline-flex flex-wrap items-center gap-1.5"><Button size="sm" variant="outline" className="border-app-line bg-app-soft" disabled={!!jiraBlocked} aria-describedby={jiraBlocked ? 'jira-bulk-blocked' : undefined} onClick={() => setExporting([...selected])}><Ticket />{t('selection.jira')}</Button>
          {jiraBlocked && <span id="jira-bulk-blocked" className="text-xs text-app-subtle">{jiraBlocked}</span>}</span>}
        {audit.fromSelection && <Button size="sm" variant="outline" className="border-app-line bg-app-soft" onClick={() => setAuditOpen(true)}><FileCheck2 />{t('selection.report')}</Button>}
        <Button variant="ghost" size="sm" onClick={() => setSelected(new Set())} className="ml-auto">{t('selection.clear')}</Button>
      </div>}
      {findings.length === 0
        ? <div className="flex flex-col items-center gap-2 py-14 text-center"><ShieldCheck className="size-7 text-brand" /><p className="font-medium">{t('empty.title')}</p><p className="max-w-md text-sm text-app-muted">{t('empty.body')}</p></div>
        : <div className="overflow-hidden rounded-xl border border-app-line">
          <div className={`hidden gap-3 border-b border-app-line px-4 py-2.5 text-xs text-app-subtle md:grid ${column ? 'grid-cols-[20px_120px_90px_minmax(0,1fr)_minmax(0,0.5fr)_80px_110px]' : 'grid-cols-[20px_120px_90px_minmax(0,1fr)_110px_110px]'}`}><input type="checkbox" aria-label={t('table.select_page')} checked={allOnPage} onChange={event => toggle(pageIds, event.target.checked)} className="size-4 accent-brand" /><span>{t('filters.priority')}</span><span>{t('filters.severity')}</span><span>{t('table.finding')}</span>{column && <span>{column.label}</span>}<span>EPSS</span><span>{t('filters.source')}</span></div>
          {page.length === 0 && <div className="px-4 py-10 text-center text-sm text-app-subtle">{triageView === 'active' && dismissed ? t('table.no_match_dismissed', { count: dismissed }) : t('table.no_match')}</div>}
          {page.map(group => { const expanded = open === group.key
            const ids = group.findings.map(idOf)
            const first = group.findings[0]
            const statuses = new Set(group.findings.map(statusOf))
            const groupState = statuses.size === 1 ? first.triage : undefined
            return <div key={group.key} className={`flex items-start border-b border-app-line last:border-b-0 ${SUPPRESSED.includes(statusOf(first)) && statuses.size === 1 ? 'opacity-70' : ''}`}>
              <input type="checkbox" aria-label={t('table.select_item', { name: column ? `${group.label} · ${column.text(first)}` : group.label })} checked={ids.every(item => selected.has(item))} onChange={event => toggle(ids, event.target.checked)} className="mt-4 ml-4 size-4 shrink-0 accent-brand" />
              <div className="min-w-0 flex-1">
              <button type="button" aria-expanded={expanded} onClick={() => setOpen(expanded ? null : group.key)} className={`grid w-full gap-2 py-3 pr-4 pl-3 text-left motion-safe:transition hover:bg-app-soft md:items-center ${grid}`}>
                <Badge variant="outline" className={`w-fit ${actionClass(group.action)}`}>{labelOf(t, ACTION_LABEL, group.action)}</Badge>
                <Badge variant="outline" className={`w-fit ${severityClass(group.severity)}`}>{labelOf(t, SEVERITY_LABEL, group.severity)}</Badge>
                <span className="flex min-w-0 items-start gap-2"><ChevronRight className={`mt-1 size-3.5 shrink-0 text-app-subtle motion-safe:transition ${expanded ? 'rotate-90' : ''}`} /><span className="min-w-0"><span className="block truncate text-sm font-medium">{group.label}</span><span className="block truncate text-xs text-app-subtle">{group.meta}{group.kev ? ' · CISA KEV' : ''}{group.findings.some(item => item.ticket) ? ` · ${[...new Set(group.findings.flatMap(item => item.ticket ? [item.ticket.key] : []))].join(', ')}` : ''}</span>{first.lifecycle?.origin?.kind === 'pr' && <span className="mt-1 mr-1 inline-block rounded border border-info-line px-1.5 text-[11px] text-info">{first.lifecycle.origin.merged ? t('group.pr_merged', { number: first.lifecycle.origin.pr }) : t('group.pr', { number: first.lifecycle.origin.pr })}</span>}{first.lifecycle?.origin?.kind === 'import' && <span className="mt-1 mr-1 inline-block rounded border border-app-line px-1.5 text-[11px] text-app-muted">{t('group.imported')}</span>}<SlaPill sla={group.sla} />{group.findings.some(item => item.malicious) && <span className="mt-1 mr-1 inline-block rounded bg-danger-solid px-1.5 text-[11px] font-semibold text-on-solid" title={t('group.malicious_hint')}>{t('group.malicious')}</span>}{statuses.size > 1 ? <span className="mt-1 block text-[11px] text-app-subtle">{t('group.mixed', { statuses: [...statuses].map(item => t(TRIAGE_LABEL[item])).join(', ') })}</span> : <span className="mt-1 block"><TriageBadge state={groupState} /></span>}</span></span>
                {column?.cell(first)}
                <span className="font-mono text-xs text-app-muted">{group.epss !== null ? formatNumber(group.epss, { style: 'percent', minimumFractionDigits: 1, maximumFractionDigits: 1 }) : '—'}</span>
                <span className="text-xs text-app-muted">{labelOf(t, SCANNER_LABEL, group.scanner)}{first.tool ? <span className="block text-[11px] text-app-subtle">{toolsOf(t, first)}</span> : null}</span>
              </button>
              {expanded && <div className="space-y-3 border-t border-app-line bg-inset py-4 pr-4 pl-3">{group.findings.map(finding => <FindingDetail key={finding.finding_id} finding={finding} runId={finding.asset ? stateId(finding.asset.key) : runId} demo={(finding.asset?.key ?? assetKey) === DEMO_SOURCE} canAccept={canAccept} onChanged={onChanged} onPick={status => setDecision({ status, ids: [idOf(finding)] })}
                jira={<JiraFindingAction ticket={finding.ticket} pending={isPending(finding)} availability={availability} name={finding.advisory?.summary || finding.title} onCreate={() => setExporting([idOf(finding)])} />} />)}</div>}
              </div>
            </div> })}
          <Pagination total={groups.length} limit={PAGE} offset={Math.min(offset, Math.max(0, groups.length - 1))} onPrev={() => setOffset(current => Math.max(0, current - PAGE))} onNext={() => setOffset(current => current + PAGE)} noun={t('table.pagination', { count: findings.length })} />
        </div>}
    </CardContent></Card>

    {exports(() => setAuditOpen(true))}

    {auditOpen && <AuditReportDialog open onClose={() => setAuditOpen(false)} name={audit.name} target={audit.target}
      selected={refs([...selected]).map(item => item.fingerprint)} filtered={groups.flatMap(group => group.findings.map(item => item.fingerprint))} total={findings.length} />}
    <JiraExportDialog key={`jira:${exporting?.join(',') ?? 'none'}`} selection={jira.selection} target={availability.target}
      findings={exporting && refs(exporting).map(item => ({ fingerprint: item.fingerprint, label: item.advisory?.summary || item.title, asset: item.asset?.key }))}
      onClose={() => { setExporting(null); setSelected(new Set()) }} onDone={onChanged} />
    <TriageDialog key={`triage:${decision ? `${decision.status}:${decision.ids.length}` : 'none'}`} runId={runId} status={decision?.status ?? null} fingerprints={decision ? refs(decision.ids).map(item => item.fingerprint) : []}
      selections={decision ? triageParts(decision.ids) : undefined} onClose={() => setDecision(null)} onDone={decided} onPartial={() => { setSelected(new Set()); onChanged() }} />
  </>
}

// The accessible name says what it filters and its value ("Severity: High"), not just the value (1.3.1 / 2.5.3).
function Filter({ label, value, onChange, all, options }: { label: string; value: string; onChange: (value: string) => void; all: string; options: [string, string][] }) {
  const current = value === 'all' ? all : options.find(([id]) => id === value)?.[1] ?? all
  return <Select value={value} onValueChange={next => onChange(next ?? 'all')}><SelectTrigger aria-label={`${label}: ${current}`} size="sm" className="min-w-40 border-app-line bg-app-soft text-app-secondary">{value === 'all' ? all : options.find(([id]) => id === value)?.[1]}</SelectTrigger><SelectContent align="start" className="border border-app-line bg-panel p-1 text-app-fg shadow-xl"><SelectItem value="all">{all}</SelectItem>{options.map(([id, label]) => <SelectItem key={id} value={id}>{label}</SelectItem>)}</SelectContent></Select>
}
