import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { CheckCheck, ChevronDown, CircleDot, Clock3, LoaderCircle, RotateCcw, ShieldX, ThumbsUp, Wrench } from 'lucide-react'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { Input } from '@/shared/ui/input'
import { Menu, MenuContent, MenuItem, MenuTrigger } from '@/shared/ui/menu'
import { apiPost } from '@/shared/api/client'
import { formatDate } from '@/shared/lib/types'
import { SUPPRESSED, TRIAGE_LABEL, type TriageState, type TriageStatus } from '@/features/findings/triage-status'
import { stateId } from '@/features/findings/finding-model'

const triageClass: Record<TriageStatus, string> = {
  open: 'border-app-line text-app-muted', in_progress: 'border-info-line text-info',
  false_positive: 'border-app-line bg-app-soft text-app-subtle line-through decoration-app-faint', accepted: 'border-brand/30 text-brand',
  fixed: 'border-success-line text-success',
}
const icon: Record<TriageStatus, typeof CircleDot> = { open: RotateCcw, in_progress: Wrench, false_positive: ShieldX, accepted: ThumbsUp, fixed: CheckCheck }
const VERB = {
  open: 'triage.verb.open', in_progress: 'triage.verb.in_progress', false_positive: 'triage.verb.false_positive', accepted: 'triage.verb.accepted', fixed: 'triage.verb.fixed',
} as const satisfies Record<TriageStatus, string>
const DESCRIPTION = {
  open: 'triage.description.open', in_progress: 'triage.description.in_progress', false_positive: 'triage.description.false_positive',
  accepted: 'triage.description.accepted', fixed: 'triage.description.fixed',
} as const satisfies Record<TriageStatus, string>
const PLACEHOLDER: Partial<Record<TriageStatus, string>> = {
  false_positive: 'triage.placeholder.false_positive', accepted: 'triage.placeholder.accepted', fixed: 'triage.placeholder.fixed',
}
const needsReason = (status: TriageStatus) => SUPPRESSED.includes(status)
const inDays = (days: number) => new Date(Date.now() + days * 86400000).toISOString().slice(0, 10)

export function TriageBadge({ state }: { state?: TriageState }) {
  const { t } = useTranslation('findings')
  const status = state?.status ?? 'open'
  if (status === 'open' && !state?.expired) return null
  return <Badge variant="outline" className={`w-fit text-[11px] ${triageClass[status]}`}>{state?.expired ? t('triage.expired') : t(TRIAGE_LABEL[status])}</Badge>
}

// A triage decision. Hick's law: one main action (the usual one) and the rest in a menu, instead of four or five equal
// buttons per finding. "Accept risk" is for administrators only: it is a business decision.
export function TriageActions({ current, canAccept, onPick, size = 'sm' }: { current?: TriageStatus; canAccept: boolean; onPick: (status: TriageStatus) => void; size?: 'sm' | 'xs' }) {
  const { t } = useTranslation('findings')
  const options = (['fixed', 'in_progress', 'false_positive', ...(canAccept ? ['accepted' as const] : []), 'open'] as TriageStatus[])
    .filter(status => status !== current && !(status === 'open' && !current))
  const [primary, ...rest] = options
  if (!primary) return null
  const Primary = icon[primary]
  return <div className="flex flex-wrap gap-1.5">
    <Button type="button" size={size} variant="outline" onClick={() => onPick(primary)} className="border-app-line bg-app-soft"><Primary />{t(VERB[primary])}</Button>
    {rest.length > 0 && <Menu><MenuTrigger render={<Button type="button" size={size} variant="outline" className="border-app-line bg-app-soft" />}>{t('triage.more_states')}<ChevronDown className="size-3.5" /></MenuTrigger>
      <MenuContent align="start">{rest.map(status => { const Icon = icon[status]; return <MenuItem key={status} onClick={() => onPick(status)}><Icon />{t(VERB[status])}</MenuItem> })}</MenuContent></Menu>}
  </div>
}

// Findings of several assets, one part per asset: each part is decided against its own asset's state.
export type TriageSelection = { asset: string; name: string; fingerprints: string[] }

// The decision on one finding or many: it asks for a reason when the findings stop counting. With `selections`
// (findings of several assets) all go in one request; the assets whose part failed are listed, and a retry sends only
// those.
export function TriageDialog({ runId = '', status, fingerprints = [], selections, onClose, onDone, onPartial }: {
  runId?: string; status: TriageStatus | null; fingerprints?: string[]; selections?: TriageSelection[]; onClose: () => void; onDone: () => void; onPartial?: () => void
}) {
  const { t } = useTranslation('findings')
  const [reason, setReason] = useState('')
  const [note, setNote] = useState('')
  const [expires, setExpires] = useState(inDays(90))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [failed, setFailed] = useState<(TriageSelection & { error: string })[]>([])
  if (!status) return null
  const pending = failed.length ? failed : selections
  const count = selections ? selections.reduce((sum, part) => sum + part.fingerprints.length, 0) : fingerprints.length
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (busy) return
    setBusy(true); setError('')
    const decision = { status, reason: reason.trim() || undefined, note: note.trim() || undefined, expires_at: status === 'accepted' ? expires : undefined }
    try {
      if (!pending) { await apiPost('/api/findings/triage', 'triage', { run_id: runId, fingerprints, ...decision }); onDone(); return }
      const { results } = await apiPost('/api/findings/triage', 'triage', { selections: pending.map(part => ({ run_id: stateId(part.asset), fingerprints: part.fingerprints })), ...decision })
      const missed = pending.flatMap(part => { const error = results?.find(item => item.run_id === stateId(part.asset))?.error; return error ? [{ ...part, error }] : [] })
      if (!missed.length) { onDone(); return }
      if (missed.length < pending.length) onPartial?.()
      setFailed(missed)
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  const placeholder = PLACEHOLDER[status]
  return <Dialog open onOpenChange={next => { if (!next) onClose() }}><DialogContent className="max-w-lg">
    <DialogHeader><DialogTitle>{t('triage.dialog_title', { action: t(VERB[status]), count })}</DialogTitle><DialogDescription>{t(DESCRIPTION[status])}{selections && selections.length > 1 ? ` ${t('scope.triage_across', { count: selections.length })}` : ''}</DialogDescription></DialogHeader>
    <form className="space-y-4" onSubmit={submit}>
      <div className="space-y-1.5"><label htmlFor="triage-reason" className="text-xs text-app-muted">{needsReason(status) ? t('triage.reason') : t('triage.reason_optional')}</label>
        <textarea id="triage-reason" required={needsReason(status)} minLength={needsReason(status) ? 10 : undefined} maxLength={500} rows={3} value={reason} onChange={event => setReason(event.target.value)}
          placeholder={placeholder ? t(placeholder) : ''}
          className="w-full rounded-lg border border-app-line bg-app-soft px-3 py-2 text-sm outline-none focus-visible:ring-2 focus-visible:ring-brand/40" /></div>
      {status === 'accepted' && <div className="space-y-1.5"><label htmlFor="triage-expires" className="text-xs text-app-muted">{t('triage.expires')}</label><Input id="triage-expires" type="date" required min={inDays(1)} max={inDays(365)} value={expires} onChange={event => setExpires(event.target.value)} className="w-48 border-app-line bg-app-soft" /></div>}
      <div className="space-y-1.5"><label htmlFor="triage-note" className="text-xs text-app-muted">{t('triage.note')}</label><Input id="triage-note" maxLength={1000} value={note} onChange={event => setNote(event.target.value)} className="border-app-line bg-app-soft" /></div>
      {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{error}</div>}
      {selections && failed.length > 0 && <div role="alert" className="space-y-1 rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">
        <p className="font-medium">{t('scope.triage_partial', { count: selections.length - failed.length, total: selections.length })}</p>
        <ul className="max-h-32 space-y-0.5 overflow-y-auto">{failed.map(part => <li key={part.asset}><span className="font-medium">{part.name}</span> · {part.error}</li>)}</ul></div>}
      <DialogFooter><Button type="button" variant="ghost" onClick={onClose}>{t('common:actions.cancel')}</Button><Button type="submit" disabled={busy || (needsReason(status) && reason.trim().length < 10)} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy && <LoaderCircle className="motion-safe:animate-spin" />}{failed.length ? t('scope.triage_retry', { count: failed.length }) : t('common:actions.save')}</Button></DialogFooter>
    </form>
  </DialogContent></Dialog>
}

export function TriageHistory({ state }: { state?: TriageState }) {
  const { t } = useTranslation('findings')
  const history = state?.history ?? []
  if (!history.length) return null
  return <details className="mt-3"><summary className="cursor-pointer text-xs text-app-muted">{t('triage.history', { total: history.length })}</summary>
    <ol className="mt-2 space-y-1.5 border-l border-app-line pl-3 text-xs">{[...history].reverse().map((event, index) => <li key={index} className="text-app-muted">
      <span className="flex items-center gap-1.5"><Clock3 className="size-3 text-app-subtle" /><span className="font-medium text-app-secondary">{t(TRIAGE_LABEL[event.status])}</span> · {event.by} · {formatDate(event.at)}{event.expires_at ? ` · ${t('triage.expires_on', { date: event.expires_at })}` : ''}</span>
      {event.reason && <span className="block pl-4.5">{event.reason}</span>}{event.note && <span className="block pl-4.5 text-app-subtle">{event.note}</span>}
    </li>)}</ol></details>
}
