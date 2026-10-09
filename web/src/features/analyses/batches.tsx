import { useEffect, useState } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import type { TFunction } from 'i18next'
import { Layers3, LoaderCircle } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { useConfirm } from '@/shared/ui/confirm'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { api, query } from '@/shared/api/http'
import type { BatchSummary } from '@/features/analyses/use-batches'

const duration = (t: TFunction<'analyses'>, seconds: number) => seconds < 90 ? t('duration.under_two_minutes') : seconds < 5400 ? t('duration.minutes', { value: Math.round(seconds / 60) }) : t('duration.hours', { value: Math.round(seconds / 3600) })

// `viewer`: quién mira. Cancelar es cosa de quien lanzó el lote o de un administrador; sin `viewer`, se muestra siempre.
export function BatchPanel({ active, last, onChanged, viewer }: { active: BatchSummary | null; last: BatchSummary | null; onChanged: () => void; viewer?: { username: string; admin: boolean } }) {
  const { t } = useTranslation('analyses')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const confirm = useConfirm()
  if (!active && !last) return null
  if (!active && last) return <p className="text-xs text-app-muted">{t('batch.last', { label: last.label, count: last.done, failed: last.failed ? t('batch.failed', { count: last.failed }) : '', cancelled: last.status === 'cancelled' ? t('batch.cancelled') : '', critical: last.critical ? t('batch.critical', { count: last.critical }) : '' })}</p>
  const batch = active!
  const finished = batch.done + batch.failed
  const percent = batch.total ? Math.round((finished / batch.total) * 100) : 0
  const cancel = async () => {
    if (!await confirm({ title: t('batch.cancel_title'), description: t('batch.confirm_cancel'), confirmLabel: t('batch.cancel'), cancelLabel: t('batch.keep_running'), destructive: true })) return
    setBusy(true); setError('')
    try { await api.post('/api/repositories/batches/cancel', 'cancel-batch', { id: batch.id }); onChanged() }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  return <div className="space-y-2 rounded-xl border border-brand/30 bg-brand/[0.06] p-4">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <p className="flex items-center gap-2 text-sm font-medium"><Layers3 className="size-4 text-brand" />{t('batch.running', { label: batch.label })}</p>
      {(!viewer || viewer.admin || viewer.username === batch.by) && <Button size="sm" variant="ghost" disabled={busy} onClick={() => void cancel()}>{busy && <LoaderCircle className="animate-spin" />}{t('batch.cancel')}</Button>}
    </div>
    <div role="progressbar" aria-label={t('batch.progress_label', { done: finished, total: batch.total })} aria-valuemin={0} aria-valuemax={batch.total} aria-valuenow={finished}
      className="h-1.5 overflow-hidden rounded-full bg-app-soft"><div className="h-full rounded-full bg-brand transition-all" style={{ width: `${Math.max(2, percent)}%` }} /></div>
    <p role="status" className="text-xs text-app-muted">{t('batch.progress', { done: finished, total: batch.total, failed: batch.failed ? t('batch.progress_failed', { count: batch.failed }) : '', critical: batch.critical, high: batch.high, duration: duration(t, batch.eta_seconds) })}</p>
    {batch.failed_items.length > 0 && <details className="text-xs text-app-muted"><summary className="cursor-pointer">{t('batch.show_failed')}</summary><ul className="mt-1 space-y-0.5">{batch.failed_items.map(item => <li key={item.name}><span className="font-medium">{item.name}</span>: {item.error}</li>)}</ul></details>}
    {error && <p role="alert" className="text-xs text-danger">{error}</p>}
  </div>
}

// Confirmación antes de analizar una organización entera: cuántos repositorios y cuánto tardará.
export function OrganizationScanDialog({ account, onClose, onStarted }: { account: string | null; onClose: () => void; onStarted: () => void }) {
  const { t } = useTranslation('analyses')
  const [total, setTotal] = useState<number | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  // Another organization starts counting again.
  const [counted, setCounted] = useState(account)
  if (account !== counted) { setCounted(account); if (account) { setTotal(null); setError('') } }
  useEffect(() => {
    if (!account) return
    api.get<{ total: number }>(`/api/sources?${query({ account, provider: 'github', per_page: 1 })}`).then(data => setTotal(data.total)).catch(caught => setError(String(caught)))
  }, [account])
  const start = async () => {
    setBusy(true); setError('')
    try { await api.post('/api/repositories/batches', 'scan-batch', { account }); onStarted(); onClose() }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  return <Dialog open={!!account} onOpenChange={next => { if (!next) onClose() }}><DialogContent className="max-w-lg">
    <DialogHeader><DialogTitle>{t('org.dialog_title', { name: account })}</DialogTitle>
      <DialogDescription>{t('org.dialog_description')}</DialogDescription></DialogHeader>
    <p className="rounded-lg border border-app-line bg-inset p-3 text-sm">{total === null ? t('org.counting') : <Trans t={t} i18nKey="org.estimate" count={total} values={{ duration: duration(t, total * 60) }} components={{ strong: <strong /> }} />}</p>
    {error && <p role="alert" className="text-sm text-danger">{error}</p>}
    <DialogFooter><Button variant="ghost" onClick={onClose}>{t('common:actions.cancel')}</Button>
      <Button disabled={busy || !total} onClick={() => void start()} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy && <LoaderCircle className="animate-spin" />}{total === null ? t('org.scan_pending') : t('org.scan', { count: total })}</Button></DialogFooter>
  </DialogContent></Dialog>
}
