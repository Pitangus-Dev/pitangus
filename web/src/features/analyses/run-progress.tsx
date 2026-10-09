import { formatTime } from '@/shared/i18n/format'
import { useEffect, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {} from '@/shared/i18n'
import { runQuery } from '@/shared/api/queries'
import { CircleAlert, CircleCheck, LoaderCircle, Terminal } from 'lucide-react'
import { Card, CardContent } from '@/shared/ui/card'

export type ProgressEvent = { at: string; level: 'info' | 'ok' | 'warn' | 'error'; message: string }
export type RunningRun = { id: string; status: string; created_at: string; started_at?: string; finished_at?: string; source?: { name: string }; progress?: ProgressEvent[] }

// Consola de progreso del escaneo: solo eventos pensados para el usuario, nunca salida del servidor.
export function RunProgress({ run }: { run: RunningRun }) {
  const { t } = useTranslation('analyses')
  // La consulta sondea sola mientras la ejecución está en cola o corriendo (ver runQuery) y comparte caché.
  // `dataUpdatedAt` is the clock for the elapsed time: it advances with every poll.
  const { data, dataUpdatedAt: now } = useQuery({ ...runQuery<RunningRun>(run.id), initialData: run })
  const live = data ?? run
  const bottom = useRef<HTMLDivElement>(null)
  useEffect(() => { bottom.current?.scrollIntoView({ block: 'nearest' }) }, [live.progress?.length])
  const active = ['queued', 'running'].includes(live.status)
  const elapsed = live.started_at ? Math.max(0, Math.round((now - Date.parse(live.started_at)) / 1000)) : 0
  return <Card className="overflow-hidden border-app-line bg-console">
    <div className="flex items-center justify-between gap-3 border-b border-app-line bg-console-top px-4 py-3 text-xs">
      <span className="flex items-center gap-2 font-mono text-app-muted"><Terminal className="size-3.5" />{live.source?.name ?? t('progress.scan')} · {live.id.slice(0, 8)}</span>
      <span className={`flex items-center gap-1.5 ${active ? 'text-brand' : live.status === 'failed' ? 'text-danger' : 'text-app-muted'}`}>
        {active ? <LoaderCircle className="size-3.5 animate-spin" /> : live.status === 'failed' ? <CircleAlert className="size-3.5" /> : <CircleCheck className="size-3.5" />}
        {/* The seconds tick with every poll: only the change of state is announced. */}
        <span aria-hidden>{live.status === 'queued' ? t('common:run_status.queued') : live.status === 'running' ? t('progress.running', { seconds: elapsed }) : live.status === 'failed' ? t('progress.failed') : t('progress.done')}</span>
        <span role="status" className="sr-only">{live.status === 'queued' ? t('common:run_status.queued') : live.status === 'running' ? t('common:run_status.running') : live.status === 'failed' ? t('progress.failed') : t('progress.done')}</span>
      </span>
    </div>
    {/* 4.1.3: cada paso nuevo se anuncia; el nivel no depende solo del color (1.4.1). */}
    <CardContent role="log" aria-live="polite" aria-label={t('progress.log')} tabIndex={0} className="max-h-72 overflow-y-auto p-4 font-mono text-xs leading-6">
      {(live.progress ?? []).map((event, index) => <div key={index} className="flex gap-3"><span className="shrink-0 text-app-subtle">{formatTime(event.at)}</span><span className={event.level === 'ok' ? 'text-success' : event.level === 'warn' ? 'text-warning' : event.level === 'error' ? 'text-danger' : 'text-app-secondary'}>{event.level === 'warn' ? <span className="font-semibold">{t('progress.warning')} </span> : event.level === 'error' ? <span className="font-semibold">{t('progress.error')} </span> : null}{event.message}</span></div>)}
      {active && <div aria-hidden className="flex gap-3 text-app-subtle"><span className="shrink-0">{formatTime(now)}</span><span className="motion-safe:animate-pulse">…</span></div>}
      <div ref={bottom} />
    </CardContent>
  </Card>
}
