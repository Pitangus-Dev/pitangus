import { useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { X } from 'lucide-react'
import { BRAND } from '@/shared/lib/brand'

export function useToasts() {
  const { t } = useTranslation('analyses')
  const [toasts, setToasts] = useState<{ id: number; tone: 'ok' | 'error'; text: string }[]>([])
  // 2.2.1: a notice pauses while the pointer or focus is on it, and can be dismissed.
  const timers = useRef(new Map<number, number>())
  const nextId = useRef(0)
  const dismiss = (id: number) => { window.clearTimeout(timers.current.get(id)); timers.current.delete(id); setToasts(previous => previous.filter(item => item.id !== id)) }
  const schedule = (id: number) => { window.clearTimeout(timers.current.get(id)); timers.current.set(id, window.setTimeout(() => dismiss(id), 8000)) }
  const hold = (id: number) => { window.clearTimeout(timers.current.get(id)); timers.current.delete(id) }
  const push = (tone: 'ok' | 'error', text: string) => {
    const id = ++nextId.current
    setToasts(previous => [...previous, { id, tone, text }])
    schedule(id)
    // A browser notification only if already allowed: permission is never asked without a user action.
    if (typeof Notification !== 'undefined' && Notification.permission === 'granted') { try { new Notification(BRAND.name, { body: text, icon: '/assets/favicon.svg' }) } catch { /* sin notificaciones */ } }
  }
  const view = <div aria-live="polite" className="pointer-events-none fixed right-4 bottom-4 z-50 flex w-80 flex-col gap-2">{toasts.map(item =>
    <div key={item.id} role={item.tone === 'error' ? 'alert' : 'status'} onMouseEnter={() => hold(item.id)} onMouseLeave={() => schedule(item.id)} onFocus={() => hold(item.id)} onBlur={() => schedule(item.id)}
      className={`pointer-events-auto flex items-start gap-2 rounded-xl border px-4 py-3 text-sm shadow-xl ${item.tone === 'ok' ? 'border-brand/30 bg-panel text-app-fg' : 'border-danger-line bg-panel text-danger'}`}>
      <span className="min-w-0 flex-1">{item.text}</span>
      <button type="button" onClick={() => dismiss(item.id)} aria-label={t('progress.dismiss')} className="-m-1 grid size-6 shrink-0 place-items-center rounded-md text-app-muted hover:bg-app-soft hover:text-app-fg"><X className="size-3.5" /></button>
    </div>)}</div>
  return { push, view }
}
