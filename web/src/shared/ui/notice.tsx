import type { ReactNode } from 'react'
import { CheckCircleIcon, InfoIcon, WarningIcon, XCircleIcon } from '@phosphor-icons/react'
import { cn } from 'cn'

export type NoticeTone = 'ok' | 'attention' | 'info' | 'critical'
const ICON = { ok: CheckCircleIcon, attention: WarningIcon, info: InfoIcon, critical: XCircleIcon } as const
const ICON_TONE: Record<NoticeTone, string> = { ok: 'text-success', attention: 'text-attention', info: 'text-info', critical: 'text-danger' }

// Manual (Notice): a row on the normal surface, the status icon in its family colour and the text in ink. Only an error
// that blocks the task (`blocking`) gets the critical-soft ground with its line. No pastel boxes for information.
export function Notice({ tone, blocking = false, role, className, children }: {
  tone: NoticeTone; blocking?: boolean; role?: 'status' | 'alert' | 'group'; className?: string; children: ReactNode
}) {
  const Icon = ICON[tone]
  return <div role={role} className={cn('flex items-start gap-2.5 rounded-lg border px-3 py-2.5 text-sm leading-5 text-app-fg',
    blocking ? 'border-danger-line bg-danger-soft' : 'border-app-line bg-panel', className)}>
    <Icon aria-hidden className={cn('mt-0.5 size-4 shrink-0', ICON_TONE[tone])} />
    <div className="min-w-0 flex-1">{children}</div>
  </div>
}
