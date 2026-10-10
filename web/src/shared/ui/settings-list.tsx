import { useId, useState, type ReactNode } from 'react'
import { CaretDownIcon } from '@phosphor-icons/react'
import { cn } from 'cn'
import { Button } from '@/shared/ui/button'
import { Bone } from '@/shared/ui/loading'

export type StatusTone = 'success' | 'attention' | 'danger' | 'muted'
const TONE: Record<StatusTone, string> = { success: 'text-success', attention: 'text-attention', danger: 'text-danger', muted: 'text-app-muted' }

// A plain page section: small heading, one line of description, then its rows. No card around it.
export function SettingsSection({ id, title, description, action, children }: { id: string; title: string; description?: ReactNode; action?: ReactNode; children: ReactNode }) {
  return <section aria-labelledby={id} className="space-y-3">
    <div className="flex flex-wrap items-end justify-between gap-x-4 gap-y-2">
      <div className="min-w-0"><h2 id={id} className="text-base font-semibold">{title}</h2>
        {description && <p className="mt-0.5 max-w-3xl text-sm text-app-muted">{description}</p>}</div>
      {action}
    </div>
    {children}
  </section>
}

export function SettingsRows({ children, label }: { children: ReactNode; label?: string }) {
  return <ul aria-label={label} className="divide-y divide-app-line border-y border-app-line">{children}</ul>
}

type Disclosure = { label: string; content: ReactNode; open?: boolean; onOpenChange?: (open: boolean) => void }

// One integration: what it is, one status line and a right-aligned action. Its configuration unfolds below the row
// and stays mounted while folded, so a half-written form survives closing it. `empty` is the "nothing here yet" row.
export function SettingsRow({ title, status, tone = 'muted', meta, loading, actions, disclosure, empty = false }: {
  title: ReactNode; status?: ReactNode; tone?: StatusTone; meta?: ReactNode; loading?: string; actions?: ReactNode; disclosure?: Disclosure; empty?: boolean
}) {
  const id = useId()
  const [local, setLocal] = useState(false)
  const open = disclosure?.open ?? local
  const toggle = () => { const next = !open; setLocal(next); disclosure?.onOpenChange?.(next) }
  return <li className="py-3">
    <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
      <div className="min-w-0 flex-1">
        {empty ? <p className="text-sm text-app-muted">{title}</p> : <h3 id={`${id}-title`} className="truncate text-sm font-medium">{title}</h3>}
        {loading ? <span role="status" className="flex h-5 items-center"><span className="sr-only">{loading}</span><Bone className="h-3 w-40" /></span>
          : (status || meta) && <p className="text-xs leading-5">{status && <span className={TONE[tone]}>{status}</span>}
            {status && meta && <span className="text-app-subtle"> · </span>}{meta && <span className="text-app-subtle">{meta}</span>}</p>}
      </div>
      {(actions || disclosure) && <div className="ml-auto flex shrink-0 flex-wrap items-center justify-end gap-1">
        {actions}
        {disclosure && <Button size="sm" variant="outline" aria-expanded={open} aria-controls={`${id}-panel`} aria-describedby={empty ? undefined : `${id}-title`} onClick={toggle}>
          {disclosure.label}<CaretDownIcon className={cn('motion-safe:transition-transform', open && 'rotate-180')} /></Button>}
      </div>}
    </div>
    {disclosure && <div id={`${id}-panel`} hidden={!open} className="pt-4 pb-2">{disclosure.content}</div>}
  </li>
}
