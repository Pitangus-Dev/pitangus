import type { ReactNode } from 'react'
import { cn } from 'cn'

export type FigureTone = 'danger' | 'warning' | 'attention' | 'success' | 'neutral'
const TONE: Record<FigureTone, string> = { danger: 'text-danger', warning: 'text-warning', attention: 'text-attention', success: 'text-success', neutral: 'text-app-fg' }

// Headline numbers as one ruled row, not a grid of boxes: the same rule as the reports' `kpis`.
export function KeyFigures({ children, className }: { children: ReactNode; className?: string }) {
  return <dl className={cn('grid grid-cols-2 border-t border-app-line xl:border-b sm:grid-cols-3 xl:auto-cols-fr xl:grid-flow-col xl:grid-cols-none', className)}>{children}</dl>
}

export function KeyFigure({ label, value, suffix, hint, tone = 'neutral' }: { label: string; value: ReactNode; suffix?: string; hint?: string; tone?: FigureTone }) {
  return <div className="min-w-0 border-app-line py-3 pr-4 max-xl:border-b xl:border-l xl:px-4 xl:first:border-l-0 xl:first:pl-0">
    <dt className="text-xs text-balance text-app-muted">{label}</dt>
    <dd className={cn('mt-1 text-2xl font-semibold tabular-nums', TONE[tone])}>{value}{suffix && <span className="text-sm font-normal text-app-subtle">{suffix}</span>}</dd>
    {hint && <dd className="mt-0.5 line-clamp-2 text-xs text-app-subtle">{hint}</dd>}
  </div>
}
