import type { ReactNode } from 'react'
import { cn } from 'cn'

export type FigureTone = 'danger' | 'warning' | 'attention' | 'success' | 'neutral'
const TONE: Record<FigureTone, string> = { danger: 'text-danger', warning: 'text-warning', attention: 'text-attention', success: 'text-success', neutral: 'text-app-fg' }

// Headline numbers as one ruled row, not a grid of boxes: the same rule as the reports' `kpis`. Each figure spans three
// rows of the parent grid (label, value, hint) through a subgrid, so a label that wraps moves every value in its row
// down with it and the numbers keep one baseline.
export function KeyFigures({ children, className }: { children: ReactNode; className?: string }) {
  return <dl className={cn('grid grid-cols-2 border-t border-app-line xl:border-b sm:grid-cols-3 xl:auto-cols-fr xl:grid-flow-col xl:grid-cols-none xl:grid-rows-[auto_auto_auto]', className)}>{children}</dl>
}

export function KeyFigure({ label, value, suffix, hint, title, tone = 'neutral' }: { label: string; value: ReactNode; suffix?: string; hint?: string; title?: string; tone?: FigureTone }) {
  return <div title={title} className="row-span-3 grid min-w-0 grid-rows-subgrid content-start border-app-line py-3 pr-4 max-xl:border-b xl:border-l xl:px-4 xl:first:border-l-0 xl:first:pl-0">
    <dt className="self-end text-xs text-balance text-app-muted">{label}</dt>
    <dd className={cn('mt-1 text-2xl font-semibold tabular-nums', TONE[tone])}>{value}{suffix && <span className="text-sm font-normal text-app-subtle">{suffix}</span>}</dd>
    {hint && <dd className="mt-0.5 line-clamp-2 text-xs text-app-subtle">{hint}</dd>}
  </div>
}
