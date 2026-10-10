import type { ReactNode } from 'react'
import { ChevronRight } from 'lucide-react'
import { cn } from 'cn'

// A fold for what only some people need: a chevron and a muted line, no filled box. The native <details> keeps
// keyboard and screen reader support; the marker is hidden and the chevron turns when it opens.
export function Disclosure({ summary, children, open, className, summaryClassName, bodyClassName }: {
  summary: ReactNode; children: ReactNode; open?: boolean; className?: string; summaryClassName?: string; bodyClassName?: string
}) {
  return <details open={open} className={cn('group', className)}>
    <summary className={cn('flex min-h-6 w-fit cursor-pointer list-none items-center gap-1.5 text-sm text-app-secondary hover:text-app-fg [&::-webkit-details-marker]:hidden', summaryClassName)}>
      <ChevronRight className="size-4 shrink-0 text-app-subtle motion-safe:transition group-open:rotate-90" aria-hidden />{summary}</summary>
    <div className={cn('mt-2 pl-5.5', bodyClassName)}>{children}</div>
  </details>
}
