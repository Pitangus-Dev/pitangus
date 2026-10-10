import type { ComponentProps } from 'react'
import { cn } from 'cn'

// A filter that is on or off (aria-pressed). Selected reads as ink on a soft neutral, like every other selection:
// the brand yellow stays for the one primary action of the view.
export function FilterChip({ pressed, className, ...props }: ComponentProps<'button'> & { pressed: boolean }) {
  return <button type="button" aria-pressed={pressed} {...props}
    className={cn('inline-flex min-h-7 items-center gap-1 rounded-lg border px-3 text-sm whitespace-nowrap motion-safe:transition-colors',
      pressed ? 'border-app-fg bg-app-soft font-medium text-app-fg' : 'border-app-line text-app-muted hover:bg-app-soft hover:text-app-fg', className)} />
}
