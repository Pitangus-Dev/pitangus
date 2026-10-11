import { cn } from 'cn'

// A key hint, kept quiet: it helps whoever looks for it and stays out of the way of everyone else.
export function Kbd({ className, ...props }: React.ComponentProps<'kbd'>) {
  return <kbd data-slot="kbd" className={cn('inline-flex h-5 min-w-5 items-center justify-center rounded-sm border border-app-line px-1 font-mono text-[11px] leading-none font-normal text-app-subtle', className)} {...props} />
}

// Several keys pressed one after the other or together ("G O", "⌘ K").
export function Keys({ keys, className }: { keys: string[]; className?: string }) {
  return <span aria-hidden className={cn('inline-flex shrink-0 items-center gap-1', className)}>{keys.map(key => <Kbd key={key}>{key}</Kbd>)}</span>
}
