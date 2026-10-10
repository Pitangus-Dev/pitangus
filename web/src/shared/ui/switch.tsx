import type { ReactNode } from "react"
import { cn } from "cn"

// An on/off option with its label beside it (role="switch"): the whole row is the target, and the hint below it is
// tied to the control with aria-describedby.
export function Switch({ id, checked, onCheckedChange, label, hint, disabled, className }: {
  id: string; checked: boolean; onCheckedChange: (checked: boolean) => void; label: ReactNode; hint?: ReactNode; disabled?: boolean; className?: string
}) {
  return <div className={cn("flex items-start gap-3", className)}>
    <button id={id} type="button" role="switch" aria-checked={checked} aria-describedby={hint ? `${id}-hint` : undefined} disabled={disabled}
      onClick={() => onCheckedChange(!checked)}
      className={cn("relative inline-flex h-6 w-10 shrink-0 items-center rounded-full border motion-safe:transition-colors disabled:opacity-50",
        checked ? "border-brand bg-brand" : "border-app-faint bg-app-soft")}>
      <span aria-hidden className={cn("inline-block size-4 rounded-full bg-panel shadow motion-safe:transition-transform", checked ? "translate-x-5" : "translate-x-1")} />
    </button>
    <span className="min-w-0 space-y-0.5 pt-0.5">
      <label htmlFor={id} className="block cursor-pointer text-sm text-app-fg">{label}</label>
      {hint && <span id={`${id}-hint`} className="block text-xs text-app-muted">{hint}</span>}
    </span>
  </div>
}
