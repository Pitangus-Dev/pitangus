import { useRef, type KeyboardEvent } from "react"
import { cn } from "cn"

export type SegmentOption<T extends string> = { value: T; label: string }

// A few mutually exclusive choices side by side (role="radiogroup"): arrows move the choice, Tab leaves the group.
export function Segmented<T extends string>({ value, onChange, options, label, className, disabled }: { value: T; onChange: (value: T) => void; options: SegmentOption<T>[]; label: string; className?: string; disabled?: boolean }) {
  const buttons = useRef<(HTMLButtonElement | null)[]>([])
  const move = (event: KeyboardEvent, index: number) => {
    const step = event.key === "ArrowRight" || event.key === "ArrowDown" ? 1 : event.key === "ArrowLeft" || event.key === "ArrowUp" ? -1 : 0
    if (!step || disabled) return
    event.preventDefault()
    const next = (index + step + options.length) % options.length
    onChange(options[next].value)
    buttons.current[next]?.focus()
  }
  return <div role="radiogroup" aria-label={label} aria-disabled={disabled || undefined} className={cn("inline-flex rounded-lg border border-app-line bg-app-soft p-0.5", disabled && "opacity-60", className)}>
    {options.map((option, index) => <button key={option.value} ref={node => { buttons.current[index] = node }} type="button" role="radio" aria-checked={value === option.value}
      tabIndex={value === option.value ? 0 : -1} disabled={disabled} onClick={() => { if (option.value !== value) onChange(option.value) }} onKeyDown={event => move(event, index)}
      className={cn("min-h-7 rounded-md px-3 text-sm", value === option.value ? "bg-panel font-medium text-app-fg ring-1 ring-app-fg" : "text-app-muted enabled:hover:text-app-fg", disabled && "cursor-not-allowed")}>{option.label}</button>)}
  </div>
}
