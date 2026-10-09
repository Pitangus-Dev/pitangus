import { cn } from "cn"

import { Select, SelectContent, SelectGroup, SelectItem, SelectLabel, SelectTrigger, SelectValue } from "@/shared/ui/select"

export type SelectOption = { value: string; label: string; lang?: string; disabled?: boolean }
export type SelectOptionGroup = { label: string; options: SelectOption[] }

export const selectPopup = "border border-app-line bg-panel p-1 text-app-fg shadow-xl"

type SelectFieldProps = {
  value: string
  onValueChange: (value: string) => void
  options?: SelectOption[]
  groups?: SelectOptionGroup[]
  /** Label of the empty choice (value ""), shown in the trigger while nothing is chosen. */
  placeholder?: string
  id?: string
  "aria-label"?: string
  "aria-invalid"?: boolean
  "aria-describedby"?: string
  title?: string
  disabled?: boolean
  required?: boolean
  size?: "sm" | "default"
  className?: string
  align?: "start" | "center" | "end"
}

// A single-choice list with the panel's look. "" stands for "nothing chosen", like an empty <option>.
export function SelectField({ value, onValueChange, options = [], groups = [], placeholder, id, title, disabled, required, size, className, align = "start", ...aria }: SelectFieldProps) {
  const all = [...options, ...groups.flatMap(group => group.options)]
  const items = [...(placeholder !== undefined ? [{ value: null, label: placeholder }] : []), ...all.map(option => ({ value: option.value, label: option.label }))]
  return (
    <Select items={items} value={value === "" ? null : value} onValueChange={(next, details) => {
      // base-ui 1.8 resets to null when an item before the chosen one leaves the list, though the choice is still offered.
      if (next == null && details.reason === "none" && all.some(option => option.value === value)) return
      onValueChange(next == null ? "" : String(next))
    }} disabled={disabled} required={required}>
      <SelectTrigger id={id} title={title} size={size} {...aria}
        className={cn("w-full min-w-0 border-app-line bg-app-soft text-app-fg", className)}>
        <SelectValue placeholder={placeholder} className="min-w-0 truncate" />
      </SelectTrigger>
      <SelectContent align={align} className={selectPopup}>
        {placeholder !== undefined && <SelectItem value={null}>{placeholder}</SelectItem>}
        {options.map(option => <SelectItem key={option.value} value={option.value} lang={option.lang} disabled={option.disabled}>{option.label}</SelectItem>)}
        {groups.map(group => <SelectGroup key={group.label}><SelectLabel>{group.label}</SelectLabel>
          {group.options.map(option => <SelectItem key={option.value} value={option.value} lang={option.lang} disabled={option.disabled}>{option.label}</SelectItem>)}</SelectGroup>)}
      </SelectContent>
    </Select>
  )
}

