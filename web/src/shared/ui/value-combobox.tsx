import { useId, useRef, useState, type KeyboardEvent } from 'react'
import { CaretUpDownIcon, CheckIcon, PlusIcon } from '@phosphor-icons/react'
import { useTranslation } from 'react-i18next'

export type ValueOption = { value: string; label: string; hint?: string; group?: string }

// Tags go until none is left (taking one out can join what surrounded it into another); then spaces are collapsed.
function clean(text: string, maxLength: number) {
  let previous
  do {
    previous = text
    text = text.replace(/<[^>]*>/g, '')
  } while (text !== previous)
  return text.replace(/\s+/g, ' ').trim().slice(0, maxLength)
}

// A field with suggestions that also takes the person's own value: our list helps, it doesn't limit.
// `check` rejects a typed value that can't work (e.g. a malformed ATT&CK ID) and explains why.
export function ValueCombobox({ value, options, onChange, label, placeholder, maxLength = 80, check, className = '', describedBy, size = 'sm' }: {
  value: string; options: ValueOption[]; onChange: (value: string) => void; label: string; placeholder?: string; maxLength?: number
  check?: (text: string) => string | null; className?: string; describedBy?: string; size?: 'sm' | 'xs'
}) {
  const { t } = useTranslation('ui')
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const input = useRef<HTMLInputElement>(null)
  const listId = useId()
  const current = options.find(option => option.value === value)
  const shown = current?.label ?? value
  const text = clean(query, 200)
  const needle = text.toLowerCase()
  const matches = needle ? options.filter(option => `${option.value} ${option.label} ${option.hint ?? ''}`.toLowerCase().includes(needle)) : options
  const exact = options.find(option => option.value.toLowerCase() === needle || option.label.toLowerCase() === needle)
  const problem = !text || exact ? null : text.length > maxLength ? t('value_combobox.too_long', { count: maxLength }) : check ? check(text) : null
  const custom = text && !exact && !problem ? { value: text, label: t('value_combobox.use', { value: text }), create: true } : null
  const items: (ValueOption & { create?: boolean })[] = [...matches.slice(0, 60), ...(custom ? [custom] : [])]

  const choose = (next: string) => { onChange(next); setOpen(false); setQuery('') }
  const keys = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown') { event.preventDefault(); if (!open) setOpen(true); setActive(index => Math.min(index + 1, items.length - 1)) }
    else if (event.key === 'ArrowUp') { event.preventDefault(); setActive(index => Math.max(index - 1, 0)) }
    else if (event.key === 'Enter' && open) { event.preventDefault(); const item = items[active]; if (item) choose(item.value) }
    else if (event.key === 'Escape' && open) { event.preventDefault(); event.stopPropagation(); setOpen(false); setQuery('') }
  }
  const height = size === 'xs' ? 'h-7' : 'h-8'
  let lastGroup: string | undefined
  return <div className={`relative ${className}`} onBlur={event => {
    if (event.currentTarget.contains(event.relatedTarget as Node)) return
    // Leaving the field with Tab or a click keeps what was typed, as long as it's a usable value.
    if (open && exact) onChange(exact.value)
    else if (open && custom) onChange(custom.value)
    setOpen(false); setQuery('')
  }}>
    <div className={`flex ${height} items-center gap-1 rounded-lg border border-input bg-card px-2 has-[input:focus-visible]:border-focus has-[input:focus-visible]:shadow-[inset_0_0_0_1px_var(--focus)]`}>
      <input ref={input} role="combobox" aria-label={label} aria-expanded={open} aria-controls={listId} aria-autocomplete="list" aria-describedby={describedBy}
        aria-activedescendant={open && items[active] ? `${listId}-${active}` : undefined} data-bare maxLength={200}
        value={open ? query : shown} placeholder={open ? (current?.label ?? value) || placeholder : placeholder}
        onFocus={() => { setOpen(true); setQuery(''); setActive(0) }} onClick={() => { if (!open) { setOpen(true); setQuery(''); setActive(0) } }}
        onChange={event => {
          // Typing into the closed field (focus kept after choosing) starts a new search, not an edit of the shown label.
          const typed = event.target.value
          setQuery(!open && typed.startsWith(shown) ? typed.slice(shown.length) : typed); setActive(0); setOpen(true)
        }} onKeyDown={keys}
        className="min-w-0 flex-1 bg-transparent text-xs outline-none placeholder:text-app-subtle" />
      <CaretUpDownIcon className="size-3.5 shrink-0 text-app-subtle" />
    </div>
    {open && <div className="absolute z-30 mt-1 max-h-72 w-full min-w-56 overflow-y-auto rounded-lg border border-app-line bg-panel p-1 shadow-md">
      <ul id={listId} role="listbox" aria-label={label}>
        {items.map((item, index) => {
          const heading = !item.create && item.group && item.group !== lastGroup ? item.group : null
          lastGroup = item.create ? lastGroup : item.group
          return [heading && <li key={`group-${heading}`} role="presentation" className="px-2.5 pt-2 pb-1 text-[11px] font-medium text-app-subtle">{heading}</li>,
            <li key={`${item.create ? 'new' : 'option'}-${item.value}`} id={`${listId}-${index}`} role="option" aria-label={item.group && !item.create ? `${item.label}, ${item.group}` : undefined} aria-selected={!item.create && item.value === value}
              onMouseEnter={() => setActive(index)} onMouseDown={event => { event.preventDefault(); choose(item.value) }}
              className={`flex cursor-pointer items-center gap-2 rounded-md px-2.5 py-1.5 text-xs ${index === active ? 'bg-app-soft' : ''} ${item.create ? 'border-t border-app-line' : ''}`}>
              {item.create ? <PlusIcon className="size-3.5 shrink-0" /> : <CheckIcon className={`size-3.5 shrink-0 ${item.value === value ? 'text-brand' : 'text-transparent'}`} />}
              <span className="min-w-0 flex-1"><span className="block truncate">{item.label}</span>{item.hint && <span className="block truncate text-[11px] text-app-subtle">{item.hint}</span>}</span>
            </li>]
        })}
      </ul>
      <p role="status" className="empty:hidden">{problem ? <span className="block px-2.5 py-2 text-xs text-danger">{problem}</span>
        : items.length === 0 ? <span className="block px-2.5 py-2 text-xs text-app-subtle">{t('value_combobox.type_own')}</span> : null}</p>
    </div>}
  </div>
}
