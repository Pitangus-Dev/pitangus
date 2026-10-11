import { useEffect, useRef } from 'react'

export const isMac = () => typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent)

// Single-key shortcuts must not fire while someone types, or inside a list that reads letters itself (select, menu).
export function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false
  if (target.isContentEditable || target.closest('[contenteditable=""], [contenteditable="true"]')) return true
  if (target.closest('input, textarea, select')) return true
  return !!target.closest('[role="listbox"], [role="menu"], [role="combobox"], [role="textbox"], [role="grid"]')
}

// Any modal (a confirmation, the add-domain form, the mobile navigation) owns the keyboard while it is open.
export const dialogOpen = () => !!document.querySelector('[role="dialog"], [role="alertdialog"]')

export type ShortcutHandlers = {
  palette: () => void
  help: () => void
  create: () => void
  go: (letter: string) => boolean
}

const SEQUENCE_MS = 1500

// ⌘K/Ctrl+K anywhere; N, ? and "G then a letter" only outside text fields and dialogs. `go` returns whether the
// letter meant a page, so an unknown one falls through to the page.
export function useShortcuts(handlers: ShortcutHandlers) {
  const latest = useRef(handlers)
  useEffect(() => { latest.current = handlers })
  useEffect(() => {
    let pendingG = 0
    const onKey = (event: KeyboardEvent) => {
      if (event.defaultPrevented || event.isComposing) return
      const key = event.key.toLowerCase()
      if (key === 'k' && (event.metaKey || event.ctrlKey) && !event.altKey && !event.shiftKey) {
        event.preventDefault()
        latest.current.palette()
        return
      }
      if (event.metaKey || event.ctrlKey || event.altKey) return
      if (isTypingTarget(event.target) || dialogOpen()) { pendingG = 0; return }
      if (pendingG && Date.now() - pendingG < SEQUENCE_MS) {
        pendingG = 0
        if (latest.current.go(key)) event.preventDefault()
        return
      }
      pendingG = 0
      if (event.key === '?') { event.preventDefault(); latest.current.help() }
      else if (key === 'g' && !event.shiftKey) pendingG = Date.now()
      else if (key === 'n' && !event.shiftKey) { event.preventDefault(); latest.current.create() }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])
}
