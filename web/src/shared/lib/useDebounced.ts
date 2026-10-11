import { useEffect, useState } from 'react'

// `value` once it has stopped changing for `delay` ms (a probe or a search shouldn't fire on every keystroke).
export function useDebounced<T>(value: T, delay: number): T {
  const [settled, setSettled] = useState(value)
  useEffect(() => {
    const timer = window.setTimeout(() => setSettled(value), delay)
    return () => window.clearTimeout(timer)
  }, [value, delay])
  return settled
}
