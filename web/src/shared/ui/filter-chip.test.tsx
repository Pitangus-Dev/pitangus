import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { FilterChip } from '@/shared/ui/filter-chip'

describe('filter chip', () => {
  it('marks the selected one with ink, never with the brand yellow', () => {
    render(<div><FilterChip pressed>All</FilterChip><FilterChip pressed={false}>acme</FilterChip></div>)
    const on = screen.getByRole('button', { name: 'All' })
    const off = screen.getByRole('button', { name: 'acme' })
    expect(on.getAttribute('aria-pressed')).toBe('true')
    expect(off.getAttribute('aria-pressed')).toBe('false')
    expect(on.className).toContain('border-app-fg')
    for (const chip of [on, off]) expect(chip.className).not.toMatch(/bg-primary|bg-brand/)
  })
})
