import { afterEach, describe, expect, it, vi } from 'vitest'
import { render } from '@testing-library/react'
import { FoundVsFixed, StackedSeverityBars } from '@/shared/charts/charts'

const days = (count: number) => Array.from({ length: count }, (_, index) => {
  const day = new Date(Date.UTC(2026, 8, 11 + index)).toISOString().slice(0, 10)
  return { day, critical: index % 3, high: 1, medium: 0, low: 2, found: index, fixed: index >> 1 }
})

// The width a label takes (`10/08` at 11 px is ~30 px) and the room the axis promises between two.
const spans = (container: HTMLElement) => [...container.querySelectorAll('text')]
  .filter(text => /^\d\d\/\d\d$/.test(text.textContent ?? ''))
  .map(text => {
    const x = Number(text.getAttribute('x')), anchor = text.getAttribute('text-anchor')
    return anchor === 'start' ? [x, x + 36] : anchor === 'end' ? [x - 36, x] : [x - 18, x + 18]
  })

describe('day axis', () => {
  afterEach(() => vi.restoreAllMocks())

  for (const width of [340, 520, 640, 760, 900, 1180, 1500])
    for (const count of [7, 14, 29, 30, 31])
      it(`labels never crowd each other (${count} days, ${width} px)`, () => {
        vi.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockReturnValue(width)
        for (const Chart of [StackedSeverityBars, FoundVsFixed]) {
          const { container, unmount } = render(<Chart data={days(count)} />)
          const placed = spans(container)
          expect(placed.length).toBeGreaterThanOrEqual(2)
          for (let index = 1; index < placed.length; index++) expect(placed[index][0] - placed[index - 1][1]).toBeGreaterThanOrEqual(12)
          unmount()
        }
      })
})
