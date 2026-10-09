import { describe, expect, it } from 'vitest'
import { readRoute, writeRoute } from '@/shared/lib/route'

describe('routes', () => {
  it('writes English paths and reads them back', () => {
    writeRoute('findings', { repo: 'github#1' })
    expect(window.location.hash).toBe('#/findings?repo=github%231')
    expect(readRoute().view).toBe('findings')
    writeRoute('cves')
    expect(window.location.hash).toBe('#/cve-tracker')
  })

  it('keeps the Spanish paths of earlier links working, rewritten to English', () => {
    window.history.replaceState(null, '', '#/hallazgos?run=abc')
    const route = readRoute()
    expect(route.view).toBe('findings')
    expect(route.params.get('run')).toBe('abc')
    expect(window.location.hash).toBe('#/findings?run=abc')
    window.history.replaceState(null, '', '#/no-existe')
    expect(readRoute().view).toBeNull()
  })
})
