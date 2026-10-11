import { act, renderHook } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { useRouteState } from '@/app/route-state'

const go = (hash: string) => act(() => {
  window.history.replaceState(null, '', hash)
  window.dispatchEvent(new HashChangeEvent('hashchange'))
})

describe('route state', () => {
  afterEach(() => window.history.replaceState(null, '', '#/'))

  it('preselects the wizard when a link in the same tab names a domain and a type', () => {
    window.history.replaceState(null, '', '#/overview')
    const { result } = renderHook(() => useRouteState())
    go('#/new?type=web&domain=d1')
    expect(result.current.view).toBe('new')
    expect(result.current.wizardStart).toEqual({ source: null, domain: 'd1', type: 'web' })
  })

  it('keeps a wizard in progress when the address names the same start', () => {
    window.history.replaceState(null, '', '#/new')
    const { result } = renderHook(() => useRouteState())
    act(() => result.current.setWizardStart({ source: 'repo-1', domain: null, type: null }))
    const before = result.current.wizardStart
    go('#/new')
    expect(result.current.wizardStart).toBe(before)
    go('#/new?type=import')
    expect(result.current.wizardStart).toEqual({ source: null, domain: null, type: 'import' })
  })

  it('follows the run and the domain from the address', () => {
    window.history.replaceState(null, '', '#/overview')
    const { result } = renderHook(() => useRouteState())
    go('#/findings?run=r1')
    expect(result.current.view).toBe('findings')
    expect(result.current.selectedId).toBe('r1')
    go('#/domain?id=d2&tab=scans')
    expect(result.current.domainRoute).toEqual({ id: 'd2', tab: 'scans' })
    const before = result.current.domainRoute
    go('#/domain?id=d2&tab=scans')
    expect(result.current.domainRoute).toBe(before)
    go('#/domain?id=d2&tab=access')
    expect(result.current.domainRoute).toEqual({ id: 'd2', tab: 'overview' })
  })
})
