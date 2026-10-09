import { describe, expect, it } from 'vitest'
import { ALL, scopeBody, scopeQuery, scopeReady, type Scope } from '@/features/compliance/scope'

describe('portfolio scope', () => {
  const chosen: Scope = { kind: 'assets', account: '', images: false, assets: [{ key: 'github#1', name: 'org/api', image: false }, { key: 'image:ghcr.io/org/api', name: 'ghcr.io/org/api', image: true }] }

  it('sends nothing for everything, and the chosen kind otherwise', () => {
    expect(scopeBody(ALL)).toEqual({})
    expect(scopeQuery(ALL)).toBe('')
    expect(scopeBody({ ...ALL, kind: 'account', account: 'org' })).toEqual({ account: 'org', include_images: true })
    expect(scopeQuery(chosen)).toBe('assets=github%231&assets=image%3Aghcr.io%2Forg%2Fapi&include_images=false')
  })

  it('is ready only once an organization or an asset is chosen', () => {
    expect(scopeReady(ALL)).toBe(true)
    expect(scopeReady({ ...ALL, kind: 'account' })).toBe(false)
    expect(scopeReady({ ...chosen, assets: [] })).toBe(false)
    expect(scopeReady(chosen)).toBe(true)
    expect(scopeReady({ ...chosen, kind: 'one' })).toBe(false)
  })
})
