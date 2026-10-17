import fc from 'fast-check'
import { describe, expect, it } from 'vitest'
import { readRoute, writeRoute } from '@/shared/lib/route'
import { ALL, scopeBody, scopeFromParams, scopeParams, scopeQuery, scopeReady, withNames, type Scope } from '@/shared/lib/scope'

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

describe('scope in the address', () => {
  it('round-trips each kind and ignores what it does not know', () => {
    const chosen: Scope = { kind: 'assets', account: '', images: false, assets: [{ key: 'github#1', name: 'github#1', image: false }, { key: 'image:ghcr.io/org/a,b', name: 'image:ghcr.io/org/a,b', image: true }] }
    const back = (scope: Scope) => scopeFromParams(new URLSearchParams(Object.entries(scopeParams(scope)).filter(([, value]) => value) as [string, string][]))
    expect(back(chosen)).toEqual(chosen)
    expect(back({ ...ALL, kind: 'account', account: 'org' })).toEqual({ kind: 'account', account: 'org', assets: [], images: true })
    expect(back(ALL)).toEqual(ALL)
    expect(scopeParams({ ...ALL, kind: 'one' })).toEqual({ scope: null, account: null, assets: null, images: null })
    expect(scopeFromParams(new URLSearchParams('scope=nope'))).toBeNull()
    expect(scopeFromParams(new URLSearchParams('repo=github%231'))).toBeNull()
  })
})

describe('naming a scope read from the address', () => {
  it('names the assets known only by their key, and leaves the rest', () => {
    const read: Scope = { kind: 'assets', account: '', images: true, assets: [{ key: 'github#1', name: 'github#1', image: false }, { key: 'image:x', name: 'chosen name', image: true }] }
    const rows = [{ key: 'github#1', name: 'org/api', kind: 'repository' }, { key: 'image:x', name: 'ghcr.io/x', kind: 'image' }]
    expect(withNames(read, rows).assets).toEqual([{ key: 'github#1', name: 'org/api', image: false }, { key: 'image:x', name: 'chosen name', image: true }])
    expect(withNames(read, undefined)).toBe(read)
    expect(withNames({ ...ALL, kind: 'account', account: 'org' }, rows)).toEqual({ ...ALL, kind: 'account', account: 'org' })
  })
})

describe('scope in the address, for any key or link', () => {
  // Keys are opaque to the panel: a local folder or an image reference can hold commas, `%`, `&`, `#`, spaces or any
  // script, and the link must bring back exactly the same assets.
  const key = fc.oneof(fc.string({ unit: 'grapheme', minLength: 1, maxLength: 30 }),
    fc.array(fc.constantFrom('a', ',', '%', '%2C', '&', '=', '#', '+', '?', ' ', '/', ':', 'é', '😀'), { minLength: 1, maxLength: 10 }).map(parts => parts.join('')))
  const scope: fc.Arbitrary<Scope> = fc.oneof(
    fc.record({ kind: fc.constant('assets' as const), account: fc.constant(''), images: fc.boolean(),
      assets: fc.uniqueArray(key, { minLength: 1, maxLength: 6 }).map(keys => keys.map(item => ({ key: item, name: item, image: item.startsWith('image:') }))) }),
    fc.record({ kind: fc.constant('account' as const), account: fc.string({ unit: 'grapheme', minLength: 1, maxLength: 40 }), images: fc.boolean(), assets: fc.constant<Scope['assets']>([]) }),
    fc.constant(ALL))

  it('comes back unchanged from the address bar', () => {
    fc.assert(fc.property(scope, chosen => {
      writeRoute('findings', scopeParams(chosen))
      expect(scopeFromParams(readRoute().params)).toEqual(chosen)
    }))
  })

  it('read from any link, can always be sent to the API', () => {
    // A link is outside input: whatever it says, reading it and asking the API for it must not throw.
    const link = fc.dictionary(fc.constantFrom('scope', 'account', 'assets', 'images'), fc.oneof(
      fc.constantFrom('account', 'assets', 'all', '0'), fc.string({ unit: 'binary', maxLength: 120, size: 'max' }),
      fc.array(fc.constantFrom('a', '😀', '%', '%E0%A4%A', ','), { maxLength: 120, size: 'max' }).map(parts => parts.join(''))))
    fc.assert(fc.property(link, values => {
      const read = scopeFromParams(new URLSearchParams(values))
      if (read) { scopeQuery(read); scopeParams(read) }
    }))
  })
})
