import { describe, expect, it } from 'vitest'
import { externalLink } from '@/shared/lib/links'

describe('external links from server data', () => {
  it('links http(s) and names its host', () => {
    expect(externalLink('https://github.com/advisories/GHSA-x')).toEqual({ href: 'https://github.com/advisories/GHSA-x', host: 'github.com' })
    expect(externalLink('http://example.org/a b')?.host).toBe('example.org')
  })

  it('never links another scheme, and never throws on text that is not a URL', () => {
    for (const value of ['javascript:alert(1)', 'data:text/html,<b>x</b>', 'file:///etc/passwd', 'https://exa mple.com/x', 'https://', 'not a url', '', null, undefined, 42])
      expect(externalLink(value)).toBeNull()
  })
})
