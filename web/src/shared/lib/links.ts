// A link from data the server passed through (advisories, scanners): only http(s) becomes a link, and a string that
// can't be parsed is shown as text instead of breaking the view that renders it.
export function externalLink(url: unknown): { href: string; host: string } | null {
  if (typeof url !== 'string') return null
  try {
    const parsed = new URL(url)
    return parsed.protocol === 'https:' || parsed.protocol === 'http:' ? { href: parsed.href, host: parsed.hostname } : null
  } catch { return null }
}
