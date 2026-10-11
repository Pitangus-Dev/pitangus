// Fails the build when dist/_headers would break a page or weaken the site: every inline script on every page must have
// its hash in the CSP, no page may rely on inline event handlers or javascript: URLs (the CSP blocks both), and each
// security header must be there with the expected value.
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { htmlPages, inlineScripts, scriptHash } from '../integrations/security-headers.mjs'

const dist = path.resolve(fileURLToPath(new URL('../dist', import.meta.url)))
const headersFile = await readFile(path.join(dist, '_headers'), 'utf8')

const rules = new Map()
let current
for (const line of headersFile.split('\n')) {
  if (!line.trim()) continue
  if (!/^\s/.test(line)) rules.set((current = line.trim()), new Map())
  else {
    const [name, ...value] = line.trim().split(':')
    rules.get(current).set(name.toLowerCase(), value.join(':').trim())
  }
}

const problems = []
const all = rules.get('/*') ?? new Map()
const expect = (name, test) => {
  const value = all.get(name)
  if (!value || !test(value)) problems.push(`_headers: ${name} is missing or weak (${value ?? 'absent'})`)
}
expect('strict-transport-security', (v) => /max-age=(\d+)/.exec(v)?.[1] >= 63072000 && /includeSubDomains/.test(v) && /preload/.test(v))
expect('x-content-type-options', (v) => v === 'nosniff')
expect('x-frame-options', (v) => v === 'DENY')
expect('referrer-policy', (v) => v === 'strict-origin-when-cross-origin')
expect('cross-origin-opener-policy', (v) => v === 'same-origin')
expect('permissions-policy', (v) => ['camera', 'microphone', 'geolocation', 'payment', 'usb'].every((f) => v.includes(`${f}=()`)))
expect('content-security-policy', (v) => /frame-ancestors 'none'/.test(v) && /object-src 'none'/.test(v) && !/script-src[^;]*'unsafe-(inline|eval)'/.test(v))
if (!/immutable/.test(rules.get('/_astro/*')?.get('cache-control') ?? '')) problems.push('_headers: /_astro/* is not cached as immutable')

const scriptSrc = /script-src([^;]*)/.exec(all.get('content-security-policy') ?? '')?.[1] ?? ''
const allowed = new Set(scriptSrc.trim().split(/\s+/))
let scripts = 0
let pages = 0
for await (const page of htmlPages(dist)) {
  pages++
  const html = await readFile(page, 'utf8')
  const name = path.relative(dist, page)
  for (const body of inlineScripts(html)) {
    scripts++
    if (!allowed.has(scriptHash(body))) problems.push(`${name}: inline script not allowed by the CSP: ${body.trim().slice(0, 60)}…`)
  }
  for (const [tag] of html.matchAll(/<[a-z][a-z0-9-]*\s[^>]*>/gi)) {
    if (/\son[a-z]+\s*=/i.test(tag)) problems.push(`${name}: inline event handler, blocked by the CSP: ${tag.slice(0, 80)}`)
    if (/\s(?:href|src|action)\s*=\s*["']?\s*javascript:/i.test(tag)) problems.push(`${name}: javascript: URL, blocked by the CSP`)
  }
}

if (problems.length) {
  console.error(`Security headers:\n${problems.join('\n')}`)
  process.exit(1)
}
console.log(`Security headers: ${pages} pages, ${scripts} inline scripts, all allowed by the CSP.`)
