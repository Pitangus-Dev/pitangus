// Security headers for Cloudflare (dist/_headers, read by Workers static assets), written once the build is done. The
// CSP allows each inline script by its SHA-256, so it stays strict (no 'unsafe-inline' for scripts) and never needs
// editing by hand when Starlight changes one of them. scripts/check-headers.mjs then fails the build if any inline
// script on any page is missing from it.
// - 'wasm-unsafe-eval': Pagefind (the search) compiles its WebAssembly index reader; it allows WebAssembly only, not eval.
// - Styles keep 'unsafe-inline': Starlight and Expressive Code use style attributes, which hashes cannot cover.
// - Cloudflare Web Analytics, if it is turned on for the site, injects its beacon at the edge and reports to
//   cloudflareinsights.com; the same allowance as pitangus.dev.
import { createHash } from 'node:crypto'
import { readdir, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

export async function* htmlPages(dir) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) yield* htmlPages(path)
    else if (entry.name.endsWith('.html')) yield path
  }
}

// Every inline script the browser would run: no src, and not a data block (JSON, JSON-LD). Tag and attribute names
// in any case, and an end tag as HTML ends it (`</script >` too), so none is missed whatever writes the page.
export function inlineScripts(html) {
  const scripts = []
  for (const [, attributes = '', body] of html.matchAll(/<script(\s[^>]*)?>([\s\S]*?)<\/script(?:[\s/][^>]*)?>/gi)) {
    if (/\ssrc=/i.test(attributes)) continue
    const type = attributes.match(/\stype=["']?([^"'\s>]+)/i)?.[1]?.toLowerCase()
    if (type && type !== 'module' && !/javascript/.test(type)) continue
    scripts.push(body)
  }
  return scripts
}

export const scriptHash = (body) => `'sha256-${createHash('sha256').update(body).digest('base64')}'`

export default function securityHeaders() {
  return {
    name: 'security-headers',
    hooks: {
      'astro:build:done': async ({ dir, logger }) => {
        const root = fileURLToPath(dir)
        const hashes = new Set()
        for await (const page of htmlPages(root)) {
          for (const body of inlineScripts(await readFile(page, 'utf8'))) hashes.add(scriptHash(body))
        }
        const csp = [
          "default-src 'self'",
          `script-src 'self' 'wasm-unsafe-eval' https://static.cloudflareinsights.com ${[...hashes].sort().join(' ')}`.trim(),
          "style-src 'self' 'unsafe-inline'",
          "img-src 'self' data:",
          "font-src 'self'",
          "connect-src 'self' https://cloudflareinsights.com",
          "object-src 'none'",
          "base-uri 'self'",
          "form-action 'self'",
          "frame-ancestors 'none'",
          'upgrade-insecure-requests',
        ].join('; ')
        const headers = [
          '/*',
          `  Content-Security-Policy: ${csp}`,
          '  Strict-Transport-Security: max-age=63072000; includeSubDomains; preload',
          '  X-Content-Type-Options: nosniff',
          '  X-Frame-Options: DENY',
          '  Referrer-Policy: strict-origin-when-cross-origin',
          '  Permissions-Policy: accelerometer=(), autoplay=(), browsing-topics=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), usb=(), xr-spatial-tracking=()',
          '  Cross-Origin-Opener-Policy: same-origin',
          '',
          // Hashed file names: they never change, so browsers can keep them for a year.
          '/_astro/*',
          '  Cache-Control: public, max-age=31536000, immutable',
          '',
        ].join('\n')
        await writeFile(join(root, '_headers'), headers)
        logger.info(`_headers written (${hashes.size} inline script hash${hashes.size === 1 ? '' : 'es'} in the CSP)`)
      },
    },
  }
}
