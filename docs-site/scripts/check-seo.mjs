// Fails the build when a page loses what search engines and assistants rely on: one h1, a meta description, canonical
// and hreflang links, Open Graph and Twitter tags, valid JSON-LD of the expected types (FAQ answers visible on the page),
// a sitemap entry with its date, and a line in llms.txt.
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { htmlPages } from '../integrations/security-headers.mjs'

const dist = path.resolve(fileURLToPath(new URL('../dist', import.meta.url)))
const problems = []

const entities = { amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'", '#x27': "'", nbsp: ' ' }
// Until none is left: taking one block out can join what surrounded it into another.
const withoutHiddenBlocks = (html) => {
  let previous
  do {
    previous = html
    html = html.replace(/<(script|style|template)[\s\S]*?<\/\1>/g, '')
  } while (html !== previous)
  return html
}
const visible = (html) => withoutHiddenBlocks(html)
  .replace(/<[^>]+>/g, ' ')
  .replace(/&(#?\w+);/g, (whole, name) => entities[name] ?? whole)
  .replace(/\s+/g, ' ')
const attr = (html, pattern) => new RegExp(`<${pattern}[^>]*>`).exec(html)?.[0]
const content = (tag) => tag && /content="([^"]*)"/.exec(tag)?.[1]

const sitemap = (await readFile(path.join(dist, 'sitemap-0.xml'), 'utf8'))
const llms = (await readFile(path.join(dist, 'llms.txt'), 'utf8')) + (await readFile(path.join(dist, 'es', 'llms.txt'), 'utf8'))
const robots = await readFile(path.join(dist, 'robots.txt'), 'utf8')
if (!/^Sitemap: https?:\/\/\S+sitemap-index\.xml$/m.test(robots)) problems.push('robots.txt: no Sitemap line')
for (const bot of ['GPTBot', 'ClaudeBot', 'PerplexityBot', 'Google-Extended']) {
  if (!robots.includes(`User-agent: ${bot}\nAllow: /`)) problems.push(`robots.txt: ${bot} not allowed`)
}

let checked = 0
for await (const file of htmlPages(dist)) {
  const name = path.relative(dist, file)
  const html = await readFile(file, 'utf8')
  if (name === '404.html' || /http-equiv="refresh"/.test(html)) continue
  checked++
  const fail = (message) => problems.push(`${name}: ${message}`)

  const h1 = html.match(/<h1[\s>]/g)?.length ?? 0
  if (h1 !== 1) fail(`${h1} h1 elements`)
  const description = content(attr(html, 'meta name="description"'))
  if (!description || description.length < 50 || description.length > 170) fail(`meta description missing or ${description?.length} characters`)
  const canonical = /<link rel="canonical" href="([^"]+)"/.exec(html)?.[1]
  if (!canonical) fail('no canonical link')
  for (const lang of ['en', 'es', 'x-default']) {
    if (!html.includes(`hreflang="${lang}"`)) fail(`no hreflang="${lang}" alternate`)
  }
  for (const tag of ['property="og:title"', 'property="og:description"', 'property="og:url"', 'property="og:image"', 'name="twitter:card"', 'name="twitter:title"', 'name="twitter:image"']) {
    if (!html.includes(`<meta ${tag}`)) fail(`no <meta ${tag}>`)
  }
  if (canonical && !sitemap.includes(`<loc>${canonical}</loc>`)) fail('not in the sitemap')
  if (canonical && !sitemap.includes(`<loc>${canonical}</loc><lastmod>`) && /<time datetime/.test(html)) fail('no <lastmod> in the sitemap')
  if (canonical && !llms.includes(`](${canonical})`)) fail('not listed in llms.txt')

  const blocks = [...html.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)]
  if (blocks.length !== 1) { fail(`${blocks.length} JSON-LD blocks`); continue }
  let data
  try { data = JSON.parse(blocks[0][1]) } catch (error) { fail(`JSON-LD doesn't parse (${error.message})`); continue }
  if (data['@context'] !== 'https://schema.org') fail('JSON-LD without the schema.org context')
  const graph = data['@graph'] ?? []
  const byType = (type) => graph.find((node) => node['@type'] === type)
  const org = byType('Organization')
  if (!org?.name || !org.logo || !org.sameAs?.length) fail('JSON-LD Organization incomplete')
  if (!byType('WebSite')?.url) fail('JSON-LD WebSite incomplete')
  const isHome = /^(es\/)?index\.html$/.test(name)
  if (isHome) {
    if (!byType('WebPage')) fail('home without a JSON-LD WebPage')
  } else {
    const article = byType('TechArticle')
    if (!article?.headline || !article.description || !article.inLanguage || !article.isPartOf) fail('JSON-LD TechArticle incomplete')
    if (article?.url !== canonical) fail('JSON-LD TechArticle url differs from the canonical link')
    const shown = /<time datetime="([^"]+)"/.exec(html)?.[1]?.slice(0, 10)
    if (shown && article?.dateModified !== shown) fail(`JSON-LD dateModified ${article?.dateModified} differs from the page's ${shown}`)
    const crumbs = byType('BreadcrumbList')?.itemListElement ?? []
    if (crumbs.length < 2 || crumbs.some((item, index) => item.position !== index + 1 || !item.name || !item.item)) fail('JSON-LD BreadcrumbList invalid')
  }
  if (/^(es\/)?faq\/index\.html$/.test(name)) {
    const faq = byType('FAQPage')
    if (!faq?.mainEntity?.length) fail('FAQ page without JSON-LD FAQPage questions')
    // Compared without whitespace: the page's inline tags may sit next to spaces the answer text doesn't keep.
    const squash = (value) => value.replace(/\s+/g, '')
    const text = squash(visible(html))
    for (const item of faq?.mainEntity ?? []) {
      if (!text.includes(squash(item.name))) fail(`FAQ question not visible: ${item.name}`)
      if (!text.includes(squash(item.acceptedAnswer.text))) fail(`FAQ answer not visible: ${item.name}`)
    }
  }
}

if (problems.length) {
  console.error(`SEO:\n${problems.join('\n')}`)
  process.exit(1)
}
console.log(`SEO: ${checked} pages with one h1, description, canonical, hreflang, Open Graph, JSON-LD, sitemap date and llms.txt entry.`)
