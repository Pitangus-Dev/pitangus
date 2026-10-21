// /llms.txt and /llms-full.txt (llmstxt.org) for assistants and answer engines, in English at the root and in Spanish
// under /es/, written once the build is done from the same Markdown the pages render. llms.txt lists every page in
// sidebar order with its meta description; llms-full.txt carries the full text, with links made absolute.
import { readFile, readdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

export async function* markdownFiles(dir) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const file = path.join(dir, entry.name)
    if (entry.isDirectory()) yield* markdownFiles(file)
    else if (/\.mdx?$/.test(entry.name)) yield file
  }
}

// Only top-level `key: value` lines: the synced pages write JSON strings, the hand-written home pages plain YAML.
export function parse(source) {
  const match = /^---\n([\s\S]*?)\n---\n?/.exec(source)
  const data = {}
  for (const line of (match?.[1] ?? '').split('\n')) {
    const field = /^([A-Za-z]+):\s*(.+)$/.exec(line)
    if (!field) continue
    const [, key, raw] = field
    try { data[key] = raw.startsWith('"') ? JSON.parse(raw) : raw.replace(/^'(.*)'$/, '$1') } catch { data[key] = raw }
  }
  return { data, body: source.slice(match?.[0].length ?? 0) }
}

const decode = (text) => text.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&')

// Each removal runs until nothing is left to remove: taking one comment or tag out can join what surrounded it into
// another one.
const withoutComments = (text) => {
  let previous
  do {
    previous = text
    text = text.replace(/<!--[\s\S]*?-->/g, '')
  } while (text !== previous)
  return text
}
const withoutTags = (text) => {
  let previous
  do {
    previous = text
    text = text.replace(/<\/?[a-zA-Z][^>]*>/g, '')
  } while (text !== previous)
  return text
}

// MDX and the HTML the sync step writes (figures, diagrams, link lists) turned back into plain Markdown.
function toMarkdown(body, pageUrl) {
  const absolute = (href) => (/^(?:[a-z]+:|#)/i.test(href) ? href : new URL(href, pageUrl).href)
  const prose = (part) => {
    const linked = withoutComments(part)
      .replace(/<figure[\s\S]*?<\/figure>/g, (figure) => {
        const alt = /alt="([^"]*)"/.exec(figure)?.[1]
        const caption = /<figcaption[^>]*>([\s\S]*?)<\/figcaption>/.exec(figure)?.[1]
        return alt ? `[Image: ${decode(alt)}${caption ? ` (${decode(withoutTags(caption))})` : ''}]` : ''
      })
      .replace(/<img\s[^>]*alt="([^"]*)"[^>]*>/g, (_, alt) => (alt ? `[Image: ${decode(alt)}]` : ''))
      .replace(/<li><a href="([^"]+)">([\s\S]*?)<\/a><p>([\s\S]*?)<\/p><\/li>/g, (_, href, label, note) => `- [${label}](${absolute(href)}): ${note}`)
      .replace(/<a href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/g, (_, href, label) => `[${label}](${absolute(href)})`)
    return withoutTags(linked).replace(/(?<!!)\[([^\]]+)\]\(([^)\s]+)\)/g, (_, label, href) => `[${label}](${absolute(href)})`)
  }
  // Code (fenced or inline) is left exactly as written; only the prose around it is cleaned.
  const parts = body.replace(/^import\s.+$/gm, '').split(/(^```[\s\S]*?^```|`[^`\n]+`)/m)
  return parts
    .map((part, index) => (index % 2 ? part : prose(part)))
    .join('')
    .replace(/\n{3,}/g, '\n\n')
    .trim()
}

const texts = {
  en: {
    pages: 'Documentation',
    other: 'Other languages',
    otherLinks: (url) => [
      `- [Índice en español](${url('es/llms.txt')}): the same documentation in Spanish`,
      `- [Texto completo en español](${url('es/llms-full.txt')}): every Spanish page in one file`,
    ],
    full: (url) => `- [Full text](${url('llms-full.txt')}): every page of this documentation in one Markdown file`,
    source: 'Source',
    updated: 'Last updated',
  },
  es: {
    pages: 'Documentación',
    other: 'Otros idiomas',
    otherLinks: (url) => [
      `- [English index](${url('llms.txt')}): la misma documentación en inglés`,
      `- [English full text](${url('llms-full.txt')}): todas las páginas en inglés en un solo archivo`,
    ],
    full: (url) => `- [Texto completo](${url('es/llms-full.txt')}): todas las páginas de esta documentación en un solo archivo Markdown`,
    source: 'Fuente',
    updated: 'Última actualización',
  },
}

/**
 * @param {{ title: string, summary: Record<'en' | 'es', string>, details: Record<'en' | 'es', string>, sidebar: any[] }} options
 */
export default function llmsTxt({ title, summary, details, sidebar }) {
  let config
  return {
    name: 'llms-txt',
    hooks: {
      'astro:config:done': ({ config: done }) => { config = done },
      'astro:build:done': async ({ dir, logger }) => {
        const root = fileURLToPath(dir)
        const contentRoot = path.join(fileURLToPath(config.root), 'src', 'content', 'docs')
        const base = config.base.replace(/\/?$/, '/')
        const url = (route) => new URL(`${base}${route}`, config.site).href

        const pages = { en: new Map(), es: new Map() }
        for await (const file of markdownFiles(contentRoot)) {
          const relative = path.relative(contentRoot, file).split(path.sep).join('/')
          const lang = relative.startsWith('es/') ? 'es' : 'en'
          const slug = relative.replace(/^es\//, '').replace(/\.mdx?$/, '').replace(/(^|\/)index$/, '')
          const { data, body } = parse(await readFile(file, 'utf8'))
          const route = `${lang === 'es' ? 'es/' : ''}${slug ? `${slug}/` : ''}`
          pages[lang].set(slug, { slug, route, url: url(route), title: data.title, description: data.description, lastUpdated: data.lastUpdated, body })
        }

        // Sidebar groups become sections; anything not in the sidebar (but published) goes last.
        const label = (item, lang) => (lang === 'es' ? item.translations?.es : undefined) ?? item.label
        const sections = (lang) => {
          const seen = new Set([''])
          const out = []
          const loose = []
          for (const item of sidebar) {
            if (item.items) {
              out.push({ heading: label(item, lang), slugs: item.items.map((child) => child.slug) })
            } else loose.push(item.slug)
          }
          out.push({ heading: lang === 'es' ? 'Más' : 'More', slugs: loose })
          for (const section of out) section.slugs.forEach((slug) => seen.add(slug))
          const rest = [...pages[lang].keys()].filter((slug) => !seen.has(slug)).sort()
          if (rest.length) out.at(-1).slugs.push(...rest)
          return out
        }

        for (const lang of ['en', 'es']) {
          const t = texts[lang]
          const prefix = lang === 'es' ? 'es/' : ''
          const home = pages[lang].get('')
          const index = [`# ${title}`, '', `> ${summary[lang]}`, '', details[lang], '']
          const full = [`# ${title}`, '', `> ${summary[lang]}`, '']
          for (const section of sections(lang)) {
            const listed = section.slugs.map((slug) => pages[lang].get(slug)).filter(Boolean)
            if (!listed.length) continue
            index.push(`## ${section.heading}`, '', ...listed.map((page) => `- [${page.title}](${page.url}): ${page.description}`), '')
            for (const page of listed) {
              full.push('---', '', `# ${page.title}`, '', `${t.source}: ${page.url}${page.lastUpdated ? `  \n${t.updated}: ${page.lastUpdated}` : ''}`, '', `> ${page.description}`, '', toMarkdown(page.body, page.url), '')
            }
          }
          index.push('## Optional', '', t.full(url), `- [${home?.title ?? title}](${url(prefix)}): ${home?.description ?? summary[lang]}`, '', `## ${t.other}`, '', ...t.otherLinks(url), '')
          await writeFile(path.join(root, prefix, 'llms.txt'), index.join('\n'))
          await writeFile(path.join(root, prefix, 'llms-full.txt'), full.join('\n'))
        }
        logger.info(`llms.txt and llms-full.txt written (${pages.en.size} English and ${pages.es.size} Spanish pages)`)
      },
    },
  }
}
