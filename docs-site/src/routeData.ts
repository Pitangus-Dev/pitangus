// Structured data (JSON-LD) in every page's <head>, so search engines and assistants can tell who publishes the docs,
// what each page is and when it last changed. Everything comes from what the page already shows: its title, meta
// description, "Last updated" date and, on the FAQ, its visible questions and answers.
import { defineRouteMiddleware } from '@astrojs/starlight/route-data'

const ORGANIZATION = {
  '@type': 'Organization',
  // The same entity pitangus.dev declares, so both sites resolve to one publisher.
  '@id': 'https://pitangus.dev/#arodium',
  name: 'Arodium',
  url: 'https://arodium.com',
  sameAs: ['https://github.com/Pitangus-Dev'],
}

const NAMES = {
  en: { home: 'Pitangus documentation', site: 'Pitangus Docs' },
  es: { home: 'Documentación de Pitangus', site: 'Pitangus Docs' },
}

// Inside a <script>, "</" would end it early: escape "<" (still valid JSON).
const json = (data: unknown) => JSON.stringify(data).replace(/</g, '\\u003c')

const entities: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'", '#x27': "'", nbsp: ' ' }
// Until none is left: taking one tag out can join what surrounded it into another.
const withoutTags = (html: string) => {
  let previous
  do {
    previous = html
    html = html.replace(/<[^>]+>/g, '')
  } while (html !== previous)
  return html
}
const text = (html: string) =>
  withoutTags(html.replace(/<\/?(?:p|li|ul|ol|br|div|h[1-6]|pre|table|tr|td|th|blockquote)\b[^>]*>/g, ' '))
    .replace(/&(#?\w+);/g, (whole, name) => entities[name] ?? (name.startsWith('#') ? String.fromCodePoint(Number(name.replace(/^#x?/, name[1] === 'x' ? '0x' : ''))) : whole))
    .replace(/\s+/g, ' ')
    .trim()

// Each <h2> of the rendered FAQ is a question; everything up to the next <h2> is its answer.
function faqItems(html: string) {
  const clean = html.replace(/<a class="sl-anchor-link"[\s\S]*?<\/a>/g, '')
  return [...clean.matchAll(/<h2[^>]*>([\s\S]*?)<\/h2>([\s\S]*?)(?=<h2|$)/g)]
    .map(([, question, answer]) => ({
      '@type': 'Question',
      name: text(question),
      acceptedAnswer: { '@type': 'Answer', text: text(answer) },
    }))
    .filter((item) => item.name && item.acceptedAnswer.text)
}

export const onRequest = defineRouteMiddleware((context) => {
  const route = context.locals.starlightRoute
  const site = context.site
  if (!site) return
  const lang = route.lang === 'es' ? 'es' : 'en'
  const base = import.meta.env.BASE_URL.replace(/\/?$/, '/')
  const root = new URL(base, site).href
  const localeHome = new URL(`${base}${lang === 'es' ? 'es/' : ''}`, site).href
  const page = new URL(context.url.pathname, site).href
  const logo = new URL(`${base}favicon.svg`, site).href
  const image = new URL(`${base}og.png`, site).href
  const organization = { ...ORGANIZATION, logo }
  const websiteId = `${root}#website`
  const website = {
    '@type': 'WebSite',
    '@id': websiteId,
    url: root,
    name: NAMES.en.site,
    description: 'Documentation for Pitangus, the self-hosted, open-source application security platform.',
    inLanguage: ['en', 'es'],
    publisher: { '@id': ORGANIZATION['@id'] },
  }
  const { title, description } = route.entry.data
  const isHome = page === localeHome

  const graph: Record<string, unknown>[] = [organization, website]
  if (isHome) {
    graph.push({
      '@type': 'WebPage',
      '@id': page,
      url: page,
      name: title,
      description,
      inLanguage: lang,
      isPartOf: { '@id': websiteId },
      publisher: { '@id': ORGANIZATION['@id'] },
      ...(route.lastUpdated ? { dateModified: route.lastUpdated.toISOString().slice(0, 10) } : {}),
    })
  } else {
    graph.push(
      {
        '@type': 'TechArticle',
        '@id': `${page}#article`,
        url: page,
        mainEntityOfPage: page,
        headline: title.length > 110 ? `${title.slice(0, 109)}…` : title,
        description,
        inLanguage: lang,
        image,
        isPartOf: { '@id': websiteId },
        author: { '@id': ORGANIZATION['@id'] },
        publisher: { '@id': ORGANIZATION['@id'] },
        ...(route.lastUpdated ? { dateModified: route.lastUpdated.toISOString().slice(0, 10) } : {}),
      },
      {
        '@type': 'BreadcrumbList',
        '@id': `${page}#breadcrumb`,
        itemListElement: [
          { '@type': 'ListItem', position: 1, name: NAMES[lang].home, item: localeHome },
          { '@type': 'ListItem', position: 2, name: title, item: page },
        ],
      },
    )
  }
  const slug = route.id.replace(/^es\/?/, '')
  if (slug === 'faq' && route.entry.rendered?.html) {
    graph.push({
      '@type': 'FAQPage',
      '@id': `${page}#faq`,
      url: page,
      name: title,
      inLanguage: lang,
      isPartOf: { '@id': websiteId },
      mainEntity: faqItems(route.entry.rendered.html),
    })
  }

  route.head.push({
    tag: 'script',
    attrs: { type: 'application/ld+json' },
    content: json({ '@context': 'https://schema.org', '@graph': graph }),
  })
  route.head.push({ tag: 'meta', attrs: { name: 'twitter:title', content: title } })
  if (description) route.head.push({ tag: 'meta', attrs: { name: 'twitter:description', content: description } })
})
