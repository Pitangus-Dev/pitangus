// Completes the sitemap Starlight generates: each page's <lastmod> (its source's last commit, the date the page shows)
// and an x-default alternate pointing to the English page, as the pages' own <head> already declares.
import { readFile, readdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { markdownFiles, parse } from './llms-txt.mjs'

export default function sitemapLastmod() {
  let config
  return {
    name: 'sitemap-lastmod',
    hooks: {
      'astro:config:done': ({ config: done }) => { config = done },
      'astro:build:done': async ({ dir, logger }) => {
        const root = fileURLToPath(dir)
        const contentRoot = path.join(fileURLToPath(config.root), 'src', 'content', 'docs')
        const base = config.base.replace(/\/?$/, '/')
        const dates = new Map()
        for await (const file of markdownFiles(contentRoot)) {
          const { data } = parse(await readFile(file, 'utf8'))
          if (!data.lastUpdated) continue
          const route = path.relative(contentRoot, file).split(path.sep).join('/').replace(/\.mdx?$/, '').replace(/(^|\/)index$/, '')
          dates.set(new URL(`${base}${route ? `${route}/` : ''}`, config.site).href, data.lastUpdated)
        }
        const sitemaps = (await readdir(root)).filter((name) => /^sitemap-\d+\.xml$/.test(name))
        if (!sitemaps.length) throw new Error('sitemap-lastmod: no sitemap-N.xml in the build; is the sitemap integration still on?')
        let dated = 0
        for (const name of sitemaps) {
          const file = path.join(root, name)
          const xml = (await readFile(file, 'utf8')).replace(/<url><loc>([^<]+)<\/loc>([\s\S]*?)<\/url>/g, (whole, loc, rest) => {
            let extra = rest
            const english = /<xhtml:link rel="alternate" hreflang="en" href="([^"]+)"\/>/.exec(rest)?.[1]
            if (english && !rest.includes('hreflang="x-default"')) extra += `<xhtml:link rel="alternate" hreflang="x-default" href="${english}"/>`
            const date = dates.get(loc)
            if (date && !rest.includes('<lastmod>')) dated++
            return `<url><loc>${loc}</loc>${date && !rest.includes('<lastmod>') ? `<lastmod>${date}</lastmod>` : ''}${extra}</url>`
          })
          await writeFile(file, xml)
        }
        logger.info(`sitemap: ${dated} pages dated, x-default added`)
      },
    },
  }
}
