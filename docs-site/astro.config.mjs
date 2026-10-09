// @ts-check
import { defineConfig } from 'astro/config'
import starlight from '@astrojs/starlight'

const site = process.env.SITE_URL ?? 'https://docs.pitangus.dev'
const base = process.env.BASE_PATH ?? '/'

const translations = (es) => ({ es })

export default defineConfig({
  site,
  base,
  output: 'static',
  trailingSlash: 'always',
  integrations: [
    starlight({
      title: { en: 'Pitangus Docs', es: 'Documentación de Pitangus' },
      description: 'Open-source documentation for Pitangus, the self-hosted application security platform.',
      logo: {
        src: './src/assets/pitangus.svg',
        alt: 'Pitangus',
      },
      favicon: '/favicon.svg',
      disable404Route: true,
      locales: {
        root: { label: 'English', lang: 'en' },
        es: { label: 'Español', lang: 'es' },
      },
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/Pitangus-Dev/pitangus' },
      ],
      customCss: ['./src/styles/custom.css'],
      expressiveCode: { useStarlightUiThemeColors: true },
      pagefind: true,
      tableOfContents: { minHeadingLevel: 2, maxHeadingLevel: 3 },
      head: [
        { tag: 'meta', attrs: { name: 'theme-color', content: '#fbf5e6', media: '(prefers-color-scheme: light)' } },
        { tag: 'meta', attrs: { name: 'theme-color', content: '#16140f', media: '(prefers-color-scheme: dark)' } },
        { tag: 'meta', attrs: { property: 'og:site_name', content: 'Pitangus Docs' } },
      ],
      sidebar: [
        {
          label: 'Start here',
          translations: translations('Empieza aquí'),
          items: [
            { slug: 'quickstart' },
            { slug: 'installation' },
          ],
        },
        {
          label: 'Use Pitangus',
          translations: translations('Usa Pitangus'),
          items: [
            { slug: 'features' },
            { slug: 'github-app' },
            { slug: 'integrations' },
            { slug: 'cli' },
          ],
        },
        {
          label: 'Deploy and operate',
          translations: translations('Despliega y opera'),
          items: [
            { slug: 'configuration' },
            { slug: 'containers' },
            { slug: 'deploy' },
            { slug: 'deploy-vps' },
            { slug: 'scaling' },
            { slug: 'security' },
            { slug: 'troubleshooting' },
          ],
        },
        {
          label: 'Reference',
          translations: translations('Referencia'),
          items: [
            { slug: 'reference/api' },
            { slug: 'architecture' },
            { slug: 'third-party-notices' },
            { slug: 'brand' },
          ],
        },
        {
          label: 'Contribute',
          translations: translations('Contribuye'),
          items: [
            { slug: 'contributing' },
            { slug: 'development' },
          ],
        },
      ],
    }),
  ],
})
