// @ts-check
import { defineConfig } from 'astro/config'
import starlight from '@astrojs/starlight'
import { ExpressiveCodeTheme } from '@astrojs/starlight/expressive-code'

const site = process.env.SITE_URL ?? 'https://docs.pitangus.dev'
const base = process.env.BASE_PATH ?? '/'
const absolute = (file) => new URL(`${base.replace(/\/?$/, '/')}${file}`, site).href

const es = (label) => ({ es: label })
const page = (slug, label, spanish) => ({ slug, label, translations: es(spanish) })

// Code blocks in the identity manual's colours, nearly monochrome so no state colour reads as a meaning: ink text on
// `sunken`, keywords in ink and semibold, strings in ink-2, literals in info, comments in muted; ok and critical only
// for inserted and deleted lines. Every pair is AA on `sunken` in its theme.
const codeTheme = (type, c) => new ExpressiveCodeTheme({
  name: `pitangus-${type}`,
  type,
  colors: { 'editor.background': c.bg, 'editor.foreground': c.ink },
  tokenColors: [
    { scope: ['comment', 'punctuation.definition.comment'], settings: { foreground: c.muted, fontStyle: 'italic' } },
    { scope: ['keyword', 'storage', 'storage.type', 'keyword.operator.new', 'entity.name.tag', 'support.type.property-name'], settings: { foreground: c.ink, fontStyle: 'bold' } },
    { scope: ['string', 'string.quoted', 'markup.inline.raw'], settings: { foreground: c.ink2 } },
    { scope: ['constant', 'constant.numeric', 'constant.language', 'support.constant', 'entity.other.attribute-name', 'variable.other.constant'], settings: { foreground: c.info } },
    { scope: ['entity.name.function', 'support.function', 'meta.function-call'], settings: { foreground: c.ink } },
    { scope: ['punctuation', 'meta.brace', 'keyword.operator'], settings: { foreground: c.ink2 } },
    { scope: ['markup.deleted'], settings: { foreground: c.critical } },
    { scope: ['markup.inserted'], settings: { foreground: c.ok } },
    { scope: ['markup.bold'], settings: { fontStyle: 'bold' } },
  ],
})

const lightCode = codeTheme('light', { bg: '#ECEEF1', ink: '#16181B', ink2: '#3D434A', muted: '#5C636B', info: '#2D5A87', ok: '#1E7444', critical: '#B42318' })
const darkCode = codeTheme('dark', { bg: '#202428', ink: '#ECEEF0', ink2: '#C3C8CE', muted: '#9AA1A9', info: '#8DB4DD', ok: '#5CC98A', critical: '#FF8B7B' })

export default defineConfig({
  site,
  base,
  output: 'static',
  trailingSlash: 'always',
  // The old single features page was split by topic in 0.13.
  redirects: {
    '/features': '/overview/',
    '/es/features': '/es/overview/',
  },
  integrations: [
    starlight({
      title: 'Pitangus Docs',
      description: 'Documentation for Pitangus, the self-hosted, open-source application security platform: install it, scan code, images and websites, triage findings and operate it.',
      logo: {
        light: './src/assets/pitangus-logo.svg',
        dark: './src/assets/pitangus-icon.svg',
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
      customCss: [
        '@fontsource/ibm-plex-sans/latin-400.css',
        '@fontsource/ibm-plex-sans/latin-ext-400.css',
        '@fontsource/ibm-plex-sans/latin-500.css',
        '@fontsource/ibm-plex-sans/latin-ext-500.css',
        '@fontsource/ibm-plex-sans/latin-600.css',
        '@fontsource/ibm-plex-sans/latin-ext-600.css',
        '@fontsource/ibm-plex-mono/latin-400.css',
        '@fontsource/ibm-plex-mono/latin-ext-400.css',
        './src/styles/custom.css',
      ],
      expressiveCode: {
        themes: [darkCode, lightCode],
        useStarlightUiThemeColors: false,
        minSyntaxHighlightingColorContrast: 4.5,
        styleOverrides: {
          borderRadius: '8px',
          borderColor: 'var(--p-line)',
          codeFontFamily: 'var(--__sl-font-mono)',
          uiFontFamily: 'var(--__sl-font)',
          codeFontSize: '0.875rem',
          codeLineHeight: '1.6',
          frames: {
            frameBoxShadowCssValue: 'none',
            editorTabBarBackground: 'var(--p-sunken)',
            editorActiveTabBackground: 'var(--p-sunken)',
            editorActiveTabForeground: 'var(--p-ink)',
            editorActiveTabIndicatorTopColor: 'transparent',
            editorActiveTabIndicatorBottomColor: 'var(--p-ink)',
            editorTabBarBorderBottomColor: 'var(--p-line)',
            terminalTitlebarBackground: 'var(--p-sunken)',
            terminalTitlebarForeground: 'var(--p-muted)',
            terminalTitlebarBorderBottomColor: 'var(--p-line)',
            terminalTitlebarDotsForeground: 'var(--p-line-strong)',
            terminalBackground: 'var(--p-sunken)',
            inlineButtonForeground: 'var(--p-ink)',
            inlineButtonBorder: 'var(--p-line-strong)',
            tooltipSuccessBackground: 'var(--p-ok)',
            tooltipSuccessForeground: 'var(--p-surface)',
          },
        },
      },
      pagefind: true,
      tableOfContents: { minHeadingLevel: 2, maxHeadingLevel: 3 },
      lastUpdated: true,
      head: [
        { tag: 'meta', attrs: { name: 'theme-color', content: '#FFFFFF', media: '(prefers-color-scheme: light)' } },
        { tag: 'meta', attrs: { name: 'theme-color', content: '#181B1E', media: '(prefers-color-scheme: dark)' } },
        { tag: 'meta', attrs: { property: 'og:image', content: absolute('og.png') } },
        { tag: 'meta', attrs: { property: 'og:image:width', content: '1200' } },
        { tag: 'meta', attrs: { property: 'og:image:height', content: '630' } },
        { tag: 'meta', attrs: { property: 'og:image:alt', content: 'Pitangus Docs' } },
        { tag: 'meta', attrs: { name: 'twitter:image', content: absolute('og.png') } },
      ],
      sidebar: [
        {
          label: 'Start here',
          translations: es('Empieza aquí'),
          items: [
            page('overview', 'Overview', 'Vista general'),
            page('quickstart', 'Quickstart', 'Inicio rápido'),
            page('concepts', 'Concepts', 'Conceptos'),
            page('installation', 'Installation', 'Instalación'),
          ],
        },
        {
          label: 'Scanning',
          translations: es('Análisis'),
          items: [
            page('scanning-code', 'Code and dependencies', 'Código y dependencias'),
            page('scanning-images', 'Container images', 'Imágenes de contenedor'),
            page('scanning-web', 'Websites and APIs', 'Sitios web y APIs'),
          ],
        },
        {
          label: 'Findings and triage',
          translations: es('Hallazgos y triage'),
          items: [
            page('findings', 'Findings and triage', 'Hallazgos y triage'),
            page('compliance', 'Compliance evidence', 'Evidencia de cumplimiento'),
            page('threat-modeling', 'Threat modeling', 'Modelado de amenazas'),
          ],
        },
        {
          label: 'Integrations',
          translations: es('Integraciones'),
          items: [
            page('integrations', 'Integrations and automation', 'Integraciones y automatización'),
            page('github-app', 'Connect GitHub', 'Conectar GitHub'),
          ],
        },
        {
          label: 'Deploy and operate',
          translations: es('Despliega y opera'),
          items: [
            page('deploy', 'Where to deploy', 'Dónde desplegar'),
            page('deploy-vps', 'Deploy on a VPS', 'Desplegar en un VPS'),
            page('containers', 'Containers and Makefile', 'Contenedores y Makefile'),
            page('scaling', 'Scaling', 'Escalar'),
            page('upgrading', 'Upgrading', 'Actualizar'),
            page('troubleshooting', 'Troubleshooting', 'Solución de problemas'),
          ],
        },
        {
          label: 'Security',
          translations: es('Seguridad'),
          items: [
            page('security', 'Security model', 'Modelo de seguridad'),
          ],
        },
        {
          label: 'Reference',
          translations: es('Referencia'),
          items: [
            page('cli', 'Command line and CI', 'Línea de comandos y CI'),
            page('reference/api', 'Automation API', 'API de automatización'),
            page('configuration', 'Configuration', 'Configuración'),
            page('architecture', 'Architecture', 'Arquitectura'),
            page('glossary', 'Glossary', 'Glosario'),
            page('faq', 'FAQ', 'Preguntas frecuentes'),
            page('third-party-notices', 'Third-party software', 'Software de terceros'),
            page('brand', 'Brand', 'Marca'),
          ],
        },
        page('changelog', 'Changelog', 'Historial de cambios'),
        {
          label: 'Contribute',
          translations: es('Contribuye'),
          collapsed: true,
          items: [
            page('contributing', 'Contributing', 'Cómo contribuir'),
            page('development', 'Development', 'Desarrollo'),
          ],
        },
      ],
    }),
  ],
})
