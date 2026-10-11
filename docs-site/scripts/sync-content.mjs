import { execFile } from 'node:child_process'
import { cp, mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'
import { descriptions, spanishNames } from './pages.mjs'

const siteRoot = path.resolve(fileURLToPath(new URL('..', import.meta.url)))
const repositoryRoot = path.resolve(siteRoot, '..')
const docsRoot = path.join(repositoryRoot, 'docs')
const generatedRoot = path.join(siteRoot, 'src', 'content', 'docs')
const repositoryUrl = 'https://github.com/Pitangus-Dev/pitangus'
const screenshotsRoot = path.join(siteRoot, 'public', 'screenshots')
// `--placeholders` (the dev server) marks where a missing screenshot goes; a build simply leaves it out.
const placeholders = process.argv.includes('--placeholders')

const yaml = (value) => JSON.stringify(value)
const slash = (value) => value.split(path.sep).join('/')

function outputForSource(source) {
  const relative = path.relative(docsRoot, source)
  if (relative === 'README.md') return 'index.md'
  if (relative === path.join('es', 'README.md')) return 'es/index.md'
  if (relative.startsWith(`es${path.sep}`)) {
    const name = spanishNames[path.basename(relative)] ?? path.basename(relative)
    return `es/${name}`
  }
  return slash(relative)
}

function routeFor(output) {
  const extensionless = slash(output).replace(/\.(?:md|mdx)$/, '')
  const route = extensionless === 'index' ? '' : extensionless.replace(/\/index$/, '')
  return `/${route}${route ? '/' : ''}`
}

async function exists(target) {
  try {
    await stat(target)
    return true
  } catch {
    return false
  }
}

async function rewriteLinks(markdown, source, output) {
  const matches = [...markdown.matchAll(/(?<!!)\[([^\]]+)\]\(([^)\s]+)(?:\s+"([^"]*)")?\)/g)]
  let cursor = 0
  let result = ''

  for (const match of matches) {
    const [whole, label, rawTarget, title] = match
    result += markdown.slice(cursor, match.index)
    cursor = match.index + whole.length
    if (/^(?:[a-z]+:|#)/i.test(rawTarget)) {
      result += whole
      continue
    }

    const [pathname, fragment] = rawTarget.split('#', 2)
    const resolved = path.resolve(path.dirname(source), decodeURIComponent(pathname))
    const inDocs = path.relative(docsRoot, resolved)
    let replacement

    if (!inDocs.startsWith('..') && /\.mdx?$/.test(resolved) && await exists(resolved)) {
      const targetOutput = outputForSource(resolved)
      const relativeRoute = path.posix.relative(routeFor(output), routeFor(targetOutput)) || '.'
      replacement = `${relativeRoute.replace(/\/$/, '')}/${fragment ? `#${fragment}` : ''}`
    } else if (await exists(resolved) && !path.relative(repositoryRoot, resolved).startsWith('..')) {
      const repositoryPath = slash(path.relative(repositoryRoot, resolved))
      const kind = (await stat(resolved)).isDirectory() ? 'tree' : 'blob'
      replacement = `${repositoryUrl}/${kind}/main/${repositoryPath}${fragment ? `#${fragment}` : ''}`
    } else {
      replacement = rawTarget
    }

    result += `[${label}](${replacement}${title ? ` "${title}"` : ''})`
  }
  return result + markdown.slice(cursor)
}

const run = promisify(execFile)

async function lastCommitDate(source) {
  try {
    const { stdout } = await run('git', ['log', '-1', '--format=%cs', '--', source], { cwd: repositoryRoot })
    return stdout.trim() || null
  } catch {
    return null
  }
}

// Outside fenced code, so a sample that shows the syntax stays as written.
function outsideCode(markdown, transform) {
  return markdown.split(/(^```[\s\S]*?^```)/m).map((part, index) => (index % 2 ? part : transform(part))).join('')
}

// GitHub alerts (`> [!NOTE]`) render on GitHub and become Starlight asides here.
const ASIDES = { NOTE: 'note', IMPORTANT: 'note', TIP: 'tip', WARNING: 'caution', CAUTION: 'danger' }
function convertAlerts(markdown) {
  return markdown.replace(/^> \[!(NOTE|IMPORTANT|TIP|WARNING|CAUTION)\][^\n]*\n((?:>[^\n]*\n?)*)/gm, (_, kind, body) => {
    const text = body.split('\n').map((line) => line.replace(/^> ?/, '')).join('\n').trim()
    return `:::${ASIDES[kind]}\n${text}\n:::\n`
  })
}

const escapeHtml = (value) => value.replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')

// `<!-- screenshot: name | alt text -->` shows docs-site/public/screenshots/name-{light,dark}.png following the theme.
// A missing image is left out of a build, so the site never shows a broken picture.
async function convertScreenshots(markdown, assetPrefix, locale) {
  const matches = [...markdown.matchAll(/^<!--\s*screenshot:\s*([a-z0-9-]+)\s*\|\s*(.+?)\s*-->$/gm)]
  let result = markdown
  for (const [whole, name, alt] of matches) {
    const variants = {}
    for (const theme of ['light', 'dark']) {
      if (await exists(path.join(screenshotsRoot, `${name}-${theme}.png`))) variants[theme] = `${assetPrefix}screenshots/${name}-${theme}.png`
    }
    const light = variants.light ?? variants.dark
    const dark = variants.dark ?? variants.light
    let html = ''
    if (light) {
      const image = (src, hiddenIn) => `<img class="${hiddenIn}:sl-hidden" src="${src}" alt="${escapeHtml(alt)}" width="1440" height="900" loading="lazy" decoding="async">`
      html = light === dark
        ? `<figure class="screenshot"><img src="${light}" alt="${escapeHtml(alt)}" width="1440" height="900" loading="lazy" decoding="async"></figure>`
        : `<figure class="screenshot">${image(light, 'dark')}${image(dark, 'light')}</figure>`
    } else if (placeholders) {
      const label = locale === 'es' ? 'Captura pendiente' : 'Screenshot pending'
      html = `<figure class="screenshot screenshot--pending"><figcaption><strong>${label}: ${name}</strong> ${escapeHtml(alt)}</figcaption></figure>`
    }
    result = result.replace(whole, () => html)
  }
  return result
}

// GitHub renders Mermaid; the site doesn't, so a ```mermaid block must be preceded by
// `<!-- diagram: name | alt text | caption -->` and is replaced by docs/assets/name-<locale>-{light,dark}.svg
// (or name-{light,dark}.svg), following the theme. The Mermaid source stays the one GitHub shows.
async function convertDiagrams(markdown, assetPrefix, locale, source) {
  const where = path.relative(repositoryRoot, source)
  const pattern = /^<!--\s*diagram:\s*([a-z0-9-]+)\s*\|\s*([^|]+?)\s*\|\s*(.+?)\s*-->\n```mermaid\n[\s\S]*?^```$/gm
  let result = markdown
  for (const [whole, name, alt, caption] of [...markdown.matchAll(pattern)]) {
    const files = {}
    for (const theme of ['light', 'dark']) {
      for (const file of [`${name}-${locale}-${theme}.svg`, `${name}-${theme}.svg`]) {
        if (!files[theme] && await exists(path.join(docsRoot, 'assets', file))) files[theme] = file
      }
      if (!files[theme]) throw new Error(`Missing docs/assets/${name}-${locale}-${theme}.svg for the diagram in ${where}`)
    }
    const { width, height } = await svgSize(path.join(docsRoot, 'assets', files.light))
    const image = (file, hiddenIn) => `<img class="${hiddenIn}:sl-hidden" src="${assetPrefix}assets/${file}" alt="${escapeHtml(alt)}" width="${width}" height="${height}" loading="lazy" decoding="async">`
    const html = `<figure class="diagram"><div class="diagram__frame" tabindex="0" role="region" aria-labelledby="diagram-${name}">${image(files.light, 'dark')}${image(files.dark, 'light')}</div><figcaption id="diagram-${name}">${escapeHtml(caption)}</figcaption></figure>`
    result = result.replace(whole, () => html)
  }
  if (/^```mermaid$/m.test(result)) throw new Error(`A Mermaid block in ${where} has no <!-- diagram: name | alt | caption --> line before it`)
  return result
}

async function svgSize(file) {
  const viewBox = (await readFile(file, 'utf8')).match(/viewBox="0 0 (\d+(?:\.\d+)?) (\d+(?:\.\d+)?)"/)
  if (!viewBox) throw new Error(`${path.relative(repositoryRoot, file)} has no viewBox`)
  return { width: Math.round(Number(viewBox[1])), height: Math.round(Number(viewBox[2])) }
}

async function prepareMarkdown(source, output, locale) {
  let markdown = (await readFile(source, 'utf8')).replace(/\r\n/g, '\n')
  markdown = markdown.replace(/^(?:English\b.*|\[English\].*)\n+/, '')
  const heading = markdown.match(/^#\s+(.+)$/m)
  if (!heading) throw new Error(`Missing H1 in ${path.relative(repositoryRoot, source)}`)
  // The title is plain text (the <title>, the sidebar, search results): no Markdown code marks.
  const title = heading[1].replaceAll('`', '').trim()
  markdown = `${markdown.slice(0, heading.index)}${markdown.slice(heading.index + heading[0].length)}`.replace(/^\n+/, '')
  const assetPrefix = '../'.repeat(routeFor(output).split('/').filter(Boolean).length)
  markdown = markdown.replace(/(<img\s+[^>]*src=["'])\.\.\/assets\//g, `$1${assetPrefix}assets/`)
  markdown = markdown.replace(/(<img\s+[^>]*src=["'])assets\//g, `$1${assetPrefix}assets/`)
  markdown = await rewriteLinks(markdown, source, output)
  markdown = await convertDiagrams(markdown, assetPrefix, locale, source)
  markdown = outsideCode(markdown, convertAlerts)
  markdown = await convertScreenshots(markdown, assetPrefix, locale)
  const slug = path.basename(output).replace(/\.md$/, '')
  const description = descriptions[locale][slug]
  if (!description) throw new Error(`Missing ${locale} description for "${slug}" in scripts/pages.mjs`)
  const sourceUrl = `${repositoryUrl}/edit/main/${slash(path.relative(repositoryRoot, source))}`
  const updated = await lastCommitDate(source)
  return `---\ntitle: ${yaml(title)}\ndescription: ${yaml(description)}\neditUrl: ${yaml(sourceUrl)}\n${updated ? `lastUpdated: ${updated}\n` : ''}---\n\n${markdown.trim()}\n`
}

function schemaName(schema) {
  if (!schema) return '—'
  if (schema.$ref) return `\`${schema.$ref.split('/').at(-1)}\``
  if (schema.type === 'array') return `array of ${schemaName(schema.items)}`
  return `\`${schema.type ?? 'object'}\``
}

function securityLabel(security, locale) {
  const names = new Set((security ?? []).flatMap((entry) => Object.keys(entry)))
  if (names.has('metrics')) return locale === 'es' ? 'Bearer: token de métricas' : 'Bearer: metrics token'
  if (names.has('cron')) return locale === 'es' ? 'Bearer: token de cron' : 'Bearer: cron token'
  if (names.has('import')) return locale === 'es' ? 'Bearer: token de importación' : 'Bearer: import token'
  return locale === 'es' ? 'Público' : 'Public'
}

function generateApi(spec, locale) {
  const spanish = locale === 'es'
  const allowedSchemes = new Set(['metrics', 'cron', 'import'])
  const operations = []
  for (const [route, methods] of Object.entries(spec.paths)) {
    for (const [method, operation] of Object.entries(methods)) {
      if (!['get', 'post', 'put', 'patch', 'delete'].includes(method)) continue
      const security = operation.security ?? spec.security
      const schemes = new Set((security ?? []).flatMap((entry) => Object.keys(entry)))
      const explicitlyPublic = (operation.security ?? []).some((entry) => Object.keys(entry).length === 0)
      if (!explicitlyPublic && ![...schemes].some((name) => allowedSchemes.has(name))) continue
      operations.push({ method: method.toUpperCase(), route, operation, security })
    }
  }

  const lines = [
    '---',
    `title: ${yaml(spanish ? 'API de automatización' : 'Automation API')}`,
    `description: ${yaml(spanish ? 'Referencia generada desde OpenAPI para las rutas públicas de salud, métricas, tareas periódicas e importación SARIF.' : 'OpenAPI-generated reference for the public health, metrics, periodic-task, and SARIF import routes.')}`,
    `editUrl: ${yaml(`${repositoryUrl}/edit/main/web/src/shared/api/openapi.json`)}`,
    '---',
    '',
    spanish
      ? 'Esta referencia se genera durante el build a partir de `web/src/shared/api/openapi.json`. No se mantiene una lista paralela de rutas.'
      : 'This reference is generated at build time from `web/src/shared/api/openapi.json`. There is no separately maintained endpoint list.',
    '',
    spanish
      ? ':::caution[No es una API pública general]\nLas rutas de sesión que usa el panel no son una API estable para integraciones y se excluyen deliberadamente. El servidor tampoco publica Swagger UI, ReDoc ni el documento OpenAPI. Ejecuta `make openapi` después de cambiar una ruta.\n:::'
      : ':::caution[Not a general public API]\nThe session routes used by the panel are not a stable integration API and are deliberately excluded. The server also does not serve Swagger UI, ReDoc, or the OpenAPI document. Run `make openapi` after changing a route.\n:::',
    '',
    `| ${spanish ? 'Método' : 'Method'} | ${spanish ? 'Ruta' : 'Path'} | ${spanish ? 'Propósito' : 'Purpose'} | ${spanish ? 'Acceso' : 'Access'} |`,
    '| --- | --- | --- | --- |',
  ]

  for (const item of operations) {
    lines.push(`| \`${item.method}\` | \`${item.route}\` | ${item.operation.summary ?? '—'} | ${securityLabel(item.security, locale)} |`)
  }

  for (const item of operations) {
    const { operation } = item
    lines.push('', `## ${item.method} ${item.route}`, '', operation.description || operation.summary || '')
    lines.push('', `**${spanish ? 'Autenticación' : 'Authentication'}:** ${securityLabel(item.security, locale)}.`)
    const parameters = operation.parameters ?? []
    if (parameters.length) {
      lines.push('', `### ${spanish ? 'Parámetros' : 'Parameters'}`, '', `| ${spanish ? 'Nombre' : 'Name'} | ${spanish ? 'Ubicación' : 'In'} | ${spanish ? 'Tipo' : 'Type'} | ${spanish ? 'Obligatorio' : 'Required'} |`, '| --- | --- | --- | --- |')
      for (const parameter of parameters) {
        lines.push(`| \`${parameter.name}\` | ${parameter.in} | ${schemaName(parameter.schema)} | ${parameter.required ? (spanish ? 'Sí' : 'Yes') : (spanish ? 'No' : 'No')} |`)
      }
    }
    const request = operation.requestBody?.content?.['application/json']?.schema
      ?? operation.requestBody?.content?.['multipart/form-data']?.schema
    if (request) lines.push('', `**${spanish ? 'Cuerpo' : 'Body'}:** ${schemaName(request)}.`)
    lines.push('', `### ${spanish ? 'Respuestas' : 'Responses'}`, '', `| ${spanish ? 'Estado' : 'Status'} | ${spanish ? 'Descripción' : 'Description'} |`, '| --- | --- |')
    for (const [status, response] of Object.entries(operation.responses ?? {})) {
      lines.push(`| \`${status}\` | ${response.description ?? '—'} |`)
    }
  }
  return `${lines.join('\n')}\n`
}

await rm(generatedRoot, { recursive: true, force: true })
await mkdir(generatedRoot, { recursive: true })

for (const locale of ['en', 'es']) {
  const sourceDirectory = locale === 'en' ? docsRoot : path.join(docsRoot, 'es')
  for (const entry of await readdir(sourceDirectory, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith('.md') || entry.name === 'README.md') continue
    const source = path.join(sourceDirectory, entry.name)
    const output = outputForSource(source)
    const destination = path.join(generatedRoot, output)
    await mkdir(path.dirname(destination), { recursive: true })
    await writeFile(destination, await prepareMarkdown(source, output, locale))
  }
}

for (const [locale, sourceName] of [['en', 'CONTRIBUTING.md'], ['es', 'CONTRIBUTING.es.md']]) {
  const source = path.join(repositoryRoot, '.github', sourceName)
  const output = `${locale === 'es' ? 'es/' : ''}contributing.md`
  await mkdir(path.dirname(path.join(generatedRoot, output)), { recursive: true })
  await writeFile(path.join(generatedRoot, output), await prepareMarkdown(source, output, locale))
}

// The changelog is written in English only; the Spanish page says so and shows the same text.
const changelog = path.join(repositoryRoot, 'CHANGELOG.md')
await writeFile(path.join(generatedRoot, 'changelog.md'), await prepareMarkdown(changelog, 'changelog.md', 'en'))
const spanishChangelog = (await prepareMarkdown(changelog, 'es/changelog.md', 'es'))
  .replace(/^title: .*$/m, `title: ${yaml('Historial de cambios')}`)
  .replace(/^---\n\n/m, '---\n\n:::note\nEl historial de cambios se publica solo en inglés, tal como lo escribe el proyecto en cada versión.\n:::\n\n')
await writeFile(path.join(generatedRoot, 'es', 'changelog.md'), spanishChangelog)

await cp(path.join(siteRoot, 'content'), generatedRoot, { recursive: true })
await cp(path.join(docsRoot, 'assets'), path.join(generatedRoot, 'assets'), { recursive: true })

const openapiSource = path.join(repositoryRoot, 'web', 'src', 'shared', 'api', 'openapi.json')
const openapi = JSON.parse(await readFile(openapiSource, 'utf8'))
await mkdir(path.join(generatedRoot, 'reference'), { recursive: true })
await mkdir(path.join(generatedRoot, 'es', 'reference'), { recursive: true })
await writeFile(path.join(generatedRoot, 'reference', 'api.md'), generateApi(openapi, 'en'))
await writeFile(path.join(generatedRoot, 'es', 'reference', 'api.md'), generateApi(openapi, 'es'))

await mkdir(path.join(siteRoot, 'public'), { recursive: true })
await mkdir(path.join(siteRoot, 'src', 'assets'), { recursive: true })
await rm(path.join(siteRoot, 'public', 'openapi.json'), { force: true })
await cp(path.join(docsRoot, 'assets'), path.join(siteRoot, 'public', 'assets'), { recursive: true })
for (const logo of ['pitangus-logo.svg', 'pitangus-icon.svg']) {
  await cp(path.join(repositoryRoot, 'web', 'public', 'assets', logo), path.join(siteRoot, 'src', 'assets', logo))
}
await cp(path.join(repositoryRoot, 'web', 'public', 'assets', 'favicon.svg'), path.join(siteRoot, 'public', 'favicon.svg'))

console.log(`Synced documentation into ${path.relative(repositoryRoot, generatedRoot)}`)
