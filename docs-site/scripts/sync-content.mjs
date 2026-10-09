import { cp, mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const siteRoot = path.resolve(fileURLToPath(new URL('..', import.meta.url)))
const repositoryRoot = path.resolve(siteRoot, '..')
const docsRoot = path.join(repositoryRoot, 'docs')
const generatedRoot = path.join(siteRoot, 'src', 'content', 'docs')
const repositoryUrl = 'https://github.com/Pitangus-Dev/pitangus'

const spanishNames = {
  'arquitectura.md': 'architecture.md',
  'avisos-de-terceros.md': 'third-party-notices.md',
  'configuracion.md': 'configuration.md',
  'contenedores.md': 'containers.md',
  'desarrollo.md': 'development.md',
  'despliegue-vps.md': 'deploy-vps.md',
  'despliegue.md': 'deploy.md',
  'funcionalidades.md': 'features.md',
  'inicio-rapido.md': 'quickstart.md',
  'instalacion.md': 'installation.md',
  'integraciones.md': 'integrations.md',
  'marca.md': 'brand.md',
  'seguridad.md': 'security.md',
  'solucion-problemas.md': 'troubleshooting.md',
}

const descriptions = {
  en: {
    architecture: 'How the FastAPI API, React panel, workers, PostgreSQL, scan engines, and modular-monolith boundaries fit together.',
    brand: 'Pitangus name, logo, color palette, mascot, and editorial voice.',
    cli: 'Run Pitangus from the terminal and CI, understand exit codes, and export SARIF.',
    configuration: 'Reference for every supported Pitangus environment variable.',
    containers: 'Docker Compose services, Make targets, images, resource limits, and hardening.',
    contributing: 'How to propose changes, meet quality checks, sign the CLA, and work with the project community.',
    development: 'Set up a development environment, run the backend and panel, update OpenAPI, and execute checks.',
    deploy: 'Choose a supported deployment model and configure workers, storage, and periodic tasks.',
    'deploy-vps': 'Deploy Pitangus on a dedicated VPS with HTTPS, backups, monitoring, and safe upgrades.',
    features: 'Verified capabilities of the Pitangus panel, scanners, finding lifecycle, compliance, and threat modeling.',
    'github-app': 'Create and connect the least-privilege GitHub App used for repositories and pull request reviews.',
    installation: 'Requirements, first start, upgrades, backups, restoration, and uninstalling.',
    integrations: 'Connect GitHub, CI, Jira, Slack, Teams, webhooks, and periodic automation without exposing secrets.',
    quickstart: 'Install Pitangus, create the first administrator, run the demo, and verify a finding.',
    security: 'Secret storage, authentication, network boundaries, outbound traffic, and known security trade-offs.',
    'third-party-notices': 'Licenses and provenance for scan engines, advisory data, and bundled dependencies.',
    troubleshooting: 'Diagnose common startup, engine, permission, authentication, and localization problems.',
  },
  es: {
    architecture: 'Cómo encajan la API en FastAPI, el panel en React, los workers, PostgreSQL, los motores y los límites del monolito modular.',
    brand: 'Nombre, logo, paleta de color, mascota y voz editorial de Pitangus.',
    cli: 'Ejecuta Pitangus desde la terminal y CI, entiende los códigos de salida y exporta SARIF.',
    configuration: 'Referencia de todas las variables de entorno compatibles con Pitangus.',
    containers: 'Servicios de Docker Compose, objetivos de Make, imágenes, límites de recursos y endurecimiento.',
    contributing: 'Cómo proponer cambios, cumplir las verificaciones, firmar el CLA y participar en la comunidad.',
    development: 'Prepara el entorno de desarrollo, ejecuta backend y panel, actualiza OpenAPI y corre las verificaciones.',
    deploy: 'Elige un modelo de despliegue compatible y configura workers, almacenamiento y tareas periódicas.',
    'deploy-vps': 'Despliega Pitangus en un VPS dedicado con HTTPS, copias, monitorización y actualizaciones seguras.',
    features: 'Capacidades verificadas del panel, los motores, el ciclo de los hallazgos, cumplimiento y amenazas.',
    'github-app': 'Crea y conecta la GitHub App de privilegios mínimos para repositorios y revisiones de pull requests.',
    installation: 'Requisitos, primer arranque, actualizaciones, copias, restauración y desinstalación.',
    integrations: 'Conecta GitHub, CI, Jira, Slack, Teams, webhooks y automatización periódica sin exponer secretos.',
    quickstart: 'Instala Pitangus, crea la primera cuenta administradora, ejecuta la demo y verifica un hallazgo.',
    security: 'Secretos, autenticación, límites de red, tráfico saliente y concesiones de seguridad conocidas.',
    'third-party-notices': 'Licencias y procedencia de los motores, los datos de avisos y las dependencias incluidas.',
    troubleshooting: 'Diagnostica problemas frecuentes de arranque, motores, permisos, autenticación e idioma.',
  },
}

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

async function prepareMarkdown(source, output, locale) {
  let markdown = (await readFile(source, 'utf8')).replace(/\r\n/g, '\n')
  markdown = markdown.replace(/^(?:English\b.*|\[English\].*)\n+/, '')
  const heading = markdown.match(/^#\s+(.+)$/m)
  if (!heading) throw new Error(`Missing H1 in ${path.relative(repositoryRoot, source)}`)
  const title = heading[1].trim()
  markdown = `${markdown.slice(0, heading.index)}${markdown.slice(heading.index + heading[0].length)}`.replace(/^\n+/, '')
  const assetPrefix = '../'.repeat(routeFor(output).split('/').filter(Boolean).length)
  markdown = markdown.replace(/(<img\s+[^>]*src=["'])\.\.\/assets\//g, `$1${assetPrefix}assets/`)
  markdown = markdown.replace(/(<img\s+[^>]*src=["'])assets\//g, `$1${assetPrefix}assets/`)
  markdown = await rewriteLinks(markdown, source, output)
  const slug = path.basename(output).replace(/\.md$/, '')
  const description = descriptions[locale][slug] ?? descriptions[locale].features
  const sourceUrl = `${repositoryUrl}/edit/main/${slash(path.relative(repositoryRoot, source))}`
  return `---\ntitle: ${yaml(title)}\ndescription: ${yaml(description)}\neditUrl: ${yaml(sourceUrl)}\n---\n\n${markdown.trim()}\n`
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
await cp(path.join(docsRoot, 'assets', 'pitangus.svg'), path.join(siteRoot, 'src', 'assets', 'pitangus.svg'))
await cp(path.join(repositoryRoot, 'web', 'public', 'assets', 'favicon.svg'), path.join(siteRoot, 'public', 'favicon.svg'))

console.log(`Synced documentation into ${path.relative(repositoryRoot, generatedRoot)}`)
