import { readFile, readdir } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const siteRoot = path.resolve(fileURLToPath(new URL('..', import.meta.url)))
const root = path.resolve(siteRoot, '..')
const docs = path.join(root, 'docs')

const settingsSource = await readFile(path.join(root, 'pitangus', 'shared', 'settings.py'), 'utf8')
const settingsBlock = settingsSource.match(/SETTINGS: dict\[str, Setting\] = \{([\s\S]*?)\n\}/)?.[1]
if (!settingsBlock) throw new Error('Could not locate SETTINGS in pitangus/shared/settings.py')

const declared = [...settingsBlock.matchAll(/"([A-Z][A-Z0-9_]+)"\s*:/g)].map((match) => match[1])
const configuration = await readFile(path.join(docs, 'configuration.md'), 'utf8')
const intentionallyInternal = new Set(['PITANGUS_DB_ISOLATE'])
const undocumented = declared.filter((name) => !intentionallyInternal.has(name) && !configuration.includes(`\`${name}\``))
if (undocumented.length) throw new Error(`Environment variables missing from docs/configuration.md: ${undocumented.join(', ')}`)

const spanishNames = new Set([
  'arquitectura.md', 'avisos-de-terceros.md', 'cli.md', 'configuracion.md', 'contenedores.md', 'desarrollo.md',
  'despliegue-vps.md', 'despliegue.md', 'funcionalidades.md', 'github-app.md', 'inicio-rapido.md', 'instalacion.md',
  'integraciones.md', 'marca.md', 'seguridad.md', 'solucion-problemas.md',
])
const actualSpanish = new Set((await readdir(path.join(docs, 'es'))).filter((name) => name !== 'README.md' && name.endsWith('.md')))
for (const expected of spanishNames) {
  if (!actualSpanish.has(expected)) throw new Error(`Missing Spanish documentation source: docs/es/${expected}`)
}

const openapi = JSON.parse(await readFile(path.join(root, 'web', 'src', 'shared', 'api', 'openapi.json'), 'utf8'))
for (const route of ['/api/health', '/api/metrics', '/api/cron', '/api/ci/sarif']) {
  if (!openapi.paths[route]) throw new Error(`Automation route missing from OpenAPI: ${route}`)
}

console.log(`Validated ${declared.length - intentionallyInternal.size} documented settings, English/Spanish sources, and OpenAPI automation routes`)
