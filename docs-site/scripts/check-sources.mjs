import { readFile, readdir } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { descriptions, spanishNames } from './pages.mjs'

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

const english = (await readdir(docs)).filter((name) => name !== 'README.md' && name.endsWith('.md'))
const spanish = (await readdir(path.join(docs, 'es'))).filter((name) => name !== 'README.md' && name.endsWith('.md'))
const problems = []
for (const name of spanish) {
  const counterpart = spanishNames[name]
  if (!counterpart) problems.push(`docs/es/${name} is not mapped in scripts/pages.mjs`)
  else if (!english.includes(counterpart)) problems.push(`docs/es/${name} maps to docs/${counterpart}, which doesn't exist`)
}
const translated = new Set(Object.values(spanishNames))
for (const name of english) {
  if (!translated.has(name) || !spanish.some((es) => spanishNames[es] === name)) problems.push(`docs/${name} has no Spanish counterpart`)
}
for (const slug of [...english.map((name) => name.replace(/\.md$/, '')), 'changelog', 'contributing']) {
  for (const locale of ['en', 'es']) {
    const text = descriptions[locale][slug]
    if (!text) problems.push(`No ${locale} description for "${slug}" in scripts/pages.mjs`)
    // Search engines cut descriptions around 160 characters.
    else if (text.length < 50 || text.length > 160) problems.push(`The ${locale} description of "${slug}" has ${text.length} characters (50–160)`)
  }
}
const titles = new Map()
for (const [directory, names] of [[docs, english], [path.join(docs, 'es'), spanish]]) {
  for (const name of names) {
    const source = await readFile(path.join(directory, name), 'utf8')
    const headings = source.replace(/^```[\s\S]*?^```/gm, '').match(/^# .+$/gm) ?? []
    if (headings.length !== 1) problems.push(`${path.relative(root, path.join(directory, name))} has ${headings.length} H1 headings (one expected)`)
    const title = headings[0]?.slice(2).trim()
    if (title && titles.has(title)) problems.push(`"${title}" is the title of both ${titles.get(title)} and ${name}`)
    if (title) titles.set(title, name)
  }
}
if (problems.length) throw new Error(`Documentation sources:\n${problems.join('\n')}`)

const openapi = JSON.parse(await readFile(path.join(root, 'web', 'src', 'shared', 'api', 'openapi.json'), 'utf8'))
for (const route of ['/api/health', '/api/metrics', '/api/cron', '/api/ci/sarif']) {
  if (!openapi.paths[route]) throw new Error(`Automation route missing from OpenAPI: ${route}`)
}

console.log(`Validated ${declared.length - intentionallyInternal.size} documented settings, ${english.length} English/Spanish page pairs with unique titles and descriptions, and OpenAPI automation routes`)
