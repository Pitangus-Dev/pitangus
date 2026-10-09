import { readFile, readdir, stat } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const siteRoot = path.resolve(fileURLToPath(new URL('..', import.meta.url)))
const dist = path.join(siteRoot, 'dist')
const configuredBase = (process.env.BASE_PATH ?? '/').replace(/\/$/, '')

async function files(directory) {
  const entries = await readdir(directory, { withFileTypes: true })
  const nested = await Promise.all(entries.map((entry) => {
    const target = path.join(directory, entry.name)
    return entry.isDirectory() ? files(target) : [target]
  }))
  return nested.flat()
}

async function exists(target) {
  try {
    return (await stat(target)).isFile()
  } catch {
    return false
  }
}

const htmlFiles = (await files(dist)).filter((file) => file.endsWith('.html'))
const errors = []

for (const file of htmlFiles) {
  const html = await readFile(file, 'utf8')
  const relativeFile = path.relative(dist, file).split(path.sep).join('/')
  const prefix = configuredBase && configuredBase !== '/' ? `${configuredBase}/` : '/'
  const pageUrl = `https://docs.invalid${prefix}${relativeFile.replace(/index\.html$/, '')}`
  for (const match of html.matchAll(/(?:href|src)="([^"]+)"/g)) {
    const reference = match[1].replaceAll('&amp;', '&')
    if (/^(?:https?:|mailto:|tel:|data:|javascript:|#)/.test(reference)) continue
    const url = new URL(reference, pageUrl)
    let pathname = decodeURIComponent(url.pathname)
    if (configuredBase && configuredBase !== '/') {
      if (!pathname.startsWith(`${configuredBase}/`) && pathname !== configuredBase) {
        errors.push(`${relativeFile}: reference escapes BASE_PATH: ${reference}`)
        continue
      }
      pathname = pathname.slice(configuredBase.length) || '/'
    }
    const relativeTarget = pathname.replace(/^\//, '')
    const candidates = pathname.endsWith('/')
      ? [path.join(dist, relativeTarget, 'index.html')]
      : [path.join(dist, relativeTarget), path.join(dist, relativeTarget, 'index.html'), path.join(dist, `${relativeTarget}.html`)]
    if (!(await Promise.all(candidates.map(exists))).some(Boolean)) errors.push(`${relativeFile}: missing ${reference}`)
  }
}

if (errors.length) throw new Error(`Broken internal links:\n${errors.slice(0, 50).join('\n')}${errors.length > 50 ? `\n… and ${errors.length - 50} more` : ''}`)
console.log(`Checked internal links in ${htmlFiles.length} generated HTML pages`)
