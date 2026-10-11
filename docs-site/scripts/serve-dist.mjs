// Serves dist/ the way Cloudflare Workers static assets will (wrangler.jsonc): the rules in dist/_headers, folders as
// /path/ with a redirect from /path, and 404.html with status 404. For checking the CSP in a browser before deploying;
// no dependencies. Usage: node scripts/serve-dist.mjs [port]
import { createServer } from 'node:http'
import { readFile, stat } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const dist = path.resolve(fileURLToPath(new URL('../dist', import.meta.url)))
const port = Number(process.argv[2] ?? 4323)

const types = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png',
  '.jpg': 'image/jpeg', '.webp': 'image/webp', '.woff2': 'font/woff2', '.woff': 'font/woff', '.txt': 'text/plain; charset=utf-8',
  '.xml': 'application/xml', '.wasm': 'application/wasm',
}

const rules = []
for (const line of (await readFile(path.join(dist, '_headers'), 'utf8')).split('\n')) {
  if (!line.trim()) continue
  if (!/^\s/.test(line)) {
    const pattern = new RegExp(`^${line.trim().replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`)
    rules.push({ pattern, headers: [] })
  } else {
    const [name, ...value] = line.trim().split(':')
    rules.at(-1).headers.push([name, value.join(':').trim()])
  }
}

const isFile = async (file) => (await stat(file).catch(() => null))?.isFile()

createServer(async (request, response) => {
  const raw = new URL(request.url, 'http://localhost').pathname
  let pathname
  try { pathname = decodeURIComponent(raw) } catch { response.writeHead(400).end(); return }
  for (const rule of rules) if (rule.pattern.test(pathname)) for (const [name, value] of rule.headers) response.setHeader(name, value)
  let file = path.join(dist, pathname)
  if (file !== dist && !file.startsWith(dist + path.sep)) { response.writeHead(400).end(); return }
  let status = 200
  if (pathname.endsWith('/')) file = path.join(file, 'index.html')
  else if (!(await isFile(file)) && (await isFile(path.join(file, 'index.html')))) {
    response.writeHead(307, { location: `${raw}/` }).end()
    return
  }
  if (!(await isFile(file))) { file = path.join(dist, '404.html'); status = 404 }
  response.writeHead(status, { 'content-type': types[path.extname(file)] ?? 'application/octet-stream' })
  response.end(await readFile(file))
}).listen(port, '127.0.0.1', () => console.log(`dist/ with its _headers at http://127.0.0.1:${port}/`))
