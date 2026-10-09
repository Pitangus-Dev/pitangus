// Navigation in the URL (#/findings?repo=…&run=…): a refresh keeps the user where they were and Back works. The paths
// are English whatever the panel's language, so a shared link works for everyone. The #link=… fragment of invitations
// doesn't start with "/" and isn't touched here.
const SLUGS: Record<string, string> = {
  overview: 'overview', analyses: 'analyses', new: 'new', findings: 'findings', coverage: 'coverage', threats: 'threats',
  repositories: 'repositories', images: 'images', pulls: 'pull-requests', domains: 'domains', integrations: 'integrations',
  users: 'users', account: 'account', cves: 'cve-tracker', compliance: 'compliance', policies: 'policies',
}
// The Spanish paths of earlier versions: links already sent (Jira issues, notifications, bookmarks) keep working and
// are rewritten to the English path.
const LEGACY: Record<string, string> = {
  resumen: 'overview', analisis: 'analyses', nuevo: 'new', hallazgos: 'findings', cobertura: 'coverage', amenazas: 'threats',
  repositorios: 'repositories', imagenes: 'images', dominios: 'domains', integraciones: 'integrations', usuarios: 'users',
  cuenta: 'account', cumplimiento: 'compliance', politicas: 'policies',
}
const VIEWS: Record<string, string> = Object.fromEntries(Object.entries(SLUGS).map(([view, slug]) => [slug, view]))

export function readRoute(): { view: string | null; params: URLSearchParams } {
  const hash = window.location.hash
  if (!hash.startsWith('#/')) return { view: null, params: new URLSearchParams() }
  const [path, search = ''] = hash.slice(2).split('?')
  const legacy = LEGACY[path]
  if (legacy) window.history.replaceState(null, '', `#/${SLUGS[legacy]}${search ? `?${search}` : ''}`)
  return { view: legacy ?? VIEWS[path] ?? null, params: new URLSearchParams(search) }
}

export function writeRoute(view: string, params: Record<string, string | null | undefined> = {}, { replace = false } = {}) {
  const search = new URLSearchParams(Object.entries(params).filter(([, value]) => value) as [string, string][]).toString()
  const next = `#/${SLUGS[view] ?? 'overview'}${search ? `?${search}` : ''}`
  if (next === window.location.hash) return
  if (replace) window.history.replaceState(null, '', next)
  else window.history.pushState(null, '', next)
}

// Changes one parameter without a new history entry (e.g. when choosing a repository).
export function setRouteParam(name: string, value: string | null) {
  const { view, params } = readRoute()
  if (!view) return
  const current = Object.fromEntries(params.entries())
  writeRoute(view, { ...current, [name]: value }, { replace: true })
}
