// What a view or a file covers (Findings, the evidence files): one asset, one organization, several chosen assets or
// everything; and how a scope of more than one travels to the API (POST body and GET query string).
export type Scope = { kind: 'one' | 'account' | 'assets' | 'all'; account: string; assets: { key: string; name: string; image: boolean }[]; images: boolean }
export const ALL: Scope = { kind: 'all', account: '', assets: [], images: true }

// What the portfolio files are about, in the shape the API takes: the POST body and the GET query string.
export function scopeBody(scope: Scope): { assets?: string[]; account?: string; include_images?: boolean } {
  if (scope.kind === 'account') return { account: scope.account, include_images: scope.images }
  if (scope.kind === 'assets') return { assets: scope.assets.map(item => item.key), include_images: scope.images }
  return {}
}
export function scopeQuery(scope: Scope): string {
  const body = scopeBody(scope)
  return [...(body.assets ?? []).map(key => `assets=${encodeURIComponent(key)}`), ...(body.account ? [`account=${encodeURIComponent(body.account)}`] : []),
    ...(body.include_images === false ? ['include_images=false'] : [])].join('&')
}
// A single asset is ready once picked, which the hub knows (it holds the asset); here only the portfolio kinds.
export const scopeReady = (scope: Scope) => scope.kind === 'all' || (scope.kind === 'account' ? Boolean(scope.account) : scope.kind === 'assets' && scope.assets.length > 0)

// Assets one scope (and one consolidated report) takes: provenance.SCOPE_MAX on the server.
export const SCOPE_MAX = 500

// The scope in the address (#/findings?scope=account&account=org): a reload or a shared link lands on the same view.
// Only keys travel; names come back with the data (`withNames`; until then a chip shows its key).
export function scopeFromParams(params: URLSearchParams): Scope | null {
  const kind = params.get('scope')
  if (kind !== 'account' && kind !== 'assets' && kind !== 'all') return null
  const keys = kind === 'assets' ? (params.get('assets') ?? '').split(',').filter(Boolean).slice(0, SCOPE_MAX) : []
  const assets = keys.flatMap(raw => { try { const key = decodeURIComponent(raw); return [{ key, name: key, image: key.startsWith('image:') }] } catch { return [] } })
  return { kind, account: kind === 'account' ? (params.get('account') ?? '').slice(0, 100) : '', assets, images: params.get('images') !== '0' }
}
export function scopeParams(scope: Scope): Record<'scope' | 'account' | 'assets' | 'images', string | null> {
  const chosen = scope.kind === 'account' || scope.kind === 'assets'
  return { scope: scope.kind === 'one' ? null : scope.kind, account: scope.kind === 'account' && scope.account ? scope.account : null,
    assets: scope.kind === 'assets' && scope.assets.length ? scope.assets.map(item => encodeURIComponent(item.key)).join(',') : null,
    images: chosen && !scope.images ? '0' : null }
}
// The chosen assets named after `rows` (the assets a scoped view returned), for those still known only by their key.
export function withNames(scope: Scope, rows: { key: string; name: string; kind: string }[] | undefined): Scope {
  if (scope.kind !== 'assets' || !rows) return scope
  return { ...scope, assets: scope.assets.map(item => {
    const row = item.name === item.key ? rows.find(entry => entry.key === item.key) : undefined
    return row ? { ...item, name: row.name, image: row.kind === 'image' } : item
  }) }
}
